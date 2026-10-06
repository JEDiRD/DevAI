param([Parameter(Mandatory=$true)][string]$PackageRoot,
      [switch]$ValidateOnly,
      [switch]$ResumeServiceCreation,
      [switch]$InspectInstall,
      [string]$WorkerId='',
      [string]$ApiBaseUrl='',
      [string]$ExistingConfig='',
      [switch]$ReusePersonalFixture,
      [switch]$WorkerTokenFromStdin)
$ErrorActionPreference='Stop'
# Helpers are loaded BEFORE any validation so the authoritative manifest and
# target-state implementations are used instead of a forked copy here.
. (Join-Path $PSScriptRoot 'install-support.ps1')

$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path

# A package.json-only artifact is a legacy release format. Fail clearly; never
# crash on a missing property and never dual-read.
$hasLegacy=Test-Path -LiteralPath (Join-Path $PackageRoot 'package.json')
$hasRelease=Test-Path -LiteralPath (Join-Path $PackageRoot 'manifest.json')
if ($hasLegacy -and !$hasRelease) { throw 'UNSUPPORTED_LEGACY_PACKAGE_FORMAT' }

# --- IMMUTABLE RELEASE VERIFICATION (no target mutation may precede this) ---
$manifest=Read-ReleaseManifest $PackageRoot
$verifiedFiles=Assert-ManifestPayload $PackageRoot $manifest | Out-Null
Assert-ManifestRequiredMembers $manifest @(
  'install-worker.ps1','install-support.ps1','control/worker_agent/windows_service.py')
# Recompute the V2 identity aggregate from verified payload bytes and compare.
Assert-ManifestIdentityAggregate $PackageRoot $manifest | Out-Null

# --- INSTALL PAYLOAD PREFLIGHT (read-only; before ValidateOnly success) ---
# A manifest can be internally self-consistent yet describe an uninstallable
# payload (observed: a silently dropped sandbox-runtime verified clean, then
# failed install with PathNotFound at the copy loop). ValidateOnly success
# must therefore mean structurally installable, not merely manifest-valid:
# fail closed here, before the ValidateOnly return and before identity,
# elevation and any target mutation (ProgramData/Files, ACLs, services,
# credentials). Test-Path only, so the read-only boundary above is preserved.
foreach ($directory in @('control','host-runtime','sandbox-runtime')) {
  if (!(Test-Path -LiteralPath (Join-Path $PackageRoot $directory) -PathType Container)) { throw "INSTALL_PAYLOAD_INCOMPLETE:$directory" }
}
foreach ($required in (Get-RequiredInstallPayloadMembers)) {
  if (!(Test-Path -LiteralPath (Join-Path $PackageRoot ($required -replace '/', [IO.Path]::DirectorySeparatorChar)) -PathType Leaf)) { throw "INSTALL_PAYLOAD_INCOMPLETE:$required" }
}

if ($ValidateOnly) { Write-Output 'DEVAI_PACKAGE_VALIDATED'; return }

# --- TARGET IDENTITY (read-only; never mutates the target) ---
# Identity and endpoint are TARGET CONFIG. They are never concrete data in
# manifest.json. A fresh install must supply both; -ExistingConfig is
# explicit-only and validated here. Disagreement between CLI and config fails
# closed: there is deliberately NO precedence rule.
$stateRoot=Join-Path $env:ProgramData 'DevAIWorker'
$identity=Resolve-InstallerTargetIdentity -WorkerId $WorkerId -ApiBaseUrl $ApiBaseUrl -ExistingConfig $ExistingConfig

# Installation boundary: package validation above performs read-only operations.
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_INSTALL_REQUIRED' }
$installRoot=Join-Path $env:ProgramFiles 'DevAIWorker'
$stateRoot=Join-Path $env:ProgramData 'DevAIWorker'
. (Join-Path $PackageRoot 'install-support.ps1')
if ($InspectInstall -and !$ResumeServiceCreation) { throw 'INSPECT_REQUIRES_EXPLICIT_RESUME' }
if ($ResumeServiceCreation) {
  # Entire existing installation and volume are checked read-only FIRST.
  $partial=Assert-PartialWorkerInstall $installRoot $stateRoot $manifest
  Write-Output (@{partial_install_validated=$true;volume=$partial.volume;volume_reformatted=$false} | ConvertTo-Json -Depth 4 -Compress)
  if ($InspectInstall) { return }
  # Preserve credential/config/VHDX/workspaces. Upgrade only this manifested
  # mount helper to suppress automatic drive letters on subsequent boots.
  $helperRelative='control/worker_agent/volume_host.py'
  $helper=Join-Path $installRoot $helperRelative
  Copy-Item -LiteralPath (Join-Path $PackageRoot $helperRelative) -Destination $helper
  # The expected digest comes from the verified release manifest, never from the
  # installed-tree manifest that is being updated here.
  $partial.manifest.$helperRelative=Get-ManifestFileDigest $manifest $helperRelative
  [IO.File]::WriteAllText($partial.manifest_file,($partial.manifest | ConvertTo-Json -Depth 3))
  $manifestAcl=Get-Acl -LiteralPath $partial.manifest_file
  $manifestAcl.SetAccessRuleProtection($true,$true)
  Set-Acl -LiteralPath $partial.manifest_file -AclObject $manifestAcl
  New-WorkerService $partial.command
  Set-WorkerServiceRecovery
  Start-Service -Name DevAIWorkerVolumes
  Start-Service -Name DevAIWorker
  [IO.File]::WriteAllText((Join-Path $stateRoot 'reports/install.json'),(@{installed=$true;resumed=$true;identity='NT SERVICE\DevAIWorker';delayed_start=$true;recovery=$true;volume_reformatted=$false;workspace_max_bytes=134217728} | ConvertTo-Json))
  Write-Output 'DEVAI_WORKER_INSTALL_FINISHED'
  return
}
if (Get-Service -Name DevAIWorker -ErrorAction Ignore) { throw 'EXISTING_SERVICE_REQUIRES_REVIEWED_UPGRADE' }
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $stateRoot) -or
    (Get-Service -Name DevAIWorkerVolumes -ErrorAction Ignore)) { throw 'EXISTING_INSTALLATION_PATH_REQUIRES_REVIEW' }

function Set-ManagedAcl([string]$Path,[string]$Sid,[string]$Rights,[bool]$Directory=$true,[bool]$PublicRead=$false) {
  $acl=if ($Directory) {[Security.AccessControl.DirectorySecurity]::new()} else {[Security.AccessControl.FileSecurity]::new()}
  $acl.SetAccessRuleProtection($true,$false)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $inherit=if ($Directory) {[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'} else {[Security.AccessControl.InheritanceFlags]::None}
  foreach ($identity in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($identity),'FullControl',$inherit,'None','Allow'))
  }
  if ($Sid) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($Sid),$Rights,$inherit,'None','Allow')) }
  if ($PublicRead) { $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),'ReadAndExecute',$inherit,'None','Allow')) }
  Set-Acl -LiteralPath $Path -AclObject $acl
}

foreach ($path in @($installRoot,$stateRoot)) {
  New-Item -ItemType Directory -Path $path | Out-Null
  Set-ManagedAcl $path '' ''
}
$sidOutput=& sc.exe showsid DevAIWorker
$serviceSid=([regex]::Match(($sidOutput -join ' '),'S-1-5-80(?:-\d+){5}')).Value
if (!$serviceSid) { throw 'SERVICE_SID_UNAVAILABLE' }
Set-ManagedAcl $installRoot $serviceSid 'ReadAndExecute'
Set-ManagedAcl $stateRoot $serviceSid 'ReadAndExecute'
foreach ($directory in @('credentials','volumes','journal','logs','reports','workspace-volume')) {
  $path=Join-Path $stateRoot $directory
  New-Item -ItemType Directory -Path $path | Out-Null
  $rights=if ($directory -in @('journal','logs','reports','workspace-volume')) {'Modify'} else {'ReadAndExecute'}
  Set-ManagedAcl $path $serviceSid $rights $true ($directory -eq 'reports')
}
foreach ($directory in @('control','host-runtime','sandbox-runtime')) {
  Copy-Item -LiteralPath (Join-Path $PackageRoot $directory) -Destination $installRoot -Recurse
}
Set-ManagedAcl (Join-Path $installRoot 'sandbox-runtime') $serviceSid 'ReadAndExecute'
$sandboxAcl=Get-Acl -LiteralPath (Join-Path $installRoot 'sandbox-runtime')
$sandboxAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-15-2-1'),'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow'))
Set-Acl -LiteralPath (Join-Path $installRoot 'sandbox-runtime') -AclObject $sandboxAcl
# Ensure copied objects inherit the new managed DACL and are owned by Administrators.
foreach ($path in @('control','host-runtime','sandbox-runtime')) {
  $absolute=Join-Path $installRoot $path
  & icacls.exe $absolute /setowner '*S-1-5-32-544' /T /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'RUNTIME_OWNER_FAILED' }
  Get-ChildItem -LiteralPath $absolute -Recurse -Force | ForEach-Object {
    $acl=Get-Acl -LiteralPath $_.FullName
    $acl.SetAccessRuleProtection($false,$false)
    foreach ($rule in @($acl.Access | Where-Object {!$_.IsInherited})) { $acl.RemoveAccessRuleSpecific($rule) }
    Set-Acl -LiteralPath $_.FullName -AclObject $acl
  }
}

$vhd=Join-Path $stateRoot 'volumes/workspace.vhdx'
$mount=Join-Path $stateRoot 'workspace-volume'
$volume=New-PrivateWorkspaceVolume $vhd $mount
Set-ManagedAcl $mount $serviceSid 'Modify'
# Protect the actual mounted NTFS root as well as the host-side mount folder.
Set-WorkspaceRootPolicy $vhd $mount $volume $serviceSid | Out-Null
$attachFile=Join-Path $stateRoot 'volumes/attach.txt'
[IO.File]::WriteAllText($attachFile,"select vdisk file=`"$vhd`"`nattach vdisk`nexit`n")
Set-ManagedAcl $vhd '' '' $false
Set-ManagedAcl $attachFile '' '' $false

$credential=Join-Path $stateRoot 'credentials/worker.dpapi'
$runtime=Join-Path $installRoot 'sandbox-runtime'

# --- TARGET PROVISIONING ORDER: fixture -> service.json -> credential ---
# worker.dpapi is NEVER a release artifact. It is provisioned on the target by
# the packaged pinned runtime invoking the existing, byte-identical
# worker_agent.provision primitive, with the token delivered only over stdin.
$operatorSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$fixture=New-TargetPersonalDenialFixture -ProfileRoot $env:USERPROFILE -OwnerSid $operatorSid
Assert-TargetPersonalDenialFixture -Fixture $fixture -OwnerSid $operatorSid -ServiceSid $serviceSid

$config=@{
worker_id=$identity.WorkerId;api_base_url=$identity.ApiBaseUrl;heartbeat_seconds=20;poll_seconds=2;
credential_path=$credential;service_sid=$serviceSid;volume_guid=$volume;sandbox_runtime=$runtime;
sandbox_executable_sha256=(Get-FileHash -LiteralPath (Join-Path $runtime 'python.exe')).Hash.ToLowerInvariant();
sandbox_payload_sha256=(Get-FileHash -LiteralPath (Join-Path $runtime 'synthetic_process.py')).Hash.ToLowerInvariant();
personal_denial_fixture=$fixture
}
$configFile=Join-Path $stateRoot 'service.json'
[IO.File]::WriteAllText($configFile,($config | ConvertTo-Json))
Set-ManagedAcl $configFile $serviceSid 'Read' $false

# An ordinary reinstall must NOT silently overwrite an existing credential.
# Presence, path and ACL are validated; the DPAPI blob is never decrypted or
# re-derived here, so a stale-but-present credential cannot be detected beyond
# those checks (documented limitation; no decryption logic is invented).
if (Test-TargetCredentialPresent $credential) {
  Assert-ManagedPrivateAcl $credential $serviceSid
  Write-Output 'DEVAI_EXISTING_CREDENTIAL_PRESERVED'
} else {
  # Both token modes converge here into the same SecureString and the same
  # BSTR/stdin provisioning below. -WorkerTokenFromStdin reads exactly one
  # token line from redirected stdin (automation); without it the operator is
  # prompted interactively. There is deliberately NO plaintext token
  # parameter: the secret must never appear in argv, the environment or logs.
  $secure=Read-WorkerTokenSecureString -FromStdin:$WorkerTokenFromStdin
  $bstr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try {
    $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    # Narrow conversion for redirected stdin only. Managed copies are NOT
    # claimed to be cryptographically erasable; the requirement is no durable,
    # loggable or process-metadata exposure.
    Invoke-TargetCredentialProvisioning -InstallRoot $installRoot -RuntimeRoot (Join-Path $installRoot 'host-runtime') -WorkerId $identity.WorkerId -CredentialPath $credential -Token $plain
  } finally {
    $plain=$null
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
}
# Fail closed: the service must never start without a credential on disk.
if (!(Test-TargetCredentialPresent $credential)) { throw 'CREDENTIAL_PROVISIONING_FAILED' }

# Installed-tree manifest. This is a DIFFERENT artifact from the release-root
# manifest.json contract and is deliberately named apart from it.
$installedTreeManifest=@{}
Get-ChildItem -LiteralPath $installRoot -Recurse -File | ForEach-Object {
  $relative=Get-CanonicalPackageRelativePath -PackageRoot $installRoot -CandidatePath $_.FullName
  $installedTreeManifest[$relative]=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()
}
$manifestFile=Join-Path $installRoot 'manifest.json'
[IO.File]::WriteAllText($manifestFile,($installedTreeManifest | ConvertTo-Json -Depth 3))
Set-ManagedAcl $manifestFile $serviceSid 'Read' $false

$base=Get-WorkerServiceCommand $installRoot $configFile
New-Service -Name DevAIWorkerVolumes -BinaryPathName ($base+' --volume-host') -StartupType Automatic -DisplayName 'DevAI private workspace volume host' | Out-Null
# Virtual account: unique local service identity, no password, no Administrators membership.
New-WorkerService $base
Set-WorkerServiceRecovery
Start-Service -Name DevAIWorkerVolumes
Start-Service -Name DevAIWorker
[IO.File]::WriteAllText((Join-Path $stateRoot 'reports/install.json'),(@{installed=$true;identity='NT SERVICE\DevAIWorker';delayed_start=$true;recovery=$true;volume_guid=$volume;workspace_max_bytes=134217728} | ConvertTo-Json))
Write-Output 'DEVAI_WORKER_INSTALL_FINISHED'
