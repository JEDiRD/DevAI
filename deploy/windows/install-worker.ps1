param([Parameter(Mandatory=$true)][string]$PackageRoot,[switch]$ValidateOnly,[switch]$ResumeServiceCreation,[switch]$InspectInstall)
$ErrorActionPreference='Stop'
function Assert-PackageEntryName([string]$Name) {
  $parts=$Name -split '[\\/]'
  if ([string]::IsNullOrWhiteSpace($Name) -or [IO.Path]::IsPathRooted($Name) -or
      $parts -contains '..' -or $parts -contains '.' -or $parts -contains '' -or $Name.Contains(':')) {
    throw 'UNSAFE_PACKAGE_PATH'
  }
}

$PackageRoot=(Resolve-Path -LiteralPath $PackageRoot).Path
for ($parent=Get-Item -LiteralPath $PackageRoot; $null -ne $parent; $parent=$parent.Parent) {
  if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PACKAGE_ANCESTOR_REPARSE_POINT' }
}
$manifestPath=Join-Path $PackageRoot 'package.json'
$manifestItem=Get-Item -LiteralPath $manifestPath
if ($manifestItem.PSIsContainer -or ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'UNSAFE_PACKAGE_MANIFEST' }
$package=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if (@($package.PSObject.Properties.Name | Where-Object {$_ -notin @('worker_id','api_base_url','personal_denial_fixture','files')}).Count) { throw 'INVALID_PACKAGE_METADATA' }
$workerId=[Guid]::Empty
if (![Guid]::TryParse($package.worker_id,[ref]$workerId) -or $workerId -eq [Guid]::Empty) { throw 'INVALID_PACKAGE_WORKER_ID' }
$origin=$null
$address=[Net.IPAddress]::None
if (![Uri]::TryCreate($package.api_base_url,[UriKind]::Absolute,[ref]$origin) -or
    $origin.Scheme -notin @('http','https') -or $origin.UserInfo -or $origin.AbsolutePath -ne '/' -or
    $origin.Query -or $origin.Fragment -or ![Net.IPAddress]::TryParse($origin.Host,[ref]$address)) { throw 'INVALID_PACKAGE_API_ORIGIN' }
$bytes=$address.GetAddressBytes()
if (![Net.IPAddress]::IsLoopback($address) -and !($bytes.Length -eq 4 -and $bytes[0] -eq 100 -and $bytes[1] -ge 64 -and $bytes[1] -le 127)) { throw 'INVALID_PACKAGE_API_ORIGIN' }
if (![IO.Path]::IsPathRooted($package.personal_denial_fixture)) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
$fixtureItem=Get-Item -LiteralPath $package.personal_denial_fixture -Force
if ($fixtureItem.PSIsContainer -or ($fixtureItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
for ($parent=$fixtureItem.Directory; $null -ne $parent; $parent=$parent.Parent) {
  if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'INVALID_PERSONAL_FIXTURE_PATH' }
}
if ($null -eq $package.files -or @($package.files.PSObject.Properties).Count -eq 0) { throw 'EMPTY_PACKAGE_MANIFEST' }
$validatedFiles=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $package.files.PSObject.Properties) {
  Assert-PackageEntryName $entry.Name
  $path=[IO.Path]::GetFullPath((Join-Path $PackageRoot $entry.Name))
  if (!$path.StartsWith($PackageRoot+'\',[StringComparison]::OrdinalIgnoreCase) -or !$validatedFiles.Add($path)) { throw 'UNSAFE_PACKAGE_PATH' }
  if ($entry.Value -notmatch '^[a-f0-9]{64}$') { throw 'INVALID_PACKAGE_DIGEST' }
  $item=Get-Item -LiteralPath $path
  if ($item.PSIsContainer) { throw 'PACKAGE_ENTRY_MUST_BE_FILE' }
  for ($parent=$item.Directory; $parent.FullName -ne $PackageRoot; $parent=$parent.Parent) {
    if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PACKAGE_ANCESTOR_REPARSE_POINT' }
  }
  if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PACKAGE_REPARSE_POINT' }
  if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'PACKAGE_INTEGRITY_FAILED' }
}
# Copy-Item must not later copy files absent from the validated manifest. Inspect
# one directory at a time; reject reparse points before descending into them.
$directories=[Collections.Generic.Stack[string]]::new()
$directories.Push($PackageRoot)
while ($directories.Count) {
  foreach ($item in Get-ChildItem -LiteralPath $directories.Pop() -Force) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'PACKAGE_REPARSE_POINT' }
    if ($item.PSIsContainer) { $directories.Push($item.FullName) }
    elseif ($item.FullName -ne $manifestPath -and !$validatedFiles.Contains($item.FullName)) { throw 'UNMANIFESTED_PACKAGE_FILE' }
  }
}
foreach ($required in @('install-worker.ps1','install-support.ps1','worker.dpapi','host-runtime/python.exe','sandbox-runtime/python.exe','control/worker_agent/windows_service.py')) {
  if (!$validatedFiles.Contains([IO.Path]::GetFullPath((Join-Path $PackageRoot $required)))) { throw 'REQUIRED_PACKAGE_FILE_MISSING' }
}
if ($ValidateOnly) { Write-Output 'DEVAI_PACKAGE_VALIDATED'; return }

# Installation boundary: package validation above performs read-only operations.
$admin=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_INSTALL_REQUIRED' }
$installRoot=Join-Path $env:ProgramFiles 'DevAIWorker'
$stateRoot=Join-Path $env:ProgramData 'DevAIWorker'
. (Join-Path $PackageRoot 'install-support.ps1')
if ($InspectInstall -and !$ResumeServiceCreation) { throw 'INSPECT_REQUIRES_EXPLICIT_RESUME' }
if ($ResumeServiceCreation) {
  # Entire existing installation and volume are checked read-only FIRST.
  $partial=Assert-PartialWorkerInstall $installRoot $stateRoot $package
  Write-Output (@{partial_install_validated=$true;volume=$partial.volume;volume_reformatted=$false} | ConvertTo-Json -Depth 4 -Compress)
  if ($InspectInstall) { return }
  # Preserve credential/config/VHDX/workspaces. Upgrade only this manifested
  # mount helper to suppress automatic drive letters on subsequent boots.
  $helper=Join-Path $installRoot 'control/worker_agent/volume_host.py'
  Copy-Item -LiteralPath (Join-Path $PackageRoot 'control/worker_agent/volume_host.py') -Destination $helper
  $partial.manifest.'control/worker_agent/volume_host.py'=$package.files.'control/worker_agent/volume_host.py'
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
$attachFile=Join-Path $stateRoot 'volumes/attach.txt'
[IO.File]::WriteAllText($attachFile,"select vdisk file=`"$vhd`"`nattach vdisk`nexit`n")
Set-ManagedAcl $vhd '' '' $false
Set-ManagedAcl $attachFile '' '' $false

$credential=Join-Path $stateRoot 'credentials/worker.dpapi'
Copy-Item -LiteralPath (Join-Path $PackageRoot 'worker.dpapi') -Destination $credential
Set-ManagedAcl $credential $serviceSid 'Read' $false
$runtime=Join-Path $installRoot 'sandbox-runtime'
$config=@{
 worker_id=$package.worker_id;api_base_url=$package.api_base_url;heartbeat_seconds=20;poll_seconds=2;
 credential_path=$credential;service_sid=$serviceSid;volume_guid=$volume;sandbox_runtime=$runtime;
 sandbox_executable_sha256=(Get-FileHash -LiteralPath (Join-Path $runtime 'python.exe')).Hash.ToLowerInvariant();
 sandbox_payload_sha256=(Get-FileHash -LiteralPath (Join-Path $runtime 'synthetic_process.py')).Hash.ToLowerInvariant()
 personal_denial_fixture=$package.personal_denial_fixture
}
$configFile=Join-Path $stateRoot 'service.json'
[IO.File]::WriteAllText($configFile,($config | ConvertTo-Json))
Set-ManagedAcl $configFile $serviceSid 'Read' $false
$manifest=@{}
Get-ChildItem -LiteralPath $installRoot -Recurse -File | ForEach-Object {
  $relative=$_.FullName.Substring($installRoot.Length+1).Replace('\','/')
  $manifest[$relative]=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()
}
$manifestFile=Join-Path $installRoot 'manifest.json'
[IO.File]::WriteAllText($manifestFile,($manifest | ConvertTo-Json -Depth 3))
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
