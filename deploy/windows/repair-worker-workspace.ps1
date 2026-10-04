param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
  [Parameter(Mandatory=$true)][string]$ExpectedInstallerSHA256,
  [Parameter(Mandatory=$true)][string]$PreviousServiceHash,
  [Parameter(Mandatory=$true)][string]$PreviousWorkspaceHash,
  [switch]$DiagnoseOnly
)
$ErrorActionPreference='Stop'
if ((Get-FileHash -LiteralPath (Join-Path $PackageRoot 'manifest.json')).Hash.ToLowerInvariant() -cne $ExpectedManifestSHA256) {throw 'PACKAGE_MANIFEST_CHANGED'}
$installer=Join-Path $PackageRoot 'install-worker.ps1'
if ((Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant() -cne $ExpectedInstallerSHA256) {throw 'PACKAGE_INSTALLER_CHANGED'}
& $installer -PackageRoot $PackageRoot -ValidateOnly
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'ADMINISTRATOR_UPDATE_REQUIRED'}
$code=Join-Path $env:ProgramFiles 'DevAIWorker'
$state=Join-Path $env:ProgramData 'DevAIWorker'
. (Join-Path $PackageRoot 'install-support.ps1')
  # Immutable release identity. The external caller-supplied digest above
  # authenticates manifest.json; everything below is verified payload.
  $releaseManifest=Read-ReleaseManifest $PackageRoot
  Assert-ManifestPayload $PackageRoot $releaseManifest | Out-Null
  Assert-ManifestIdentityAggregate $PackageRoot $releaseManifest | Out-Null
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'INSTALLER_SYNTAX_INVALID'}
$entry=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
if(!$entry){throw 'PACKAGE_PATH_VALIDATOR_MISSING'}
. ([ScriptBlock]::Create($entry.Extent.Text))
$verified=Assert-PartialWorkerInstall $code $state $releaseManifest -ExistingService -PreviousServiceHash $PreviousServiceHash -PreviousWorkspaceHash $PreviousWorkspaceHash
$vhd=Join-Path $state 'volumes/workspace.vhdx'
$mount=Join-Path $state 'workspace-volume'
$sid=$verified.config.service_sid
$guid=$verified.config.volume_guid
# Independently inspect the actual NTFS root BEFORE stopping or mutating anything.
$rootPolicy=Get-WorkspaceRootPolicy $vhd $mount $guid $sid
Write-Output (@{installed_runtime_validated=$true;volume=$verified.volume;workspace_root_before=$rootPolicy.summary;
  root_policy_matches=$rootPolicy.matches;diagnostic_only=[bool]$DiagnoseOnly;credential_changed=$false;volume_reformatted=$false} | ConvertTo-Json -Depth 4 -Compress)
if($DiagnoseOnly){return}
$service=Get-Service -Name DevAIWorker
if($service.Status -ne 'Stopped') {Stop-Service -Name DevAIWorker; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
$actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
if($actual.State -ne 'Stopped' -or $actual.ProcessId -ne 0){throw 'WORKER_NOT_STOPPED'}
$updates=Join-Path $state 'updates'
Assert-ManagedPrivateAcl $updates $sid -AllowInherited
$backup=Join-Path $updates ('workspace-root-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($backup) | Out-Null
$target=Join-Path $code 'control/worker_agent/workspace.py'
Assert-ManagedPrivateAcl $target $sid -AllowInherited
$originalAcl=Get-Acl -LiteralPath $target
Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'workspace.py')
Copy-Item -LiteralPath $verified.manifest_file -Destination (Join-Path $backup 'manifest.json')
$oldRootDacl=$rootPolicy.descriptor.GetSddlForm([Security.AccessControl.AccessControlSections]::Access)
[IO.File]::WriteAllText((Join-Path $backup 'volume-root-dacl.sddl'),$oldRootDacl)
$rootChanged=$false
try {
  # Re-check volume identity immediately before applying the private root policy.
  $after=Set-WorkspaceRootPolicy $vhd $mount $guid $sid
  $rootChanged=!$rootPolicy.matches
  Copy-Item -LiteralPath (Join-Path $PackageRoot 'control/worker_agent/workspace.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  if((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant() -cne (Get-ManifestFileDigest $releaseManifest 'control/worker_agent/workspace.py')){throw 'WORKSPACE_UPDATE_INTEGRITY_FAILED'}
  $verified.manifest.'control/worker_agent/workspace.py'=(Get-ManifestFileDigest $releaseManifest 'control/worker_agent/workspace.py')
  [IO.File]::WriteAllText($verified.manifest_file,($verified.manifest | ConvertTo-Json -Depth 3))
  Assert-ManagedPrivateAcl $verified.manifest_file $sid -AllowInherited
} catch {
  # Revalidate the GUID before restoring its prior DACL. No other disk/path.
  Get-VerifiedWorkspaceVolume $vhd $mount $guid | Out-Null
  Set-NativeWorkspaceSecurity $guid $rootPolicy.descriptor
  Copy-Item -LiteralPath (Join-Path $backup 'workspace.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  Copy-Item -LiteralPath (Join-Path $backup 'manifest.json') -Destination $verified.manifest_file
  throw 'WORKSPACE_REPAIR_ROLLED_BACK'
}
$started=$false
try {Start-Service -Name DevAIWorker; $started=$true} catch { }
Write-Output (@{workspace_repair_installed=$true;root_acl_changed=$rootChanged;workspace_root_after=$after;
  worker_started=$started;credential_changed=$false;volume_reformatted=$false} | ConvertTo-Json -Depth 4 -Compress)
& (Join-Path $PSScriptRoot 'diagnose-worker-service.ps1')
