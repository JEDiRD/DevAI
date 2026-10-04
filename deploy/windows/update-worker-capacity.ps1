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
$policy=Get-WorkspaceRootPolicy (Join-Path $state 'volumes/workspace.vhdx') (Join-Path $state 'workspace-volume') $verified.config.volume_guid $verified.config.service_sid
if(!$policy.matches){throw 'WORKSPACE_ROOT_POLICY_CHANGED_REQUIRES_REVIEW'}
Write-Output (@{installed_runtime_validated=$true;volume=$verified.volume;workspace_root=$policy.summary;
  root_policy_matches=$true;diagnostic_only=[bool]$DiagnoseOnly;credential_changed=$false;volume_reformatted=$false;root_acl_changed=$false} | ConvertTo-Json -Depth 4 -Compress)
if($DiagnoseOnly){return}
$service=Get-Service -Name DevAIWorker
if($service.Status -ne 'Stopped') {Stop-Service -Name DevAIWorker; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
$actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
if($actual.State -ne 'Stopped' -or $actual.ProcessId -ne 0){throw 'WORKER_NOT_STOPPED'}
$updates=Join-Path $state 'updates'
Assert-ManagedPrivateAcl $updates $verified.config.service_sid -AllowInherited
$backup=Join-Path $updates ('directory-capacity-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($backup) | Out-Null
$target=Join-Path $code 'control/worker_agent/workspace.py'
Assert-ManagedPrivateAcl $target $verified.config.service_sid -AllowInherited
$originalAcl=Get-Acl -LiteralPath $target
Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'workspace.py')
Copy-Item -LiteralPath $verified.manifest_file -Destination (Join-Path $backup 'manifest.json')
try {
  Copy-Item -LiteralPath (Join-Path $PackageRoot 'control/worker_agent/workspace.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  if((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant() -cne (Get-ManifestFileDigest $releaseManifest 'control/worker_agent/workspace.py')){throw 'CAPACITY_UPDATE_INTEGRITY_FAILED'}
  $verified.manifest.'control/worker_agent/workspace.py'=(Get-ManifestFileDigest $releaseManifest 'control/worker_agent/workspace.py')
  [IO.File]::WriteAllText($verified.manifest_file,($verified.manifest | ConvertTo-Json -Depth 3))
  Assert-ManagedPrivateAcl $verified.manifest_file $verified.config.service_sid -AllowInherited
} catch {
  Copy-Item -LiteralPath (Join-Path $backup 'workspace.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  Copy-Item -LiteralPath (Join-Path $backup 'manifest.json') -Destination $verified.manifest_file
  throw 'CAPACITY_UPDATE_ROLLED_BACK'
}
$started=$false
try {Start-Service -Name DevAIWorker; $started=$true} catch { }
Write-Output (@{directory_capacity_installed=$true;worker_started=$started;
  credential_changed=$false;volume_reformatted=$false;root_acl_changed=$false} | ConvertTo-Json -Compress)
& (Join-Path $PSScriptRoot 'diagnose-worker-service.ps1')
