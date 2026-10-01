param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
  [Parameter(Mandatory=$true)][string]$ExpectedInstallerSHA256,
  [Parameter(Mandatory=$true)][string]$PreviousServiceHash,
  [Parameter(Mandatory=$true)][string]$PreviousWorkspaceHash,
  [switch]$DiagnoseOnly
)
$ErrorActionPreference='Stop'
if ((Get-FileHash -LiteralPath (Join-Path $PackageRoot 'package.json')).Hash.ToLowerInvariant() -cne $ExpectedManifestSHA256) {throw 'PACKAGE_MANIFEST_CHANGED'}
$installer=Join-Path $PackageRoot 'install-worker.ps1'
if ((Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant() -cne $ExpectedInstallerSHA256) {throw 'PACKAGE_INSTALLER_CHANGED'}
& $installer -PackageRoot $PackageRoot -ValidateOnly
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {throw 'ADMINISTRATOR_UPDATE_REQUIRED'}
$code=Join-Path $env:ProgramFiles 'DevAIWorker'
$state=Join-Path $env:ProgramData 'DevAIWorker'
$package=Get-Content -LiteralPath (Join-Path $PackageRoot 'package.json') -Raw | ConvertFrom-Json
. (Join-Path $PackageRoot 'install-support.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'INSTALLER_SYNTAX_INVALID'}
$entry=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
if(!$entry){throw 'PACKAGE_PATH_VALIDATOR_MISSING'}
. ([ScriptBlock]::Create($entry.Extent.Text))
$verified=Assert-PartialWorkerInstall $code $state $package -ExistingService -PreviousServiceHash $PreviousServiceHash -PreviousWorkspaceHash $PreviousWorkspaceHash
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
$backup=Join-Path $updates ('service-access-diagnostic-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($backup) | Out-Null
$targets=@()
foreach($name in @('workspace.py','windows_service.py')) {
  $relative='control/worker_agent/'+$name
  $target=Join-Path $code $relative
  Assert-ManagedPrivateAcl $target $verified.config.service_sid -AllowInherited
  $targets+=@{name=$name;relative=$relative;path=$target;acl=(Get-Acl -LiteralPath $target)}
  Copy-Item -LiteralPath $target -Destination (Join-Path $backup $name)
}
Copy-Item -LiteralPath $verified.manifest_file -Destination (Join-Path $backup 'manifest.json')
try {
  foreach($target in $targets) {
    $actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
    if($actual.State -ne 'Stopped' -or $actual.ProcessId -ne 0){throw 'WORKER_NOT_STOPPED'}
    Copy-Item -LiteralPath (Join-Path $PackageRoot $target.relative) -Destination $target.path
    Set-Acl -LiteralPath $target.path -AclObject $target.acl
    $digest=$package.files.PSObject.Properties[$target.relative].Value
    if((Get-FileHash -LiteralPath $target.path).Hash.ToLowerInvariant() -cne $digest){throw 'ACCESS_DIAGNOSTIC_UPDATE_INTEGRITY_FAILED'}
    $verified.manifest.PSObject.Properties[$target.relative].Value=$digest
  }
  [IO.File]::WriteAllText($verified.manifest_file,($verified.manifest | ConvertTo-Json -Depth 3))
  Assert-ManagedPrivateAcl $verified.manifest_file $verified.config.service_sid -AllowInherited
} catch {
  # Recovery may have raced a stopped-state check. Keep rollback fail-closed and
  # stop ONLY this Worker gracefully before restoring its two source files.
  $service=Get-Service -Name DevAIWorker
  if($service.Status -ne 'Stopped') {Stop-Service -Name DevAIWorker; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))}
  $actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
  if($actual.State -ne 'Stopped' -or $actual.ProcessId -ne 0){throw 'ACCESS_DIAGNOSTIC_ROLLBACK_REQUIRES_REVIEW'}
  foreach($target in $targets) {
    Copy-Item -LiteralPath (Join-Path $backup $target.name) -Destination $target.path
    Set-Acl -LiteralPath $target.path -AclObject $target.acl
  }
  Copy-Item -LiteralPath (Join-Path $backup 'manifest.json') -Destination $verified.manifest_file
  throw 'ACCESS_DIAGNOSTIC_UPDATE_ROLLED_BACK'
}
$started=$false
try {Start-Service -Name DevAIWorker; $started=$true} catch { }
Write-Output (@{effective_access_diagnostic_installed=$true;worker_started=$started;
  credential_changed=$false;volume_reformatted=$false;root_acl_changed=$false} | ConvertTo-Json -Compress)
& (Join-Path $PSScriptRoot 'diagnose-worker-service.ps1')
