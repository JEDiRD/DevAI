param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
  [Parameter(Mandatory=$true)][string]$ExpectedInstallerSHA256,
  [Parameter(Mandatory=$true)][string]$PreviousServiceHash,
  [switch]$DiagnoseOnly
)
$ErrorActionPreference='Stop'
# Validate the complete package BEFORE loading its support code or stopping SCM.
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
# Load just the already validated, definitions-only path validator. Do not run
# the installation branch, decrypt credentials or recreate any volume/service.
$ast=[Management.Automation.Language.Parser]::ParseFile($installer,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'INSTALLER_SYNTAX_INVALID'}
$entry=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
if(!$entry){throw 'PACKAGE_PATH_VALIDATOR_MISSING'}
. ([ScriptBlock]::Create($entry.Extent.Text))
$verified=Assert-PartialWorkerInstall $code $state $package -ExistingService -PreviousServiceHash $PreviousServiceHash
Write-Output (@{installed_runtime_validated=$true;volume=$verified.volume;diagnostic_only=[bool]$DiagnoseOnly;credential_changed=$false;volume_reformatted=$false} | ConvertTo-Json -Depth 4 -Compress)
if($DiagnoseOnly){return}
# Stop only the Worker, gracefully. Leave the running volume host intact.
$service=Get-Service -Name DevAIWorker
if($service.Status -ne 'Stopped') {
  Stop-Service -Name DevAIWorker
  $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
}
$actual=Get-CimInstance Win32_Service -Filter "Name='DevAIWorker'"
if($actual.State -ne 'Stopped' -or $actual.ProcessId -ne 0){throw 'WORKER_NOT_STOPPED'}
$updates=Join-Path $state 'updates'
if(Test-Path -LiteralPath $updates){Assert-ManagedPrivateAcl $updates $verified.config.service_sid -AllowInherited}
else {
  [IO.Directory]::CreateDirectory($updates) | Out-Null
  $acl=Get-Acl -LiteralPath $updates
  $acl.SetAccessRuleProtection($true,$true)
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  Set-Acl -LiteralPath $updates -AclObject $acl
}
$backup=Join-Path $updates ('startup-diagnostic-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($backup) | Out-Null
$target=Join-Path $code 'control/worker_agent/windows_service.py'
Assert-ManagedPrivateAcl $target $verified.config.service_sid -AllowInherited
Copy-Item -LiteralPath $target -Destination (Join-Path $backup 'windows_service.py')
Copy-Item -LiteralPath $verified.manifest_file -Destination (Join-Path $backup 'manifest.json')
$originalAcl=Get-Acl -LiteralPath $target
try {
  Copy-Item -LiteralPath (Join-Path $PackageRoot 'control/worker_agent/windows_service.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  if((Get-FileHash -LiteralPath $target).Hash.ToLowerInvariant() -cne $package.files.'control/worker_agent/windows_service.py'){throw 'DIAGNOSTIC_UPDATE_INTEGRITY_FAILED'}
  $verified.manifest.'control/worker_agent/windows_service.py'=$package.files.'control/worker_agent/windows_service.py'
  [IO.File]::WriteAllText($verified.manifest_file,($verified.manifest | ConvertTo-Json -Depth 3))
  # Preserve exact existing ACL, identity, service/recovery policy and all config.
  Assert-ManagedPrivateAcl $verified.manifest_file $verified.config.service_sid -AllowInherited
} catch {
  # Restore only the backed-up source/manifest, never disks or credentials.
  Copy-Item -LiteralPath (Join-Path $backup 'windows_service.py') -Destination $target
  Set-Acl -LiteralPath $target -AclObject $originalAcl
  Copy-Item -LiteralPath (Join-Path $backup 'manifest.json') -Destination $verified.manifest_file
  throw 'DIAGNOSTIC_UPDATE_ROLLED_BACK'
}
$started=$false
try {Start-Service -Name DevAIWorker; $started=$true} catch { }
Write-Output (@{startup_diagnostic_installed=$true;worker_started=$started;credential_changed=$false;volume_reformatted=$false} | ConvertTo-Json -Compress)
# The read-only diagnostic reconstructs only a closed schema, never raw logs.
& (Join-Path $PSScriptRoot 'diagnose-worker-service.ps1')
