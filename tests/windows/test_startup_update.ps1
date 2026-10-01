$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../../deploy/windows/update-worker-startup-diagnostic.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'UPDATE_SYNTAX_INVALID'}
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Format-Volume|Initialize-Disk|Mount-DiskImage|New-Service|New-WorkerService|Set-WorkerServiceRecovery|Set-NetFirewallRule|Set-Service|sc\.exe|diskpart\.exe)$') {throw 'UPDATE_MUTATES_UNRELATED_SYSTEM'}
}
# Real invocation with an invalid pinned hash MUST exit before any mutation.
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-update-boundary-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  [IO.File]::WriteAllText((Join-Path $temp 'package.json'),'{}')
  function Stop-Service {throw 'MUTATION_BEFORE_VALIDATION'}
  function Start-Service {throw 'MUTATION_BEFORE_VALIDATION'}
  function Copy-Item {throw 'MUTATION_BEFORE_VALIDATION'}
  function Set-Acl {throw 'MUTATION_BEFORE_VALIDATION'}
  try {& $path -PackageRoot $temp -ExpectedManifestSHA256 ('a'*64) -ExpectedInstallerSHA256 ('a'*64) -PreviousServiceHash ('a'*64);throw 'INVALID_PACKAGE_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PACKAGE_MANIFEST_CHANGED'){throw}}
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
Write-Output 'STARTUP_UPDATE_VALIDATION_BOUNDARY_PASSED'

$repair=Join-Path $PSScriptRoot '../../deploy/windows/repair-worker-workspace.ps1'
$tokens=$null;$errors=$null
$repairAst=[Management.Automation.Language.Parser]::ParseFile($repair,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'WORKSPACE_REPAIR_SYNTAX_INVALID'}
$commands=$repairAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Format-Volume|Initialize-Disk|Mount-DiskImage|New-Service|New-WorkerService|Set-WorkerServiceRecovery|Set-NetFirewallRule|Set-Service|sc\.exe|diskpart\.exe)$') {throw 'WORKSPACE_REPAIR_MUTATES_UNRELATED_SYSTEM'}
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-workspace-update-boundary-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  [IO.File]::WriteAllText((Join-Path $temp 'package.json'),'{}')
  function Set-WorkspaceRootPolicy {throw 'ROOT_MUTATION_BEFORE_VALIDATION'}
  try {& $repair -PackageRoot $temp -ExpectedManifestSHA256 ('a'*64) -ExpectedInstallerSHA256 ('a'*64) -PreviousServiceHash ('a'*64) -PreviousWorkspaceHash ('a'*64);throw 'INVALID_WORKSPACE_PACKAGE_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PACKAGE_MANIFEST_CHANGED'){throw}}
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
