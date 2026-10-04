$ErrorActionPreference='Stop'
foreach($script in @('update-worker-capacity.ps1','update-worker-access-diagnostic.ps1')) {
$path=Join-Path $PSScriptRoot ('../../deploy/windows/'+$script)
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'CAPACITY_UPDATE_SYNTAX_INVALID'}
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Set-WorkspaceRootPolicy|Set-NativeWorkspaceSecurity|Format-Volume|Initialize-Disk|Mount-DiskImage|New-Service|New-WorkerService|Set-WorkerServiceRecovery|Set-NetFirewallRule|Set-Service|sc\.exe|diskpart\.exe)$') {throw 'CAPACITY_UPDATE_MUTATES_UNRELATED_SYSTEM'}
}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-capacity-update-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  [IO.File]::WriteAllText((Join-Path $temp 'manifest.json'),'{}')
  function Stop-Service {throw 'MUTATION_BEFORE_VALIDATION'}
  function Start-Service {throw 'MUTATION_BEFORE_VALIDATION'}
  function Copy-Item {throw 'MUTATION_BEFORE_VALIDATION'}
  function Set-Acl {throw 'MUTATION_BEFORE_VALIDATION'}
  try {& $path -PackageRoot $temp -ExpectedManifestSHA256 ('a'*64) -ExpectedInstallerSHA256 ('a'*64) -PreviousServiceHash ('a'*64) -PreviousWorkspaceHash ('a'*64);throw 'INVALID_PACKAGE_ACCEPTED'}
  catch{if($_.Exception.Message -ne 'PACKAGE_MANIFEST_CHANGED'){throw}}
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
}
Write-Output 'CAPACITY_UPDATE_BOUNDARY_PASSED'
