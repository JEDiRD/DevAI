param([string]$Installer=(Join-Path $PSScriptRoot '../../deploy/windows/install-worker.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Installer,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'INSTALLER_SYNTAX_INVALID' }
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
if ($null -eq $function) { throw 'SOURCE_ENTRY_VALIDATOR_MISSING' }
# Execute the actual source function, without executing the installation body.
. ([ScriptBlock]::Create($function.Extent.Text))
$cases=@(
  @('valid/file.txt',$true),@('valid\file.txt',$true),
  @('../evil.txt',$false),@('..\evil.txt',$false),
  @('dir/../../evil.txt',$false),@('dir\..\..\evil.txt',$false),@('C:\evil.txt',$false),
  @('dir\../evil.txt',$false),@('\\server\share\evil.txt',$false),@('file.txt:hidden',$false)
)
foreach ($case in $cases) {
  $allowed=$true
  try { Assert-PackageEntryName $case[0] } catch {
    if ($_.Exception.Message -ne 'UNSAFE_PACKAGE_PATH') { throw }
    $allowed=$false
  }
  if ($allowed -ne $case[1]) { throw 'PATH_TRAVERSAL_TEST_FAILED' }
}
if ((Get-Content -LiteralPath $Installer -Raw) -match '\.Split\(') { throw 'AMBIGUOUS_SPLIT_REMAINS' }

$root=Join-Path ([IO.Path]::GetTempPath()) ('devai-installer-validation-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $required=@('install-worker.ps1','install-support.ps1','worker.dpapi','host-runtime/python.exe','sandbox-runtime/python.exe','control/worker_agent/windows_service.py')
  $files=@{}
  foreach ($relative in $required) {
    $path=Join-Path $root $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllText($path,'non-secret fixture')
    $files[$relative]=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
  }
  $fixture=Join-Path ([IO.Path]::GetTempPath()) ('devai-personal-fixture-'+[Guid]::NewGuid().ToString('N'))
  [IO.File]::WriteAllText($fixture,'non-secret fixture')
  $manifest=@{worker_id=[Guid]::NewGuid().ToString();api_base_url='http://100.91.132.78:8765';personal_denial_fixture=$fixture;files=$files}
  function Save-Manifest { [IO.File]::WriteAllText((Join-Path $root 'package.json'),($manifest | ConvertTo-Json -Depth 5)) }
  Save-Manifest
  # All installation mutations are intercepted. Valid ValidateOnly and invalid
  # normal execution must both return/throw BEFORE reaching any of these.
  function New-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  function Set-Acl { throw 'MUTATION_BEFORE_VALIDATION' }
  function Copy-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  function New-Service { throw 'MUTATION_BEFORE_VALIDATION' }
  function Start-Service { throw 'MUTATION_BEFORE_VALIDATION' }
  function Remove-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  $output=& $Installer -PackageRoot $root -ValidateOnly
  if ($output -ne 'DEVAI_PACKAGE_VALIDATED') { throw 'VALID_PACKAGE_REJECTED' }
  # Read-only metadata validation must handle hidden non-secret probes, but
  # must still reject absent probes before any installation mutation.
  [IO.File]::SetAttributes($fixture,[IO.FileAttributes]::Hidden)
  $output=& $Installer -PackageRoot $root -ValidateOnly
  if ($output -ne 'DEVAI_PACKAGE_VALIDATED') { throw 'HIDDEN_PERSONAL_FIXTURE_REJECTED' }
  [IO.File]::SetAttributes($fixture,[IO.FileAttributes]::Normal)
  $originalFixture=$manifest.personal_denial_fixture
  $manifest.personal_denial_fixture=$fixture+'-missing';Save-Manifest
  try { & $Installer -PackageRoot $root;throw 'MISSING_PERSONAL_FIXTURE_ACCEPTED' }
  catch { if ($_.Exception -isnot [Management.Automation.ItemNotFoundException]) { throw } }
  $manifest.personal_denial_fixture=$originalFixture;Save-Manifest
  foreach ($name in @('../evil.txt','..\evil.txt','dir/../../evil.txt','dir\..\..\evil.txt','C:\evil.txt')) {
    $manifest.files[$name]='0'*64;Save-Manifest
    try { & $Installer -PackageRoot $root;throw 'INVALID_PACKAGE_ACCEPTED' }
    catch { if ($_.Exception.Message -ne 'UNSAFE_PACKAGE_PATH') { throw } }
    $manifest.files.Remove($name)
  }
  $manifest.files['worker.dpapi']='0'*64;Save-Manifest
  try { & $Installer -PackageRoot $root;throw 'TAMPERED_PACKAGE_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'PACKAGE_INTEGRITY_FAILED') { throw } }
  $manifest.files['worker.dpapi']=(Get-FileHash -LiteralPath (Join-Path $root 'worker.dpapi')).Hash.ToLowerInvariant()
  Save-Manifest
  [IO.File]::WriteAllText((Join-Path $root 'unlisted.txt'),'non-secret fixture')
  try { & $Installer -PackageRoot $root;throw 'UNLISTED_FILE_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'UNMANIFESTED_PACKAGE_FILE') { throw } }
  [IO.File]::Delete((Join-Path $root 'unlisted.txt'))
  $manifest.api_base_url='http://1.1.1.1:8765';Save-Manifest
  try { & $Installer -PackageRoot $root;throw 'PUBLIC_API_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'INVALID_PACKAGE_API_ORIGIN') { throw } }
  # Static supplement: no filesystem writes, services or volume commands appear
  # before the explicit installation boundary, including .NET write methods.
  $source=Get-Content -LiteralPath $Installer -Raw
  $boundary=$source.IndexOf('# Installation boundary:')
  if ($boundary -lt 0) { throw 'INSTALLATION_BOUNDARY_MISSING' }
  $calls=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst] -or $node -is [Management.Automation.Language.InvokeMemberExpressionAst]},$true)
  foreach ($call in $calls | Where-Object {$_.Extent.StartOffset -lt $boundary}) {
    if ($call -is [Management.Automation.Language.CommandAst]) {
      if ($call.GetCommandName() -match '(?i)^(New-Item|Set-Acl|Copy-Item|New-Service|Start-Service|Remove-Item|diskpart(?:\.exe)?|icacls(?:\.exe)?|sc\.exe)$') { throw 'MUTATION_BEFORE_BOUNDARY' }
    } elseif ($call.Member.Value -match '(?i)^(Write.*|CreateDirectory)$') { throw 'MUTATION_BEFORE_BOUNDARY' }
  }
  Write-Output (@{path_cases=$cases.Count;package_flow_cases=11;mutation_interceptors=$true;source_tested=$true;passed=$true} | ConvertTo-Json -Compress)
} finally {
  # Only this verified test root is removed; no installation paths are touched.
  if ([IO.Path]::GetDirectoryName($root) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  [IO.Directory]::Delete($root,$true)
  if ($fixture) { [IO.File]::Delete($fixture) }
}
