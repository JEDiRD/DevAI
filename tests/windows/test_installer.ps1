param([string]$Installer=(Join-Path $PSScriptRoot '../../deploy/windows/install-worker.ps1'))
$ErrorActionPreference='Stop'
$tokens=$null;$parseErrors=$null
$Helper=Join-Path ([IO.Path]::GetDirectoryName($Installer)) 'install-support.ps1'
$ast=[Management.Automation.Language.Parser]::ParseFile($Installer,[ref]$tokens,[ref]$parseErrors)
if ($parseErrors.Count) { throw 'INSTALLER_SYNTAX_INVALID' }
$helperTokens=$null;$helperErrors=$null
$helperAst=[Management.Automation.Language.Parser]::ParseFile($Helper,[ref]$helperTokens,[ref]$helperErrors)
if ($helperErrors.Count) { throw 'HELPER_SYNTAX_INVALID' }
# The validator now lives in the authoritative helper layer that the installer
# dot-sources, so the search covers the installer's whole source surface.
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
if ($null -eq $function) {
  $function=$helperAst.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-PackageEntryName'},$true)
}
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
  # RH-B 5A-2A: the release contract is manifest.json. No target value
  # (worker_id, api_base_url, personal_denial_fixture) and no credential may
  # appear in the artifact.
  $required=@('install-worker.ps1','install-support.ps1','control/worker_agent/windows_service.py')
  foreach ($relative in $required) {
    $path=Join-Path $root $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($path)) | Out-Null
    [IO.File]::WriteAllText($path,'non-secret fixture')
  }
  $entries=@()
  foreach ($relative in $required) {
    $path=Join-Path $root $relative
    $entries+=@{path=$relative;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();size=(Get-Item -LiteralPath $path).Length}
  }
  $manifest=@{manifest_format='DEVAI_PACKAGE_MANIFEST';manifest_schema_version=1;
    files=$entries;policy_requirements=@('requires_worker_identity','requires_api_base_url','requires_worker_credential','requires_personal_profile_denial_fixture');
    identity=@{format='MANIFEST_FORMAT_V2';aggregate_sha256='0'*64};
    runtime=@{python_version='3.13.16';source_sha256='1'*64}}
  function Save-Manifest { [IO.File]::WriteAllText((Join-Path $root 'manifest.json'),($manifest | ConvertTo-Json -Depth 6)) }
  Save-Manifest
  # All installation mutations are intercepted. Valid ValidateOnly and invalid
  # normal execution must both return/throw BEFORE reaching any of these.
  function New-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  function Set-Acl { throw 'MUTATION_BEFORE_VALIDATION' }
  function Copy-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  function New-Service { throw 'MUTATION_BEFORE_VALIDATION' }
  function Start-Service { throw 'MUTATION_BEFORE_VALIDATION' }
  function Remove-Item { throw 'MUTATION_BEFORE_VALIDATION' }
  # The identity aggregate is recomputed from verified bytes, so a structurally
  # valid manifest still fails until the aggregate agrees.
  $aggregateMismatch='MANIFEST_IDENTITY_AGGREGATE_MISMATCH'
  # OLD: a valid manifest.json validated. NEW: unchanged, but only after the
  # aggregate is seeded correctly - the stricter gate is the point.
  try { $null=& $Installer -PackageRoot $root -ValidateOnly; throw 'AGGREGATE_NOT_ENFORCED' }
  catch { if ($_.Exception.Message -ne $aggregateMismatch) { throw } }
  # Seed the aggregate so the package can be accepted. This harness is not the
  # independent check on the aggregate ALGORITHM (that is test_release_installer_core,
  # which imports the production builder); it only needs a consistent package so
  # the later negatives exercise the gate that matters here.
  . (Join-Path ([IO.Path]::GetDirectoryName($Installer)) 'install-support.ps1')
  $doc=Read-ReleaseManifest $root
  $bytes=Get-ManifestV2Serialization $root $doc
  $sha=[Security.Cryptography.SHA256]::Create()
  try { $seed=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant() }
  finally { $sha.Dispose() }
  if ($seed -notmatch '^[a-f0-9]{64}$') { throw 'AGGREGATE_SEED_FAILED' }
  $manifest.identity.aggregate_sha256=$seed
  Save-Manifest
  $output=& $Installer -PackageRoot $root -ValidateOnly
  if ($output -ne 'DEVAI_PACKAGE_VALIDATED') { throw 'VALID_PACKAGE_REJECTED' }
  $parsed=Get-Content -LiteralPath (Join-Path $root 'manifest.json') -Raw | ConvertFrom-Json
  $topLevel=@($parsed.PSObject.Properties.Name)
  foreach ($forbidden in @('worker_id','api_base_url','personal_denial_fixture','credential_path')) {
    if ($forbidden -in $topLevel) { throw "TARGET_VALUE_IN_RELEASE_ARTIFACT:$forbidden" }
  }
  foreach ($entry in $parsed.files) {
    if ($entry.path -match 'worker[.]dpapi') { throw 'CREDENTIAL_IN_RELEASE_ARTIFACT' }
  }
  # policy_requirements DECLARE the requirement; they never carry the value.
  foreach ($need in @('requires_worker_identity','requires_api_base_url','requires_worker_credential')) {
    if ($need -notin $parsed.policy_requirements) { throw "POLICY_REQUIREMENT_MISSING:$need" }
  }
  # Traversal and drive-qualified manifest paths stay closed.
  foreach ($name in @('../evil.txt','..\evil.txt','dir/../../evil.txt','dir\..\..\evil.txt','C:\evil.txt')) {
    $manifest.files+=@{path=$name;sha256='0'*64;size=1}
    Save-Manifest
    try { $null=& $Installer -PackageRoot $root -ValidateOnly;throw 'INVALID_PACKAGE_ACCEPTED' }
    catch { if ($_.Exception.Message -notmatch '^(UNSAFE_MANIFEST_PATH|MANIFEST_PATH_ESCAPE)') { throw } }
    $manifest.files=$manifest.files | Where-Object {$_.path -ne $name}
    Save-Manifest
  }
  # A member present in files[] but altered on disk stays closed. Same LENGTH, so
  # only the digest differs and this cannot pass as a size check.
  $supportPath=Join-Path $root 'install-support.ps1'
  $supportSize=(Get-Item -LiteralPath $supportPath).Length
  $supportDigest=(Get-FileHash -LiteralPath $supportPath -Algorithm SHA256).Hash.ToLowerInvariant()
  $manifest.files=@($manifest.files | Where-Object {$_.path -ne 'install-support.ps1'}) +
    @{path='install-support.ps1';sha256='0'*64;size=$supportSize}
  Save-Manifest
  try { $null=& $Installer -PackageRoot $root -ValidateOnly;throw 'TAMPERED_PACKAGE_ACCEPTED' }
  catch { if ($_.Exception.Message -notmatch '^MANIFEST_HASH_MISMATCH') { throw } }
  # Restore the true digest so the following cases exercise their own gates.
  $manifest.files=@($manifest.files | Where-Object {$_.path -ne 'install-support.ps1'}) +
    @{path='install-support.ps1';sha256=$supportDigest;size=$supportSize}
  Save-Manifest
  # A size-only mismatch stays closed as well.
  $manifest.files=@($manifest.files | Where-Object {$_.path -ne 'install-support.ps1'}) +
    @{path='install-support.ps1';sha256=$supportDigest;size=($supportSize+1)}
  Save-Manifest
  try { $null=& $Installer -PackageRoot $root -ValidateOnly;throw 'SIZE_MISMATCH_ACCEPTED' }
  catch { if ($_.Exception.Message -notmatch '^MANIFEST_SIZE_MISMATCH') { throw } }
  $manifest.files=@($manifest.files | Where-Object {$_.path -ne 'install-support.ps1'}) +
    @{path='install-support.ps1';sha256=$supportDigest;size=$supportSize}
  Save-Manifest
  # Any unmanifested payload member stays closed - including *.json, so the
  # bootstrap model cannot be widened by a name pattern.
  foreach ($extra in @('unlisted.txt','unlisted.json')) {
    [IO.File]::WriteAllText((Join-Path $root $extra),'non-secret fixture')
    try { $null=& $Installer -PackageRoot $root -ValidateOnly;throw 'UNLISTED_FILE_ACCEPTED' }
    catch { if ($_.Exception.Message -notmatch '^UNMANIFESTED_PACKAGE_FILE') { throw } }
    [IO.File]::Delete((Join-Path $root $extra))
  }
  # A required member may be dropped from files[] and the gate must notice.
  $dropped=$manifest.files | Where-Object {$_.path -eq 'control/worker_agent/windows_service.py'}
  $manifest.files=@($manifest.files | Where-Object {$_.path -ne 'control/worker_agent/windows_service.py'})
  Save-Manifest
  try { $null=& $Installer -PackageRoot $root -ValidateOnly;throw 'MISSING_MEMBER_ACCEPTED' }
  catch { if ($_.Exception.Message -notmatch '^(UNMANIFESTED_PACKAGE_FILE|REQUIRED_MANIFEST_MEMBER_MISSING)') { throw } }
  $manifest.files+=@($dropped)
  Save-Manifest
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
