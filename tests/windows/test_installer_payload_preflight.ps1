param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

# RH-D: a dropped sandbox-runtime verified clean (manifest self-consistent)
# and died with PathNotFound at the installer copy loop. The installer now
# preflights required payload dirs/members BEFORE identity, elevation and any
# mutation. This harness proves the preflight with fixture packages plus the
# real helper: stale-but-consistent manifests fail at manifest validation,
# consistent-but-incomplete manifests fail at the preflight, and a complete
# package proceeds past both to the privilege/mutation boundary.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
$Installer = Join-Path $DeployRoot 'install-worker.ps1'
$Support = Join-Path $DeployRoot 'install-support.ps1'
. $Support

$Guid = '11111111-2222-3333-4444-555555555555'
$Url = 'http://127.0.0.1/'
$report = [ordered]@{ cases = @(); passed = $false }

function New-FixturePackage {
  param([string]$Root)
  # Idempotent: each case starts from a pristine fixture tree.
  if (Test-Path -LiteralPath $Root) { [IO.Directory]::Delete($Root, $true) }
  [IO.Directory]::CreateDirectory($Root) | Out-Null
  $required = @('install-worker.ps1', 'install-support.ps1', 'control/worker_agent/windows_service.py', 'control/worker_agent/volume_host.py',
    'host-runtime/python.exe', 'sandbox-runtime/python.exe', 'sandbox-runtime/synthetic_process.py')
  $repoRoot = Split-Path -Parent (Split-Path -Parent $DeployRoot)
  foreach ($relative in $required) {
    $p = Join-Path $Root ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p)) | Out-Null
    if ($relative -like 'control/*') {
      $src = Join-Path $repoRoot ((($relative -replace '^control/', '') -replace '/', [IO.Path]::DirectorySeparatorChar))
      # .NET copy: the Copy-Item interceptor below must only trip on the
      # INSTALLER's mutations, never on this harness's own fixture setup.
      [IO.File]::Copy($src, $p)
    } else {
      [IO.File]::WriteAllText($p, 'non-secret fixture')
    }
  }
  $entries = @()
  foreach ($relative in $required) {
    $p = Join-Path $Root ($relative -replace '/', [IO.Path]::DirectorySeparatorChar)
    $entries += @{path = $relative; sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $p).Length}
  }
  $manifest = @{manifest_format = 'DEVAI_PACKAGE_MANIFEST'; manifest_schema_version = 1; files = $entries;
    policy_requirements = @('requires_worker_identity', 'requires_api_base_url', 'requires_worker_credential', 'requires_personal_profile_denial_fixture');
    identity = @{format = 'MANIFEST_FORMAT_V2'; aggregate_sha256 = '0' * 64 }; runtime = @{python_version = '3.13.16'; source_sha256 = '1' * 64 } }
  [IO.File]::WriteAllText((Join-Path $Root 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))
  $doc = Read-ReleaseManifest $Root
  $bytes = Get-ManifestV2Serialization $Root $doc
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $seed = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
  $manifest.identity.aggregate_sha256 = $seed
  [IO.File]::WriteAllText((Join-Path $Root 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))
}

function Remove-FixtureMember {
  param([string]$Root, [string]$Relative)
  $p = Join-Path $Root ($Relative -replace '/', [IO.Path]::DirectorySeparatorChar)
  if (Test-Path -LiteralPath $p -PathType Leaf) { [IO.File]::Delete($p) }
  elseif (Test-Path -LiteralPath $p) { [IO.Directory]::Delete($p, $true) }
  # Reseed so the manifest is self-consistent again: the f1210a6 shape that
  # used to verify clean. $doc.Files is a path->digest table, not the entry
  # list, so live entries are rebuilt from the table.
  $doc = Read-ReleaseManifest $Root
  $live = @()
  foreach ($rel in $doc.Files.Keys) {
    $full = Join-Path $Root ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
    if (Test-Path -LiteralPath $full -PathType Leaf) {
      $live += @{path = $rel; sha256 = $doc.Files[$rel].sha256; size = $doc.Files[$rel].size}
    }
  }
  $manifest = @{manifest_format = 'DEVAI_PACKAGE_MANIFEST'; manifest_schema_version = 1; files = @($live);
    policy_requirements = @('requires_worker_identity', 'requires_api_base_url', 'requires_worker_credential', 'requires_personal_profile_denial_fixture');
    identity = @{format = 'MANIFEST_FORMAT_V2'; aggregate_sha256 = '0' * 64 }; runtime = @{python_version = '3.13.16'; source_sha256 = '1' * 64 } }
  [IO.File]::WriteAllText((Join-Path $Root 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))
  $doc2 = Read-ReleaseManifest $Root
  $bytes2 = Get-ManifestV2Serialization $Root $doc2
  $sha2 = [Security.Cryptography.SHA256]::Create()
  try { $seed2 = ([BitConverter]::ToString($sha2.ComputeHash($bytes2))).Replace('-', '').ToLowerInvariant() }
  finally { $sha2.Dispose() }
  $manifest.identity.aggregate_sha256 = $seed2
  [IO.File]::WriteAllText((Join-Path $Root 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))
}

# All installation mutations are intercepted: negatives must fail with the
# validation/preflight code, never with a mutation code.
function New-Item { throw 'MUTATION_INTERCEPTED' }
function Set-Acl { throw 'MUTATION_INTERCEPTED' }
function Copy-Item { throw 'MUTATION_INTERCEPTED' }
function New-Service { throw 'MUTATION_INTERCEPTED' }
function Start-Service { throw 'MUTATION_INTERCEPTED' }
function Remove-Item { throw 'MUTATION_INTERCEPTED' }

$admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated = $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$beyond = if ($elevated) { 'MUTATION_INTERCEPTED' } else { 'ADMINISTRATOR_INSTALL_REQUIRED' }

function Invoke-Installer { param([string]$Root)
  try { & $Installer -PackageRoot $Root -WorkerId $Guid -ApiBaseUrl $Url; return 'UNEXPECTED_SUCCESS' }
  catch { return $_.Exception.Message }
}

$pkg = Join-Path ([IO.Path]::GetTempPath()) ('devai-preflight-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($pkg) | Out-Null
try {
  # Positive: complete package proceeds past validation AND preflight to the
  # privilege/mutation boundary (beyond the old PathNotFound point).
  New-FixturePackage $pkg
  $code = Invoke-Installer $pkg
  if ($code -ne $beyond) { throw ('PREFLIGHT_POSITIVE_UNEXPECTED:' + $code) }
  $report.cases += 'POSITIVE:BEYOND_COPY_POINT'

  # Negative 1: sandbox-runtime dropped, manifest reseeded (consistent).
  # Must fail at the preflight, before identity/elevation/mutation.
  Remove-FixtureMember $pkg 'sandbox-runtime'
  $code = Invoke-Installer $pkg
  if ($code -ne 'INSTALL_PAYLOAD_INCOMPLETE:sandbox-runtime') { throw ('PREFLIGHT_DIR_UNEXPECTED:' + $code) }
  $report.cases += 'NEGATIVE_DIR:FAIL_CLOSED_PRE_MUTATION'

  # Negative 2: single required member dropped, manifest reseeded.
  New-FixturePackage $pkg
  Remove-FixtureMember $pkg 'sandbox-runtime/synthetic_process.py'
  $code = Invoke-Installer $pkg
  if ($code -ne 'INSTALL_PAYLOAD_INCOMPLETE:sandbox-runtime/synthetic_process.py') { throw ('PREFLIGHT_MEMBER_UNEXPECTED:' + $code) }
  $report.cases += 'NEGATIVE_MEMBER:FAIL_CLOSED_PRE_MUTATION'

  # Negative 3: stale manifest (member listed but absent) still fails at
  # manifest validation, i.e. the old gate is intact.
  New-FixturePackage $pkg
  [IO.File]::Delete((Join-Path $pkg (Join-Path 'sandbox-runtime' 'python.exe')))
  $code = Invoke-Installer $pkg
  if ($code -notmatch '^MANIFEST_(FILE_MISSING|HASH_MISMATCH|SIZE_MISMATCH)') { throw ('MANIFEST_GATE_UNEXPECTED:' + $code) }
  $report.cases += 'MANIFEST_GATE:INTACT'
  Write-Output 'INSTALLER_PREFLIGHT_CASES_PASSED'
} finally {
  if ([IO.Path]::GetDirectoryName($pkg) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  [IO.Directory]::Delete($pkg, $true)
}

$report.passed = $true
Write-Output (@{cases = $report.cases; passed = $true} | ConvertTo-Json -Compress)
