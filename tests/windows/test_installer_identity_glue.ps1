param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
$Installer = Join-Path $DeployRoot 'install-worker.ps1'
$Support = Join-Path $DeployRoot 'install-support.ps1'
foreach ($p in @($Installer, $Support)) { if (!(Test-Path -LiteralPath $p -PathType Leaf)) { throw "HARNESS_INPUT_MISSING:$p" } }

$report = [ordered]@{ collision_sites = @(); glue_cases = @(); passed = $false }

# ---------- Part 1: case-insensitive parameter/local collision audit (AST) ----------
$scripts = Get-ChildItem -LiteralPath $DeployRoot -Filter '*.ps1'
foreach ($f in $scripts) {
  $tokens = $null; $errs = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
  if ($errs.Count) { throw ('INSTALLER_SYNTAX_INVALID:' + $f.Name) }
  $scopes = @(@{ name = '<script>'; node = $ast })
  foreach ($fn in $ast.FindAll({ param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
    $scopes += @{ name = $fn.Name; node = $fn.Body }
  }
  foreach ($s in $scopes) {
    $names = @{}
    foreach ($n in $s.node.FindAll({ param($n) $true }, $false)) {
      if ($n -is [Management.Automation.Language.ParameterAst]) {
        $v = $n.Name.VariablePath.UserPath
        if ($v) {
          $key = $v.ToLowerInvariant()
          if (-not $names.ContainsKey($key)) { $names[$key] = @() }
          $names[$key] += ('param:' + $v)
        }
      } elseif ($n -is [Management.Automation.Language.AssignmentStatementAst]) {
        $t = $n.Left.Extent.Text
        if ($t -match '^\$([A-Za-z_][A-Za-z0-9_]*)') {
          $v = $Matches[1]
          $key = $v.ToLowerInvariant()
          if (-not $names.ContainsKey($key)) { $names[$key] = @() }
          $names[$key] += ('assign:' + $v + ':' + $n.Extent.StartLineNumber)
        }
      }
    }
    foreach ($k in $names.Keys) {
      $distinct = @($names[$k] | Sort-Object -Unique)
      # -CaseSensitive is load-bearing: the default -Unique folds case and
      # would hide exactly the collision class under audit.
      $spellings = @($distinct | ForEach-Object { $_.Split(':')[1] } | Sort-Object -Unique -CaseSensitive)
      if ($spellings.Count -gt 1) {
        $report.collision_sites += ($f.Name + ' [' + $s.name + '] ' + ($distinct -join ','))
      }
    }
  }
}
if ($report.collision_sites.Count) { throw ('VARIABLE_COLLISION:' + ($report.collision_sites -join ' | ')) }
Write-Output 'VARIABLE_COLLISION_AUDIT_PASSED'

# The installer must delegate identity to the single shared helper, and the
# helper must exist exactly once. The helper IS the tested glue.
$installerTokens = $null; $installerErrs = $null
$installerAst = [Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$installerTokens, [ref]$installerErrs)
$calls = @($installerAst.FindAll({ param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Resolve-InstallerTargetIdentity' }, $true))
if ($calls.Count -ne 1) { throw ('INSTALLER_GLUE_WIRING_UNEXPECTED:' + $calls.Count) }
Write-Output 'INSTALLER_GLUE_WIRING_PASSED'

# ---------- Part 2: real glue cases A-E + object-type canary ----------
. $Support
$origResolve = ${function:Resolve-TargetIdentity}
if ($null -eq $origResolve) { throw 'RESOLVE_TARGET_IDENTITY_MISSING' }
$script:observedConfigTypes = @()
function Resolve-TargetIdentity {
  param([string]$CliWorkerId, [string]$CliApiBaseUrl, $Config)
  if ($null -eq $Config) { $script:observedConfigTypes += 'null' }
  else { $script:observedConfigTypes += $Config.GetType().FullName }
  & $origResolve -CliWorkerId $CliWorkerId -CliApiBaseUrl $CliApiBaseUrl -Config $Config
}

$GuidCli = '11111111-2222-3333-4444-555555555555'
$UrlCli = 'http://127.0.0.1/'
$GuidCfg = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
$UrlCfg = 'http://100.64.0.1/'

$work = Join-Path ([IO.Path]::GetTempPath()) ('devai-identity-glue-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($work) | Out-Null
try {
  $cfgPath = Join-Path $work 'service.json'
  $writeCfg = { param($w, $u) [IO.File]::WriteAllText($cfgPath, (@{worker_id = $w; api_base_url = $u} | ConvertTo-Json)) }
  $runGlue = { param($w, $u, $c) Resolve-InstallerTargetIdentity -WorkerId $w -ApiBaseUrl $u -ExistingConfig $c }

  # A. CLI only: succeeds, null config reaches resolution.
  $script:observedConfigTypes = @()
  $id = & $runGlue $GuidCli $UrlCli ''
  if ($id.WorkerId -ne $GuidCli -or $id.ApiBaseUrl -ne $UrlCli) { throw 'GLUE_A_VALUE_MISMATCH' }
  if (@($script:observedConfigTypes)[-1] -ne 'null') { throw 'GLUE_A_CONFIG_NOT_NULL' }
  $report.glue_cases += 'A:CLI_ONLY_PASS'

  # B. ExistingConfig only: succeeds, config OBJECT (not String) reaches resolution.
  & $writeCfg $GuidCfg $UrlCfg
  $script:observedConfigTypes = @()
  $id = & $runGlue '' '' $cfgPath
  if ($id.WorkerId -ne $GuidCfg -or $id.ApiBaseUrl -ne $UrlCfg) { throw 'GLUE_B_VALUE_MISMATCH' }
  $seen = @($script:observedConfigTypes)[-1]
  if ($seen -eq 'System.String') { throw 'GLUE_B_CONFIG_STRING_COERCED' }
  if ($seen -ne 'System.Management.Automation.PSCustomObject') { throw ('GLUE_B_CONFIG_UNEXPECTED_TYPE:' + $seen) }
  $report.glue_cases += 'B:CONFIG_ONLY_PASS'

  # C. Matching CLI + config: succeeds.
  & $writeCfg $GuidCli $UrlCli
  $id = & $runGlue $GuidCli $UrlCli $cfgPath
  if ($id.WorkerId -ne $GuidCli) { throw 'GLUE_C_VALUE_MISMATCH' }
  $report.glue_cases += 'C:MATCHING_PASS'

  # D. Conflicting CLI + config: fails closed on the existing conflict contract.
  & $writeCfg $GuidCfg $UrlCfg
  try { $null = & $runGlue $GuidCli $UrlCli $cfgPath; throw 'GLUE_D_CONFLICT_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'WORKER_ID_CONFLICT') { throw ('GLUE_D_WRONG_CODE:' + $_.Exception.Message) } }
  try { $null = & $runGlue $GuidCfg 'http://127.0.0.2/' $cfgPath; throw 'GLUE_D_API_CONFLICT_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'API_BASE_URL_CONFLICT') { throw ('GLUE_D_API_WRONG_CODE:' + $_.Exception.Message) } }
  $report.glue_cases += 'D:CONFLICT_FAILS_CLOSED'

  # E. Missing identity: fails closed; missing file fails closed.
  try { $null = & $runGlue '' '' ''; throw 'GLUE_E_MISSING_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'WORKER_ID_REQUIRED') { throw ('GLUE_E_WRONG_CODE:' + $_.Exception.Message) } }
  try { $null = & $runGlue '' '' (Join-Path $work 'absent.json'); throw 'GLUE_E_ABSENT_ACCEPTED' }
  catch { if ($_.Exception.Message -ne 'EXISTING_CONFIG_MISSING') { throw ('GLUE_E_ABSENT_WRONG_CODE:' + $_.Exception.Message) } }
  $report.glue_cases += 'E:MISSING_FAILS_CLOSED'
  Write-Output 'INSTALLER_GLUE_CASES_PASSED'
} finally {
  if ([IO.Path]::GetDirectoryName($work) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  [IO.Directory]::Delete($work, $true)
}

# ---------- Part 3: full-script non-elevated progress canary ----------
$pkg = Join-Path ([IO.Path]::GetTempPath()) ('devai-glue-package-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($pkg) | Out-Null
try {
  $required = @('install-worker.ps1', 'install-support.ps1', 'control/worker_agent/windows_service.py')
  $repoRoot = Split-Path -Parent (Split-Path -Parent $DeployRoot)
  foreach ($relative in $required) {
    $p = Join-Path $pkg $relative
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($p)) | Out-Null
    if ($relative -like 'control/worker_agent/*') { $src = Join-Path $repoRoot (($relative -replace '^control/', '') -replace '/', [IO.Path]::DirectorySeparatorChar) }
    else { $src = Join-Path $DeployRoot $relative }
    Copy-Item -LiteralPath $src -Destination $p
  }
  $entries = @()
  foreach ($relative in $required) {
    $p = Join-Path $pkg $relative
    $entries += @{path = $relative; sha256 = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant(); size = (Get-Item -LiteralPath $p).Length}
  }
  $manifest = @{manifest_format = 'DEVAI_PACKAGE_MANIFEST'; manifest_schema_version = 1; files = $entries;
    policy_requirements = @('requires_worker_identity', 'requires_api_base_url', 'requires_worker_credential', 'requires_personal_profile_denial_fixture');
    identity = @{format = 'MANIFEST_FORMAT_V2'; aggregate_sha256 = '0' * 64 }; runtime = @{python_version = '3.13.16'; source_sha256 = '1' * 64 } }
  [IO.File]::WriteAllText((Join-Path $pkg 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))
  # All installation mutations are intercepted: the canary must stop at the
  # privilege boundary, never mutate.
  function New-Item { throw 'MUTATION_INTERCEPTED' }
  function Set-Acl { throw 'MUTATION_INTERCEPTED' }
  function Copy-Item { throw 'MUTATION_INTERCEPTED' }
  function New-Service { throw 'MUTATION_INTERCEPTED' }
  function Start-Service { throw 'MUTATION_INTERCEPTED' }
  function Remove-Item { throw 'MUTATION_INTERCEPTED' }
  . $Support
  $doc = Read-ReleaseManifest $pkg
  $bytes = Get-ManifestV2Serialization $pkg $doc
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $seed = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
  $manifest.identity.aggregate_sha256 = $seed
  [IO.File]::WriteAllText((Join-Path $pkg 'manifest.json'), ($manifest | ConvertTo-Json -Depth 6))

  $admin = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  $elevated = $admin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  try {
    $null = & $Installer -PackageRoot $pkg -WorkerId $GuidCli -ApiBaseUrl $UrlCli
    throw 'GLUE_CANARY_UNEXPECTED_SUCCESS'
  } catch {
    $code = $_.Exception.Message
    if ($code -match '^(EXISTING_CONFIG_|WORKER_ID_|API_BASE_URL_|INVALID_)') { throw ('GLUE_CANARY_IDENTITY_FAILURE:' + $code) }
    if (-not $elevated -and $code -ne 'ADMINISTRATOR_INSTALL_REQUIRED') { throw ('GLUE_CANARY_WRONG_BOUNDARY:' + $code) }
    if ($elevated -and $code -ne 'MUTATION_INTERCEPTED') { throw ('GLUE_CANARY_ELEVATED_UNEXPECTED:' + $code) }
    $report.glue_cases += ('CANARY:IDENTITY_GLUE_OK_NEXT=' + $code)
    Write-Output ('INSTALLER_GLUE_CANARY_PASSED:' + $code)
  }
  # Missing identity must fail closed BEFORE any privilege boundary, proving
  # the elevation check was not moved earlier to hide the defect.
  try {
    $null = & $Installer -PackageRoot $pkg
    throw 'GLUE_ORDERING_UNEXPECTED_SUCCESS'
  } catch {
    if ($_.Exception.Message -ne 'WORKER_ID_REQUIRED') { throw ('GLUE_ORDERING_WRONG_CODE:' + $_.Exception.Message) }
    $report.glue_cases += 'ORDERING:IDENTITY_BEFORE_ELEVATION'
    Write-Output 'INSTALLER_GLUE_ORDERING_PASSED'
  }
} finally {
  if ([IO.Path]::GetDirectoryName($pkg) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  [IO.Directory]::Delete($pkg, $true)
}

$report.passed = $true
Write-Output (@{collision_sites = $report.collision_sites.Count; glue_cases = $report.glue_cases; passed = $true} | ConvertTo-Json -Compress)
