param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

# The installer must not depend on a human at a console: -WorkerTokenFromStdin
# accepts exactly one token line on redirected stdin (automation), while the
# interactive Read-Host path stays the default. Both converge into
# Read-WorkerTokenSecureString so provisioning sees the same SecureString
# shape either way. This harness drives the REAL helper in child processes
# with controlled stdin and proves: exact delivery, fail-closed empty /
# ambiguous / non-redirected modes, no token residue in output, and that no
# plaintext token channel exists in the installer sources. The interactive
# prompt itself cannot be driven headless, so it is pinned by source gate.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
$Installer = Join-Path $DeployRoot 'install-worker.ps1'
. (Join-Path $DeployRoot 'install-support.ps1')

$report = [ordered]@{ cases = @(); passed = $false }

function Get-TokenSha256([string]$Text) {
  $hasher = [Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
    return (($hasher.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally { $hasher.Dispose() }
}

function Invoke-TokenChild {
  param([string]$Mode, [string]$StdinText, [bool]$RedirectStdin)
  $supportEscaped = (Join-Path $DeployRoot 'install-support.ps1')
  $script = @"
. '$supportEscaped'
try {
  `$s=Read-WorkerTokenSecureString $Mode
  `$b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR(`$s)
  try { `$p=[Runtime.InteropServices.Marshal]::PtrToStringBSTR(`$b) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR(`$b) }
  `$h=[Security.Cryptography.SHA256]::Create()
  `$d=((`$h.ComputeHash([Text.Encoding]::UTF8.GetBytes(`$p)) | ForEach-Object { `$_.ToString('x2') }) -join '')
  `$h.Dispose(); `$p=`$null
  Write-Output ('TOKEN_SHA256='+`$d)
} catch { Write-Output ('CHILD_ERROR='+`$_.Exception.Message); exit 1 }
"@
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = 'powershell'
  $psi.Arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + $script + '"'
  $psi.WorkingDirectory = Join-Path $env:SystemRoot 'System32'
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $RedirectStdin
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $proc = [Diagnostics.Process]::Start($psi)
  try {
    if ($RedirectStdin) {
      $writer = $proc.StandardInput
      if ($null -ne $StdinText) { $writer.Write($StdinText) }
      $writer.Flush()
      $writer.Close()
      $writer = $null
    }
    if (-not $proc.WaitForExit(120000)) { throw 'TOKEN_CHILD_TIMEOUT' }
    $out = $proc.StandardOutput.ReadToEnd()
    $err = $proc.StandardError.ReadToEnd()
    return @{ exit = $proc.ExitCode; out = $out; err = $err }
  } finally {
    if (-not $proc.HasExited) { $proc.Kill() }
  }
}

$token1 = 'devai_wkr_harness_stdin_case1_001'
$expect1 = Get-TokenSha256 $token1

# 1. Exact delivery: one token line on a redirected pipe round-trips byte-exact
# (proven by hash comparison, so the token never needs to appear in output).
$r = Invoke-TokenChild '-FromStdin' $token1 $true
if ($r.exit -ne 0) { throw ('STDIN_EXACT_CHILD_FAILED:' + $r.out + $r.err) }
if (-not $r.out.Contains('TOKEN_SHA256=' + $expect1)) { throw 'STDIN_TOKEN_NOT_DELIVERED_EXACTLY' }
if ($r.out.Contains($token1) -or $r.err.Contains($token1)) { throw 'TOKEN_RESIDUE_IN_CHILD_OUTPUT' }
$report.cases += 'SUCCESS:EXACT_STDIN_DELIVERY_CLEAN_OUTPUT'

# 2. Empty pipe fails closed (no credential can be provisioned from nothing).
$r = Invoke-TokenChild '-FromStdin' $null $true
if ($r.exit -eq 0) { throw 'EMPTY_STDIN_ACCEPTED' }
if (-not $r.out.Contains('CHILD_ERROR=WORKER_TOKEN_STDIN_EMPTY')) { throw ('EMPTY_STDIN_WRONG_ERROR:' + $r.out) }
$report.cases += 'FAILURE:EMPTY_STDIN_REJECTED'

# 3. Ambiguous input (two token lines) fails closed rather than guessing.
$r = Invoke-TokenChild '-FromStdin' ($token1 + "`r`n" + 'devai_wkr_harness_second_line') $true
if ($r.exit -eq 0) { throw 'AMBIGUOUS_STDIN_ACCEPTED' }
if (-not $r.out.Contains('CHILD_ERROR=WORKER_TOKEN_STDIN_AMBIGUOUS')) { throw ('AMBIGUOUS_STDIN_WRONG_ERROR:' + $r.out) }
$report.cases += 'FAILURE:AMBIGUOUS_STDIN_REJECTED'

# 4. Switch without a redirected pipe fails closed instead of hanging on a
# prompt. The child inherits this harness's stdin when not redirected, so this
# case runs live only when the harness itself owns a console; otherwise the
# skip is recorded explicitly (the guard stays pinned by source gate below).
if ([Console]::IsInputRedirected) {
  $report.cases += 'SKIPPED:NOT_REDIRECTED_CHILD_WOULD_INHERIT_REDIRECTED_STDIN'
} else {
  $r = Invoke-TokenChild '-FromStdin' $null $false
  if ($r.exit -eq 0) { throw 'NON_REDIRECTED_STDIN_ACCEPTED' }
  if (-not $r.out.Contains('CHILD_ERROR=WORKER_TOKEN_STDIN_NOT_REDIRECTED')) { throw ('NON_REDIRECTED_WRONG_ERROR:' + $r.out) }
  $report.cases += 'FAILURE:NON_REDIRECTED_STDIN_REJECTED'
}

# 5. Interactive default preserved: without the switch the installer still
# prompts (source gate; the prompt itself cannot be driven headless).
$installerSource = [IO.File]::ReadAllText($Installer)
if (-not $installerSource.Contains('[switch]$WorkerTokenFromStdin')) { throw 'STDIN_SWITCH_MISSING' }
if (-not $installerSource.Contains("Read-WorkerTokenSecureString -FromStdin:`$WorkerTokenFromStdin")) { throw 'SWITCH_NOT_CONVERGED' }
$supportSource = [IO.File]::ReadAllText((Join-Path $DeployRoot 'install-support.ps1'))
if (-not $supportSource.Contains("Read-Host -Prompt 'Worker token' -AsSecureString")) { throw 'INTERACTIVE_PROMPT_REMOVED' }
$report.cases += 'INTERACTIVE:DEFAULT_PROMPT_PRESERVED_AND_CONVERGED'

# 6. No plaintext token channel exists anywhere in the installer surface. The
# only [string]$Token in the tree is the internal parameter of
# Invoke-TargetCredentialProvisioning (the converged stdin-feed
# implementation itself), never a user-facing CLI parameter.
foreach ($forbidden in @('[string]$WorkerToken', '--token', '$env:DEVAI')) {
  if ($installerSource.Contains($forbidden) -or $supportSource.Contains($forbidden)) {
    throw ('PLAINTEXT_TOKEN_CHANNEL:' + $forbidden)
  }
}
$paramBlock = $installerSource.Substring(0, $installerSource.IndexOf("`$ErrorActionPreference"))
if ($paramBlock -match '\[string\]\$Token') { throw 'PLAINTEXT_TOKEN_CLI_PARAMETER' }
$codeLines = @($supportSource -split "`r?`n" | Where-Object { $_ -notmatch '^\s*#' })
if (($codeLines -join "`n") -match '\$Token\s*=(?!\$null)') { throw 'TOKEN_REASSIGNED_IN_HELPER' }
# The SecureString/BSTR/stdin provisioning it converges into is unchanged.
foreach ($required in @('SecureStringToBSTR', 'Invoke-TargetCredentialProvisioning', 'ZeroFreeBSTR')) {
  if (-not $installerSource.Contains($required)) { throw ('CONVERGENCE_BROKEN:' + $required) }
}
$report.cases += 'SECRECY:NO_PLAINTEXT_CHANNEL_CONVERGENCE_INTACT'

$report.passed = $true
Write-Output 'WORKER_TOKEN_STDIN_CASES_PASSED'
Write-Output ($report | ConvertTo-Json -Depth 4 -Compress)
