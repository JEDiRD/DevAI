param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'))
$ErrorActionPreference = 'Stop'

# RH-D: Invoke-TargetCredentialProvisioning assigned $null to
# $process.StandardInput, which is a read-only property, so every fresh
# install died with PropertyAssignmentException AFTER the operator typed the
# token. The fix takes the writer into a local, flushes/closes it, and drops
# the local. This harness executes the REAL function with a disposable
# token and a controlled child (a real interpreter running a fixture
# provision module -- no DPAPI, no network, no secrets), and proves the ten
# required properties. Nothing here weakens secret handling: the token
# travels SecureString (operator/host) -> BSTR -> child stdin only.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
. (Join-Path $DeployRoot 'install-support.ps1')

$report = [ordered]@{ cases = @(); passed = $false }

# Controlled child interpreter: real python.exe + its DLLs + full Lib from
# the base install (never the host's identity, only its bytes to start a
# process). Full Lib because the fixture module uses json/os like any
# ordinary payload; subsetting it would rot the same way the sandbox did.
$pyBase = (& python -c 'import sys; print(sys.base_prefix)').Trim()
if (-not $pyBase -or !(Test-Path -LiteralPath (Join-Path $pyBase 'python.exe'))) { throw 'PROBE_INTERPRETER_UNAVAILABLE' }
$probe = Join-Path ([IO.Path]::GetTempPath()) ('rhb-prov-probe-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($probe) | Out-Null
try {
  $rt = Join-Path $probe 'runtime'
  [IO.Directory]::CreateDirectory($rt) | Out-Null
  Copy-Item -LiteralPath (Join-Path $pyBase 'python.exe') -Destination (Join-Path $rt 'python.exe')
  foreach ($dll in @(Get-ChildItem -LiteralPath $pyBase -Filter '*.dll' -File)) {
    Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $rt $dll.Name)
  }
  foreach ($dir in @('Lib', 'DLLs')) {
    $src = Join-Path $pyBase $dir
    if (Test-Path -LiteralPath $src) {
      Copy-Item -LiteralPath $src -Destination (Join-Path $rt $dir) -Recurse
    }
  }

  $installRoot = Join-Path $probe 'install'
  # Production layout mirrored: the package lives under control/, and the
  # fixed function runs the child with control/ as its working directory so
  # that -m worker_agent.provision resolves. Observation files land there.
  $controlRoot = Join-Path $installRoot 'control'
  [IO.Directory]::CreateDirectory((Join-Path $controlRoot 'worker_agent')) | Out-Null
  [IO.File]::WriteAllText((Join-Path $controlRoot 'worker_agent/__init__.py'), '')
  # Fixture twin of worker_agent.provision: same CLI shape and stdin
  # protocol, but records observations instead of touching DPAPI. It writes
  # the credential marker file itself so the caller's post-condition
  # (credential present after exit 0) is exercisable without secrets.
  [IO.File]::WriteAllText((Join-Path $controlRoot 'worker_agent/provision.py'), @'
import sys, os, json
def main():
    args = sys.argv[1:]
    data = sys.stdin.buffer.read()
    with open("provision-argv.json", "w") as fh:
        json.dump(args, fh)
    with open("provision-stdin.bin", "wb") as fh:
        fh.write(data)
    with open("provision-env.json", "w") as fh:
        json.dump(dict(os.environ), fh)
    store = None
    if "--store-path" in args:
        store = args[args.index("--store-path") + 1]
    if data == b"TRIGGER-CHILD-FAIL":
        sys.exit(3)
    with open(store, "wb") as fh:
        fh.write(b"TEST-FIXTURE-CREDENTIAL")
    sys.exit(0)
main()
'@)

  $InvokeProvision = {
    param([string]$WorkerId, [string]$Cred, [string]$Tok)
    Push-Location $installRoot
    try {
      Remove-Item -LiteralPath (Join-Path $controlRoot 'provision-argv.json') -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath (Join-Path $controlRoot 'provision-stdin.bin') -Force -ErrorAction SilentlyContinue
      Remove-Item -LiteralPath (Join-Path $controlRoot 'provision-env.json') -Force -ErrorAction SilentlyContinue
      return Invoke-TargetCredentialProvisioning -InstallRoot $installRoot -RuntimeRoot $rt -WorkerId $WorkerId -CredentialPath $Cred -Token $Tok
    } finally { Pop-Location }
  }

  $workerId = '11111111-2222-3333-4444-555555555555'
  $cred1 = Join-Path $probe 'cred1.dpapi'
  $token1 = 'tok en"with-quotes"-and-$dollar-\back&semi:colon'
  $tokBytes1 = [Text.Encoding]::UTF8.GetBytes($token1)

  # Success path: real function, disposable token.
  $r = & $InvokeProvision $workerId $cred1 $token1
  if ($r -ne $true) { throw 'PROVISION_SUCCESS_NOT_TRUE' }
  # 2. child received exactly the stdin payload.
  $got = [IO.File]::ReadAllBytes((Join-Path $controlRoot 'provision-stdin.bin'))
  if (([BitConverter]::ToString($got)) -ne ([BitConverter]::ToString($tokBytes1))) { throw 'STDIN_PAYLOAD_MISMATCH' }
  # 3. token nowhere in argv; exact expected argv otherwise.
  $argv = Get-Content -LiteralPath (Join-Path $controlRoot 'provision-argv.json') -Raw | ConvertFrom-Json
  $joinedArgv = ($argv -join ' ')
  if ($joinedArgv.Contains($token1)) { throw 'TOKEN_IN_ARGV' }
  $expectArgv = @('--worker-id', $workerId, '--store-path', $cred1)
  if ((@($argv) -join "`0") -ne ($expectArgv -join "`0")) { throw ('ARGV_UNEXPECTED:' + $joinedArgv) }
  # 4. token nowhere in the child environment.
  $envDoc = Get-Content -LiteralPath (Join-Path $controlRoot 'provision-env.json') -Raw | ConvertFrom-Json
  foreach ($prop in $envDoc.PSObject.Properties) {
    if ([string]$prop.Value -like ('*' + $token1 + '*')) { throw ('TOKEN_IN_ENV:' + $prop.Name) }
  }
  # 8. writer closed: an immediate second, distinct provisioning works.
  $cred2 = Join-Path $probe 'cred2.dpapi'
  $r2 = & $InvokeProvision $workerId $cred2 ($token1 + '-second')
  if ($r2 -ne $true) { throw 'SECOND_PROVISION_FAILED' }
  $got2 = [IO.File]::ReadAllBytes((Join-Path $controlRoot 'provision-stdin.bin'))
  if (([BitConverter]::ToString($got2)) -ne ([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($token1 + '-second')))) { throw 'SECOND_STDIN_MISMATCH' }
  $report.cases += 'SUCCESS:EXACT_STDIN_CLEAN_ARGV_CLEAN_ENV_REPEATABLE'
  # 6+10 implicit: both credential markers exist (post-condition held).
  foreach ($c in @($cred1, $cred2)) { if (!(Test-Path -LiteralPath $c -PathType Leaf)) { throw 'CREDENTIAL_MARKER_MISSING' } }

  # 7+10. Child failure propagates fail-closed; no credential artifact.
  $credFail = Join-Path $probe 'cred-fail.dpapi'
  try {
    $null = & $InvokeProvision $workerId $credFail 'TRIGGER-CHILD-FAIL'
    throw 'CHILD_FAILURE_ACCEPTED'
  } catch {
    if ($_.Exception.Message -ne 'CREDENTIAL_PROVISIONING_FAILED') { throw ('CHILD_FAILURE_WRONG_CODE:' + $_.Exception.Message) }
  }
  if (Test-Path -LiteralPath $credFail) { throw 'FAILED_RUN_LEFT_CREDENTIAL' }
  $report.cases += 'FAILURE:PROPAGATED_NO_CREDENTIAL'

  # Negative control: the pre-fix shape (assigning the read-only property)
  # must die with the reproduced error, proving this harness detects it.
  function TestOnly-OldProvision {
    param([string]$InstallRoot, [string]$RuntimeRoot, [string]$WorkerId, [string]$CredentialPath, [string]$Token)
    $python = Join-Path $RuntimeRoot 'python.exe'
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $python
    $psi.Arguments = '-m worker_agent.provision --worker-id ' + $WorkerId + ' --store-path "' + $CredentialPath + '"'
    $psi.WorkingDirectory = Join-Path $InstallRoot 'control'
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($psi)
    try {
      $process.StandardInput.Write($Token)
      $process.StandardInput.Close()
      $process.StandardInput = $null
    } finally {
      if (!$process.HasExited) { $process.Kill() }
    }
  }
  Push-Location $installRoot
  try {
    try {
      TestOnly-OldProvision -InstallRoot $installRoot -RuntimeRoot $rt -WorkerId $workerId -CredentialPath (Join-Path $probe 'cred-neg.dpapi') -Token $token1
      throw 'NEGATIVE_CONTROL_BLIND'
    } catch {
      $msg = $_.Exception.Message + ' ' + $_.FullyQualifiedErrorId
      if ($msg -notmatch 'ReadOnly') { throw ('NEGATIVE_WRONG_ERROR:' + $msg) }
    }
  } finally { Pop-Location }
  $report.cases += 'NEGATIVE:OLD_SHAPE_REJECTED_WITH_READONLY'

  # 9. Secret-memory cleanup behavior intact (structural guard on the fix).
  $funcText = (Get-Command Invoke-TargetCredentialProvisioning).ScriptBlock.ToString()
  if ($funcText -notmatch '\$Token=\$null') { throw 'TOKEN_CLEANUP_REMOVED' }
  if ($funcText -match '\$process\.StandardInput\s*=') { throw 'READONLY_ASSIGNMENT_STILL_PRESENT' }
  $report.cases += 'CLEANUP:INTACT_NO_PROPERTY_ASSIGNMENT'

  Write-Output 'CREDENTIAL_PROVISIONING_CASES_PASSED'
  # 5. No token in any harness-written artifact except the stdin capture
  # itself (deleted below with the probe root). Runtime binaries are copies
  # of system files the test never writes, so only test-written files are
  # in scope. Stdout carries only fixed markers ($token is never
  # Write-Output here).
  foreach ($name in @('provision-argv.json', 'provision-env.json')) {
    $text = [IO.File]::ReadAllText((Join-Path $controlRoot $name))
    foreach ($needle in @($token1, ($token1 + '-second'))) {
      if ($text.Contains($needle)) { throw ('TOKEN_LEAKED_INTO_FILE:' + $name) }
    }
  }
  foreach ($cred in @($cred1, $cred2)) {
    if ([IO.File]::ReadAllText($cred).Contains($token1)) { throw 'TOKEN_STORED_AS_CREDENTIAL' }
  }
  $report.cases += 'SECRECY:NO_TOKEN_IN_FILES_OR_OUTPUT'
} finally {
  if ((Split-Path -Parent $probe) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP_PATH' }
  if (Test-Path -LiteralPath $probe) { [IO.Directory]::Delete($probe, $true) }
  if (Test-Path -LiteralPath $probe) { throw 'PROBE_RESIDUE_REMAINS' }
}

$report.passed = $true
Write-Output (@{cases = $report.cases; passed = $true} | ConvertTo-Json -Compress)
