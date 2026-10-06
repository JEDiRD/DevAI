param([string]$DeployRoot = (Join-Path $PSScriptRoot '../../deploy/windows'),
      [string]$PackageSource = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'

# RH-D: the worker service was launched as
#   host-runtime/python.exe -I -S -B -m worker_agent.windows_service --config ...
# The pinned embedded interpreter carries python313._pth, which honors neither
# the working directory nor PYTHONPATH and skips site, and SCM starts the
# service with cwd=System32. Every install therefore died at service start with
# "ModuleNotFoundError: No module named 'worker_agent'". The command now
# establishes the packaged control path explicitly and runs the module through
# runpy, keeping -I -S -B and the exact argument tail.
#
# This harness executes the REAL generated command against a REAL interpreter
# and the REAL worker_agent package in the production control/ layout, with
# cwd=System32, and pins the legacy shape as a negative control so the fix can
# never silently regress into an environment-dependent pass. No service is
# created: ServiceHost.run() reaches StartServiceCtrlDispatcherW, which fails
# immediately outside SCM (SCM_SERVICE_DISPATCH_FAILED) before any state,
# volume, credential or network access.
$DeployRoot = (Resolve-Path -LiteralPath $DeployRoot).Path
$PackageSource = (Resolve-Path -LiteralPath $PackageSource).Path
. (Join-Path $DeployRoot 'install-support.ps1')

$report = [ordered]@{ cases = @(); passed = $false }

# Real interpreter bytes (never the host identity, only its files to start a
# process), mirroring the credential harness: python.exe + DLLs + Lib + DLLs.
$pyBase = (& python -c 'import sys; print(sys.base_prefix)').Trim()
if (-not $pyBase -or !(Test-Path -LiteralPath (Join-Path $pyBase 'python.exe'))) { throw 'PROBE_INTERPRETER_UNAVAILABLE' }

$probe = Join-Path ([IO.Path]::GetTempPath()) ('rhb-svc-resolve-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($probe) | Out-Null
try {
  $installRoot = Join-Path $probe 'install'
  $runtimeRoot = Join-Path $installRoot 'host-runtime'
  [IO.Directory]::CreateDirectory($runtimeRoot) | Out-Null
  Copy-Item -LiteralPath (Join-Path $pyBase 'python.exe') -Destination (Join-Path $runtimeRoot 'python.exe')
  foreach ($dll in @(Get-ChildItem -LiteralPath $pyBase -Filter '*.dll' -File)) {
    Copy-Item -LiteralPath $dll.FullName -Destination (Join-Path $runtimeRoot $dll.Name)
  }
  foreach ($dir in @('Lib', 'DLLs')) {
    $src = Join-Path $pyBase $dir
    if (Test-Path -LiteralPath $src) {
      Copy-Item -LiteralPath $src -Destination (Join-Path $runtimeRoot $dir) -Recurse
    }
  }

  # Production package layout: the package lives under control/worker_agent.
  $controlRoot = Join-Path $installRoot 'control'
  [IO.Directory]::CreateDirectory($controlRoot) | Out-Null
  Copy-Item -LiteralPath (Join-Path $PackageSource 'worker_agent') -Destination (Join-Path $controlRoot 'worker_agent') -Recurse
  if (-not (Test-Path -LiteralPath (Join-Path $controlRoot 'worker_agent/windows_service.py'))) {
    throw 'PRODUCTION_PACKAGE_LAYOUT_NOT_MIRRORED'
  }

  $configFile = 'C:\ProgramData\DevAIWorker\service.json'
  $command = Get-WorkerServiceCommand $installRoot $configFile

  # 1. The generated command no longer depends on -m resolution.
  if ($command.Contains('-m worker_agent')) { throw 'SERVICE_COMMAND_STILL_USES_DASH_M' }
  # 2. Isolation flags retained.
  if ($command -notmatch ' -I -S -B ') { throw 'ISOLATION_FLAGS_MISSING' }
  # 3. The service argument tail is preserved exactly.
  if (-not $command.Contains('--config "' + $configFile + '"')) { throw 'SERVICE_CONFIG_ARG_CHANGED' }

  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = Join-Path $runtimeRoot 'python.exe'
  $psi.Arguments = $command.Substring($command.IndexOf(' -I') + 1)
  # 4. SCM-style context: the working directory is outside the package.
  $psi.WorkingDirectory = Join-Path $env:SystemRoot 'System32'
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $proc = [Diagnostics.Process]::Start($psi)
  $stdout = $proc.StandardOutput.ReadToEnd()
  $stderr = $proc.StandardError.ReadToEnd()
  $proc.WaitForExit()

  if ($stderr.Contains('ModuleNotFoundError')) { throw ('SERVICE_MODULE_UNRESOLVED:' + $stderr.Trim()) }
  # exit 2 would be argparse rejecting the arguments; anything else means the
  # module was imported and main() ran to the SCM dispatcher.
  if ($proc.ExitCode -eq 2) { throw ('SERVICE_ARGUMENTS_REJECTED:' + $stderr.Trim()) }
  if (-not $stderr.Contains('SCM_SERVICE_DISPATCH_FAILED')) {
    throw ('SERVICE_COMMAND_DID_NOT_REACH_SERVICE_HOST:' + $stderr.Trim())
  }
  if (-not $stderr.Contains('windows_service.py')) { throw 'SERVICE_COMMAND_DID_NOT_RUN_THE_SERVICE_MODULE' }
  $report.cases += 'RESOLVES_FROM_SYSTEM32:EXACT_GENERATED_COMMAND'

  # 5. The volume-host helper service is the same command plus one flag, and
  # the flag is accepted (a rejected flag exits 2).
  $helperCommand = $command + ' --volume-host'
  $psi.Arguments = $helperCommand.Substring($helperCommand.IndexOf(' -I') + 1)
  $helper = [Diagnostics.Process]::Start($psi)
  $helperErr = $helper.StandardError.ReadToEnd()
  $helper.WaitForExit()
  if ($helperErr.Contains('ModuleNotFoundError')) { throw 'VOLUME_HELPER_MODULE_UNRESOLVED' }
  if ($helper.ExitCode -eq 2) { throw 'VOLUME_HELPER_FLAG_REJECTED' }
  if (-not $helperErr.Contains('SCM_SERVICE_DISPATCH_FAILED')) { throw 'VOLUME_HELPER_DID_NOT_REACH_SERVICE_HOST' }
  $report.cases += 'VOLUME_HELPER:FLAG_PRESERVED_AND_RESOLVES'

  # 6. Negative control: the legacy shape, identical runtime, package layout
  # and working directory, still fails. This is what proves the fix -- not the
  # environment -- is responsible for the resolution.
  $legacy = '-I -S -B -m worker_agent.windows_service --config "' + $configFile + '"'
  $psi.Arguments = $legacy
  $old = [Diagnostics.Process]::Start($psi)
  $oldErr = $old.StandardError.ReadToEnd()
  $old.WaitForExit()
  if (-not $oldErr.Contains('ModuleNotFoundError')) { throw 'LEGACY_SHAPE_DID_NOT_REPRODUCE_DEFECT' }
  $report.cases += 'NEGATIVE_CONTROL:LEGACY_DASH_M_REPRODUCES_MODULE_NOT_FOUND'

  # 7. No bypass was introduced to reach resolution.
  $codeLines = @([IO.File]::ReadAllText((Join-Path $DeployRoot 'install-support.ps1')) -split "`r?`n" |
                 Where-Object { $_ -notmatch '^\s*#' })
  foreach ($forbidden in @('PYTHONPATH', 'import site')) {
    if (($codeLines -join "`n").Contains($forbidden)) { throw ('ISOLATION_BYPASS_INTRODUCED:' + $forbidden) }
  }
  $report.cases += 'NO_BYPASS:ISOLATION_FLAGS_AND_NO_ENV_DEPENDENCY'

  $report.passed = $true
}
finally {
  Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output 'SERVICE_COMMAND_RESOLUTION_CASES_PASSED'
Write-Output ($report | ConvertTo-Json -Depth 4 -Compress)
