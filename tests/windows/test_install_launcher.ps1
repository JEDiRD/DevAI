param([string]$Launcher=(Join-Path $PSScriptRoot '../../deploy/windows/launch-worker-install.ps1'))
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('devai-launcher-test-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($root) | Out-Null
try {
  $installer=Join-Path $root 'install-worker.ps1'
  [IO.File]::WriteAllText((Join-Path $root 'package.json'),'{}')
  # Deliberately simulate the original failure with secret-bearing exception
  # text. The diagnostic output must preserve location without the text.
  [IO.File]::WriteAllText($installer,@'
param($PackageRoot,[switch]$ValidateOnly)
throw [System.Management.Automation.ItemNotFoundException]::new('token=DO_NOT_LOG_THIS_FIXTURE')
'@)
  $manifestHash=(Get-FileHash -LiteralPath (Join-Path $root 'package.json')).Hash.ToLowerInvariant()
  $installerHash=(Get-FileHash -LiteralPath $installer).Hash.ToLowerInvariant()
  $result=Join-Path $root 'result.json'
  $failed=$false
  try {
    $captured=& $Launcher -PackageRoot $root -ExpectedManifestSHA256 $manifestHash -ExpectedInstallerSHA256 $installerHash -ResultPath $result -DiagnoseOnly
  } catch {
    $failed=$true
    if ($_.Exception.Message -notmatch '^DEVAI_INSTALL_FAILED phase=package_validation ') { throw }
    if ($_.Exception.Message -match 'DO_NOT_LOG_THIS_FIXTURE') { throw 'SECRET_IN_ERROR' }
  }
  if (!$failed) { throw 'FAILURE_NOT_REPORTED' }
  $raw=Get-Content -LiteralPath $result -Raw
  if ($raw -match 'DO_NOT_LOG_THIS_FIXTURE') { throw 'SECRET_IN_DIAGNOSTIC' }
  $report=$raw | ConvertFrom-Json
  if ($report.phase -ne 'package_validation' -or $report.frames.Count -lt 1 -or
      !($report.frames | Where-Object {$_.file -eq 'install-worker.ps1' -and $_.line -eq 2})) { throw 'ORIGINAL_ERROR_LOCATION_LOST' }
  Write-Output 'LAUNCHER_DIAGNOSTICS_TEST_PASSED'
} finally {
  if ([IO.Path]::GetDirectoryName($root) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')) { throw 'UNSAFE_TEST_CLEANUP' }
  [IO.Directory]::Delete($root,$true)
}
