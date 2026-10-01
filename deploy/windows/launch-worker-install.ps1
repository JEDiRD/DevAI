param(
  [Parameter(Mandatory=$true)][string]$PackageRoot,
  [Parameter(Mandatory=$true)][string]$ExpectedManifestSHA256,
  [Parameter(Mandatory=$true)][string]$ExpectedInstallerSHA256,
  [Parameter(Mandatory=$true)][string]$ResultPath,
  [switch]$DiagnoseOnly,
  [switch]$ResumeServiceCreation
)
$ErrorActionPreference='Stop'
$phase='manifest_hash'
try {
  if ((Get-FileHash -LiteralPath (Join-Path $PackageRoot 'package.json') -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedManifestSHA256) { throw 'PACKAGE_MANIFEST_CHANGED' }
  $phase='installer_hash'
  $installer=Join-Path $PackageRoot 'install-worker.ps1'
  if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExpectedInstallerSHA256) { throw 'PACKAGE_INSTALLER_CHANGED' }
  $phase='package_validation'
  & $installer -PackageRoot $PackageRoot -ValidateOnly
  $phase='installation_preflight'
  $principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
  $admin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  $programFiles=Get-Item -LiteralPath $env:ProgramFiles -Force
  $programData=Get-Item -LiteralPath $env:ProgramData -Force
  $service=[bool](Get-Service -Name DevAIWorker -ErrorAction Ignore)
  $existingCode=Test-Path -LiteralPath (Join-Path $programFiles.FullName 'DevAIWorker')
  $existingState=Test-Path -LiteralPath (Join-Path $programData.FullName 'DevAIWorker')
  if ($DiagnoseOnly) {
    if ($ResumeServiceCreation) {
      & $installer -PackageRoot $PackageRoot -ResumeServiceCreation -InspectInstall
    }
    $proof=@{diagnostic_only=$true;package_validated=$true;administrator=$admin;service_exists=$service;installation_directory_exists=$existingCode;state_directory_exists=$existingState;process_64_bit=[Environment]::Is64BitProcess;phase=$phase;at=[DateTime]::UtcNow.ToString('o')}
    [IO.File]::WriteAllText($ResultPath,($proof | ConvertTo-Json))
    Write-Output ($proof | ConvertTo-Json -Compress)
    return
  }
  $phase='installation'
  & $installer -PackageRoot $PackageRoot -ResumeServiceCreation:$ResumeServiceCreation
  [IO.File]::WriteAllText($ResultPath,(@{completed=$true;phase='completed';at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json))
} catch {
  $original=$_
  $code=($original.FullyQualifiedErrorId -split ',')[0]
  if ($code -notmatch '^[A-Za-z0-9_.]{1,100}$') { $code=$original.Exception.GetType().Name }
  $frames=@([regex]::Matches($original.ScriptStackTrace,'([\w-]+\.ps1):[^\d\r\n]*(\d+)') | ForEach-Object {
    # Source locations only, never full traces, command text, values or URLs.
    @{file=$_.Groups[1].Value;line=[int]$_.Groups[2].Value}
  })
  $report=@{completed=$false;phase=$phase;error=$original.Exception.GetType().Name;code=$code;frames=$frames;at=[DateTime]::UtcNow.ToString('o')}
  [IO.File]::WriteAllText($ResultPath,($report | ConvertTo-Json -Depth 5))
  Write-Output ($report | ConvertTo-Json -Depth 5 -Compress)
  throw ('DEVAI_INSTALL_FAILED phase='+$phase+' code='+$code)
}
