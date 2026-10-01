$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../../deploy/windows/diagnose-worker-service.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'DIAGNOSTIC_SYNTAX_INVALID'}
$function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-SafeServiceFailureTypes'},$true)
. ([ScriptBlock]::Create($function.Extent.Text))
$types=@(Get-SafeServiceFailureTypes @('Service failed: AdapterError','request token=DO_NOT_LOG_THIS_FIXTURE','Service failed: DO_NOT_LOG_THIS_FIXTURE','Service failed: RuntimeError','Service failed: RuntimeError token=DO_NOT_LOG_THIS_FIXTURE'))
if(($types -join '|') -ne 'AdapterError|UNKNOWN_ERROR_CLASS|RuntimeError') {throw 'FAILURE_TYPE_REDACTION_TEST_FAILED'}
if(($types -join '|') -match 'DO_NOT_LOG_THIS_FIXTURE') {throw 'SECRET_IN_DIAGNOSTIC'}
$safeFunction=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-SafeStartupFailure'},$true)
. ([ScriptBlock]::Create($safeFunction.Extent.Text))
$value=[pscustomobject]@{phase='personal_probe';error='FileNotFoundError';errno=2;winerror=3;message='DO_NOT_LOG_THIS_FIXTURE';
  frames=@([pscustomobject]@{file='windows_security.py';line=40;locals='DO_NOT_LOG_THIS_FIXTURE'},[pscustomobject]@{file='DO_NOT_LOG_THIS_FIXTURE';line=10})}
$safe=Get-SafeStartupFailure $value
if($safe.phase -ne 'personal_probe' -or $safe.errno -ne 2 -or $safe.winerror -ne 3 -or $safe.frames.Count -ne 1 -or
   ($safe | ConvertTo-Json -Depth 5) -match 'DO_NOT_LOG_THIS_FIXTURE'){throw 'STRUCTURED_REDACTION_TEST_FAILED'}
$value.phase='DO_NOT_LOG_THIS_FIXTURE'
if((Get-SafeStartupFailure $value).status -ne 'UNAVAILABLE'){throw 'UNKNOWN_PHASE_ACCEPTED'}
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Start-Service|Stop-Service|Set-Service|Set-Acl|Set-ItemProperty|New-Service|New-Item|Copy-Item|Remove-Item|Format-Volume|Initialize-Disk|Mount-DiskImage|sc\.exe)$') {throw 'DIAGNOSTIC_MUTATES_SYSTEM'}
}
Write-Output 'SAFE_SERVICE_DIAGNOSTIC_TEST_PASSED'
