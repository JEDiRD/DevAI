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
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Start-Service|Stop-Service|Set-Service|Set-Acl|Set-ItemProperty|New-Service|New-Item|Copy-Item|Remove-Item|Format-Volume|Initialize-Disk|Mount-DiskImage|sc\.exe)$') {throw 'DIAGNOSTIC_MUTATES_SYSTEM'}
}
Write-Output 'SAFE_SERVICE_DIAGNOSTIC_TEST_PASSED'
