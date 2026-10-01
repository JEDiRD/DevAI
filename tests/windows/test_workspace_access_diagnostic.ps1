$ErrorActionPreference='Stop'
$path=Join-Path $PSScriptRoot '../../deploy/windows/diagnose-worker-workspace-access.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'ACCESS_DIAGNOSTIC_SYNTAX_INVALID'}
foreach($name in @('Initialize-WorkspaceAccessReader','Get-WorkspaceAccessSummary')) {
  $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
  if(!$function){throw 'ACCESS_DIAGNOSTIC_FUNCTION_MISSING'}
  . ([ScriptBlock]::Create($function.Extent.Text))
}
Initialize-WorkspaceAccessReader
$serviceSid='S-1-5-80-1-2-3-4-5'
$descriptor=[Security.AccessControl.RawSecurityDescriptor]::new(('O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;'+$serviceSid+')'))
$bytes=[byte[]]::new($descriptor.BinaryLength)
$descriptor.GetBinaryForm($bytes,0)
$result=[pscustomobject]@{Error=0;SecurityError=0;TagError=0;Attributes=0x410;Tag=0xa0000003L;Descriptor=$bytes;secret='DO_NOT_LOG_THIS_FIXTURE'}
$summary=Get-WorkspaceAccessSummary 'mount_host_entry' $result $serviceSid
if(!$summary.acl_readable -or !$summary.is_mount_point -or !$summary.worker_explicit_allow_modify -or
    !$summary.worker_explicit_allow_list -or !$summary.worker_explicit_allow_traverse -or !$summary.protected -or
    !$summary.owner_trusted -or ($summary | ConvertTo-Json) -match 'DO_NOT_LOG_THIS_FIXTURE|S-1-5-80') {throw 'ACCESS_DIAGNOSTIC_SCHEMA_FAILED'}
$inherited=[Security.AccessControl.RawSecurityDescriptor]::new(('O:SYG:SYD:P(A;OICIIO;0x1301bf;;;'+$serviceSid+')(D;;FR;;;WD)'))
$bytes=[byte[]]::new($inherited.BinaryLength);$inherited.GetBinaryForm($bytes,0);$result.Descriptor=$bytes
$summary=Get-WorkspaceAccessSummary 'mount_target' $result $serviceSid
if($summary.worker_explicit_allow_list -or $summary.worker_explicit_allow_modify -or $summary.deny_entries -ne 1 -or $summary.inherit_only_entries -ne 1){throw 'INHERIT_ONLY_OR_DENY_MISREPRESENTED'}
$result.Error=5;$result.SecurityError=5;$result.Descriptor=$null
$summary=Get-WorkspaceAccessSummary 'mount_target' $result $serviceSid
if($summary.opened_as_admin -or $summary.acl_readable -or $summary.open_winerror -ne 5){throw 'ACCESS_DENIAL_HIDDEN'}
try {Get-WorkspaceAccessSummary 'DO_NOT_LOG_THIS_FIXTURE' $result $serviceSid;throw 'UNKNOWN_LABEL_ACCEPTED'}
catch {if($_.Exception.Message -ne 'ACCESS_DIAGNOSTIC_LABEL_INVALID'){throw}}
$commands=$ast.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true)
foreach($command in $commands) {
  if($command.GetCommandName() -match '(?i)^(Start-Service|Stop-Service|Set-Service|Set-Acl|Set-ItemProperty|New-Service|New-Item|Copy-Item|Remove-Item|Format-Volume|Initialize-Disk|Mount-DiskImage|Set-WorkspaceRootPolicy|Set-NativeWorkspaceSecurity|Set-NetFirewallRule|sc\.exe|diskpart\.exe)$'){throw 'ACCESS_DIAGNOSTIC_MUTATES_SYSTEM'}
}
$source=[IO.File]::ReadAllText($path)
if($source -match 'SetSecurityInfo|SetFileSecurity|WriteFile|DeviceIoControl|AdjustTokenPrivileges|CryptUnprotectData'){throw 'ACCESS_DIAGNOSTIC_NATIVE_MUTATION'}
if($source -notmatch "effective_service_access='NOT_TESTED'"){throw 'ADMIN_CHECK_MISREPRESENTED_AS_SERVICE_PROOF'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('devai-access-diagnostic-'+[Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
  [IO.File]::WriteAllText((Join-Path $temp 'package.json'),'{}')
  try {& $path -PackageRoot $temp -ExpectedManifestSHA256 ('a'*64) -ExpectedInstallerSHA256 ('a'*64) | Out-Null;throw 'INVALID_PACKAGE_ACCEPTED'}
  catch {if($_.Exception.Message -ne 'PACKAGE_MANIFEST_CHANGED'){throw}}
  $native=[DevAIWorkspaceAccessReader]::Read($temp,$false)
  if($native.Error -ne 0 -or $native.SecurityError -ne 0 -or $native.TagError -ne 0 -or !$native.Descriptor){throw 'NATIVE_METADATA_READ_FAILED'}
  $summary=Get-WorkspaceAccessSummary 'mount_target' $native $serviceSid
  if(!$summary.is_directory -or $summary.is_mount_point -or !$summary.acl_readable){throw 'NATIVE_METADATA_SCHEMA_FAILED'}
  # Create and delete ONLY our own junction entry, never recurse into its target.
  $target=Join-Path $temp 'target';$junction=Join-Path $temp 'junction'
  [IO.Directory]::CreateDirectory($target) | Out-Null
  New-Item -ItemType Junction -Path $junction -Target $target | Out-Null
  try {
    $hostSummary=Get-WorkspaceAccessSummary 'mount_host_entry' ([DevAIWorkspaceAccessReader]::Read($junction,$true)) $serviceSid
    $follow=Get-WorkspaceAccessSummary 'mount_target' ([DevAIWorkspaceAccessReader]::Read($junction,$false)) $serviceSid
    if(!$hostSummary.is_mount_point -or !$hostSummary.acl_readable -or $follow.is_mount_point -or !$follow.acl_readable){throw 'REPARSE_AND_TARGET_NOT_DISTINGUISHED'}
  } finally {
    if([IO.Path]::GetDirectoryName($junction) -cne $temp){throw 'UNSAFE_JUNCTION_CLEANUP'}
    [IO.Directory]::Delete($junction,$false)
  }
} finally {
  if([IO.Path]::GetDirectoryName($temp) -ne [IO.Path]::GetTempPath().TrimEnd([char[]]'\/')){throw 'UNSAFE_TEST_CLEANUP'}
  [IO.Directory]::Delete($temp,$true)
}
Write-Output 'WORKSPACE_ACCESS_DIAGNOSTIC_PASSED'
