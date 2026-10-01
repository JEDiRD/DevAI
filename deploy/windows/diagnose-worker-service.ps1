param()
$ErrorActionPreference='Stop'
function Get-SafeServiceFailureTypes([string[]]$Lines) {
  $allowed=@('RuntimeError','AdapterError','PermissionError','FileNotFoundError','OSError','TimeoutError','ValueError','KeyError','JSONDecodeError')
  foreach ($line in $Lines) {
    if ($line -match 'Service failed: ([A-Za-z][A-Za-z0-9_]*)\s*$') {
      if ($matches[1] -in $allowed) { $matches[1] } else { 'UNKNOWN_ERROR_CLASS' }
    }
  }
}
function Get-SafeStartupFailure($Value) {
  $phases=@('config','install_verification','logging','volume_attach','workspace_open','workspace_recovery','process_allowlist','personal_probe','native_gates','journal','agent','startup_proof','running','unknown')
  $types=@('RuntimeError','AdapterError','PermissionError','FileNotFoundError','OSError','TimeoutError','ValueError','KeyError','JSONDecodeError','UNKNOWN_ERROR_CLASS')
  $files=@('windows_service.py','windows_security.py','workspace.py','windows_process.py','service_acceptance.py','execution_journal.py','service_credentials.py','agent.py','process_adapter.py','adapters.py','volume_host.py')
  if (!$Value -or $Value.phase -notin $phases -or $Value.error -notin $types) {return @{status='UNAVAILABLE'}}
  $safe=@{phase=[string]$Value.phase;error=[string]$Value.error;frames=@()}
  if(($Value.at -is [double] -or $Value.at -is [long] -or $Value.at -is [int]) -and $Value.at -ge 1000000000 -and $Value.at -le 4102444800) {$safe.failure_at_epoch=$Value.at}
  foreach($key in @('errno','winerror')) {
    $number=$Value.$key
    if($number -is [int] -and $number -ge 0 -and $number -le 65535) {$safe[$key]=$number}
  }
  foreach($frame in @($Value.frames | Select-Object -Last 8)) {
    if($frame.file -cin $files -and $frame.line -is [int] -and $frame.line -gt 0 -and $frame.line -le 100000) {
      $safe.frames+=@{file=[string]$frame.file;line=[int]$frame.line}
    }
  }
  $probe=$Value.workspace_access
  if($probe.status -ceq 'UNAVAILABLE') {$safe.workspace_access=@{status='UNAVAILABLE'}}
  elseif($probe.status -ceq 'AVAILABLE' -and $probe.context -ceq 'VERIFIED_WORKER_STARTUP') {
    $checked=@{status='AVAILABLE';context='VERIFIED_WORKER_STARTUP';opens=@();token=@{status='UNAVAILABLE'}}
    $token=$probe.token
    if($token.status -ceq 'AVAILABLE' -and $token.source -cin @('process','thread')) {
      $checked.token=@{status='AVAILABLE';source=[string]$token.source}
      foreach($field in @('elevated','has_restrictions','appcontainer','change_notify_present','change_notify_enabled','backup_present','backup_enabled','restore_present','restore_enabled')) {
        if($token.$field -is [bool]){$checked.token[$field]=[bool]$token.$field}
      }
      if($token.restricted_sid_count -is [int] -and $token.restricted_sid_count -ge 0 -and $token.restricted_sid_count -le 128){$checked.token.restricted_sid_count=[int]$token.restricted_sid_count}
    }
    foreach($row in @($probe.opens | Select-Object -First 18)) {
      if($row.label -cin @('state_parent','state_root','mount_host_entry','mount_target','mount_target_trailing','guid_root') -and
          $row.access -cin @('list','attributes','read_control') -and $row.opened -is [bool] -and
          $row.winerror -is [int] -and $row.winerror -ge 0 -and $row.winerror -le 65535) {
        $checked.opens+=@{label=[string]$row.label;access=[string]$row.access;opened=[bool]$row.opened;winerror=[int]$row.winerror}
      }
    }
    $safe.workspace_access=$checked
  }
  return $safe
}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'ADMINISTRATOR_DIAGNOSTIC_REQUIRED' }
$state=Join-Path $env:ProgramData 'DevAIWorker'
$code=Join-Path $env:ProgramFiles 'DevAIWorker'
$report=@{read_only=$true;at=[DateTime]::UtcNow.ToString('o');services=@();logs=@();acl=@()}
foreach ($name in @('DevAIWorkerVolumes','DevAIWorker')) {
  $service=Get-CimInstance Win32_Service -Filter ("Name='"+$name+"'")
  $report.services+=@{name=$name;state=$service.State;account=$service.StartName;exit_code=$service.ExitCode;specific_exit_code=$service.ServiceSpecificExitCode;pid=$service.ProcessId}
  $path=Join-Path $state ('logs/'+$name+'.log')
  try {
    $types=@(Get-SafeServiceFailureTypes (Get-Content -LiteralPath $path -Tail 30))
    $report.logs+=@{service=$name;readable=$true;recent_failure_types=$types}
  } catch { $report.logs+=@{service=$name;readable=$false} }
  $startup=Join-Path $state ('reports/'+$name+'-startup-failure.json')
  try {
    $failure=Get-SafeStartupFailure (Get-Content -LiteralPath $startup -Raw | ConvertFrom-Json)
  } catch {$failure=@{status='UNAVAILABLE'}}
  $report.logs[-1].startup_failure=$failure
}
# Only public paths/IDs/hash configuration is read. The DPAPI file is NEVER read.
$config=Get-Content -LiteralPath (Join-Path $state 'service.json') -Raw | ConvertFrom-Json
$sid=$config.service_sid
$labels=@{code_root=$code;state_root=$state;config=(Join-Path $state 'service.json');credentials_directory=(Join-Path $state 'credentials');credential_file=(Join-Path $state 'credentials/worker.dpapi');journal=(Join-Path $state 'journal');logs=(Join-Path $state 'logs');manifest=(Join-Path $code 'manifest.json')}
foreach ($label in $labels.Keys) {
  try {
    $acl=Get-Acl -LiteralPath $labels[$label]
    $owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
    $foreign=0;$workerWrite=$false;$workerRead=$false
    foreach ($entry in $acl.Access) {
      $entrySid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
      if ($entry.AccessControlType -eq 'Allow') {
        if ($entrySid -notin @('S-1-5-18','S-1-5-32-544',$sid)) {$foreign++}
        if ($entrySid -eq $sid) {
          $workerWrite=$workerWrite -or ([int]$entry.FileSystemRights -band 0x000d0116) -ne 0
          $workerRead=$workerRead -or ([int]$entry.FileSystemRights -band 0x00020001) -eq 0x00020001
        }
      }
    }
    $report.acl+=@{label=$label;owner_trusted=($owner -in @('S-1-5-18','S-1-5-32-544'));protected=$acl.AreAccessRulesProtected;foreign_allow_entries=$foreign;worker_can_write=$workerWrite;worker_can_read=$workerRead}
  } catch {$report.acl+=@{label=$label;readable=$false}}
}
$profile=Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'+$sid) -ErrorAction Ignore
$report.service_profile_registered=[bool]$profile
$report.service_profile_directory_exists=[bool]($profile -and (Test-Path -LiteralPath $profile.ProfileImagePath))
# Replay the existing ACL checker as administrator only. This does not replay
# Worker execution, identity checks, DPAPI, jobs, process adapters or heartbeat.
$python=Join-Path $code 'host-runtime/python.exe'
$probe=@'
import json,os
from pathlib import Path
from worker_agent.windows_service import verify_install
path=Path(os.environ['ProgramData'])/'DevAIWorker'/'service.json'
try:
    cfg=json.loads(path.read_text())
    verify_install(path,cfg,volume_host=True)
    print(json.dumps({'acl_check_as_admin':'PASSED'}))
except Exception as error:
    allowed={'UNMANAGED_SERVICE_CONFIG','SERVICE_ACL_UNSAFE','REPARSE_POINT_REJECTED'}
    value=getattr(error,'code',None)
    if value not in allowed:
        value=error.args[0] if isinstance(error,RuntimeError) and len(error.args)==1 and error.args[0] in allowed else 'UNKNOWN_ERROR'
    print(json.dumps({'acl_check_as_admin':'FAILED','code':value}))
'@
try {
  $output=@(& $python -I -S -B -c $probe 2>&1)
  $report.runtime_acl_probe=(($output | Where-Object {$_ -is [string] -and $_.StartsWith('{')}) -join '') | ConvertFrom-Json
  if(!$report.runtime_acl_probe){$report.runtime_acl_probe=@{status='UNAVAILABLE'}}
}
catch {$report.runtime_acl_probe=@{status='UNAVAILABLE'}}
# Emit fixed fields only; never print raw Python output, logs or config.
Write-Output ($report | ConvertTo-Json -Depth 6 -Compress)
