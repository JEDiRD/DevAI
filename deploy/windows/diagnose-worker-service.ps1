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
