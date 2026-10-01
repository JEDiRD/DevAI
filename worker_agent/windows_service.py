"""Native SCM service hosting. No wrapper password, token argument or user login."""
import argparse
import base64
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import subprocess
import threading
import time

from .agent import AgentConfig, WorkerAgent
from .execution_journal import ExecutionJournal
from .process_adapter import process_registry
from .service_credentials import ServiceCredentialStore
from .windows_process import ProcessAllowlist, WindowsProcessTreeLauncher
from .windows_security import api, check, no_reparse, windows_only
from .workspace import WorkspaceManager, workspace_access_metadata

SERVICE_NAME = 'DevAIWorker'
VOLUME_SERVICE = 'DevAIWorkerVolumes'

STARTUP_PHASES = frozenset(('config', 'install_verification', 'logging', 'volume_attach',
    'workspace_open', 'workspace_recovery', 'process_allowlist', 'personal_probe',
    'native_gates', 'journal', 'agent', 'startup_proof', 'running'))
FAILURE_TYPES = frozenset(('RuntimeError', 'AdapterError', 'PermissionError',
    'FileNotFoundError', 'OSError', 'TimeoutError', 'ValueError', 'KeyError', 'JSONDecodeError'))
FAILURE_SOURCES = frozenset(('windows_service.py', 'windows_security.py', 'workspace.py',
    'windows_process.py', 'service_acceptance.py', 'execution_journal.py',
    'service_credentials.py', 'agent.py', 'process_adapter.py', 'adapters.py', 'volume_host.py'))


def safe_startup_failure(failure, phase):
    """Only closed-schema metadata. Never exception text, filenames or locals."""
    kind = type(failure).__name__
    result = {'phase': phase if phase in STARTUP_PHASES else 'unknown',
        'error': kind if kind in FAILURE_TYPES else 'UNKNOWN_ERROR_CLASS', 'frames': []}
    for name in ('errno', 'winerror'):
        value = getattr(failure, name, None)
        if type(value) is int and 0 <= value <= 65535:
            result[name] = value
    frame = failure.__traceback__
    root = Path(__file__).parent
    while frame:
        source = Path(frame.tb_frame.f_code.co_filename)
        if source.parent == root and source.name in FAILURE_SOURCES:
            result['frames'].append({'file': source.name, 'line': frame.tb_lineno})
        frame = frame.tb_next
    result['frames'] = result['frames'][-8:]
    return result


def verify_install(config_path, config, *, volume_host=False):
    """Administrator-created config/runtime/state must not be writable by payloads."""
    import os
    root = Path(os.environ['ProgramFiles'])/'DevAIWorker'
    state = Path(os.environ['ProgramData'])/'DevAIWorker'
    if Path(config_path) != state/'service.json':
        raise RuntimeError('UNMANAGED_SERVICE_CONFIG')
    for path in (root, state, Path(config_path), state/'credentials', state/'credentials'/'worker.dpapi',state/'journal',state/'logs'):
        no_reparse(path)
    # Checks use literal paths, fixed commands, fixed outputs. No secret contents.
    input_data = base64.b64encode(json.dumps({'paths':[str(path) for path in
        (root,state,Path(config_path),state/'credentials',state/'credentials'/'worker.dpapi',state/'journal',state/'logs')],
        'sid':config['service_sid']}).encode()).decode()
    ps = r'''
$ErrorActionPreference='Stop'
$policy=ConvertFrom-Json ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__POLICY__')))
$paths=$policy.paths
$serviceSid=$policy.sid
foreach ($path in $paths) {
  $acl=Get-Acl -LiteralPath $path
  $owner=([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { exit 11 }
  if (!$acl.AreAccessRulesProtected) { exit 12 }
  foreach ($entry in $acl.Access) {
    $sid=$entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($entry.AccessControlType -eq 'Allow' -and $sid -notin @('S-1-5-18','S-1-5-32-544',$serviceSid)) { exit 13 }
    if ($path -in $paths[0..4] -and $sid -eq $serviceSid -and ([int]$entry.FileSystemRights -band 0x000d0116)) { exit 14 }
  }
}
'''
    # Script is local fixed code; all arguments are LOCAL fixed paths/public SID.
    encoded = base64.b64encode(ps.replace('__POLICY__',input_data).encode('utf-16-le')).decode()
    verification = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
        capture_output=True,timeout=20)
    if verification.returncode:
        raise RuntimeError('SERVICE_ACL_UNSAFE')
    if volume_host:
        return
    who = subprocess.check_output(['whoami.exe','/user','/fo','csv','/nh'],text=True)
    if config['service_sid'] not in who:
        raise RuntimeError('DEDICATED_SERVICE_IDENTITY_REQUIRED')
    groups = subprocess.check_output(['whoami.exe','/groups','/fo','csv','/nh'],text=True)
    if 'S-1-5-32-544' in groups:
        raise RuntimeError('NON_ADMINISTRATIVE_IDENTITY_REQUIRED')
    manifest = json.loads((root/'manifest.json').read_text())
    for relative, digest in manifest.items():
        if Path(relative).is_absolute() or '..' in Path(relative).parts:
            raise RuntimeError('UNSAFE_RUNTIME_MANIFEST')
        file = root/relative
        if not file.is_relative_to(root):
            raise RuntimeError('UNSAFE_RUNTIME_MANIFEST')
        no_reparse(file)
        if hashlib.sha256(file.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('RUNTIME_INTEGRITY_FAILED')


class SERVICE_STATUS(C.Structure):
    _fields_=[('service_type',W.DWORD),('state',W.DWORD),('accepted',W.DWORD),
        ('exit_code',W.DWORD),('specific_exit',W.DWORD),('checkpoint',W.DWORD),('wait_hint',W.DWORD)]


class ServiceHost:
    def __init__(self, name, config_path, *, volume_host=False):
        windows_only()
        self.name, self.config_path, self.volume_host=name,Path(config_path),volume_host
        self.stop = threading.Event()
        self.agent = None
        self.advapi = C.WinDLL('advapi32', use_last_error=True)
        self.handle = None
        self.checkpoint = 0
        self.main_callback = C.WINFUNCTYPE(None,W.DWORD,C.POINTER(W.LPWSTR))(self.main)
        self.control_callback = C.WINFUNCTYPE(W.DWORD,W.DWORD,W.DWORD,C.c_void_p,C.c_void_p)(self.control)

    def status(self, state, *, error=0):
        if state in (2,3):
            self.checkpoint+=1
        info=SERVICE_STATUS(0x10,state,1|4|0x100 if state==4 else 0,
            1066 if error else 0,error,self.checkpoint if state in (2,3) else 0,30000 if state in (2,3) else 0)
        setter=api(self.advapi,'SetServiceStatus',W.BOOL,[W.HANDLE,C.POINTER(SERVICE_STATUS)])
        check(setter(self.handle,C.byref(info)))

    def control(self, control, event, data, context):
        if control in (1,5,15):
            self.status(3)
            self.stop.set()
            if self.agent:
                self.agent.stop()
        return 0

    def main(self, count, arguments):
        register=api(self.advapi,'RegisterServiceCtrlHandlerExW',W.HANDLE,[W.LPCWSTR,C.c_void_p,C.c_void_p])
        self.handle=register(self.name,self.control_callback,None)
        if not self.handle:
            return
        self.status(2)
        error=0
        phase='config'
        try:
            config=json.loads(self.config_path.read_text())
            phase='install_verification'
            verify_install(self.config_path,config,volume_host=self.volume_host)
            state=self.config_path.parent
            logs=state/'logs'
            phase='logging'
            handler=RotatingFileHandler(logs/(self.name+'.log'),maxBytes=1024*1024,backupCount=3)
            handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
            logging.getLogger().addHandler(handler)
            logging.getLogger().setLevel(logging.INFO)
            if self.volume_host:
                from .volume_host import attach_workspace_volume
                phase='volume_attach'
                attach_workspace_volume(config)
                self.status(4)
                self.stop.wait()
            else:
                phase='workspace_open'
                workspaces=WorkspaceManager(state/'workspace-volume',config['service_sid'],volume_guid=config['volume_guid'],recovery_dir=state/'journal')
                phase='workspace_recovery'
                workspaces.recover()
                phase='process_allowlist'
                runtime=Path(config['sandbox_runtime'])
                allowlist=ProcessAllowlist(runtime/'python.exe',runtime/'synthetic_process.py',
                    config['sandbox_executable_sha256'],config['sandbox_payload_sha256'])
                registry=process_registry(WindowsProcessTreeLauncher(allowlist),workspaces)
                from .service_acceptance import native_gates
                # This exact non-secret fixture was created by the installer
                # preparation in a separate private personal-profile directory.
                phase='personal_probe'
                personal_fixture=Path(config['personal_denial_fixture'])
                try:
                    no_reparse(personal_fixture)
                    with personal_fixture.open('rb') as personal:personal.read(1)
                except PermissionError:
                    personal_denied=True
                else:
                    raise RuntimeError('SERVICE_PERSONAL_PROFILE_ACCESS_NOT_DENIED')
                phase='native_gates'
                gates=native_gates(workspaces,registry._allowlisted['synthetic_process'].launcher,state)
                gates['service_personal_profile_denied']=personal_denied
                phase='journal'
                journal=ExecutionJournal(state/'journal'/'executions.sqlite')
                journal.recover_after_containment()
                phase='agent'
                self.agent=WorkerAgent(AgentConfig.load(self.config_path),ServiceCredentialStore(state/'credentials'/'worker.dpapi'),
                    adapters=registry,journal=journal)
                proof={'service':'DevAIWorker','service_sid':config['service_sid'],'started_at':time.time(),
                    'boot_tick_ms':api(C.WinDLL('kernel32'),'GetTickCount64',C.c_uint64,[])(),'identity_verified':True,
                    'runtime_verified':True,'workspace_hard_quota_verified':True}
                proof['native_gates']=gates
                phase='startup_proof'
                (state/'reports'/'service-start.json').write_text(json.dumps(proof))
                self.status(4)
                phase='running'
                self.agent.run_forever()
                if not self.stop.is_set():
                    raise RuntimeError('WORKER_SAFETY_STOP')
        except Exception as failure:
            error=1
            diagnostic=safe_startup_failure(failure,phase)
            if not self.volume_host and phase == 'workspace_open':
                # Identity/runtime verification already passed. Probe in THIS
                # service thread without impersonation or privilege adjustment.
                # A probe failure cannot change the original error or allow startup.
                try:
                    diagnostic['workspace_access'] = workspace_access_metadata(
                        state/'workspace-volume', config['volume_guid'])
                except Exception:
                    diagnostic['workspace_access'] = {'status': 'UNAVAILABLE'}
            logging.getLogger(__name__).error('Service failed: %s',diagnostic['error'])
            # Fixed local destination, no config values or exception text. Keep
            # early verification failures observable without following links or
            # allowing any further startup operation. Report writes are best-effort.
            try:
                import os
                report=Path(os.environ['ProgramData'])/'DevAIWorker'/'reports'/(self.name+'-startup-failure.json')
                no_reparse(report.parent)
                if report.exists(): no_reparse(report)
                report.write_text(json.dumps({**diagnostic,'at':time.time()}))
            except Exception:
                pass
        finally:
            self.status(1,error=error)

    def run(self):
        class ENTRY(C.Structure):
            _fields_=[('name',W.LPWSTR),('main',C.c_void_p)]
        table=(ENTRY*2)(ENTRY(self.name,C.cast(self.main_callback,C.c_void_p)),ENTRY(None,None))
        dispatcher=api(self.advapi,'StartServiceCtrlDispatcherW',W.BOOL,[C.POINTER(ENTRY)])
        check(dispatcher(table),'SCM_SERVICE_DISPATCH_FAILED')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--config',type=Path,required=True)
    parser.add_argument('--volume-host',action='store_true')
    args=parser.parse_args()
    ServiceHost(VOLUME_SERVICE if args.volume_host else SERVICE_NAME,args.config,volume_host=args.volume_host).run()


if __name__=='__main__':
    main()
