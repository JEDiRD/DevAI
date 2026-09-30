"""Fixed local test payload; prompt is consumed as data and never executed."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import ctypes
import winreg


def run():
    role = sys.argv[1] if len(sys.argv) > 1 else 'parent'
    if role not in ('parent', 'child', 'grandchild'):
        raise SystemExit(2)
    Path(role + '.pid').write_text(str(os.getpid()))
    if role != 'grandchild':
        next_role = 'child' if role == 'parent' else 'grandchild'
        subprocess.Popen([sys.executable, '-I', '-S', '-B', str(Path(__file__).absolute()), next_role],
            shell=False, env={key: value for key, value in os.environ.items() if key in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP','USERPROFILE','LOCALAPPDATA','APPDATA')},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000)
    if role == 'parent':
        sys.stdin.buffer.read(65537)  # Data only; no eval, interpretation, shell or command.
        probes = json.loads(Path('probes.json').read_text()) if Path('probes.json').exists() else {}
        results = {'secret_environment_absent': not any(key in os.environ for key in ('WORKER_TOKEN','API_KEY','DEVAI_DATABASE_URL','TELEGRAM_BOT_TOKEN'))}
        if probes.get('outside_file'):
            try:
                with open(probes['outside_file'], 'rb') as target:
                    target.read(1)
                results['outside_denied'] = False
            except PermissionError:
                results['outside_denied'] = True
        if probes.get('profile_folder'):
            try:
                (Path(probes['profile_folder'])/'escape.txt').write_text('synthetic')
                results['profile_write_denied']=False
            except PermissionError:
                results['profile_write_denied']=True
            k=ctypes.WinDLL('kernel32',use_last_error=True)
            create=k.CreateFileW
            create.restype=ctypes.c_void_p
            create.argtypes=[ctypes.c_wchar_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_void_p]
            handle=create(probes['profile_folder'],0x40000,7,None,3,0x02000000,None)
            results['profile_acl_change_denied']=handle==ctypes.c_void_p(-1).value and ctypes.get_last_error()==5
            if handle!=ctypes.c_void_p(-1).value:
                k.CloseHandle.argtypes=[ctypes.c_void_p]
                k.CloseHandle(handle)
            try:
                with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,r'Software\DevAIQuotaEscape',0,winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key,'fixture',0,winreg.REG_SZ,'synthetic')
                results['registry_write_denied']=False
            except PermissionError:
                results['registry_write_denied']=True
        results['network'] = []
        for host, port in probes.get('network', []):
            socket_error=None
            connected=False
            try:
                with socket.create_connection((host, port), timeout=.5):
                    denied = False
                    connected=True
            except OSError as error:
                denied = error.winerror == 10013 or error.errno == 10013
                socket_error = {'winerror':error.winerror,'errno':error.errno}
            results['network'].append({'host': host, 'port': port, 'access_denied': denied, 'connected':connected,'error_code':socket_error})
        Path('probe-result.json').write_text(json.dumps(results))
        print('SYNTHETIC_PROCESS_STARTED', flush=True)
        if probes.get('output_overflow'):
            sys.stdout.write('X'*131072)
            sys.stdout.flush()
    while True:
        time.sleep(.1)


if __name__ == '__main__':
    run()
