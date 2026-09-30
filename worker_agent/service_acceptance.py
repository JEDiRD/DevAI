"""Fixed startup probes under the actual service identity, before heartbeat.

No dispatch-supplied paths or probe parameters. Fixtures contain no personal data.
"""
import json
from pathlib import Path
import socket
import threading
import time
from .adapters import AdapterError,ExecutionContext,LocalProcessPolicy,sanitized_environment


def native_gates(manager,launcher,state):
    results={}
    fixture=state/'journal'/'outside-fixture.txt'
    fixture.write_text('non-secret synthetic service fixture')
    try:
        for action in ('cancel','timeout'):
            workspace=manager.create();session=None;launch_unconfirmed=False
            try:
                environment={**sanitized_environment(),**{key:str(workspace.path) for key in ('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA')}}
                policy=LocalProcessPolicy(launcher.allowlist.executable,workspace.path,('-I','-S','-B',str(launcher.allowlist.payload)))
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1',0));listener.listen(8);listener.settimeout(.1)
                    port=listener.getsockname()[1]
                    with socket.create_connection(('127.0.0.1',port),timeout=1):pass
                    control,_=listener.accept();control.close()
                    (workspace.path/'probes.json').write_text(json.dumps({'outside_file':str(fixture),
                        'profile_folder':str(workspace.sid.folder),'network':[['100.91.132.78',8765],
                            ['100.91.132.78',5432],['100.91.132.78',3100],['100.73.25.15',443],
                            ['192.168.1.1',443],['127.0.0.1',port]]}))
                    session=launcher.launch(policy,stdin_payload=b'fixed service acceptance fixture',environment=environment,workspace=workspace)
                    until=time.monotonic()+10
                    while not ((workspace.path/'grandchild.pid').exists() and (workspace.path/'probe-result.json').exists()):
                        if time.monotonic()>=until:raise AdapterError('SERVICE_PROCESS_PROBE_FAILED')
                        time.sleep(.02)
                    probes=json.loads((workspace.path/'probe-result.json').read_text())
                    pids=[int((workspace.path/(role+'.pid')).read_text()) for role in ('parent','child','grandchild')]
                    if not set(pids)<=set(session.process_ids()):raise AdapterError('SERVICE_TREE_NOT_CONTAINED')
                    required=('outside_denied','profile_write_denied','profile_acl_change_denied','registry_write_denied','secret_environment_absent')
                    if not all(probes.get(key) is True for key in required) or not all(item['access_denied'] for item in probes['network'][:-1]) or probes['network'][-1]['connected']:
                        raise AdapterError('SERVICE_ISOLATION_PROBE_FAILED')
                    try:
                        connection,_=listener.accept();connection.close()
                        raise AdapterError('SERVICE_LOOPBACK_ISOLATION_FAILED')
                    except TimeoutError:pass
                event=threading.Event()
                if action=='cancel':event.set()
                try: session.bounded_result(ExecutionContext(event,time.monotonic()+.05 if action=='timeout' else time.monotonic()+10))
                except AdapterError as error:
                    if error.code!=('EXECUTION_CANCELLED' if action=='cancel' else 'EXECUTION_TIMEOUT'):raise
                else:raise AdapterError('SERVICE_TERMINATION_PROBE_FAILED')
                if not session.termination_confirmed:raise AdapterError('SERVICE_TERMINATION_PROBE_FAILED')
                results[action+'_tree_terminated']=True
                results.update({key:True for key in required})
                results['network_isolation']=True
            except AdapterError as error:
                launch_unconfirmed=error.code=='PROCESS_TREE_TERMINATION_UNCONFIRMED'
                raise
            finally:
                if session:
                    session.terminate_tree_and_wait()
                if not launch_unconfirmed:
                    workspace.termination_confirmed=True
                    workspace.close()
    finally:
        fixture.unlink(missing_ok=True)
    return results
