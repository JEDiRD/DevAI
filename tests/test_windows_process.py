"""Native Windows gates. No mocked Job Object/AppContainer boundary."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from uuid import uuid4
from worker_agent.adapters import AdapterError,ExecutionContext,LocalProcessPolicy,sanitized_environment,LIMITS
from worker_agent.windows_security import api,set_directory_acl
from worker_agent.windows_process import ProcessAllowlist,WindowsProcessTreeLauncher
from worker_agent.workspace import WorkspaceManager
from worker_agent.service_credentials import ServiceCredentialStore


@unittest.skipUnless(sys.platform=='win32','Native Windows isolation required')
class WindowsProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='devai-native-gates-')
        cls.root=Path(cls.temp.name)
        cls.owner=re.search(r'S-1-5-\d+(?:-\d+)+',subprocess.check_output(['whoami.exe','/user','/fo','csv','/nh'],text=True)).group()
        cls.runtime=cls.root/'runtime'
        cls.runtime.mkdir()
        base=Path(sys.base_prefix)
        for file in ('python.exe','python313.dll','python3.dll','vcruntime140.dll','vcruntime140_1.dll'):
            if (base/file).exists(): shutil.copy2(base/file,cls.runtime/file)
        shutil.copytree(base/'DLLs',cls.runtime/'DLLs')
        shutil.copytree(base/'Lib',cls.runtime/'Lib',ignore=shutil.ignore_patterns('site-packages','__pycache__','test','tests','idlelib','tkinter','ensurepip'))
        (cls.runtime/'python313._pth').write_text('Lib\nDLLs\n')
        shutil.copy2(Path(__file__).parent.parent/'worker_agent'/'synthetic_process.py',cls.runtime/'synthetic_process.py')
        set_directory_acl(cls.runtime,cls.owner,'S-1-15-2-1',app_read_only=True)
        cls.allow=ProcessAllowlist(cls.runtime/'python.exe',cls.runtime/'synthetic_process.py',
            hashlib.sha256((cls.runtime/'python.exe').read_bytes()).hexdigest(),hashlib.sha256((cls.runtime/'synthetic_process.py').read_bytes()).hexdigest())

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.state=self.root/uuid4().hex
        self.state.mkdir()
        set_directory_acl(self.state,self.owner)
        self.recovery=self.root/uuid4().hex
        self.recovery.mkdir()
        set_directory_acl(self.recovery,self.owner)
        self.manager=WorkspaceManager(self.state,self.owner,require_hard_quota=False,recovery_dir=self.recovery)
        self.workspace=self.manager.create()
        self.session=None
        self.policy=LocalProcessPolicy(self.allow.executable,self.workspace.path,('-I','-S','-B',str(self.allow.payload)))
        self.env={**sanitized_environment(),**{key:str(self.workspace.path) for key in ('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA')}}
        self.launcher=WindowsProcessTreeLauncher(self.allow)

    def tearDown(self):
        if self.session:
            self.session.terminate_tree_and_wait()
        self.workspace.termination_confirmed=True
        self.workspace.close()
        self.state.rmdir()
        self.recovery.rmdir()

    def launch(self,probes=None):
        if probes is not None: (self.workspace.path/'probes.json').write_text(json.dumps(probes))
        self.session=self.launcher.launch(self.policy,stdin_payload=b'prompt is data only',environment=self.env,shell=False,workspace=self.workspace)
        until=time.monotonic()+10
        while not ((self.workspace.path/'grandchild.pid').exists() and (self.workspace.path/'probe-result.json').exists()):
            if time.monotonic()>=until: self.fail('NATIVE_PROCESS_TREE_NOT_READY')
            time.sleep(.02)
        pids=[int((self.workspace.path/(role+'.pid')).read_text()) for role in ('parent','child','grandchild')]
        self.assertTrue(set(pids)<=set(self.session.process_ids()))
        return pids,json.loads((self.workspace.path/'probe-result.json').read_text())

    def assert_dead(self,pids):
        self.assertTrue(self.session.termination_confirmed)
        k=C.WinDLL('kernel32',use_last_error=True)
        for pid in pids:
            handle=api(k,'OpenProcess',W.HANDLE,[W.DWORD,W.BOOL,W.DWORD])(0x100000,False,pid)
            if handle:
                try: self.assertEqual(api(k,'WaitForSingleObject',W.DWORD,[W.HANDLE,W.DWORD])(handle,1000),0)
                finally: api(k,'CloseHandle',W.BOOL,[W.HANDLE])(handle)
            else: self.assertEqual(C.get_last_error(),87)

    def test_cancellation_kills_parent_child_grandchild(self):
        pids,_=self.launch()
        event=threading.Event();event.set()
        with self.assertRaisesRegex(AdapterError,'EXECUTION_CANCELLED'):
            self.session.bounded_result(ExecutionContext(event,time.monotonic()+10))
        self.assert_dead(pids)

    def test_timeout_kills_parent_child_grandchild(self):
        pids,_=self.launch()
        with self.assertRaisesRegex(AdapterError,'EXECUTION_TIMEOUT'):
            self.session.bounded_result(ExecutionContext(threading.Event(),time.monotonic()+.1))
        self.assert_dead(pids)

    def test_personal_profile_registry_environment_and_network_denied(self):
        # Dedicated synthetic file outside the workspace; never read personal data.
        outside=self.root/'outside-fixture.txt';outside.write_text('synthetic')
        with socket.socket() as server:
            server.bind(('127.0.0.1',0));server.listen(8);server.settimeout(.1)
            port=server.getsockname()[1]
            with socket.create_connection(('127.0.0.1',port),timeout=1): pass
            control,_=server.accept();control.close() # Proves target really reachable.
            _,result=self.launch({'outside_file':str(outside),'profile_folder':str(self.workspace.sid.folder),
                'network':[['100.91.132.78',8765],['100.91.132.78',5432],['100.91.132.78',3100],['100.73.25.15',443],['192.168.1.1',443],['127.0.0.1',port]]})
            for key in ('outside_denied','profile_write_denied','profile_acl_change_denied','registry_write_denied','secret_environment_absent'):
                self.assertTrue(result[key],key)
            self.assertTrue(all(item['access_denied'] for item in result['network'][:-1]))
            self.assertFalse(result['network'][-1]['connected'])
            with self.assertRaises(TimeoutError): server.accept()

    def test_cwd_executable_environment_and_extra_arguments_rejected(self):
        invalid=[(replace(self.policy,working_directory=self.root),self.env),
            (replace(self.policy,executable=Path(sys.executable)),self.env),
            (replace(self.policy,arguments=(*self.policy.arguments,'extra')),self.env),
            (self.policy,{**self.env,'WORKER_TOKEN':'synthetic'})]
        for policy,env in invalid:
            with self.assertRaises(AdapterError):
                self.launcher.launch(policy,stdin_payload=b'',environment=env,workspace=self.workspace)

    def test_junction_escape_rejected_and_cleanup_does_not_follow(self):
        target=self.root/('outside-'+uuid4().hex);target.mkdir()
        fixture=target/'keep.txt';fixture.write_text('synthetic')
        link=self.workspace.path/'escape'
        result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True)
        self.assertEqual(result.returncode,0,'JUNCTION_FIXTURE_FAILED')
        with self.assertRaisesRegex(AdapterError,'REPARSE_POINT_REJECTED'): self.workspace.verify()
        self.workspace.termination_confirmed=True;self.workspace.close()
        self.assertEqual(fixture.read_text(),'synthetic')
        shutil.rmtree(target)

    def test_output_limit_terminates_entire_tree(self):
        pids,_=self.launch({'output_overflow':True})
        with self.assertRaisesRegex(AdapterError,'OUTPUT_LIMIT_EXCEEDED'):
            self.session.bounded_result(ExecutionContext(threading.Event(),time.monotonic()+10))
        self.assertLessEqual(len(self.session.stdout)+len(self.session.stderr),LIMITS.max_output_bytes)
        self.assert_dead(pids)

    def test_machine_dpapi_ciphertext_and_worker_scope(self):
        identifier=uuid4();token='devai_wkr_synthetic_credential_fixture'
        file=self.root/('secret-fixture-'+uuid4().hex)
        encrypted=ServiceCredentialStore.encrypted(identifier,token)
        file.write_bytes(encrypted)
        try:
            self.assertNotIn(token.encode(),encrypted)
            self.assertEqual(ServiceCredentialStore(file).load(identifier),token)
            with self.assertRaises(ValueError): ServiceCredentialStore(file).load(uuid4())
        finally: file.unlink()

    def test_recovery_terminates_named_job_and_cleans_orphan_workspace(self):
        pids,_=self.launch()
        # Mimic worker crash by closing its sole non-inherited job handle.
        self.launcher.close(self.session.job);self.session.job=None
        for thread in self.session._threads: thread.join(timeout=2)
        self.launcher.close(self.session.process);self.session.process=None
        self.session.termination_confirmed=True
        self.manager.recover()
        self.assert_dead(pids)
        self.workspace.closed=True
        self.workspace.sid._free(self.workspace.sid.pointer)
        self.workspace.sid.pointer=C.c_void_p()

    def test_service_startup_probes_use_the_native_boundaries(self):
        from worker_agent.service_acceptance import native_gates
        self.workspace.termination_confirmed=True;self.workspace.close()
        service_state=self.root/('service-fixture-'+uuid4().hex)
        (service_state/'journal').mkdir(parents=True)
        try:
            result=native_gates(self.manager,self.launcher,service_state)
            self.assertTrue(all(result.values()))
        finally:shutil.rmtree(service_state)


if __name__=='__main__': unittest.main()
