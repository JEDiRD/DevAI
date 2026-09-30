from dataclasses import replace
from datetime import datetime,timedelta,timezone
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

from worker_agent.adapters import (AdapterRegistry,AdapterError,AdapterResult,
    ExecutionContext,LocalProcessPolicy,DisabledProcessTreeLauncher,sanitized_environment,
    bounded_redacted_stream,LIMITS)
from worker_agent.client import Dispatch,WorkerApiClient,ProtocolError
from worker_agent.agent import WorkerAgent,AgentConfig
from worker_agent.execution_journal import ExecutionJournal
from test_worker_agent import FakeClient,FakeStore,FakeOpener,FakeResponse


def dispatch():
    return Dispatch(uuid4(),'synthetic/local','model','safe synthetic prompt',1,
        datetime.now(timezone.utc)+timedelta(seconds=30),uuid4(),'synthetic_test',30,1,
        '1.0',datetime.now(timezone.utc)+timedelta(seconds=30),uuid4())


class WorkerAdapterTests(unittest.TestCase):
    def journal(self):
        journal=ExecutionJournal(':memory:')
        self.addCleanup(journal.db.close)
        return journal

    def context(self,end=None):
        return ExecutionContext(threading.Event(),end or time.monotonic()+30)

    def test_allowlist_version_limits_and_deadline_fail_closed(self):
        registry=AdapterRegistry();original=dispatch()
        cases=[({'adapter_key':'codex_cli'},'UNSUPPORTED_ADAPTER'),
            ({'spec_version':2},'UNSUPPORTED_SPEC_VERSION'),
            ({'spec_version':True},'UNSUPPORTED_SPEC_VERSION'),
            ({'adapter_version':'2.0'},'INCOMPATIBLE_ADAPTER_VERSION'),
            ({'execution_timeout_seconds':61},'TIMEOUT_LIMIT_EXCEEDED'),
            ({'prompt':'x'*65537},'PROMPT_LIMIT_EXCEEDED'),
            ({'deadline_at':datetime.now(timezone.utc)-timedelta(seconds=1)},'DEADLINE_EXCEEDED')]
        for changes,code in cases:
            with self.subTest(code=code),self.assertRaises(AdapterError) as found:
                registry.execute(replace(original,**changes),self.context())
            self.assertEqual(found.exception.code,code)
        self.assertEqual(registry.capabilities,['synthetic_test'])

    def test_prompt_and_model_are_never_executable_commands(self):
        d=replace(dispatch(),gateway_model='C:/Windows/System32/cmd.exe',prompt='powershell -Command malicious')
        with patch('subprocess.Popen',side_effect=AssertionError('must not spawn')):
            self.assertEqual(AdapterRegistry().execute(d,self.context()).content,'REMOTE_ADAPTER_OK')
            with self.assertRaises(AdapterError):
                DisabledProcessTreeLauncher().launch(None,stdin_payload=b'fake',environment={},shell=False)
        self.assertFalse(LocalProcessPolicy(Path.cwd()/'allowed.exe',Path.cwd()).shell)
        with self.assertRaises(AdapterError): LocalProcessPolicy(Path('relative.exe'),Path.cwd()).validate()

    def test_minimal_environment_and_bounded_redaction(self):
        with patch.dict(os.environ,{'WORKER_TOKEN':'FAKE','API_KEY':'FAKE','DEVAI_DATABASE_URL':'FAKE','SystemRoot':'local'},clear=True):
            self.assertEqual(sanitized_environment(),{'SystemRoot':'local'})
        text=bounded_redacted_stream(b'Bearer FAKE token=FAKE devai_wkr_FAKE '+b'x'*70000)
        self.assertNotIn('FAKE',text)
        self.assertLessEqual(len(text),65536)
        private_key=bounded_redacted_stream(b'-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----')
        self.assertEqual(private_key,'[REDACTED]')
        self.assertLessEqual(len(bounded_redacted_stream(b'\xff'*65536).encode('utf-8')),65536)

    def test_timeout_cancellation_and_output_are_bounded(self):
        registry=AdapterRegistry()
        ctx=self.context();ctx.cancellation.set()
        with self.assertRaises(AdapterError): registry.execute(dispatch(),ctx)
        with self.assertRaises(AdapterError): registry.execute(dispatch(),self.context(time.monotonic()-1))
        class TooLarge:
            key='synthetic_test';version='1.0'
            def execute(self,d,c): return AdapterResult('x'*65537)
        registry._allowlisted['synthetic_test']=TooLarge()
        with self.assertRaises(AdapterError) as found: registry.execute(dispatch(),self.context())
        self.assertEqual(found.exception.code,'OUTPUT_LIMIT_EXCEEDED')
        self.assertTrue(registry._slots.acquire(blocking=False))
        with self.assertRaises(AdapterError) as found: registry.execute(dispatch(),self.context())
        self.assertEqual(found.exception.code,'LOCAL_CONCURRENCY_LIMIT')
        registry._slots.release()

    def test_agent_idempotency_no_reexecution(self):
        class Counting(AdapterRegistry):
            def __init__(self): super().__init__();self.calls=0
            def execute(self,d,c): self.calls+=1;return super().execute(d,c)
        registry=Counting();client=FakeClient();journal=self.journal()
        config=AgentConfig(uuid4(),'http://100.91.132.78:8765',Path('unused'))
        agent=WorkerAgent(config,FakeStore('FAKE'),client=client,adapters=registry,journal=journal)
        d=dispatch();agent._process(d);agent._process(d)
        self.assertEqual(registry.calls,1)
        self.assertEqual(len(client.completed),2)
        self.assertFalse(client.failed)

    def test_crash_journal_fail_closed_and_conflicting_duplicate(self):
        d=dispatch()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'journal'
            journal=ExecutionJournal(path);journal.begin(d);journal.db.close()
            restarted=ExecutionJournal(path)
            with self.assertRaises(AdapterError) as found: restarted.begin(d)
            self.assertEqual(found.exception.code,'EXECUTION_OUTCOME_UNKNOWN')
            with self.assertRaises(AdapterError) as found: restarted.begin(replace(d,prompt='changed'))
            self.assertEqual(found.exception.code,'IDEMPOTENCY_CONFLICT')
            restarted.db.close()

    def test_agent_unsupported_adapter_sends_code_no_fallback(self):
        client=FakeClient();config=AgentConfig(uuid4(),'http://100.91.132.78:8765',Path('unused'))
        agent=WorkerAgent(config,FakeStore('FAKE'),client=client,journal=self.journal())
        d=replace(dispatch(),adapter_key='unsupported')
        agent._process(d)
        self.assertEqual(client.failed,[(d.id,1,'UNSUPPORTED_ADAPTER')])
        self.assertFalse(client.completed)

    def test_client_rejects_execution_injection_fields(self):
        d=dispatch()
        payload={k:str(v) if k in ('id','connection_id','idempotency_key') else v.isoformat() if isinstance(v,datetime) else v for k,v in d.__dict__.items() if k!='local_deadline_monotonic'}
        payload['server_time']=datetime.now(timezone.utc).isoformat()
        for forbidden in ('command','executable','shell','powershell','arbitrary_args','environment','arbitrary_working_directory'):
            opener=FakeOpener([FakeResponse(200,json.dumps({**payload,forbidden:'FAKE'}).encode())])
            client=WorkerApiClient('http://100.91.132.78:8765',uuid4(),'FAKE',opener=opener)
            with self.assertRaises(ProtocolError): client.claim()
