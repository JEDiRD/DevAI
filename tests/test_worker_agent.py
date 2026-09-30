import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

from worker_agent.agent import AgentConfig, Backoff, WorkerAgent
from worker_agent.client import (
    ConnectivityError,
    Dispatch,
    WorkerApiClient,
    validate_private_base_url,
)
from worker_agent.credential_store import WindowsDpapiCredentialStore
from worker_agent.adapters import AdapterResult
from worker_agent.execution_journal import ExecutionJournal


def sample_dispatch(**kwargs):
    return Dispatch(connection_id=uuid4(),adapter_key=kwargs.pop('adapter_key','synthetic_test'),
        execution_timeout_seconds=30,spec_version=1,adapter_version='1.0',
        deadline_at=datetime.now(timezone.utc)+timedelta(seconds=30),
        idempotency_key=uuid4(),**kwargs)


class FakeResponse:
    def __init__(self, status, payload=b""):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit=-1):
        return self.payload


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, outgoing, timeout):
        self.requests.append(outgoing)
        return self.responses.pop(0)


class FakeStore:
    def __init__(self, token):
        self.token = token

    def load(self, worker_id):
        return self.token


class FakeClient:
    def __init__(self):
        self.completed = []
        self.failed = []

    def replace_token(self, token):
        pass

    def complete(self, dispatch, content, **usage):
        self.completed.append((dispatch.id, dispatch.claim_version, content))

    def fail(self, dispatch, error_message):
        self.failed.append((dispatch.id, dispatch.claim_version, error_message))


class WorkerAgentTests(unittest.TestCase):
    def test_client_accepts_only_private_origins(self):
        self.assertEqual(
            validate_private_base_url("http://100.91.132.78:8765/"),
            "http://100.91.132.78:8765",
        )
        for url in (
            "http://1.1.1.1:8765",
            "http://public.example:8765",
            "http://user:password@100.91.132.78:8765",
            "http://100.91.132.78:8765/path",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_private_base_url(url)

    def test_client_claim_parses_lease_and_sends_identity(self):
        worker_id = uuid4()
        dispatch_id = uuid4()
        expires = datetime.now(timezone.utc) + timedelta(minutes=2)
        opener = FakeOpener([
            FakeResponse(204),
            FakeResponse(200, json.dumps({
                "id": str(dispatch_id),
                "route_key": "synthetic/windows",
                "gateway_model": "synthetic",
                "prompt": "sample",
                "claim_version": 4,
                "lease_expires_at": expires.isoformat(),
                'connection_id':str(uuid4()),'adapter_key':'synthetic_test',
                'execution_timeout_seconds':30,'spec_version':1,'adapter_version':'1.0',
                'deadline_at':expires.isoformat(),'idempotency_key':str(uuid4()),
                'server_time':datetime.now(timezone.utc).isoformat(),
            }).encode()),
        ])
        client = WorkerApiClient(
            "http://100.91.132.78:8765", worker_id,
            "devai_wkr_test_secret", opener=opener,
        )
        self.assertIsNone(client.claim())
        dispatch = client.claim()
        self.assertEqual(dispatch.id, dispatch_id)
        self.assertEqual(dispatch.claim_version, 4)
        self.assertEqual(dispatch.lease_expires_at, expires)
        self.assertEqual(
            opener.requests[1].get_header("Authorization"),
            "Bearer devai_wkr_test_secret",
        )
        self.assertEqual(
            opener.requests[1].get_header("X-worker-id"),
            str(worker_id),
        )

    def test_synthetic_handler_reports_one_result_with_claim_version(self):
        config = AgentConfig(
            worker_id=uuid4(),
            api_base_url="http://100.91.132.78:8765",
            credential_path=Path("unused"),
        )
        client = FakeClient()
        agent = WorkerAgent(config, FakeStore("devai_wkr_test"), client=client,journal=ExecutionJournal(':memory:'))
        dispatch = sample_dispatch(
            id=uuid4(),
            route_key="synthetic/windows",
            gateway_model="synthetic",
            prompt="sample",
            claim_version=7,
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        )
        agent._process(dispatch)
        self.assertEqual(
            client.completed,
            [(dispatch.id, 7, "REMOTE_ADAPTER_OK")],
        )
        self.assertEqual(client.failed, [])

        unsupported = sample_dispatch(
            id=uuid4(),
            route_key="unknown/route",
            gateway_model="other",
            adapter_key='unknown',
            prompt="sample",
            claim_version=8,
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        )
        agent._process(unsupported)
        self.assertEqual(
            client.failed,
            [(unsupported.id, 8, "UNSUPPORTED_ADAPTER")],
        )

    def test_connectivity_backoff_is_bounded(self):
        backoff = Backoff(maximum=10)
        delays = [backoff.next_delay() for _ in range(12)]
        self.assertTrue(all(0 < delay <= 10 for delay in delays))
        backoff.reset()
        self.assertEqual(backoff.failures, 0)

    def test_heartbeat_recovers_after_connection_loss(self):
        class FlakyClient(FakeClient):
            def __init__(self):
                super().__init__()
                self.calls = 0

            def heartbeat(self, platform, architecture, capabilities):
                self.calls += 1
                if self.calls == 1:
                    raise ConnectivityError("offline")

        client = FlakyClient()
        config = AgentConfig(
            worker_id=uuid4(),
            api_base_url="http://100.91.132.78:8765",
            credential_path=Path("unused"),
            heartbeat_seconds=1,
        )
        agent = WorkerAgent(config, FakeStore("devai_wkr_test"), client=client,journal=ExecutionJournal(':memory:'))
        with patch.object(Backoff, "next_delay", return_value=0):
            thread = threading.Thread(target=agent._heartbeat_loop)
            thread.start()
            try:
                self.assertTrue(agent.online.wait(timeout=2))
                self.assertGreaterEqual(client.calls, 2)
            finally:
                agent.stop()
                thread.join(timeout=2)
        self.assertFalse(thread.is_alive())

    def test_result_retry_does_not_rerun_handler(self):
        class CountingHandler:
            def __init__(self):
                self.calls = 0

            def execute(self, dispatch, context):
                self.calls += 1
                return AdapterResult("REMOTE_ADAPTER_OK")

        class FlakyClient(FakeClient):
            def complete(self, dispatch, content, **usage):
                super().complete(dispatch, content)
                if len(self.completed) == 1:
                    raise ConnectivityError("offline")

        handler = CountingHandler()
        adapters = type("Adapters", (), {"execute": lambda _, d, c: handler.execute(d,c)})()
        client = FlakyClient()
        config = AgentConfig(
            worker_id=uuid4(),
            api_base_url="http://100.91.132.78:8765",
            credential_path=Path("unused"),
        )
        agent = WorkerAgent(
            config, FakeStore("devai_wkr_test"),
            client=client, adapters=adapters,journal=ExecutionJournal(':memory:'),
        )
        dispatch = sample_dispatch(
            id=uuid4(),
            route_key="synthetic/windows",
            gateway_model="synthetic",
            prompt="sample",
            claim_version=3,
            lease_expires_at=datetime.now(timezone.utc) + timedelta(minutes=2),
        )
        with patch.object(Backoff, "next_delay", return_value=0):
            with self.assertLogs("worker_agent.agent", level="WARNING"):
                agent._process(dispatch)
        self.assertEqual(handler.calls, 1)
        self.assertEqual(
            client.completed,
            [
                (dispatch.id, 3, "REMOTE_ADAPTER_OK"),
                (dispatch.id, 3, "REMOTE_ADAPTER_OK"),
            ],
        )

    @unittest.skipUnless(sys.platform == "win32", "Windows DPAPI only")
    def test_dpapi_store_encrypts_and_checks_worker_id(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WindowsDpapiCredentialStore(
                Path(directory) / "credential.dpapi"
            )
            worker_id = uuid4()
            token = "devai_wkr_test_secret"
            store.save(worker_id, token)
            self.assertNotIn(token.encode(), store.path.read_bytes())
            self.assertEqual(store.load(worker_id), token)
            with self.assertRaises(ValueError):
                store.load(uuid4())
