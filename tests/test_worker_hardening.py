"""Controller authority, crash recovery and no-ack on uncertain containment."""
from pathlib import Path
import threading
import time
import unittest
from uuid import uuid4
from datetime import datetime,timedelta,timezone
from worker_agent.adapters import AdapterError,AdapterResult
from worker_agent.agent import WorkerAgent,AgentConfig
from worker_agent.execution_journal import ExecutionJournal
from test_worker_agent import FakeStore,FakeClient,sample_dispatch


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self.journal=ExecutionJournal(':memory:')
        self.addCleanup(self.journal.db.close)
        self.config=AgentConfig(uuid4(),'http://100.91.132.78:8765',Path('unused'))
        self.dispatch=sample_dispatch(id=uuid4(),route_key='test',gateway_model='synthetic',prompt='data',
            claim_version=1,lease_expires_at=datetime.now(timezone.utc)+timedelta(seconds=30))

    def agent(self,client,handler=None):
        return WorkerAgent(self.config,FakeStore('devai_wkr_synthetic'),client=client,
            journal=self.journal,adapters=handler)

    def test_controller_cancellation_reaches_execution_context(self):
        class Client(FakeClient):
            calls=0;acks=0
            def status(self,dispatch):
                self.calls+=1
                return 'claimed' if self.calls==1 else 'cancelled'
            def terminated(self,dispatch): self.acks+=1
        class Handler:
            def execute(self,dispatch,context):
                while True:
                    context.check();time.sleep(.01)
        client=Client();self.agent(client,Handler())._process(self.dispatch)
        self.assertEqual(client.failed[0][2],'EXECUTION_CANCELLED')
        self.assertEqual(client.acks,1)

    def test_uncertain_termination_stops_without_terminal_ack(self):
        class Client(FakeClient):
            acks=0
            def terminated(self,dispatch):self.acks+=1
        class Handler:
            def execute(self,*_):raise AdapterError('PROCESS_TREE_TERMINATION_UNCONFIRMED')
        client=Client();agent=self.agent(client,Handler());agent._process(self.dispatch)
        self.assertTrue(agent.stop_event.is_set())
        self.assertEqual((client.acks,client.failed),(0,[]))
        self.assertEqual(self.journal.pending_terminations(),[])

    def test_graceful_shutdown_submits_failure_after_handler_stops(self):
        class Client(FakeClient):
            acks=0
            def terminated(self,dispatch):self.acks+=1
        client=Client();holder={}
        class Handler:
            def execute(self,dispatch,context):
                holder['agent'].stop()
                while True:context.check();time.sleep(.01)
        agent=self.agent(client,Handler());holder['agent']=agent
        agent._process(self.dispatch)
        self.assertEqual(client.failed[0][2],'WORKER_SHUTDOWN')
        self.assertEqual(client.acks,1)

    def test_crash_journal_never_reruns_and_reconciles_ack(self):
        self.journal.begin(self.dispatch)
        self.journal.recover_after_containment()
        with self.assertRaisesRegex(AdapterError,'EXECUTION_OUTCOME_UNKNOWN'):
            self.journal.begin(self.dispatch)
        client=FakeClient()
        agent=self.agent(client);agent._reconcile_terminations()
        self.assertEqual(client.failed[0][2],'EXECUTION_OUTCOME_UNKNOWN')
        self.assertEqual(self.journal.pending_terminations(),[])
