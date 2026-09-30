"""PostgreSQL foundation coverage; every fixture is rolled back."""
import os
import time
import unittest
from decimal import Decimal
from uuid import uuid4
from unittest.mock import patch
import psycopg

from devai import provider_registry as routes, worker_dispatch as queue
from devai import transport, ledger, budget, accounting, pricing
from devai.budgeted_observer import BudgetedLedgerObserver,UsageMissing
from devai.pricing import PricingNotConfigured
from devai.types import ModelCandidate,Capability,ExecutionAttempt
from test_stabilization import SharedTransaction


@unittest.skipUnless(os.environ.get('DEVAI_TEST_DATABASE_URL'),'PostgreSQL integration URL required')
class AdapterFoundationTests(unittest.TestCase):
    def setUp(self):
        self.conn=psycopg.connect(os.environ['DEVAI_TEST_DATABASE_URL'])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        for module in (routes,queue,transport,ledger,budget,accounting,pricing):
            p=patch.object(module,'connect',return_value=SharedTransaction(self.conn))
            p.start();self.addCleanup(p.stop)
        self.tenant,self.worker,self.connection=uuid4(),uuid4(),uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'foundation test')",(self.tenant,str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')",(self.worker,self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')",(self.connection,self.tenant,self.worker))
        routes.upsert_route(tenant_id=self.tenant,connection_id=self.connection,
            route_key='test/local',provider='synthetic',gateway_model='synthetic-model',
            capability='basic',cost_class='free',priority=1,pricing_key='no-price',billing_mode='local')

    def sql(self,statement,params=()):
        with self.conn.cursor() as c:
            c.execute(statement,params)
            return c.fetchall() if c.description else None

    def create(self,**kwargs):
        return queue.create_dispatch(tenant_id=self.tenant,worker_node_id=self.worker,
            route_key='test/local',prompt=kwargs.pop('prompt','safe test'),**kwargs)

    def claim(self,**kwargs):
        return queue.claim_next_dispatch(tenant_id=self.tenant,worker_node_id=self.worker,**kwargs)

    def test_capabilities_and_all_availability_gates(self):
        self.assertEqual(len(routes.list_available_routes(self.tenant)),1)
        cases=[("UPDATE worker_nodes SET capabilities='[]' WHERE id=%s",(self.worker,),"UPDATE worker_nodes SET capabilities='[\"synthetic_test\"]' WHERE id=%s"),
            ("UPDATE worker_nodes SET status='draining' WHERE id=%s",(self.worker,),"UPDATE worker_nodes SET status='online' WHERE id=%s"),
            ("UPDATE worker_nodes SET last_seen_at=clock_timestamp()-interval '91 seconds' WHERE id=%s",(self.worker,),"UPDATE worker_nodes SET last_seen_at=clock_timestamp() WHERE id=%s"),
            ("UPDATE provider_connections SET adapter_key=NULL WHERE id=%s",(self.connection,),"UPDATE provider_connections SET adapter_key='synthetic_test' WHERE id=%s"),
            ("UPDATE provider_connections SET enabled=FALSE WHERE id=%s",(self.connection,),"UPDATE provider_connections SET enabled=TRUE WHERE id=%s")]
        for statement,params,restore in cases:
            self.sql(statement,params)
            self.assertEqual(routes.list_available_routes(self.tenant),[])
            with self.assertRaises(queue.DispatchUnavailable): self.create()
            self.sql(restore,params)
        self.sql("UPDATE provider_routes SET enabled=FALSE WHERE tenant_id=%s",(self.tenant,))
        self.assertEqual(routes.list_available_routes(self.tenant),[])
        self.sql("UPDATE provider_routes SET enabled=TRUE,cooldown_until=clock_timestamp()+interval '1 hour' WHERE tenant_id=%s",(self.tenant,))
        self.assertEqual(routes.list_available_routes(self.tenant),[])

    def test_idempotency_and_snapshot_immutable_after_route_change(self):
        key=uuid4();ident=self.create(idempotency_key=key)
        self.assertEqual(self.create(idempotency_key=key),ident)
        with self.assertRaises(queue.DispatchConflict): self.create(idempotency_key=key,prompt='different')
        self.sql("UPDATE provider_connections SET adapter_key='future_adapter',config='{\"adapter_version\":\"2.0\"}' WHERE id=%s",(self.connection,))
        self.sql("UPDATE provider_routes SET gateway_model='changed' WHERE tenant_id=%s",(self.tenant,))
        d=self.claim()
        self.assertEqual((d.id,d.gateway_model,d.adapter_key,d.adapter_version),(ident,'synthetic-model','synthetic_test','1.0'))
        self.assertIsNone(self.claim())
        with self.assertRaises(psycopg.Error),self.conn.transaction():
            self.sql("UPDATE worker_dispatches SET prompt='mutated' WHERE id=%s",(ident,))

    def test_deadline_expiry_and_reaper_idempotent(self):
        self.sql("UPDATE provider_connections SET config='{\"execution_timeout_seconds\":1}' WHERE id=%s",(self.connection,))
        ident=self.create()
        time.sleep(1.05)
        self.assertIsNone(self.claim())
        self.assertEqual(queue.get_dispatch_result(ident,tenant_id=self.tenant)[0],'expired')
        self.assertEqual(queue.reap_dispatches(tenant_id=self.tenant),0)

    def test_lease_loss_never_reclaims_and_fences_complete_fail(self):
        ident=self.create();d=self.claim(lease_seconds=1)
        time.sleep(1.05)
        for action,payload in ((queue.complete_dispatch,{'content':'late'}),(queue.fail_dispatch,{'error':'TIMEOUT'})):
            with self.assertRaises(queue.DispatchLeaseLost):
                action(tenant_id=self.tenant,worker_node_id=self.worker,dispatch_id=ident,claim_version=d.claim_version,**payload)
        self.assertIsNone(self.claim())
        result=queue.get_dispatch_result(ident,tenant_id=self.tenant)
        self.assertEqual((result[0],result[5]),('failed','LEASE_EXPIRED'))

    def test_claimed_deadline_fences_both_result_endpoints(self):
        self.sql("UPDATE provider_connections SET config='{\"execution_timeout_seconds\":1}' WHERE id=%s",(self.connection,))
        ident=self.create();d=self.claim()
        time.sleep(1.05)
        for action,payload in ((queue.complete_dispatch,{'content':'late'}),(queue.fail_dispatch,{'error':'TIMEOUT'})):
            with self.assertRaises(queue.DispatchLeaseLost):
                action(tenant_id=self.tenant,worker_node_id=self.worker,dispatch_id=ident,claim_version=d.claim_version,**payload)
        self.assertEqual(queue.get_dispatch_result(ident,tenant_id=self.tenant)[0],'expired')

    def test_cancellation_and_cross_tenant_result_access(self):
        ident=self.create();d=self.claim()
        with self.assertRaises(queue.DispatchUnavailable): queue.get_dispatch_result(ident,tenant_id=uuid4())
        self.assertFalse(queue.cancel_dispatch(tenant_id=uuid4(),dispatch_id=ident))
        self.assertTrue(queue.cancel_dispatch(tenant_id=self.tenant,dispatch_id=ident))
        self.assertFalse(queue.cancel_dispatch(tenant_id=self.tenant,dispatch_id=ident))
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(tenant_id=self.tenant,worker_node_id=self.worker,dispatch_id=ident,claim_version=d.claim_version,content='cancelled')

    def test_secrets_rejected_and_no_arbitrary_execution_fields(self):
        for prompt in ('devai_wkr_FAKE_SECRET','Bearer FAKE_SECRET','API_KEY=FAKE_SECRET'):
            with self.assertRaises(queue.DispatchUnavailable): self.create(prompt=prompt)
        ident=self.create()
        names={r[0] for r in self.sql("SELECT column_name FROM information_schema.columns WHERE table_name='worker_dispatches'")}
        self.assertFalse(names & {'command','executable','shell','powershell','arbitrary_args','environment','arbitrary_working_directory','token','credential_ref'})
        row=self.sql('SELECT row_to_json(d)::text FROM worker_dispatches d WHERE id=%s',(ident,))[0][0]
        self.assertNotIn('FAKE_SECRET',row)

    def test_non_metered_zero_cost_no_pricing_or_usage_requirement(self):
        job=ledger.create_job('test',self.tenant)
        task=ledger.create_task(job,'a','a','a','basic','low',False)
        observer=BudgetedLedgerObserver(job,task,{})
        for number,mode in enumerate(('free','subscription','local'),1):
            route=ModelCandidate('test/'+mode,'test',Capability.BASIC,'free',1,billing_mode=mode)
            with patch('devai.budgeted_observer.get_active_price',side_effect=AssertionError('must not price')):
                observer.attempt_started(number,route,'model')
                observer.attempt_finished(number,ExecutionAttempt(route.key,'test','model',True,
                    prompt_tokens=12 if mode=='subscription' else None,
                    completion_tokens=34 if mode=='subscription' else None))
        rows=self.sql("SELECT billing_mode,reconciled_cost_usd,pricing_version,prompt_tokens,completion_tokens FROM execution_attempts WHERE task_id=%s ORDER BY attempt_number",(task,))
        self.assertEqual(rows,[('free',Decimal(0),None,None,None),
            ('subscription',Decimal(0),None,12,34),('local',Decimal(0),None,None,None)])

    def test_metered_fails_closed_even_when_cost_class_free(self):
        job=ledger.create_job('test',self.tenant)
        task=ledger.create_task(job,'a','a','a','basic','low',False)
        budget.configure_budget(job,Decimal('.1'))
        route=ModelCandidate('missing','test',Capability.BASIC,'free',1,pricing_key='missing',billing_mode='metered')
        observer=BudgetedLedgerObserver(job,task,{'free':Decimal('.01')})
        with self.assertRaises(PricingNotConfigured): observer.attempt_started(1,route,'model')
        self.assertEqual(budget.get_budget(job)[1],Decimal(0))
        self.sql("INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES ('foundation-test',1,2,3,TRUE)")
        route=ModelCandidate('metered','test',Capability.BASIC,'free',1,pricing_key='foundation-test',billing_mode='metered')
        observer.attempt_started(1,route,'model')
        with self.assertRaises(accounting.AccountingError),self.conn.transaction():
            accounting.finalize_attempt_and_budget(job,observer._state[1][0],
                ExecutionAttempt('metered','test','model',True),Decimal(0),Decimal(0),None,None,'local')
        with self.assertRaises(UsageMissing): observer.attempt_finished(1,ExecutionAttempt('metered','test','model',True))
        self.assertEqual(budget.get_budget(job)[1:],(Decimal('.01'),Decimal(0)))
        observer.attempt_finished(1,ExecutionAttempt('metered','test','model',True,prompt_tokens=1000,completion_tokens=500))
        self.assertEqual(budget.get_budget(job)[1:],(Decimal(0),Decimal('.0035')))
