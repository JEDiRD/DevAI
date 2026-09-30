"""Committed isolated fixtures for true multi-connection race checks; cleanup."""
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4
import psycopg
from devai import worker_dispatch as queue


@unittest.skipUnless(os.environ.get('DEVAI_TEST_DATABASE_URL'),'PostgreSQL integration URL required')
class DispatchConcurrencyTests(unittest.TestCase):
    def setUp(self):
        connector=patch.object(queue,'connect',side_effect=lambda:psycopg.connect(os.environ['DEVAI_TEST_DATABASE_URL']))
        connector.start()
        self.addCleanup(connector.stop)
        self.tenant,self.worker,self.connection=uuid4(),uuid4(),uuid4()
        with psycopg.connect(os.environ['DEVAI_TEST_DATABASE_URL']) as conn,conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'concurrency fixture')",(self.tenant,str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'fixture','online',clock_timestamp(),'[\"synthetic_test\"]')",(self.worker,self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,adapter_key,worker_node_id) VALUES (%s,%s,'fixture','local_cli','local_none','synthetic_test',%s)",(self.connection,self.tenant,self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','race-model','basic','free','no-price','local')",(self.tenant,self.connection))
        self.addCleanup(self.cleanup_fixture)

    def cleanup_fixture(self):
        with psycopg.connect(os.environ['DEVAI_TEST_DATABASE_URL']) as conn,conn.cursor() as c:
            for table in ('worker_dispatches','provider_routes','provider_connections','worker_nodes'):
                c.execute(f'DELETE FROM {table} WHERE tenant_id=%s',(self.tenant,))
            c.execute('DELETE FROM tenants WHERE id=%s',(self.tenant,))

    def race(self,call):
        barrier=threading.Barrier(2)
        def run():
            barrier.wait(timeout=5)
            return call()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(run) for _ in range(2)]
            return [f.result(timeout=10) for f in futures]

    def create(self,key):
        return queue.create_dispatch(tenant_id=self.tenant,worker_node_id=self.worker,
            route_key='race',prompt='concurrency test',idempotency_key=key)

    def test_concurrent_create_and_claim_exactly_once(self):
        key=uuid4()
        identifiers=self.race(lambda:self.create(key))
        self.assertEqual(identifiers[0],identifiers[1])
        claims=self.race(lambda:queue.claim_next_dispatch(tenant_id=self.tenant,worker_node_id=self.worker))
        claimed=[d for d in claims if d is not None]
        self.assertEqual(len(claimed),1)
        self.assertEqual(claimed[0].claim_version,1)

    def test_concurrent_reaper_idempotent_without_reexecution(self):
        ident=self.create(uuid4())
        queue.claim_next_dispatch(tenant_id=self.tenant,worker_node_id=self.worker)
        with psycopg.connect(os.environ['DEVAI_TEST_DATABASE_URL']) as conn,conn.cursor() as c:
            c.execute("UPDATE worker_dispatches SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=%s",(ident,))
        counts=self.race(lambda:queue.reap_dispatches(tenant_id=self.tenant))
        self.assertEqual(sum(counts),1)
        self.assertEqual(queue.get_dispatch_result(ident,tenant_id=self.tenant)[0],'failed')
        self.assertIsNone(queue.claim_next_dispatch(tenant_id=self.tenant,worker_node_id=self.worker))
