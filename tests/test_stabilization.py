import os
import unittest
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import psycopg

from devai import (
    checkpoint,
    provider_registry,
    runtime,
    scheduler,
    worker_dispatch,
    worker_registry,
)


class SharedTransaction:
    """Let production helpers share a transaction rolled back after each test."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


@unittest.skipUnless(
    os.environ.get("DEVAI_TEST_DATABASE_URL"),
    "set DEVAI_TEST_DATABASE_URL to run PostgreSQL integration tests",
)
class StabilizationTests(unittest.TestCase):
    def setUp(self):
        self.connection = psycopg.connect(
            os.environ["DEVAI_TEST_DATABASE_URL"]
        )
        self.addCleanup(self.connection.close)
        self.addCleanup(self.connection.rollback)
        shared = SharedTransaction(self.connection)
        for module in (
            checkpoint,
            provider_registry,
            runtime,
            scheduler,
            worker_dispatch,
            worker_registry,
        ):
            patcher = patch.object(module, "connect", return_value=shared)
            patcher.start()
            self.addCleanup(patcher.stop)

        self.tenant_id = uuid4()
        with self.connection.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                (self.tenant_id, str(self.tenant_id), "Stabilization test"),
            )

    def connection_id(self):
        connection_id = uuid4()
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO provider_connections (
                    id, tenant_id, name, transport, auth_type
                ) VALUES (%s, %s, %s, 'local_cli', 'subscription_session')
                """,
                (connection_id, self.tenant_id, str(connection_id)),
            )
        return connection_id

    def route(self, connection_id, route_key="test/route"):
        provider_registry.upsert_route(
            tenant_id=self.tenant_id,
            connection_id=connection_id,
            route_key=route_key,
            provider="test",
            gateway_model="test-model",
            capability="basic",
            cost_class="free",
            priority=10,
            pricing_key="test-price",
        )

    def worker(self, status="offline"):
        worker_id = uuid4()
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO worker_nodes(id, tenant_id, name, status)
                VALUES (%s, %s, %s, %s)
                """,
                (worker_id, self.tenant_id, str(worker_id), status),
            )
        return worker_id

    def test_no_route_defers_without_attempt_or_hot_loop(self):
        job_id, task_id = uuid4(), uuid4()
        with self.connection.cursor() as cur:
            cur.execute(
                """
                INSERT INTO jobs(id, tenant_id, objective, status)
                VALUES (%s, %s, 'test', 'running')
                """,
                (job_id, self.tenant_id),
            )
            cur.execute(
                """
                INSERT INTO tasks (
                    id, job_id, external_id, title, description,
                    capability, risk, status
                ) VALUES (
                    %s, %s, 'test-task', 'test', 'test',
                    'basic', 'low', 'pending'
                )
                """,
                (task_id, job_id),
            )

        lease = scheduler.claim_next_ready_task(job_id, uuid4())
        self.assertIsNotNone(lease)
        self.assertIsNone(runtime.run_claimed_task(lease, {"free": Decimal(0)}))

        with self.connection.cursor() as cur:
            cur.execute(
                """
                SELECT status, lease_owner, lease_expires_at,
                       next_attempt_at > now() + interval '55 seconds',
                       next_attempt_at <= now() + interval '60 seconds'
                FROM tasks WHERE id = %s
                """,
                (task_id,),
            )
            self.assertEqual(
                cur.fetchone(), ("pending", None, None, True, True)
            )
            cur.execute(
                "SELECT count(*) FROM execution_attempts WHERE task_id = %s",
                (task_id,),
            )
            self.assertEqual(cur.fetchone()[0], 0)

        latest = checkpoint.load_latest_checkpoint(task_id)
        self.assertEqual(latest.payload["phase"], "waiting_for_route")
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(lease)
        self.assertEqual(scheduler.list_ready_tasks(job_id), [])
        self.assertIsNone(scheduler.claim_next_ready_task(job_id, uuid4()))

        with self.connection.cursor() as cur:
            cur.execute(
                """
                UPDATE tasks SET next_attempt_at = now() - interval '1 second'
                WHERE id = %s
                """,
                (task_id,),
            )
        self.assertEqual(len(scheduler.list_ready_tasks(job_id)), 1)
        self.assertIsNotNone(scheduler.claim_next_ready_task(job_id, uuid4()))

    def test_upsert_route_requires_and_updates_connection(self):
        first, second = self.connection_id(), self.connection_id()
        self.route(first)
        self.route(second)
        with self.connection.cursor() as cur:
            cur.execute(
                """
                SELECT connection_id FROM provider_routes
                WHERE tenant_id = %s AND route_key = 'test/route'
                """,
                (self.tenant_id,),
            )
            self.assertEqual(cur.fetchone()[0], second)

    def test_heartbeat_preserves_draining_and_rejects_disabled(self):
        worker_id = self.worker()
        worker_registry.heartbeat_worker(self.tenant_id, worker_id)
        with self.connection.cursor() as cur:
            cur.execute(
                "SELECT status FROM worker_nodes WHERE id = %s",
                (worker_id,),
            )
            self.assertEqual(cur.fetchone()[0], "online")
        worker_registry.heartbeat_worker(self.tenant_id, worker_id)
        with self.connection.cursor() as cur:
            cur.execute(
                "SELECT status FROM worker_nodes WHERE id = %s",
                (worker_id,),
            )
            self.assertEqual(cur.fetchone()[0], "online")

        worker_registry.set_worker_status(self.tenant_id, worker_id, "draining")
        worker_registry.heartbeat_worker(self.tenant_id, worker_id)
        with self.connection.cursor() as cur:
            cur.execute(
                "SELECT status, last_seen_at IS NOT NULL FROM worker_nodes WHERE id = %s",
                (worker_id,),
            )
            self.assertEqual(cur.fetchone(), ("draining", True))

        worker_registry.set_worker_status(self.tenant_id, worker_id, "disabled")
        with self.assertRaises(worker_registry.WorkerNotFound):
            worker_registry.heartbeat_worker(self.tenant_id, worker_id)

    def test_dispatch_claim_requires_fresh_online_worker(self):
        connection_id = self.connection_id()
        self.route(connection_id)
        worker_id = self.worker()
        dispatch_id = worker_dispatch.create_dispatch(
            tenant_id=self.tenant_id,
            worker_node_id=worker_id,
            route_key="test/route",
            gateway_model="test-model",
            prompt="test",
        )

        for status in ("offline", "draining", "disabled"):
            worker_registry.set_worker_status(self.tenant_id, worker_id, status)
            self.assertIsNone(worker_dispatch.claim_next_dispatch(
                tenant_id=self.tenant_id, worker_node_id=worker_id
            ))

        worker_registry.set_worker_status(self.tenant_id, worker_id, "online")
        with self.connection.cursor() as cur:
            cur.execute(
                """
                UPDATE worker_nodes
                SET last_seen_at = now() - interval '91 seconds'
                WHERE id = %s
                """,
                (worker_id,),
            )
        self.assertIsNone(worker_dispatch.claim_next_dispatch(
            tenant_id=self.tenant_id, worker_node_id=worker_id
        ))

        with self.connection.cursor() as cur:
            cur.execute(
                "UPDATE worker_nodes SET last_seen_at = now() WHERE id = %s",
                (worker_id,),
            )
        claimed = worker_dispatch.claim_next_dispatch(
            tenant_id=self.tenant_id, worker_node_id=worker_id
        )
        self.assertEqual(claimed.id, dispatch_id)
        self.assertEqual(claimed.claim_version, 1)
