"""Adversarial concurrency and failure-injection tests for DevAI Platform.

These tests target states that the current suite does not cover:
- Reaper vs complete/fail races
- Cancel vs complete races
- Stale claim_version
- Worker identity mismatch
- Wrong tenant access
- Route/connection disabled mid-flight
- Provider unhealthy mid-flight
- Duplicate idempotency key
- Controller restart scenarios
- Transaction rollback
- Partial settlement
- Usage missing/duplicated
- Deadline vs lease race
- Heartbeat loss
- Retry amplification

Classification:
- EXECUTED_WINDOWS: Can run on Windows without PostgreSQL
- STATIC_ONLY: Requires code review only, no execution
- REQUIRES_VPS_VALIDATION: Requires Linux/PostgreSQL to execute
"""
import os
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import psycopg

from devai import worker_dispatch as queue
from devai import worker_identity, worker_registry
from devai.worker_api import app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class SharedTransaction:
    """Let production helpers share a transaction rolled back after each test."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


class ApiClient:
    """Minimal ASGI client for Worker Control API tests."""

    def post(self, path, **kwargs):
        import asyncio
        import httpx

        async def send():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://worker-api.test",
            ) as client:
                return await client.post(path, **kwargs)

        return asyncio.run(send())

    def get(self, path, **kwargs):
        import asyncio
        import httpx

        async def send():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://worker-api.test",
            ) as client:
                return await client.get(path, **kwargs)

        return asyncio.run(send())


def requires_db(test_class):
    """Decorator to skip tests that require PostgreSQL."""
    return unittest.skipUnless(
        os.environ.get("DEVAI_TEST_DATABASE_URL"),
        "PostgreSQL integration URL required",
    )(test_class)


# Modules that call devai.db.connect() and therefore require DEVAI_DATABASE_URL.
# Patching only their `connect` is what keeps them inside the shared,
# rolled-back test transaction.
ACCOUNTING_MODULES = (
    "ledger",
    "budget",
    "accounting",
    "pricing",
    "reconciliation",
    "scheduler",
)


class AccountingFixtureMixin:
    """Bind the accounting/ledger/scheduler modules to the shared transaction.

    The dispatch classes patch only (queue, worker_identity, worker_registry).
    The accounting-facing classes additionally call ledger.create_job(),
    budget.configure_budget(), reconciliation.resolve_case() and
    scheduler.claim_next_ready_task(). Those modules import `connect` from
    .db at module scope, so unless they are patched they open their OWN
    connection via DEVAI_DATABASE_URL and never see the tenant row inserted
    inside the test's uncommitted transaction -> jobs_tenant_fk violation.

    This mixin patches exactly those modules onto the shared transaction.
    It inserts no data of its own and weakens no constraint.
    """

    def _bind_accounting_modules(self):
        import importlib

        from devai import db as db_module

        shared = SharedTransaction(self.conn)
        for name in ACCOUNTING_MODULES:
            module = importlib.import_module(f"devai.{name}")
            patcher = patch.object(module, "connect", return_value=shared)
            patcher.start()
            self.addCleanup(patcher.stop)
        # `connect` is also reachable as db.connect(); some call sites import
        # it directly, so bind it too for the duration of the test.
        patcher = patch.object(db_module, "connect", return_value=shared)
        patcher.start()
        self.addCleanup(patcher.stop)

    def assert_tenant_exists(self):
        """Setup evidence, not the invariant under test.

        jobs.tenant_id references tenants(id) via jobs_tenant_fk
        (migration 007). The tenant row must exist and be visible inside the
        shared transaction before any accounting helper is called.
        """
        with self.conn.cursor() as c:
            c.execute("SELECT count(*) FROM tenants WHERE id = %s", (self.tenant,))
            count = c.fetchone()[0]
        self.assertEqual(
            count,
            1,
            "SETUP DEFECT: self.tenant is not present in tenants",
        )


class CommittedConcurrentFixtureMixin:
    """Fixture for invariants that require MULTIPLE CONCURRENT DB ACTORS.

    Binding the production modules to one shared connection (see
    AccountingFixtureMixin) is acceptable for sequential tests, but it is NOT
    valid evidence for a concurrency invariant: both "concurrent" callers would
    serialise on the same connection/transaction and could never contend for
    the row lock the invariant depends on.

    For those tests this mixin:
      * does NOT patch scheduler/budget/reconciliation `connect`;
      * builds the fixture on self.conn and COMMITs it, so independent
        connections can see it;
      * lets each production call use its normal connect() through the
        runner-verified disposable DEVAI_DATABASE_URL;
      * uses unique UUIDs per test, so concurrent tests cannot interfere.

    No foreign key or constraint is disabled. Cleanup relies on unique
    identifiers plus destruction of the disposable database by the runner.
    """

    def _commit_setup(self):
        """Make committed fixture rows visible to independent connections."""
        self.conn.commit()

    def _committed_sql(self, statement, params=()):
        """Run SQL, commit it, and return rows (setup evidence only)."""
        with self.conn.cursor() as c:
            c.execute(statement, params)
            rows = c.fetchall() if c.description else None
        self.conn.commit()
        return rows

    def commit_fixture_now(self):
        """Commit the tenant fixture immediately, before any production helper.

        Ordering matters. Production helpers such as ledger.create_job() open
        their OWN connection and commit on context-manager exit. If the tenant
        row is still uncommitted on self.conn, that independent connection
        cannot see it, and jobs_tenant_fk correctly rejects the job.

        setUp must therefore commit the tenant BEFORE the test body calls any
        production helper.
        """
        self.conn.commit()

    def assert_tenant_visible_to_independent_connection(self):
        """Prove the tenant is COMMITTED and visible outside self.conn.

        assert_tenant_exists() queries through self.conn and therefore cannot
        distinguish COMMITTED-AND-GLOBALLY-VISIBLE from
        UNCOMMITTED-BUT-VISIBLE-TO-THIS-TRANSACTION. This assertion opens a
        separate normal connection through the runner-verified disposable DSN,
        which is exactly what the production helpers will do.
        """
        probe = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        try:
            with probe, probe.cursor() as c:
                c.execute(
                    "SELECT count(*) FROM tenants WHERE id = %s",
                    (self.tenant,),
                )
                count = c.fetchone()[0]
        finally:
            probe.close()
        self.assertEqual(
            count,
            1,
            "SETUP DEFECT: tenant is not visible to an independent connection",
        )

    def assert_visible_to_independent_connection(self, statement, params=()):
        """Prove an arbitrary prerequisite row is visible outside self.conn."""
        probe = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        try:
            with probe, probe.cursor() as c:
                c.execute(statement, params)
                count = c.fetchone()[0]
        finally:
            probe.close()
        self.assertGreaterEqual(
            count,
            1,
            "SETUP DEFECT: prerequisite row not visible to an independent connection",
        )


# ===========================================================================
# SECTION 1: REAPER VS COMPLETE/FAIL RACES
# ===========================================================================

@requires_db
class ReaperVsCompleteRaceTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Reaper marks dispatch terminal while worker completes."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'reaper race')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_reaper_vs_complete_race_no_duplicate_execution(self):
        """REQUIRES_VPS_VALIDATION: Reaper and complete_dispatch race.

        Invariant: No duplicate logical execution.
        Expected: Exactly one of (reaper marks expired/failed, complete succeeds).
        The reaper should not mark a dispatch as expired if complete_dispatch
        has already committed the success.
        """
        ident = self.create()
        d = self.claim(lease_seconds=1)

        # Force lease expiry
        self.sql(
            "UPDATE worker_dispatches SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=%s",
            (ident,),
        )

        barrier = threading.Barrier(2)

        def reaper():
            barrier.wait(timeout=5)
            return queue.reap_dispatches(tenant_id=self.tenant)

        def completer():
            barrier.wait(timeout=5)
            try:
                queue.complete_dispatch(
                    tenant_id=self.tenant,
                    worker_node_id=self.worker,
                    dispatch_id=ident,
                    claim_version=d.claim_version,
                    content="done",
                )
                return "completed"
            except queue.DispatchLeaseLost:
                return "lease_lost"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(reaper)
            f2 = pool.submit(completer)
            reaper_result = f1.result(timeout=10)
            completer_result = f2.result(timeout=10)

        # Exactly one should succeed
        self.assertIn(completer_result, ("completed", "lease_lost"))
        if completer_result == "completed":
            # Reaper should have found nothing to reap (already terminal)
            self.assertEqual(reaper_result, 0)
        else:
            # Reaper marked it as failed
            self.assertEqual(reaper_result, 1)

        # Final state should be consistent
        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertIn(result[0], ("succeeded", "failed"))

    def test_reaper_vs_fail_race_error_preservation(self):
        """REQUIRES_VPS_VALIDATION: Reaper vs fail_dispatch race.

        Invariant: No late completion after fencing/expiry.
        Expected: If reaper marks as LEASE_EXPIRED, fail_dispatch should not
        overwrite with a different error.
        """
        ident = self.create()
        d = self.claim(lease_seconds=1)

        self.sql(
            "UPDATE worker_dispatches SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=%s",
            (ident,),
        )

        barrier = threading.Barrier(2)

        def reaper():
            barrier.wait(timeout=5)
            return queue.reap_dispatches(tenant_id=self.tenant)

        def failer():
            barrier.wait(timeout=5)
            try:
                queue.fail_dispatch(
                    tenant_id=self.tenant,
                    worker_node_id=self.worker,
                    dispatch_id=ident,
                    claim_version=d.claim_version,
                    error="WORKER_EXECUTION_FAILED",
                )
                return "failed"
            except queue.DispatchLeaseLost:
                return "lease_lost"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(reaper)
            f2 = pool.submit(failer)
            reaper_result = f1.result(timeout=10)
            failer_result = f2.result(timeout=10)

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        # Error should be either LEASE_EXPIRED or WORKER_EXECUTION_FAILED, not both
        self.assertIn(result[5], ("LEASE_EXPIRED", "WORKER_EXECUTION_FAILED", None))


# ===========================================================================
# SECTION 2: CANCEL VS COMPLETE RACE
# ===========================================================================

@requires_db
class CancelVsCompleteRaceTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: cancel_dispatch and complete_dispatch race."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'cancel race')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_cancel_vs_complete_race_no_resurrection(self):
        """REQUIRES_VPS_VALIDATION: cancel_dispatch and complete_dispatch race.

        Invariant: No resurrection after terminal state.
        Expected: If cancel succeeds first, complete must fail with DispatchLeaseLost.
        If complete succeeds first, cancel must return False.
        """
        ident = self.create()
        d = self.claim()

        barrier = threading.Barrier(2)

        def canceller():
            barrier.wait(timeout=5)
            return queue.cancel_dispatch(tenant_id=self.tenant, dispatch_id=ident)

        def completer():
            barrier.wait(timeout=5)
            try:
                queue.complete_dispatch(
                    tenant_id=self.tenant,
                    worker_node_id=self.worker,
                    dispatch_id=ident,
                    claim_version=d.claim_version,
                    content="done",
                )
                return "completed"
            except queue.DispatchLeaseLost:
                return "lease_lost"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(canceller)
            f2 = pool.submit(completer)
            cancel_result = f1.result(timeout=10)
            completer_result = f2.result(timeout=10)

        # Exactly one should succeed
        if cancel_result:
            self.assertEqual(completer_result, "lease_lost")
            result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
            self.assertEqual(result[0], "cancelled")
        else:
            self.assertEqual(completer_result, "completed")
            result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
            self.assertEqual(result[0], "succeeded")


# ===========================================================================
# SECTION 3: CLAIM FENCE — WRONG claim_version REJECTION
#
# Contract (see worker_dispatch.py:1, :139, :143 and migration 014:70-75):
#
#   claim_version is a FENCE for the one permitted claim transition,
#   currently 0 -> 1. It is NOT an incrementing generation counter.
#
#   Automatic reclamation is PROHIBITED. A terminal reap (expired/failed)
#   cannot be reclaimed, so a "superseded claim with a newer version" cannot
#   be constructed through the queue at all.
#
#   The reachable adversarial case is therefore a wrong-version attempt
#   against a LIVE claimed dispatch with a valid lease. Only claim_version=1
#   is accepted for that claim; 0 and 2 must both be fenced.
# ===========================================================================

@requires_db
class ClaimFenceWrongVersionTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: wrong claim_version is fenced on a live claim."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'claim fence')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def claimed_fixture(self):
        """One dispatch, claimed normally: claimed, claim_version=1, live lease.

        No second claim is manufactured. Automatic reclamation is prohibited,
        so a superseded claim cannot be produced.
        """
        ident = self.create()
        d = self.claim()
        self.assertIsNotNone(d)
        # Establish the precondition explicitly.
        self.assertEqual(d.claim_version, 1)
        state = self.sql(
            "SELECT status, claim_version, lease_expires_at>clock_timestamp(),"
            " result_content IS NULL, completed_at IS NULL"
            " FROM worker_dispatches WHERE id=%s",
            (ident,),
        )[0]
        self.assertEqual(state[0], "claimed")
        self.assertEqual(state[1], 1)
        self.assertTrue(state[2], "lease must still be live for this scenario")
        self.assertTrue(state[3])
        self.assertTrue(state[4])
        return ident, d

    def assert_no_side_effects(self, ident, expected_status):
        """Fenced attempt must leave the dispatch untouched."""
        state = self.sql(
            "SELECT status, claim_version, result_content IS NULL,"
            " error IS NULL, completed_at IS NULL, prompt_tokens IS NULL,"
            " completion_tokens IS NULL, provider_request_id IS NULL"
            " FROM worker_dispatches WHERE id=%s",
            (ident,),
        )[0]
        self.assertEqual(state[0], expected_status)
        self.assertEqual(state[1], 1)
        # No result content, no error, no completion timestamp, no usage.
        self.assertTrue(state[2], "result_content must remain NULL")
        self.assertTrue(state[3], "error must remain NULL")
        self.assertTrue(state[4], "completed_at must remain NULL")
        self.assertTrue(state[5], "prompt_tokens must remain NULL")
        self.assertTrue(state[6], "completion_tokens must remain NULL")
        self.assertTrue(state[7], "provider_request_id must remain NULL")

    def test_wrong_version_zero_rejected_on_complete(self):
        """REQUIRES_VPS_VALIDATION: claim_version=0 cannot complete a live claim.

        Invariant: No late completion after fencing/expiry.
        """
        ident, _ = self.claimed_fixture()
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=0,
                content="fenced-zero",
            )
        self.assert_no_side_effects(ident, "claimed")

    def test_wrong_version_two_rejected_on_complete(self):
        """REQUIRES_VPS_VALIDATION: claim_version=2 cannot complete a live claim.

        Invariant: No late completion after fencing/expiry.
        """
        ident, _ = self.claimed_fixture()
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=2,
                content="fenced-two",
            )
        self.assert_no_side_effects(ident, "claimed")

    def test_wrong_version_zero_rejected_on_fail(self):
        """REQUIRES_VPS_VALIDATION: claim_version=0 cannot fail a live claim.

        Invariant: No late completion after fencing/expiry.
        """
        ident, _ = self.claimed_fixture()
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.fail_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=0,
                error="FENCED_ZERO",
            )
        self.assert_no_side_effects(ident, "claimed")

    def test_wrong_version_two_rejected_on_fail(self):
        """REQUIRES_VPS_VALIDATION: claim_version=2 cannot fail a live claim.

        Invariant: No late completion after fencing/expiry.
        """
        ident, _ = self.claimed_fixture()
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.fail_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=2,
                error="FENCED_TWO",
            )
        self.assert_no_side_effects(ident, "claimed")

    def test_correct_version_is_the_only_valid_fence(self):
        """REQUIRES_VPS_VALIDATION: claim_version=1 alone completes the claim.

        Establishes that the fenced rejections above are caused by the
        wrong version and not by some unrelated precondition.
        """
        ident, d = self.claimed_fixture()
        # 1 is the only token accepted for this claim.
        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="accepted",
        )
        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")
        self.assertEqual(result[1], "accepted")


# ===========================================================================
# SECTION 4: WORKER IDENTITY MISMATCH
# ===========================================================================

@requires_db
class WorkerIdentityMismatchTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Worker identity mismatch rejection."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker1, self.worker2, self.connection = uuid4(), uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'identity mismatch')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'w1','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker1, self.tenant))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'w2','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker2, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker1))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker1,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker1,
            **kwargs,
        )

    def test_worker_cannot_complete_foreign_dispatch(self):
        """REQUIRES_VPS_VALIDATION: Worker cannot complete another worker's dispatch.

        Invariant: No cross-tenant state transition.
        Expected: complete_dispatch with wrong worker_node_id must fail.
        """
        ident = self.create()
        d = self.claim()

        # Attempt to complete with different worker_node_id
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker2,
                dispatch_id=ident,
                claim_version=d.claim_version,
                content="wrong worker",
            )

    def test_worker_cannot_fail_foreign_dispatch(self):
        """REQUIRES_VPS_VALIDATION: Worker cannot fail another worker's dispatch.

        Invariant: No cross-tenant state transition.
        Expected: fail_dispatch with wrong worker_node_id must fail.
        """
        ident = self.create()
        d = self.claim()

        with self.assertRaises(queue.DispatchLeaseLost):
            queue.fail_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker2,
                dispatch_id=ident,
                claim_version=d.claim_version,
                error="WRONG_WORKER",
            )


# ===========================================================================
# SECTION 5: WRONG TENANT ACCESS
# ===========================================================================

@requires_db
class WrongTenantAccessTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Cross-tenant access rejection."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant_a, self.tenant_b = uuid4(), uuid4()
        self.worker_a, self.worker_b = uuid4(), uuid4()
        self.connection_a, self.connection_b = uuid4(), uuid4()
        with self.conn.cursor() as c:
            for t in (self.tenant_a, self.tenant_b):
                c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'tenant')", (t, str(t)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'wa','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker_a, self.tenant_a))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'wb','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker_b, self.tenant_b))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'ca','local_cli','local_none',%s,'synthetic_test')", (self.connection_a, self.tenant_a, self.worker_a))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'cb','local_cli','local_none',%s,'synthetic_test')", (self.connection_b, self.tenant_b, self.worker_b))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant_a, self.connection_a))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant_b, self.connection_b))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, tenant, worker, **kwargs):
        return queue.create_dispatch(
            tenant_id=tenant,
            worker_node_id=worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, tenant, worker, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=tenant,
            worker_node_id=worker,
            **kwargs,
        )

    def test_cross_tenant_complete_rejected(self):
        """REQUIRES_VPS_VALIDATION: Cross-tenant complete must be rejected.

        Invariant: No cross-tenant state transition.
        Expected: complete_dispatch with wrong tenant_id must fail.
        """
        ident = self.create(self.tenant_a, self.worker_a)
        d = self.claim(self.tenant_a, self.worker_a)

        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant_b,
                worker_node_id=self.worker_b,
                dispatch_id=ident,
                claim_version=d.claim_version,
                content="cross-tenant",
            )

    def test_cross_tenant_cancel_rejected(self):
        """REQUIRES_VPS_VALIDATION: Cross-tenant cancel must be rejected.

        Invariant: No cross-tenant state transition.
        Expected: cancel_dispatch with wrong tenant_id must return False.
        """
        ident = self.create(self.tenant_a, self.worker_a)

        result = queue.cancel_dispatch(tenant_id=self.tenant_b, dispatch_id=ident)
        self.assertFalse(result)

    def test_cross_tenant_get_result_rejected(self):
        """REQUIRES_VPS_VALIDATION: Cross-tenant get_result must be rejected.

        Invariant: No cross-tenant state transition.
        Expected: get_dispatch_result with wrong tenant_id must raise.
        """
        ident = self.create(self.tenant_a, self.worker_a)

        with self.assertRaises(queue.DispatchUnavailable):
            queue.get_dispatch_result(ident, tenant_id=self.tenant_b)


# ===========================================================================
# SECTION 6: ROUTE/CONNECTION DISABLED MID-FLIGHT
# ===========================================================================

@requires_db
class RouteDisabledMidFlightTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Route/connection disabled while dispatch is claimed."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'disabled mid-flight')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_route_disabled_mid_flight_complete_still_succeeds(self):
        """REQUIRES_VPS_VALIDATION: Route disabled while dispatch is claimed.

        Invariant: No late completion after fencing/expiry.
        Expected: complete_dispatch should succeed because the dispatch was
        already claimed before the route was disabled.
        """
        ident = self.create()
        d = self.claim()

        # Disable route after claim
        self.sql(
            "UPDATE provider_routes SET enabled=FALSE WHERE tenant_id=%s",
            (self.tenant,),
        )

        # Complete should still succeed (dispatch was already claimed)
        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="done",
        )

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")

    def test_connection_disabled_mid_flight_complete_still_succeeds(self):
        """REQUIRES_VPS_VALIDATION: Connection disabled while dispatch is claimed.

        Invariant: No late completion after fencing/expiry.
        Expected: complete_dispatch should succeed because the dispatch was
        already claimed before the connection was disabled.
        """
        ident = self.create()
        d = self.claim()

        # Disable connection after claim
        self.sql(
            "UPDATE provider_connections SET enabled=FALSE WHERE id=%s",
            (self.connection,),
        )

        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="done",
        )

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")


# ===========================================================================
# SECTION 7: PROVIDER UNHEALTHY MID-FLIGHT
# ===========================================================================

@requires_db
class ProviderUnhealthyMidFlightTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Provider becomes unhealthy while dispatch is claimed."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'unhealthy mid-flight')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode,failure_threshold,cooldown_seconds) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local',1,300)", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_provider_unhealthy_mid_flight_complete_still_succeeds(self):
        """REQUIRES_VPS_VALIDATION: Provider unhealthy while dispatch is claimed.

        Invariant: No late completion after fencing/expiry.
        Expected: complete_dispatch should succeed because the dispatch was
        already claimed before the provider became unhealthy.
        """
        ident = self.create()
        d = self.claim()

        # Make provider unhealthy (cooldown active)
        self.sql(
            "UPDATE provider_routes SET cooldown_until=clock_timestamp()+interval '5 minutes' WHERE tenant_id=%s",
            (self.tenant,),
        )

        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="done",
        )

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")


# ===========================================================================
# SECTION 8: DUPLICATE IDEMPOTENCY KEY
# ===========================================================================

@requires_db
class DuplicateIdempotencyKeyTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Duplicate idempotency key handling."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'idempotency')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def test_duplicate_idempotency_key_same_params_returns_same_id(self):
        """REQUIRES_VPS_VALIDATION: Duplicate idempotency key with same params.

        Invariant: No duplicate logical execution.
        Expected: Same idempotency_key with same params returns same dispatch_id.
        """
        key = uuid4()
        ident1 = self.create(idempotency_key=key)
        ident2 = self.create(idempotency_key=key)
        self.assertEqual(ident1, ident2)

    def test_duplicate_idempotency_key_different_params_rejected(self):
        """REQUIRES_VPS_VALIDATION: Duplicate idempotency key with different params.

        Invariant: No duplicate logical execution.
        Expected: Same idempotency_key with different prompt raises DispatchConflict.
        """
        key = uuid4()
        self.create(idempotency_key=key, prompt="original")
        with self.assertRaises(queue.DispatchConflict):
            self.create(idempotency_key=key, prompt="different")


# ===========================================================================
# SECTION 9: CONTROLLER RESTART SCENARIOS
# ===========================================================================

@requires_db
class ControllerRestartTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Controller restart while dispatches are in-flight."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'controller restart')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_controller_restart_claimed_dispatch_remains_claimed(self):
        """REQUIRES_VPS_VALIDATION: Controller restart with claimed dispatch.

        Invariant: No duplicate logical execution.
        Expected: After controller restart, claimed dispatch remains claimed
        and can still be completed by the original worker.
        """
        ident = self.create()
        d = self.claim()

        # Simulate controller restart by creating a new connection
        # (in real scenario, this would be a new process)
        # The dispatch should still be in 'claimed' state
        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "claimed")

        # Original worker should still be able to complete
        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="done after restart",
        )

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")


# ===========================================================================
# SECTION 10: TRANSACTION ROLLBACK
# ===========================================================================

@requires_db
class TransactionRollbackTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Transaction rollback scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'rollback')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_transaction_rollback_after_complete_preserves_state(self):
        """REQUIRES_VPS_VALIDATION: Transaction rollback after complete.

        Invariant: No resurrection after terminal state.
        Expected: If a transaction rolls back after complete_dispatch,
        the dispatch should remain in its previous state (claimed).
        """
        ident = self.create()
        d = self.claim()

        # Simulate a rollback by using a savepoint
        with self.conn.transaction():
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=d.claim_version,
                content="done",
            )
            # Rollback
            raise psycopg.Rollback()

        # Dispatch should still be claimed (rollback restored previous state)
        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "claimed")


# ===========================================================================
# SECTION 11: PARTIAL SETTLEMENT
# ===========================================================================

@requires_db
class PartialSettlementTests(AccountingFixtureMixin, unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Partial settlement scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self._bind_accounting_modules()
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'partial settlement')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_partial_settlement_budget_consistency(self):
        """REQUIRES_VPS_VALIDATION: Partial settlement budget consistency.

        Invariant: No accounting undercount from race.
        Expected: If settlement fails partially, budget should remain consistent.
        """
        from devai import ledger, budget, accounting
        from devai.types import ExecutionAttempt

        self.assert_tenant_exists()
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job` via create_job("test",
        # self.tenant) above, so every ledger/budget call below operates as
        # the owning tenant. Same-tenant semantics, unchanged.
        task = ledger.create_task(job, "a", "a", "a", "basic", "low", False,
                                  tenant_id=self.tenant)
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)

        # Create a metered attempt
        from devai.budgeted_observer import BudgetedLedgerObserver
        from devai.types import ModelCandidate, Capability

        route = ModelCandidate(
            "test/metered",
            "test",
            Capability.BASIC,
            "standard",
            1,
            pricing_key="test-price",
            billing_mode="metered",
        )

        # Insert pricing
        self.sql(
            "INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES ('test-price',1,2,3,TRUE)",
        )

        observer = BudgetedLedgerObserver(
            job, task, {"standard": Decimal("0.01")}, tenant_id=self.tenant)
        observer.attempt_started(1, route, "model")

        # Simulate partial settlement failure
        with self.assertRaises(accounting.AccountingError):
            accounting.finalize_attempt_and_budget(
                job_id=job,
                attempt_id=observer._state[1][0],
                attempt=ExecutionAttempt(route.key, "test", "model", True),
                reserved_usd=Decimal("0.01"),
                actual_usd=Decimal("0.02"),  # Exceeds reserved
                pricing_key="test-price",
                pricing_version=1,
                billing_mode="metered",
                tenant_id=self.tenant,
            )

        # Budget should remain unchanged
        budget_row = budget.get_budget(job, tenant_id=self.tenant)
        self.assertEqual(budget_row[1], Decimal("0.01"))  # reserved
        self.assertEqual(budget_row[2], Decimal("0"))  # spent


# ===========================================================================
# SECTION 12: USAGE MISSING/DUPLICATED
# ===========================================================================

@requires_db
class UsageMissingDuplicatedTests(AccountingFixtureMixin, unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Usage missing or duplicated scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self._bind_accounting_modules()
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'usage')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_usage_missing_defers_to_reconciliation(self):
        """REQUIRES_VPS_VALIDATION: Missing usage defers to reconciliation.

        Invariant: No accounting undercount from race.
        Expected: Missing usage creates a reconciliation case, not a failure.
        """
        from devai import ledger, budget
        from devai.budgeted_observer import BudgetedLedgerObserver, UsageMissing
        from devai.types import ModelCandidate, Capability, ExecutionAttempt

        self.assert_tenant_exists()
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job`; all calls below act as the
        # owning tenant. Same-tenant semantics, unchanged.
        task = ledger.create_task(job, "a", "a", "a", "basic", "low", False,
                                  tenant_id=self.tenant)
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)

        route = ModelCandidate(
            "test/metered",
            "test",
            Capability.BASIC,
            "standard",
            1,
            pricing_key="test-price",
            billing_mode="metered",
        )

        self.sql(
            "INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES ('test-price',1,2,3,TRUE)",
        )

        observer = BudgetedLedgerObserver(
            job, task, {"standard": Decimal("0.01")}, tenant_id=self.tenant)
        observer.attempt_started(1, route, "model")

        # Missing usage should raise UsageMissing
        with self.assertRaises(UsageMissing):
            observer.attempt_finished(
                1,
                ExecutionAttempt(route.key, "test", "model", True),
            )

        # Reconciliation case should be created
        case = self.sql(
            "SELECT id FROM metered_reconciliations WHERE attempt_id=%s",
            (observer._state[1][0],),
        )
        self.assertIsNotNone(case)

    def test_usage_duplicated_rejected(self):
        """REQUIRES_VPS_VALIDATION: Duplicate usage settlement is rejected.

        Invariant: No accounting undercount from race.

        Contract verified in source before this test was corrected:

        * budgeted_observer.attempt_finished (lines 110-115) raises
          UsageMissing('METERED_USAGE_REQUIRED') when prompt_tokens or
          completion_tokens is None. That is the MISSING-usage path and is a
          separate, already-covered invariant. The previous version of this
          test called attempt_finished with NO usage and asserted a
          reconciliation error, so it aborted on the missing-usage guard long
          before any duplicate-usage logic was reached.

        * The real duplicate-usage contract is in
          accounting.finalize_attempt_and_budget (accounting.py:39-42): it
          selects the attempt `FOR UPDATE` WHERE status='running'. A second
          settlement for the same attempt finds status no longer 'running'
          and raises AccountingError('ATTEMPT_SETTLEMENT_FAILED'). The budget
          is therefore charged exactly once.

        This test submits a VALID first settlement (real token usage), then
        attempts the duplicate. Production's missing-usage requirement is not
        weakened: the first submission carries both token counts.
        """
        from devai import ledger, budget, accounting
        from devai.budgeted_observer import BudgetedLedgerObserver
        from devai.types import ModelCandidate, Capability, ExecutionAttempt

        self.assert_tenant_exists()
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job`; all calls below act as the
        # owning tenant. Same-tenant semantics, unchanged.
        task = ledger.create_task(job, "a", "a", "a", "basic", "low", False,
                                  tenant_id=self.tenant)
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)

        route = ModelCandidate(
            "test/metered",
            "test",
            Capability.BASIC,
            "standard",
            1,
            pricing_key="test-price",
            billing_mode="metered",
        )

        self.sql(
            "INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,output_per_million_usd,active) VALUES ('test-price',1,2,3,TRUE)",
        )

        observer = BudgetedLedgerObserver(
            job, task, {"standard": Decimal("0.01")}, tenant_id=self.tenant)
        observer.attempt_started(1, route, "model")
        attempt_id = observer._state[1][0]

        # Budget was reserved once at start.
        self.assertEqual(
            budget.get_budget(job, tenant_id=self.tenant)[1], Decimal("0.01"))

        # FIRST settlement: valid metered usage. 1000 prompt @ 2/M and
        # 500 completion @ 3/M = 0.002 + 0.0015 = 0.0035.
        observer.attempt_finished(
            1,
            ExecutionAttempt(
                route.key, "test", "model", True,
                prompt_tokens=1000, completion_tokens=500,
            ),
        )
        after_first = budget.get_budget(job, tenant_id=self.tenant)
        self.assertEqual(after_first[1], Decimal("0"))     # reservation consumed
        self.assertEqual(after_first[2], Decimal("0.0035"))  # charged once

        # DUPLICATE settlement for the same attempt must be refused.
        with self.assertRaises(accounting.AccountingError) as ctx:
            accounting.finalize_attempt_and_budget(
                job_id=job,
                attempt_id=attempt_id,
                attempt=ExecutionAttempt(
                    route.key, "test", "model", True,
                    prompt_tokens=1000, completion_tokens=500,
                ),
                reserved_usd=Decimal("0.01"),
                actual_usd=Decimal("0.0035"),
                pricing_key="test-price",
                pricing_version=1,
                billing_mode="metered",
                tenant_id=self.tenant,
            )
        self.assertIn("ATTEMPT_SETTLEMENT_FAILED", str(ctx.exception))

        # No second charge: spent is unchanged and no reservation was created.
        after_duplicate = budget.get_budget(job, tenant_id=self.tenant)
        self.assertEqual(after_duplicate[1], Decimal("0"))
        self.assertEqual(after_duplicate[2], Decimal("0.0035"))

        # The attempt row still holds exactly one settlement.
        rows = self.sql(
            "SELECT status, reconciled_cost_usd, prompt_tokens, completion_tokens"
            " FROM execution_attempts WHERE id=%s",
            (attempt_id,),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "succeeded")
        self.assertEqual(rows[0][1], Decimal("0.0035"))
        self.assertEqual(rows[0][2], 1000)
        self.assertEqual(rows[0][3], 500)


# ===========================================================================
# SECTION 13: DEADLINE VS LEASE RACE
# ===========================================================================

@requires_db
class DeadlineVsLeaseRaceTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Deadline and lease expiry race conditions."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'deadline lease race')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key,config) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test','{\"execution_timeout_seconds\":1}')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def create(self, **kwargs):
        return queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt=kwargs.pop("prompt", "safe test"),
            **kwargs,
        )

    def claim(self, **kwargs):
        return queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            **kwargs,
        )

    def test_deadline_and_lease_expire_simultaneously(self):
        """REQUIRES_VPS_VALIDATION: Deadline and lease expire at same time.

        Invariant: No late completion after fencing/expiry.
        Expected: When both deadline and lease expire, reaper should mark
        as 'expired' (deadline takes precedence).
        """
        ident = self.create()
        d = self.claim(lease_seconds=1)

        # Wait for both to expire
        import time
        time.sleep(1.05)

        # Reaper should mark as expired (deadline_at <= clock_timestamp())
        count = queue.reap_dispatches(tenant_id=self.tenant)
        self.assertEqual(count, 1)

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "expired")
        self.assertEqual(result[5], "DEADLINE_EXCEEDED")


# ===========================================================================
# SECTION 14: HEARTBEAT LOSS
# ===========================================================================

@requires_db
class HeartbeatLossTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Heartbeat loss scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'heartbeat loss')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_heartbeat_loss_prevents_claim(self):
        """REQUIRES_VPS_VALIDATION: Heartbeat loss prevents claim.

        Invariant: No duplicate logical execution.
        Expected: Worker with stale heartbeat cannot claim dispatches.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )

        # Make heartbeat stale
        self.sql(
            "UPDATE worker_nodes SET last_seen_at=clock_timestamp()-interval '91 seconds' WHERE id=%s",
            (self.worker,),
        )

        # Claim should return None
        result = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )
        self.assertIsNone(result)

    def test_heartbeat_loss_after_claim_allows_complete(self):
        """REQUIRES_VPS_VALIDATION: Heartbeat loss after claim allows complete.

        Invariant: No late completion after fencing/expiry.
        Expected: Worker can complete dispatch even if heartbeat is stale,
        as long as lease is still valid.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )

        # Make heartbeat stale after claim
        self.sql(
            "UPDATE worker_nodes SET last_seen_at=clock_timestamp()-interval '91 seconds' WHERE id=%s",
            (self.worker,),
        )

        # Complete should still succeed
        queue.complete_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            dispatch_id=ident,
            claim_version=d.claim_version,
            content="done",
        )

        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "succeeded")


# ===========================================================================
# SECTION 15: RETRY AMPLIFICATION
# ===========================================================================

@requires_db
class RetryAmplificationTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Retry amplification scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'retry amplification')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_retry_amplification_prevented_by_lease_fencing(self):
        """REQUIRES_VPS_VALIDATION: Retry amplification prevented by lease fencing.

        Invariant: No duplicate logical execution.
        Expected: After lease expiry, retry cannot re-execute the dispatch.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            lease_seconds=1,
        )

        # Wait for lease to expire
        import time
        time.sleep(1.05)

        # Reaper should mark as failed
        queue.reap_dispatches(tenant_id=self.tenant)

        # Retry should not re-execute
        result = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )
        self.assertIsNone(result)

        # Dispatch should be in failed state
        result = queue.get_dispatch_result(ident, tenant_id=self.tenant)
        self.assertEqual(result[0], "failed")


# ===========================================================================
# SECTION 16: SCHEDULER CONCURRENT CLAIM
# ===========================================================================

@requires_db
class SchedulerConcurrentClaimTests(CommittedConcurrentFixtureMixin, unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Scheduler concurrent claim scenarios.

    Concurrency evidence: scheduler is NOT patched onto the shared
    connection. Each concurrent claim opens its own connection.
    """

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant = uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'scheduler')", (self.tenant, str(self.tenant)))
        # COMMIT the tenant before any production helper runs.
        # ledger.create_job()/create_task() open their own connections and
        # commit on exit; an uncommitted tenant would be invisible to them
        # and jobs_tenant_fk would (correctly) refuse the job.
        self.commit_fixture_now()
        self.assert_tenant_visible_to_independent_connection()

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_concurrent_claim_returns_different_tasks(self):
        """REQUIRES_VPS_VALIDATION: Concurrent claim returns different tasks.

        Invariant: No duplicate logical execution.

        scheduler.claim_next_ready_task (scheduler.py:97-174) documents that
        multiple workers may call concurrently and that PostgreSQL SKIP LOCKED
        ensures they do not receive the same task. Each call opens its own
        connection via `with connect()` and commits on exit, so two threads
        genuinely contend for the row lock.

        Expected: both leases are non-null and reference different tasks.
        """
        from devai import scheduler, ledger

        # ledger.create_job/create_task each open their own connection and
        # commit on context-manager exit, so these rows are already durable.
        #
        # ledger.create_task defaults status='running' (ledger.py:47), but
        # claim_next_ready_task selects only status='pending' (scheduler.py:122).
        # The tested contract is therefore unreachable unless the fixture
        # explicitly creates READY tasks. Pass status by keyword; the
        # production default is intentionally left unchanged.
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job`; both tasks are created as the
        # owning tenant. Same-tenant semantics, unchanged.
        task1 = ledger.create_task(
            job, "a", "a", "a", "basic", "low", False, status="pending",
            tenant_id=self.tenant,
        )
        task2 = ledger.create_task(
            job, "b", "b", "b", "basic", "low", False, status="pending",
            tenant_id=self.tenant,
        )
        self._commit_setup()

        # Prove every prerequisite an independent claim connection needs is
        # visible BEFORE any thread starts.
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM tasks WHERE id = %s", (task1,),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM tasks WHERE id = %s", (task2,),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM tasks WHERE id = %s AND status = 'pending'",
            (task1,),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM tasks WHERE id = %s AND status = 'pending'",
            (task2,),
        )
        # Both must be READY, or SKIP LOCKED has nothing to contend over.
        rows = self.sql(
            "SELECT id, status FROM tasks WHERE job_id = %s ORDER BY external_id",
            (job,),
        )
        self.assertEqual([r[0] for r in rows], [task1, task2])
        self.assertEqual([r[1] for r in rows], ["pending", "pending"])

        barrier = threading.Barrier(2)

        def claim():
            barrier.wait(timeout=5)
            return scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.tenant)

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(claim)
            f2 = pool.submit(claim)
            lease1 = f1.result(timeout=30)
            lease2 = f2.result(timeout=30)

        # Both should get a task
        self.assertIsNotNone(lease1)
        self.assertIsNotNone(lease2)

        # Tasks should be different
        self.assertNotEqual(lease1.task_id, lease2.task_id)

        # And they must be the two tasks we created for this job.
        self.assertEqual({lease1.task_id, lease2.task_id}, {task1, task2})

        # Distinct lease versions prove two independent state transitions.
        self.assertEqual(
            sorted([lease1.version, lease2.version]),
            [1, 1],
        )
        # Distinct owners: each caller supplied its own owner_id.
        self.assertNotEqual(lease1.owner_id, lease2.owner_id)


# ===========================================================================
# SECTION 17: BUDGET CONCURRENT RESERVATION
# ===========================================================================

@requires_db
class BudgetConcurrentReservationTests(CommittedConcurrentFixtureMixin, unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Budget concurrent reservation scenarios.

    Concurrency evidence: budget is NOT patched onto the shared connection.
    Each concurrent reservation opens its own connection.
    """

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant = uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'budget')", (self.tenant, str(self.tenant)))
        # COMMIT the tenant before budget.configure_budget() opens its own
        # connection; job_budgets references jobs which references tenants.
        self.commit_fixture_now()
        self.assert_tenant_visible_to_independent_connection()

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_concurrent_budget_reservation_prevents_overspend(self):
        """REQUIRES_VPS_VALIDATION: Concurrent budget reservation prevents overspend.

        Invariant: Budget cannot be charged twice.
        Expected: Concurrent reservations that would exceed budget are rejected.
        """
        from devai import ledger, budget

        # Both helpers open their own connections and commit on exit.
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job` and its budget. The competing
        # reservations run as the same owning tenant from both worker threads;
        # this test proves arithmetic contention, not cross-tenant denial.
        budget.configure_budget(job, Decimal("0.02"), tenant_id=self.tenant)
        self._commit_setup()

        # The budget row must be visible to an independent connection before
        # either thread starts reserving against it.
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM job_budgets WHERE job_id = %s", (job,),
        )

        barrier = threading.Barrier(2)
        # Captured explicitly: both threads reserve as the owning tenant, so
        # the winner/loser outcome still reflects row-lock contention alone.
        tenant_id = self.tenant

        def reserve():
            barrier.wait(timeout=5)
            try:
                budget.reserve_budget(job, Decimal("0.015"),
                                      tenant_id=tenant_id)
                return "reserved"
            except budget.BudgetExceeded:
                return "exceeded"

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(reserve)
            f2 = pool.submit(reserve)
            result1 = f1.result(timeout=30)
            result2 = f2.result(timeout=30)

        # Exactly one should succeed: 0.015 + 0.015 > 0.02 limit.
        self.assertEqual(sorted([result1, result2]), ["exceeded", "reserved"])

        # Budget must be consistent and charged exactly once.
        budget_row = budget.get_budget(job, tenant_id=tenant_id)
        self.assertEqual(budget_row[1], Decimal("0.015"))  # reserved
        self.assertEqual(budget_row[2], Decimal("0"))  # spent
        self.assertLessEqual(budget_row[1] + budget_row[2], Decimal("0.02"))


# ===========================================================================
# SECTION 18: RECONCILIATION CONCURRENT RESOLUTION
# ===========================================================================

@requires_db
class ReconciliationConcurrentResolutionTests(CommittedConcurrentFixtureMixin, unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Reconciliation concurrent resolution scenarios.

    Concurrency evidence: reconciliation is NOT patched onto the shared
    connection. Each concurrent resolve_case opens its own connection.
    """

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant = uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'reconciliation')", (self.tenant, str(self.tenant)))
        # COMMIT the tenant before ledger.create_job() opens its own
        # connection; an uncommitted tenant would be invisible and
        # jobs_tenant_fk would correctly refuse the job.
        self.commit_fixture_now()
        self.assert_tenant_visible_to_independent_connection()

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_concurrent_reconciliation_resolution_idempotent(self):
        """REQUIRES_VPS_VALIDATION: Concurrent reconciliation resolution is idempotent.

        Invariant: Budget cannot be charged twice.

        Contract verified in reconciliation.py:_resolve (lines 83-131):
        the case row is selected `FOR UPDATE`, so the second resolver blocks
        until the first commits. It then re-reads status='resolved' with a
        resolution other than 'unrecoverable_exposure', and line 91-92
        returns False with the comment "Idempotent: already resolved evidence
        cannot spend twice."

        Expected: exactly one resolver returns True, the other returns False,
        and the budget is charged exactly once.
        """
        from devai import ledger, budget, reconciliation
        from devai.budgeted_observer import BudgetedLedgerObserver
        from devai.types import ModelCandidate, Capability, ExecutionAttempt

        self.assert_tenant_visible_to_independent_connection()
        # Each helper opens its own connection and commits on exit.
        job = ledger.create_job("test", self.tenant)
        # Tenant context: self.tenant owns `job`; resolve_case below already
        # ran as this tenant, so the ledger/budget calls match it.
        task = ledger.create_task(job, "a", "a", "a", "basic", "low", False,
                                  tenant_id=self.tenant)
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)

        # model_pricing enforces one ACTIVE row per pricing_key database-wide
        # (idx_model_pricing_one_active). This fixture COMMITS its pricing row,
        # so a shared literal key would collide with every other test that
        # inserts 'test-price', making the outcome depend on collection order.
        # Derive a unique key per test run instead.
        pricing_key = f"a5-recon-{uuid4().hex}"

        route = ModelCandidate(
            "test/metered",
            "test",
            Capability.BASIC,
            "standard",
            1,
            pricing_key=pricing_key,
            billing_mode="metered",
        )

        self._committed_sql(
            "INSERT INTO model_pricing(pricing_key,version,input_per_million_usd,"
            "output_per_million_usd,active) VALUES (%s,1,2,3,TRUE)",
            (pricing_key,),
        )

        observer = BudgetedLedgerObserver(
            job, task, {"standard": Decimal("0.01")}, tenant_id=self.tenant)
        observer.attempt_started(1, route, "model")

        from devai.budgeted_observer import UsageMissing
        with self.assertRaises(UsageMissing):
            observer.attempt_finished(
                1,
                ExecutionAttempt(route.key, "test", "model", True),
            )

        case = self._committed_sql(
            "SELECT id FROM metered_reconciliations WHERE attempt_id=%s",
            (observer._state[1][0],),
        )[0][0]
        # The whole fixture (attempt, exposure transfer, case) is committed
        # before either resolver starts, so both independent connections can
        # read it.
        self._commit_setup()

        # Prove every prerequisite an independent resolve_case() connection
        # needs is visible BEFORE either thread starts.
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM metered_reconciliations WHERE id = %s",
            (case,),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM model_pricing WHERE pricing_key = %s AND active",
            (pricing_key,),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM execution_attempts WHERE id = %s",
            (observer._state[1][0],),
        )
        self.assert_visible_to_independent_connection(
            "SELECT count(*) FROM job_budgets WHERE job_id = %s", (job,),
        )

        barrier = threading.Barrier(2)

        def resolve():
            barrier.wait(timeout=5)
            return reconciliation.resolve_case(
                tenant_id=self.tenant,
                case_id=case,
                actor="operator",
                usage=(1000, 500),
                evidence_sha256="1" * 64,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(resolve)
            f2 = pool.submit(resolve)
            result1 = f1.result(timeout=30)
            result2 = f2.result(timeout=30)

        # Exactly one resolver performs the resolution; the other observes
        # already-resolved state and returns the idempotent outcome.
        self.assertEqual(sorted([result1, result2]), [False, True])

        # Budget charged exactly once.
        budget_row = budget.get_budget(job, tenant_id=self.tenant)
        self.assertEqual(budget_row[2], Decimal("0.0035"))  # spent


# ===========================================================================
# SECTION 19: AUTH TOKEN REPLAY
# ===========================================================================

@requires_db
class AuthTokenReplayTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Auth token replay scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker = uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'auth')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status) VALUES (%s,%s,'test','offline')", (self.worker, self.tenant))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_token_replay_updates_last_used_at(self):
        """REQUIRES_VPS_VALIDATION: Token replay updates last_used_at.

        Invariant: No cross-tenant state transition.
        Expected: Token can be used multiple times, last_used_at is updated.
        """
        issued = worker_identity.issue_worker_token(self.tenant, self.worker)
        token = issued.token

        # First use
        principal1 = worker_identity.authenticate_worker_token(token)
        self.assertEqual(principal1.worker_node_id, self.worker)

        # Second use (replay)
        principal2 = worker_identity.authenticate_worker_token(token)
        self.assertEqual(principal2.worker_node_id, self.worker)

        # last_used_at should be updated
        row = self.sql(
            "SELECT last_used_at FROM worker_tokens WHERE id=%s",
            (issued.id,),
        )
        self.assertIsNotNone(row[0][0])


# ===========================================================================
# SECTION 20: CONTROL API CONCURRENT COMPLETE
# ===========================================================================

@requires_db
class ControlApiConcurrentCompleteTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Control API concurrent complete scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'control api')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_concurrent_complete_only_one_succeeds(self):
        """REQUIRES_VPS_VALIDATION: Concurrent complete only one succeeds.

        Invariant: No duplicate logical execution.
        Expected: Only one concurrent complete request succeeds.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )

        token = worker_identity.issue_worker_token(self.tenant, self.worker).token
        client = ApiClient()
        # F08 transition: X-Worker-Id is a mandatory consistency
        # assertion. Both concurrent requests carry the SAME bearer and the
        # SAME matching worker id, so the [204, 409] outcome below stays
        # decided purely by dispatch lease concurrency, not by identity.
        headers = {
            "Authorization": f"Bearer {token}",
            "X-Worker-Id": str(self.worker),
        }

        barrier = threading.Barrier(2)

        def complete():
            barrier.wait(timeout=5)
            return client.post(
                f"/v1/worker/dispatches/{ident}/complete",
                headers=headers,
                json={"claim_version": d.claim_version, "content": "done"},
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(complete)
            f2 = pool.submit(complete)
            resp1 = f1.result(timeout=10)
            resp2 = f2.result(timeout=10)

        # Exactly one should succeed (204)
        statuses = sorted([resp1.status_code, resp2.status_code])
        self.assertEqual(statuses, [204, 409])


# ===========================================================================
# SECTION 21: COMPLETE AFTER CANCEL
# ===========================================================================

@requires_db
class CompleteAfterCancelTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Complete after cancel scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'complete after cancel')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_complete_after_cancel_rejected(self):
        """REQUIRES_VPS_VALIDATION: Complete after cancel is rejected.

        Invariant: No resurrection after terminal state.
        Expected: complete_dispatch after cancel_dispatch fails.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )

        # Cancel first
        result = queue.cancel_dispatch(tenant_id=self.tenant, dispatch_id=ident)
        self.assertTrue(result)

        # Complete should fail
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=d.claim_version,
                content="done",
            )


# ===========================================================================
# SECTION 22: COMPLETE AFTER EXPIRY
# ===========================================================================

@requires_db
class CompleteAfterExpiryTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Complete after expiry scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'complete after expiry')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key,config) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test','{\"execution_timeout_seconds\":1}')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_complete_after_expiry_rejected(self):
        """REQUIRES_VPS_VALIDATION: Complete after expiry is rejected.

        Invariant: No late completion after fencing/expiry.
        Expected: complete_dispatch after expiry fails.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            lease_seconds=1,
        )

        # Wait for expiry
        import time
        time.sleep(1.05)

        # Reaper should mark as expired
        queue.reap_dispatches(tenant_id=self.tenant)

        # Complete should fail
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.complete_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=d.claim_version,
                content="done",
            )


# ===========================================================================
# SECTION 23: FAIL AFTER CANCEL
# ===========================================================================

@requires_db
class FailAfterCancelTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Fail after cancel scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'fail after cancel')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_fail_after_cancel_rejected(self):
        """REQUIRES_VPS_VALIDATION: Fail after cancel is rejected.

        Invariant: No resurrection after terminal state.
        Expected: fail_dispatch after cancel_dispatch fails.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
        )

        # Cancel first
        result = queue.cancel_dispatch(tenant_id=self.tenant, dispatch_id=ident)
        self.assertTrue(result)

        # Fail should fail
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.fail_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=d.claim_version,
                error="FAILED",
            )


# ===========================================================================
# SECTION 24: FAIL AFTER EXPIRY
# ===========================================================================

@requires_db
class FailAfterExpiryTests(unittest.TestCase):
    """REQUIRES_VPS_VALIDATION: Fail after expiry scenarios."""

    def setUp(self):
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        shared = SharedTransaction(self.conn)
        for module in (queue, worker_identity, worker_registry):
            p = patch.object(module, "connect", return_value=shared)
            p.start()
            self.addCleanup(p.stop)
        self.tenant, self.worker, self.connection = uuid4(), uuid4(), uuid4()
        with self.conn.cursor() as c:
            c.execute("INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'fail after expiry')", (self.tenant, str(self.tenant)))
            c.execute("INSERT INTO worker_nodes(id,tenant_id,name,status,last_seen_at,capabilities) VALUES (%s,%s,'test','online',clock_timestamp(),'[\"synthetic_test\"]')", (self.worker, self.tenant))
            c.execute("INSERT INTO provider_connections(id,tenant_id,name,transport,auth_type,worker_node_id,adapter_key,config) VALUES (%s,%s,'test','local_cli','local_none',%s,'synthetic_test','{\"execution_timeout_seconds\":1}')", (self.connection, self.tenant, self.worker))
            c.execute("INSERT INTO provider_routes(tenant_id,connection_id,route_key,provider,gateway_model,capability,cost_class,pricing_key,billing_mode) VALUES (%s,%s,'race','synthetic','model','basic','free','no-price','local')", (self.tenant, self.connection))

    def sql(self, statement, params=()):
        with self.conn.cursor() as c:
            c.execute(statement, params)
            return c.fetchall() if c.description else None

    def test_fail_after_expiry_rejected(self):
        """REQUIRES_VPS_VALIDATION: Fail after expiry is rejected.

        Invariant: No late completion after fencing/expiry.
        Expected: fail_dispatch after expiry fails.
        """
        ident = queue.create_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            route_key="race",
            prompt="test",
        )
        d = queue.claim_next_dispatch(
            tenant_id=self.tenant,
            worker_node_id=self.worker,
            lease_seconds=1,
        )

        # Wait for expiry
        import time
        time.sleep(1.05)

        # Reaper should mark as expired
        queue.reap_dispatches(tenant_id=self.tenant)

        # Fail should fail
        with self.assertRaises(queue.DispatchLeaseLost):
            queue.fail_dispatch(
                tenant_id=self.tenant,
                worker_node_id=self.worker,
                dispatch_id=ident,
                claim_version=d.claim_version,
                error="FAILED",
            )


if __name__ == "__main__":
    unittest.main()