"""Approval tenant-scope coverage against real PostgreSQL.

Every fixture runs inside one transaction that is rolled back afterwards.
Tests are skipped unless DEVAI_TEST_DATABASE_URL is set; a skip is never
reported as a pass.
"""
import inspect
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg

from devai import approval
from devai.principal import make_tenant_principal
from devai.worker_identity import WorkerPrincipal
from test_stabilization import SharedTransaction

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")


class ApprovalSignatureTests(unittest.TestCase):
    """Static API/scope invariants; no database required."""

    def test_D_signature_exposes_no_raw_identity_parameters(self):
        for func in (approval.approve_task, approval.require_approval):
            params = inspect.signature(func).parameters
            self.assertNotIn("approved_by", params)
            self.assertNotIn("tenant_id", params)
            self.assertIn("approver", params)
            self.assertEqual(
                params["approver"].kind, inspect.Parameter.KEYWORD_ONLY
            )

    def test_D2_approved_by_is_sourced_only_from_approver_subject(self):
        source = inspect.getsource(approval)
        body = source.split("def approve_task(", 1)[1]
        self.assertNotIn("approved_by:", body)
        self.assertIn("approver.subject", body)

    def test_G_approval_scope_is_atomic_in_the_update_statement(self):
        """The mutating SQL itself carries the tenant predicate."""
        source = inspect.getsource(approval)
        for func in ("require_approval", "approve_task"):
            body = source.split(f"def {func}(", 1)[1]
            body = body.split("\ndef ", 1)[0]
            self.assertIn("jobs.tenant_id = %s", body)
            self.assertIn("jobs.id = tasks.job_id", body)
            self.assertIn("EXISTS (", body)

    def test_G2_actor_kind_check_precedes_any_database_use(self):
        source = inspect.getsource(approval)
        for func in ("require_approval", "approve_task"):
            body = source.split(f"def {func}(", 1)[1]
            body = body.split("\ndef ", 1)[0]
            self.assertLess(
                body.index("_require_operator(approver)"),
                body.index("connect()"),
                f"{func} must check actor kind before opening a connection",
            )


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class ApprovalScopeTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        patcher = patch.object(
            approval, "connect", return_value=SharedTransaction(self.conn)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        self.tenant = uuid4()
        self.other_tenant = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.other_tenant):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                    (tenant, str(tenant), "approval scope test"),
                )

    def operator(self, tenant=None, subject="op@example.test"):
        return make_tenant_principal(
            tenant_id=tenant or self.tenant, subject=subject, actor_kind="operator"
        )

    def task(self, tenant=None, status="pending"):
        job, task = uuid4(), uuid4()
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'scope test', 'running')",
                (job, tenant or self.tenant),
            )
            cur.execute(
                "INSERT INTO tasks("
                " id, job_id, external_id, title, description,"
                " capability, risk, status"
                ") VALUES (%s, %s, 'ext', 't', 'd', 'basic', 'low', %s)",
                (task, job, status),
            )
        return job, task

    def row(self, task):
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT status, requires_approval, approved_by, approved_at"
                " FROM tasks WHERE id = %s",
                (task,),
            )
            return cur.fetchone()

    def waiting(self, approver):
        job, task = self.task()
        approval.require_approval(task, approver=approver)
        return job, task

    def test_A_same_tenant_operator_approves_with_subject_provenance(self):
        approver = self.operator(subject="alice@example.test")
        job, task = self.waiting(approver)
        self.assertEqual(self.row(task)[0], "waiting_approval")

        approval.approve_task(task, approver=approver)

        status, requires, approved_by, approved_at = self.row(task)
        self.assertEqual(status, "pending")
        self.assertTrue(requires)
        self.assertEqual(approved_by, "alice@example.test")
        self.assertIsNotNone(approved_at)

    def test_B_foreign_tenant_operator_denied_and_row_untouched(self):
        owner = self.operator()
        job, task = self.waiting(owner)
        before = self.row(task)

        foreign = self.operator(tenant=self.other_tenant, subject="mallory@x.test")
        with self.assertRaises(approval.ApprovalError):
            approval.approve_task(task, approver=foreign)

        self.assertEqual(self.row(task), before)
        self.assertIsNone(self.row(task)[2])

    def test_C_service_principal_denied_before_any_sql(self):
        job, task = self.task(status="waiting_approval")
        service = make_tenant_principal(
            tenant_id=self.tenant, subject="svc", actor_kind="service"
        )

        with patch.object(
            approval, "connect", side_effect=AssertionError("DB touched")
        ) as connector:
            with self.assertRaises(approval.ApprovalError):
                approval.approve_task(task, approver=service)
            self.assertEqual(connector.call_count, 0)

        with patch.object(
            approval, "connect", side_effect=AssertionError("DB touched")
        ) as connector:
            with self.assertRaises(approval.ApprovalError):
                approval.require_approval(task, approver=service)
            self.assertEqual(connector.call_count, 0)

    def test_C2_worker_principal_is_not_an_approval_identity(self):
        job, task = self.task(status="waiting_approval")
        worker = WorkerPrincipal(self.tenant, uuid4(), uuid4())

        with patch.object(
            approval, "connect", side_effect=AssertionError("DB touched")
        ) as connector:
            with self.assertRaises(approval.ApprovalError):
                approval.approve_task(task, approver=worker)
            self.assertEqual(connector.call_count, 0)

    def test_E_double_approval_is_rejected(self):
        approver = self.operator()
        job, task = self.waiting(approver)
        approval.approve_task(task, approver=approver)
        after_first = self.row(task)

        with self.assertRaises(approval.ApprovalError):
            approval.approve_task(task, approver=approver)

        self.assertEqual(self.row(task), after_first)

    def test_F_require_approval_foreign_tenant_denied_and_row_untouched(self):
        job, task = self.task()
        before = self.row(task)

        foreign = self.operator(tenant=self.other_tenant)
        with self.assertRaises(approval.ApprovalError):
            approval.require_approval(task, approver=foreign)

        self.assertEqual(self.row(task), before)

    def test_F2_missing_and_foreign_are_indistinguishable(self):
        """No tenant-existence oracle: one uniform error, same message."""
        job, foreign_task = self.task(tenant=self.other_tenant)
        absent = uuid4()
        messages = set()
        for approver, task in (
            (self.operator(), foreign_task),
            (self.operator(), absent),
            (self.operator(self.other_tenant), foreign_task),
        ):
            with self.assertRaises(approval.ApprovalError) as ctx:
                approval.approve_task(task, approver=approver)
            messages.add(str(ctx.exception))
        self.assertEqual(len(messages), 1, messages)


if __name__ == "__main__":
    unittest.main()