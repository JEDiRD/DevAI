"""Approval tenant-scope coverage.

Two layers:

* Static/structural tests that need no database. They execute the real
  approval functions against a recording fake connection, so assertions are
  made about the SQL actually issued and the parameters actually bound --
  never about source text or comments.
* PostgreSQL integration tests, gated on DEVAI_TEST_DATABASE_URL, which skip
  honestly when it is absent. A skip is never reported as a pass.
"""
import ast
import inspect
import os
import threading
import unittest
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg

from devai import approval
from devai.principal import make_tenant_principal
from devai.worker_identity import WorkerPrincipal
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")


class RecordingCursor:
    """Fake cursor: records executed SQL and bound parameters."""

    def __init__(self, log):
        self._log = log
        self.rowcount = 1

    def execute(self, sql, params=()):
        self._log.append((sql, tuple(params or ())))

    def fetchone(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class RecordingConnection:
    def __init__(self):
        self.statements = []

    def cursor(self):
        return RecordingCursor(self.statements)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _sql_code(sql):
    """Canonical token form of SQL: comments and literals cannot appear."""
    return canonical(_tokenize(sql))


def _record(func, *args, **kwargs):
    conn = RecordingConnection()
    with patch.object(approval, "connect", return_value=conn):
        func(*args, **kwargs)
    return conn.statements


def _operator(tenant=None, subject="op@example.test"):
    return make_tenant_principal(
        tenant_id=tenant or uuid4(), subject=subject, actor_kind="operator"
    )


def _service(tenant=None):
    return make_tenant_principal(
        tenant_id=tenant or uuid4(), subject="svc", actor_kind="service"
    )


class ApprovalAuthorizationTests(unittest.TestCase):
    """No database required: the guard must fire before any SQL exists."""

    def test_C_service_principal_denied_before_any_connection(self):
        for func in (approval.approve_task, approval.require_approval):
            with self.subTest(func=func.__name__):
                connector = MagicMock(side_effect=AssertionError("DB touched"))
                with patch.object(approval, "connect", connector):
                    with self.assertRaises(approval.ApprovalError):
                        func(uuid4(), approver=_service())
                self.assertEqual(connector.call_count, 0)
                connector.assert_not_called()

    def test_C2_worker_principal_is_not_an_approval_identity(self):
        worker = WorkerPrincipal(uuid4(), uuid4(), uuid4())
        for func in (approval.approve_task, approval.require_approval):
            with self.subTest(func=func.__name__):
                connector = MagicMock(side_effect=AssertionError("DB touched"))
                with patch.object(approval, "connect", connector):
                    with self.assertRaises(approval.ApprovalError):
                        func(uuid4(), approver=worker)
                self.assertEqual(connector.call_count, 0)

    def test_C3_operator_guard_is_load_bearing(self):
        """Behavioural proof that the guard is what stops a service principal.

        Neutering _require_operator must let the call reach the database; the
        guard is therefore exercised by behaviour, not by matching its name
        in the source.
        """
        service = _service()
        with patch.object(approval, "_require_operator", lambda approver: None):
            statements = _record(approval.approve_task, uuid4(), approver=service)
        self.assertTrue(
            statements, "neutering the guard must reach the database layer"
        )

        connector = MagicMock(side_effect=AssertionError("DB touched"))
        with patch.object(approval, "connect", connector):
            with self.assertRaises(approval.ApprovalError):
                approval.approve_task(uuid4(), approver=service)
        self.assertEqual(connector.call_count, 0)

    def test_D_signature_exposes_no_raw_identity_parameters(self):
        for func in (approval.approve_task, approval.require_approval):
            params = inspect.signature(func).parameters
            self.assertNotIn("approved_by", params)
            self.assertNotIn("tenant_id", params)
            self.assertIn("approver", params)
            self.assertEqual(
                params["approver"].kind, inspect.Parameter.KEYWORD_ONLY
            )

    def test_D2_module_never_accepts_raw_approved_by_argument(self):
        """No def anywhere accepts approved_by positionally or by keyword."""
        tree = ast.parse(inspect.getsource(approval))
        offenders = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and any(
                a.arg == "approved_by" for a in node.args.args + node.args.kwonlyargs
            )
        ]
        self.assertEqual(offenders, [])

    def test_G_approve_executed_sql_is_tenant_scoped(self):
        approver = _operator()
        task_id = uuid4()
        statements = _record(approval.approve_task, task_id, approver=approver)
        self.assertEqual(len(statements), 1)
        sql, params = statements[0]
        code = _sql_code(sql)
        self.assertIn("JOBS . TENANT_ID", code)
        self.assertIn("JOBS . ID = TASKS . JOB_ID", code)
        self.assertIn(approver.tenant_id, params)
        self.assertIn(task_id, params)

    def test_G2_require_approval_executed_sql_is_tenant_scoped(self):
        approver = _operator()
        task_id = uuid4()
        statements = _record(
            approval.require_approval, task_id, approver=approver
        )
        self.assertEqual(len(statements), 1)
        sql, params = statements[0]
        code = _sql_code(sql)
        self.assertIn("JOBS . TENANT_ID", code)
        self.assertIn("JOBS . ID = TASKS . JOB_ID", code)
        self.assertIn(approver.tenant_id, params)

    def test_G3_tenant_scope_check_is_comment_insensitive(self):
        """The scope assertion reads code tokens, so a comment cannot satisfy it."""
        approver = _operator()
        sql, _ = _record(approval.approve_task, uuid4(), approver=approver)[0]
        self.assertIn("JOBS . TENANT_ID", _sql_code(sql))

        # Same statement with the predicate demoted to a comment: the check
        # must no longer pass, proving it is not text-presence matching.
        mutated = sql.replace(
            "AND jobs.tenant_id = %s",
            "AND 1 = 1 /* jobs.tenant_id = %s */",
        )
        self.assertNotEqual(mutated, sql, "mutation did not apply")
        self.assertNotIn("JOBS . TENANT_ID", _sql_code(mutated))

    def test_approved_by_is_bound_from_principal_subject(self):
        first = _operator(subject="alice@example.test")
        second = _operator(subject="bob@example.test")
        task_id = uuid4()

        _, params_first = _record(
            approval.approve_task, task_id, approver=first
        )[0]
        _, params_second = _record(
            approval.approve_task, task_id, approver=second
        )[0]

        self.assertEqual(params_first[0], "alice@example.test")
        self.assertEqual(params_second[0], "bob@example.test")
        self.assertNotEqual(params_first[0], params_second[0])

    def test_approved_by_binds_the_first_executed_parameter(self):
        approver = _operator(subject="carol@example.test")
        task_id = uuid4()
        sql, params = _record(approval.approve_task, task_id, approver=approver)[0]
        toks = _tokenize(sql)
        first = next(i for i, t in enumerate(toks) if t.kind == "placeholder")
        preceding = [
            t.text.lower() for t in toks[:first] if t.kind in ("name", "quoted")
        ]
        self.assertEqual(preceding[-1], "approved_by")
        self.assertEqual(
            params, ("carol@example.test", task_id, approver.tenant_id)
        )


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class ApprovalDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        patcher = patch.object(
            approval, "connect", return_value=_Shared(self.conn)
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

        foreign = self.operator(
            tenant=self.other_tenant, subject="mallory@example.test"
        )
        with self.assertRaises(approval.ApprovalError):
            approval.approve_task(task, approver=foreign)

        self.assertEqual(self.row(task), before)
        self.assertIsNone(self.row(task)[2])

    def test_E_double_approval_is_rejected(self):
        approver = self.operator(subject="alice@example.test")
        job, task = self.waiting(approver)
        approval.approve_task(task, approver=approver)
        after_first = self.row(task)

        with self.assertRaises(approval.ApprovalError):
            approval.approve_task(task, approver=approver)

        self.assertEqual(self.row(task), after_first)

    def test_F_require_approval_foreign_tenant_denied(self):
        job, task = self.task()
        before = self.row(task)

        with self.assertRaises(approval.ApprovalError):
            approval.require_approval(
                task, approver=self.operator(tenant=self.other_tenant)
            )

        self.assertEqual(self.row(task), before)

    def test_D3_error_observability_contract(self):
        """Missing, foreign and already-approved must not form an oracle.

        Product semantics today route all three through one uniform
        ApprovalError with one message, so no tenant-existence or
        state-existence signal is exposed. If a future change introduces a
        distinct already-approved message, this test fails and the
        distinction must be documented instead of silently accepted.
        """
        owner = self.operator(subject="alice@example.test")
        job, waiting_task = self.waiting(owner)
        approval.approve_task(waiting_task, approver=owner)

        missing = uuid4()
        _, foreign_task = self.task(tenant=self.other_tenant)

        messages = {}
        cases = {
            "missing": (self.operator(subject="m"), missing),
            "foreign": (self.operator(subject="f"), foreign_task),
            "already_approved": (self.operator(subject="a"), waiting_task),
        }
        for label, (approver, task) in cases.items():
            with self.assertRaises(approval.ApprovalError) as ctx:
                approval.approve_task(task, approver=approver)
            messages[label] = str(ctx.exception)

        self.assertEqual(
            len(set(messages.values())),
            1,
            f"distinguishable error messages form an oracle: {messages}",
        )

    def test_H_concurrent_approval_has_single_winner(self):
        """Two concurrent approvals: exactly one succeeds, state stays coherent."""
        setup = psycopg.connect(_DB_URL)
        self.addCleanup(setup.close)
        tenant = uuid4()
        job, task = uuid4(), uuid4()
        with setup.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, 'race')",
                (tenant, str(tenant)),
            )
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'race', 'running')",
                (job, tenant),
            )
            cur.execute(
                "INSERT INTO tasks("
                " id, job_id, external_id, title, description,"
                " capability, risk, status, requires_approval"
                ") VALUES (%s, %s, 'ext', 't', 'd', 'basic', 'low',"
                " 'waiting_approval', TRUE)",
                (task, job),
            )
        setup.commit()

        self.addCleanup(_purge, task, job, tenant)

        barrier = threading.Barrier(2)
        results = []
        lock = threading.Lock()

        def attempt(subject):
            conn = psycopg.connect(_DB_URL)
            try:
                principal = make_tenant_principal(
                    tenant_id=tenant, subject=subject, actor_kind="operator"
                )

                def connect():
                    return _Shared(conn)

                with patch.object(approval, "connect", side_effect=connect):
                    barrier.wait(timeout=10)
                    try:
                        approval.approve_task(task, approver=principal)
                    except approval.ApprovalError as exc:
                        with lock:
                            results.append(("denied", subject, str(exc)))
                    except Exception as exc:  # pragma: no cover - diagnostics
                        with lock:
                            results.append(("error", subject, repr(exc)))
                    else:
                        with lock:
                            results.append(("approved", subject, None))
            finally:
                conn.close()

        threads = [
            threading.Thread(target=attempt, args=("racer-a@example.test",)),
            threading.Thread(target=attempt, args=("racer-b@example.test",)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        approved = [r for r in results if r[0] == "approved"]
        denied = [r for r in results if r[0] == "denied"]
        errors = [r for r in results if r[0] == "error"]
        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        self.assertEqual(len(results), 2, results)
        self.assertEqual(len(approved), 1, f"expected one winner: {results}")
        self.assertEqual(len(denied), 1, f"expected one denial: {results}")

        with setup.cursor() as cur:
            cur.execute(
                "SELECT status, requires_approval, approved_by, approved_at"
                " FROM tasks WHERE id = %s",
                (task,),
            )
            status, requires, approved_by, approved_at = cur.fetchone()
        self.assertEqual(status, "pending")
        self.assertTrue(requires)
        self.assertEqual(approved_by, approved[0][1])
        self.assertIsNotNone(approved_at)


class _Shared:
    """Let production helpers share an already-open transaction."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


def _purge(task, job, tenant):
    conn = psycopg.connect(_DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tasks WHERE id = %s", (task,))
            cur.execute("DELETE FROM jobs WHERE id = %s", (job,))
            cur.execute("DELETE FROM tenants WHERE id = %s", (tenant,))
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    unittest.main()