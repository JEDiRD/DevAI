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


def _ident(tok):
    text = tok.text.replace('""', '"').strip('"').lower()
    return text.split(".")[-1]


def _bindings(sql, params):
    """Pair each executed placeholder with its bound value.

    Returns [(identifier immediately left of the placeholder, value)]. This
    is what proves parameter ORDER, not merely presence: a swapped tuple
    binds the wrong value to the wrong column.
    """
    toks = _tokenize(sql)
    pairs = []
    for index, tok in enumerate(toks):
        if tok.kind != "placeholder":
            continue
        left = [t for t in toks[:index] if t.kind in ("name", "quoted")]
        pairs.append((_ident(left[-1]) if left else None, params[len(pairs)]))
    return pairs


def _no_boolean_bypass(sql):
    """Narrow structural check: no OR anywhere in executable SQL.

    A tenant predicate neutralised by ``OR TRUE`` / ``OR 1=1`` always needs a
    top-level OR, so rejecting OR tokens is sufficient to fail those bypasses
    without attempting a full SQL parser.
    """
    offenders = [
        t.text.upper()
        for t in _tokenize(sql)
        if t.kind == "name" and t.text.upper() in ("OR", "XOR")
    ]
    return offenders


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
        self.assertEqual(_no_boolean_bypass(sql), [])

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
        self.assertEqual(_no_boolean_bypass(sql), [])

    def test_G4_boolean_bypass_variants_are_rejected(self):
        """The structural check must reject neutralised predicates."""
        base = _record(
            approval.approve_task, uuid4(), approver=_operator()
        )[0][0]
        for bypass in (
            "AND jobs.tenant_id = %s OR TRUE",
            "AND jobs.tenant_id = %s OR 1 = 1",
            "AND (jobs.tenant_id = %s OR TRUE)",
        ):
            mutated = base.replace(
                "AND jobs.tenant_id = %s", bypass
            )
            self.assertNotEqual(mutated, base, "bypass not applied")
            self.assertNotEqual(
                _no_boolean_bypass(mutated),
                [],
                f"bypass not rejected: {bypass}",
            )

    def test_G5_require_approval_parameter_order_is_exact(self):
        """ORDER matters: id first, then the tenant predicate value."""
        approver = _operator()
        task_id = uuid4()
        sql, params = _record(
            approval.require_approval, task_id, approver=approver
        )[0]
        self.assertEqual(params, (task_id, approver.tenant_id))
        self.assertEqual(
            _bindings(sql, params),
            [("id", task_id), ("tenant_id", approver.tenant_id)],
        )

    def test_G6_approve_task_parameter_order_is_exact(self):
        approver = _operator(subject="dana@example.test")
        task_id = uuid4()
        sql, params = _record(
            approval.approve_task, task_id, approver=approver
        )[0]
        self.assertEqual(
            params,
            ("dana@example.test", task_id, approver.tenant_id),
        )
        self.assertEqual(
            _bindings(sql, params),
            [
                ("approved_by", "dana@example.test"),
                ("id", task_id),
                ("tenant_id", approver.tenant_id),
            ],
        )

    def test_G7_wrong_tenant_parameter_would_be_detected(self):
        """Binding a foreign tenant value must fail the pairing check."""
        approver = _operator()
        task_id = uuid4()
        sql, _ = _record(
            approval.require_approval, task_id, approver=approver
        )[0]
        wrong = (approver.tenant_id, task_id)  # M3 mutation: swapped order
        self.assertNotEqual(_bindings(sql, wrong)[0][1], task_id)
        self.assertEqual(_bindings(sql, wrong)[1][1], task_id)
        self.assertEqual(wrong[0], approver.tenant_id)

    def test_G8_wrong_approved_by_parameter_would_be_detected(self):
        approver = _operator(subject="erin@example.test")
        task_id = uuid4()
        sql, _ = _record(
            approval.approve_task, task_id, approver=approver
        )[0]
        wrong = ("someone-else", task_id, approver.tenant_id)
        self.assertNotEqual(
            _bindings(sql, wrong)[0][1], approver.subject
        )
        self.assertEqual(
            _bindings(sql, wrong)[0][1], "someone-else"
        )

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


class ConnectionFactory:
    """Deterministic replacement for approval.connect.

    Each thread receives its own independent connection, cached in
    thread-local state, so no thread mutates the shared global differently
    from another and connection selection cannot race. The real psycopg
    connection is returned, so ``with connect() as conn`` commits on a
    successful approval and rolls back when the call raises.
    """

    def __init__(self, url):
        self.url = url
        self._local = threading.local()
        self._connections = []
        self._lock = threading.Lock()

    def __call__(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg.connect(self.url)
            self._local.conn = conn
            with self._lock:
                self._connections.append(conn)
        return conn

    def close_all(self):
        with self._lock:
            connections = list(self._connections)
            self._connections.clear()
        for conn in connections:
            try:
                conn.close()
            except Exception:  # pragma: no cover - cleanup best effort
                pass


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
        """Missing vs foreign must not expose a tenant-existence oracle.

        Required equivalence: a task that does not exist and a task owned by
        another tenant must produce the SAME error, so an operator cannot
        probe for the existence of another tenant's task id.

        Already-approved is a state-machine outcome, not an existence
        signal: the caller already holds approval rights over the task, so
        product semantics are permitted to distinguish it. This test
        therefore requires only that it raises ApprovalError, and records
        the current message rather than forcing it to match the others.
        """
        owner = self.operator(subject="alice@example.test")
        job, waiting_task = self.waiting(owner)
        approval.approve_task(waiting_task, approver=owner)

        missing = uuid4()
        _, foreign_task = self.task(tenant=self.other_tenant)

        messages = {}
        for label, (approver, task) in {
            "missing": (self.operator(subject="m"), missing),
            "foreign": (self.operator(subject="f"), foreign_task),
        }.items():
            with self.assertRaises(approval.ApprovalError) as ctx:
                approval.approve_task(task, approver=approver)
            messages[label] = str(ctx.exception)

        self.assertEqual(
            messages["missing"],
            messages["foreign"],
            "missing vs foreign must be indistinguishable "
            f"(tenant-existence oracle): {messages}",
        )

        with self.assertRaises(approval.ApprovalError) as ctx:
            approval.approve_task(waiting_task, approver=owner)
        already = str(ctx.exception)
        # Documented observation, not an enforced constraint.
        self.assertIsInstance(already, str)
        self.assertTrue(already)

    def test_H_concurrent_approval_has_single_committed_winner(self):
        """Two overlapping approvals on one task: exactly one commits.

        Harness properties this test depends on:
        * approval.connect is patched ONCE with a deterministic factory, so
          no thread mutates the shared global differently from another;
        * each thread gets its own independent connection;
        * approval uses the real connection context manager, so a successful
          approval COMMITs and a rejected one ROLLs back;
        * both attempts start from a barrier, so they genuinely overlap.
        """
        tenant = uuid4()
        job, task = uuid4(), uuid4()
        setup = psycopg.connect(_DB_URL)
        self.addCleanup(setup.close)
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

        with setup.cursor() as cur:
            cur.execute("SELECT clock_timestamp()")
            before = cur.fetchone()[0]

        factory = ConnectionFactory(_DB_URL)
        self.addCleanup(factory.close_all)
        barrier = threading.Barrier(2)
        lock = threading.Lock()
        results = []

        def attempt(subject):
            principal = make_tenant_principal(
                tenant_id=tenant, subject=subject, actor_kind="operator"
            )
            barrier.wait(timeout=30)
            try:
                approval.approve_task(task, approver=principal)
            except approval.ApprovalError as exc:
                with lock:
                    results.append(("denied", subject, str(exc), None))
            except Exception as exc:  # pragma: no cover - diagnostics
                with lock:
                    results.append(("error", subject, repr(exc), None))
            else:
                # The transaction committed when approve_task's `with` block
                # exited; read the committed row back on this same connection.
                with factory() as conn, conn.cursor() as cur:
                    cur.execute(
                        "SELECT status, requires_approval, approved_by,"
                        " approved_at FROM tasks WHERE id = %s",
                        (task,),
                    )
                    row = cur.fetchone()
                with lock:
                    results.append(("approved", subject, None, row))

        threads = [
            threading.Thread(target=attempt, args=("racer-a@example.test",)),
            threading.Thread(target=attempt, args=("racer-b@example.test",)),
        ]
        with patch.object(approval, "connect", factory):
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

        with setup.cursor() as cur:
            cur.execute("SELECT clock_timestamp()")
            after = cur.fetchone()[0]

        self.assertFalse(any(t.is_alive() for t in threads), "thread hang")
        errors = [r for r in results if r[0] == "error"]
        self.assertEqual(errors, [], f"unexpected errors: {errors}")
        approved = [r for r in results if r[0] == "approved"]
        denied = [r for r in results if r[0] == "denied"]
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
        winner = approved[0][1]
        self.assertEqual(approved_by, winner)
        self.assertNotEqual(
            approved_by, denied[0][1], "loser must not be recorded as approver"
        )
        # Strong timestamp evidence: the committed value must be the one the
        # winning transaction observed, and must fall inside the window
        # measured around the race.
        self.assertEqual(approved_at, approved[0][3][3])
        self.assertEqual(approved_by, approved[0][3][2])
        self.assertIsNotNone(approved_at)
        self.assertGreaterEqual(approved_at, before)
        self.assertLessEqual(approved_at, after)

        # No second approval transition happened after the winner committed.
        with setup.cursor() as cur:
            cur.execute(
                "SELECT approved_by FROM tasks WHERE id = %s AND approved_at "
                "IS NOT NULL",
                (task,),
            )
            self.assertEqual(cur.fetchall(), [(winner,)])


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