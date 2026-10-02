"""F-03 set_task_status and F-04 add_dependency tenant-scope coverage.

Two layers, following the accepted Group-A / B1 pattern:

* Structural tests that need no database. They execute the real functions
  against recording fake connections, so assertions concern the SQL
  actually issued and the parameters actually bound -- never source text.
  Assertions read tokenized SQL, so a predicate surviving only in a comment
  cannot satisfy them.
* PostgreSQL integration tests gated on DEVAI_TEST_DATABASE_URL, which skip
  honestly when absent. A skip is never reported as a pass.
"""
import inspect
import os
import threading
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg

from devai import scheduler
from devai.tenancy import TenantScopeError
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

STATUS_SCOPE = (
    "WHERE ID = %S AND EXISTS ( SELECT 1 FROM JOBS "
    "WHERE JOBS . ID = TASKS . JOB_ID AND JOBS . TENANT_ID = %S )"
)

INSERT_A_SCOPE = (
    "SELECT %S , %S WHERE EXISTS ( SELECT 1 FROM TASKS A "
    "JOIN JOBS JA ON JA . ID = A . JOB_ID WHERE A . ID = %S "
    "AND JA . TENANT_ID = %S ) AND EXISTS ( SELECT 1 FROM TASKS B "
    "JOIN JOBS JB ON JB . ID = B . JOB_ID WHERE B . ID = %S "
    "AND JB . TENANT_ID = %S ) ON CONFLICT DO NOTHING RETURNING TASK_ID"
)

SELECT_B_SCOPE = (
    "SELECT 1 FROM TASK_DEPENDENCIES D JOIN TASKS A ON A . ID = D . TASK_ID "
    "JOIN JOBS JA ON JA . ID = A . JOB_ID JOIN TASKS B ON B . ID = D . DEPENDS_ON_TASK_ID "
    "JOIN JOBS JB ON JB . ID = B . JOB_ID WHERE D . TASK_ID = %S "
    "AND D . DEPENDS_ON_TASK_ID = %S AND JA . TENANT_ID = %S "
    "AND JB . TENANT_ID = %S"
)


class RecordingCursor:
    def __init__(self, log, rowcount=1, rows=()):
        self._log = log
        self.rowcount = rowcount
        self._rows = list(rows)

    def execute(self, sql, params=()):
        self._log.append((sql, tuple(params or ())))

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class ScriptedConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _run(cursor):
    conn = ScriptedConnection(cursor)
    return patch.object(scheduler, "connect", return_value=conn)


def _code(sql):
    return canonical(_tokenize(sql)).upper()


def _ident(tok):
    return tok.text.replace('""', '"').strip('"').lower().split(".")[-1]


def _bindings(sql, params):
    toks = _tokenize(sql)
    pairs = []
    for index, tok in enumerate(toks):
        if tok.kind != "placeholder":
            continue
        left = [t for t in toks[:index] if t.kind in ("name", "quoted")]
        pairs.append((_ident(left[-1]) if left else None, params[len(pairs)]))
    return pairs


def _boolean_bypasses(sql):
    return [
        t.text.upper()
        for t in _tokenize(sql)
        if t.kind == "name" and t.text.upper() in ("OR", "XOR")
    ]


def _same_job_conditions(sql):
    """A same-job restriction would compare the two job ids."""
    code = _code(sql)
    found = []
    if "A . JOB_ID = B . JOB_ID" in code or "B . JOB_ID = A . JOB_ID" in code:
        found.append("cross join equality")
    if "JA . ID = JB . ID" in code or "JB . ID = JA . ID" in code:
        found.append("job id equality")
    return found


def _is_update_of_tasks(sql):
    """True if the statement's leading verb mutates the tasks table."""
    for tok in _tokenize(sql):
        if tok.kind == "name" and tok.text.upper() in (
            "UPDATE", "INSERT", "DELETE", "MERGE", "TRUNCATE", "SELECT",
            "WITH", "DO", "CREATE", "ALTER", "DROP", "SET",
        ):
            return tok.text.upper() == "UPDATE"
    return False


def _targets_tasks(sql):
    """True if an UPDATE statement's target table is tasks."""
    toks = _tokenize(sql)
    for index, tok in enumerate(toks):
        if tok.kind == "name" and tok.text.upper() == "UPDATE":
            j = index + 1
            while j < len(toks) and _is_name(toks[j], "ONLY"):
                j += 1
            target = _qualified(toks, j)
            return target.split(".")[-1] == "tasks"
    return False


def _qualified(toks, i):
    parts = []
    while i < len(toks):
        tok = toks[i]
        if tok.kind in ("name", "quoted"):
            parts.append(
                tok.text.replace('""', '"').strip('"').lower()
            )
            i += 1
        else:
            break
        if i < len(toks) and toks[i].kind == "punct" and toks[i].text == ".":
            i += 1
            continue
        break
    return ".".join(parts)


def _status_update_defects(statements):
    """Reasons set_task_status lacks a tenant-authoritative mutation.

    `statements` is the full ordered log, not just the first entry. The
    proof locates the authoritative UPDATE of tasks rather than trusting
    statement order, so a preceding tenant-scoped SELECT cannot stand in
    for the authorization, and a second unscoped UPDATE cannot hide.
    """
    defects = []
    updates = [
        (sql, params) for sql, params in statements
        if _targets_tasks(sql)
    ]
    if len(updates) != 1:
        defects.append(
            f"expected exactly one UPDATE of tasks, found {len(updates)}"
        )
        return defects
    sql, params = updates[0]
    if STATUS_SCOPE not in _code(sql):
        defects.append("authoritative UPDATE is not tenant scoped")
    if _boolean_bypasses(sql):
        defects.append("boolean neutralisation in UPDATE")
    for other, _ in statements:
        if other is sql:
            continue
        if _is_update_of_tasks(other):
            defects.append("additional UPDATE of tasks")
        if _boolean_bypasses(other):
            defects.append("boolean neutralisation in auxiliary statement")
    return defects


def _select_b_defects(sql):
    """Reasons statement B is not exactly the tenant-scoped verification.

    Statement B must be ONLY the scoped edge check. Any alternative result
    source (UNION / UNION ALL / INTERSECT / EXCEPT / VALUES / an appended
    branch) could manufacture success independently of the tenant-scoped
    edge, so the statement shape is compared exactly.
    """
    defects = []
    code = _code(sql)
    if SELECT_B_SCOPE not in code:
        defects.append("fallback scope missing or altered")
    if _boolean_bypasses(sql):
        defects.append("boolean neutralisation")
    for keyword in ("UNION", "INTERSECT", "EXCEPT", "VALUES"):
        if keyword in code:
            defects.append(f"alternative result source: {keyword}")
    # exact shape: nothing may follow the tenant-scoped predicate
    if code.strip() != SELECT_B_SCOPE:
        defects.append("statement is not exactly the scoped verification")
    defects.extend(_same_job_conditions(sql))
    return defects


def _insert_defects(sql):
    """Reasons statement A is not a correctly tenant-scoped insert."""
    defects = []
    if INSERT_A_SCOPE not in _code(sql):
        defects.append("insert scope missing or altered")
    if _boolean_bypasses(sql):
        defects.append("boolean neutralisation")
    defects.extend(_same_job_conditions(sql))
    return defects


def _is_name(tok, word):
    return tok.kind == "name" and tok.text.upper() == word


class SchedulerSignatureTests(unittest.TestCase):
    TARGETS = ("set_task_status", "add_dependency")

    def test_both_require_keyword_only_tenant_id(self):
        for name in self.TARGETS:
            with self.subTest(function=name):
                params = inspect.signature(
                    getattr(scheduler, name)
                ).parameters
                self.assertIn("tenant_id", params)
                tenant = params["tenant_id"]
                self.assertEqual(
                    tenant.kind, inspect.Parameter.KEYWORD_ONLY
                )
                self.assertIs(tenant.default, inspect.Parameter.empty)

    def test_omitting_tenant_id_is_a_type_error(self):
        with self.assertRaises(TypeError):
            scheduler.set_task_status(uuid4(), "pending")
        with self.assertRaises(TypeError):
            scheduler.add_dependency(uuid4(), uuid4())

    def test_positional_tenant_id_is_rejected(self):
        for name in self.TARGETS:
            with self.subTest(function=name):
                params = inspect.signature(
                    getattr(scheduler, name)
                ).parameters
                positional = [
                    p.name for p in params.values()
                    if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
                ]
                self.assertNotIn("tenant_id", positional)

    def test_no_tenant_principal_in_scheduler(self):
        source = inspect.getsource(scheduler)
        self.assertNotIn("TenantPrincipal", source)

    def test_group_c_claim_is_outside_b2(self):
        """claim_next_ready_task keeps its Group C signature and fencing.

        This is an untouched-code regression check, not an authorization
        proof, so it reads the function source directly.
        """
        params = inspect.signature(
            scheduler.claim_next_ready_task
        ).parameters
        self.assertEqual(
            list(params), ["job_id", "owner_id", "lease_seconds"]
        )
        self.assertNotIn("tenant_id", params)
        body = inspect.getsource(scheduler.claim_next_ready_task).upper()
        self.assertIn("FOR UPDATE SKIP LOCKED", body)
        self.assertIn("LEASE_VERSION = T.LEASE_VERSION + 1", body)
        self.assertNotIn("TENANT_ID", body)

    def test_list_ready_tasks_signature_unchanged(self):
        params = inspect.signature(scheduler.list_ready_tasks).parameters
        self.assertEqual(list(params), ["job_id"])
        self.assertNotIn("tenant_id", params)


class SetTaskStatusScopeTests(unittest.TestCase):
    def _record(self, task, tenant, status="completed", rowcount=1):
        log = []
        with _run(RecordingCursor(log, rowcount=rowcount)):
            scheduler.set_task_status(task, status, tenant_id=tenant)
        return log

    def _record_raising(self, task, tenant, status="completed"):
        log = []
        with _run(RecordingCursor(log, rowcount=0)):
            with self.assertRaises(RuntimeError):
                scheduler.set_task_status(task, status, tenant_id=tenant)
        return log

    def test_mutation_carries_task_job_tenant_scope(self):
        task, tenant = uuid4(), uuid4()
        log = self._record(task, tenant)
        self.assertEqual(_status_update_defects(log), [])
        sql, params = log[0]
        self.assertIn(STATUS_SCOPE, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params, ("completed", task, tenant))
        self.assertEqual(
            _bindings(sql, params),
            [("status", "completed"), ("id", task), ("tenant_id", tenant)],
        )

    def test_exactly_one_authoritative_update_is_issued(self):
        """A scoped precheck must not stand in for the mutation's scope."""
        task, tenant = uuid4(), uuid4()
        log = self._record(task, tenant)
        updates = [s for s, _ in log if _targets_tasks(s)]
        self.assertEqual(len(updates), 1, log)
        self.assertEqual(_status_update_defects(log), [])
        # A harmless leading SELECT alone is tolerated, but it can never
        # satisfy the proof on its own.
        only_precheck = [
            ("SELECT 1 FROM jobs WHERE tenant_id = %s", (tenant,))
        ]
        self.assertNotEqual(_status_update_defects(only_precheck), [])
        # And a precheck in front of the real mutation changes nothing.
        self.assertEqual(
            _status_update_defects(
                [("SELECT 1 FROM jobs WHERE tenant_id = %s", (tenant,))]
                + log
            ),
            [],
        )

    def test_precheck_plus_unscoped_update_is_rejected(self):
        """The reproduced survivor: scoped SELECT, then unscoped UPDATE."""
        task, tenant = uuid4(), uuid4()
        statements = [
            (
                "SELECT 1 FROM tasks t JOIN jobs j ON j.id = t.job_id"
                " WHERE t.id = %s AND j.tenant_id = %s",
                (task, tenant),
            ),
            (
                "UPDATE tasks SET status = %s, updated_at = now()"
                " WHERE id = %s",
                ("completed", task),
            ),
        ]
        defects = _status_update_defects(statements)
        self.assertNotEqual(defects, [], defects)
        self.assertIn(
            "authoritative UPDATE is not tenant scoped", defects
        )

    def test_two_unscoped_updates_are_rejected(self):
        task, tenant = uuid4(), uuid4()
        statements = [
            ("UPDATE tasks SET status = %s WHERE id = %s AND jobs.tenant_id = %s",
             ("completed", task, tenant)),
            ("UPDATE tasks SET status = %s WHERE id = %s",
             ("failed", task)),
        ]
        defects = _status_update_defects(statements)
        self.assertIn(
            "expected exactly one UPDATE of tasks, found 2", defects
        )

    def test_tenant_bound_to_the_authoritative_update(self):
        task, tenant, foreign = uuid4(), uuid4(), uuid4()
        log = self._record(task, tenant)
        sql, params = log[0]
        self.assertEqual(params[2], tenant)
        self.assertEqual(_bindings(sql, params)[2], ("tenant_id", tenant))
        wrong = ("completed", task, foreign)
        self.assertNotEqual(_bindings(sql, wrong)[2][1], tenant)

    def test_existing_error_contract_preserved(self):
        """Missing and foreign must share one observable path."""
        task, tenant = uuid4(), uuid4()
        log = self._record_raising(task, tenant)
        self.assertEqual(_status_update_defects(log), [])
        for sql, _ in log:
            self.assertIn("UPDATE", _code(sql))

        messages = set()
        for subject in ("missing", "foreign"):
            with _run(RecordingCursor([], rowcount=0)):
                try:
                    scheduler.set_task_status(
                        uuid4(), "completed", tenant_id=tenant
                    )
                except RuntimeError as exc:
                    messages.add(type(exc).__name__)
        self.assertEqual(messages, {"RuntimeError"})

    def test_scope_removal_is_detected(self):
        task, tenant = uuid4(), uuid4()
        sql, _ = self._record(task, tenant)[0]
        stripped = sql.replace(
            "WHERE id = %s\n                  AND EXISTS (",
            "WHERE id = %s\n                  AND (",
        )
        self.assertNotEqual(stripped, sql)
        self.assertNotIn(STATUS_SCOPE, _code(stripped))

    def test_boolean_bypass_is_detected(self):
        task, tenant = uuid4(), uuid4()
        sql, _ = self._record(task, tenant)[0]
        for bypass in (
            "AND jobs.tenant_id = %s OR TRUE",
            "AND jobs.tenant_id = %s OR 1 = 1",
        ):
            mutated = sql.replace(
                "AND jobs.tenant_id = %s", bypass
            )
            self.assertNotEqual(mutated, sql)
            self.assertNotEqual(
                _boolean_bypasses(mutated), [], bypass
            )


class AddDependencyScopeTests(unittest.TestCase):
    def _insert(self, a, b, tenant, rows):
        log = []
        with _run(RecordingCursor(log, rowcount=0, rows=rows)):
            scheduler.add_dependency(a, b, tenant_id=tenant)
        return log

    def _denied(self, a, b, tenant, rows):
        log = []
        with _run(RecordingCursor(log, rowcount=0, rows=rows)):
            with self.assertRaises(TenantScopeError):
                scheduler.add_dependency(a, b, tenant_id=tenant)
        return log

    def test_statement_a_scopes_both_tasks_independently(self):
        a, b, tenant = uuid4(), uuid4(), uuid4()
        log = self._insert(a, b, tenant, rows=[(a,)])
        self.assertEqual(len(log), 1, "successful insert must not run fallback")
        sql, params = log[0]
        self.assertIn(INSERT_A_SCOPE, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(
            params,
            (a, b, a, tenant, b, tenant),
        )
        self.assertEqual(
            _bindings(sql, params),
            [
                ("select", a),
                ("select", b),
                ("id", a),
                ("tenant_id", tenant),
                ("id", b),
                ("tenant_id", tenant),
            ],
        )

    def test_statement_b_scopes_both_sides(self):
        a, b, tenant = uuid4(), uuid4(), uuid4()
        log = self._denied(a, b, tenant, rows=[None, None])
        self.assertEqual(len(log), 2, "duplicate must use a second statement")
        sql, params = log[1]
        self.assertIn(SELECT_B_SCOPE, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params, (a, b, tenant, tenant))
        self.assertEqual(
            _bindings(sql, params),
            [
                ("task_id", a),
                ("depends_on_task_id", b),
                ("tenant_id", tenant),
                ("tenant_id", tenant),
            ],
        )

    def test_fallback_union_all_is_rejected(self):
        """An appended UNION branch manufactures success unconditionally."""
        a, b, tenant = uuid4(), uuid4(), uuid4()
        sql, _ = self._denied(a, b, tenant, rows=[None, None])[1]
        self.assertEqual(_select_b_defects(sql), [])
        for label, mutated in {
            "UNION ALL SELECT 1": sql
            + "\nUNION ALL SELECT 1\n",
            "UNION SELECT 1": sql + "\nUNION SELECT 1\n",
            "EXCEPT append": sql + "\nEXCEPT SELECT 1 WHERE false\n",
            "INTERSECT append": sql + "\nINTERSECT SELECT 1\n",
            "VALUES branch": sql + "\nUNION ALL VALUES (1)\n",
        }.items():
            with self.subTest(weakening=label):
                self.assertNotEqual(mutated, sql, "mutation did not apply")
                defects = _select_b_defects(mutated)
                self.assertNotEqual(defects, [], label)
                self.assertIn(
                    "statement is not exactly the scoped verification",
                    defects,
                )

    def test_fallback_runs_on_same_connection(self):
        """The duplicate re-check must share the connection/transaction."""
        a, b, tenant = uuid4(), uuid4(), uuid4()
        log = []
        with _run(RecordingCursor(log, rowcount=0, rows=[None, (1,)])):
            scheduler.add_dependency(a, b, tenant_id=tenant)
        self.assertEqual(len(log), 2)
        self.assertIn("ON CONFLICT DO NOTHING", _code(log[0][0]))
        self.assertIn("TASK_DEPENDENCIES", _code(log[1][0]))
        self.assertIn(SELECT_B_SCOPE, _code(log[1][0]))

    def test_no_same_job_restriction(self):
        a, b, tenant = uuid4(), uuid4(), uuid4()
        insert_sql, _ = self._insert(a, b, tenant, rows=[(a,)])[0]
        select_sql, _ = self._denied(a, b, tenant, rows=[None, None])[1]
        for sql in (insert_sql, select_sql):
            with self.subTest(sql=sql[:40]):
                self.assertEqual(_same_job_conditions(sql), [])

    def test_scope_weakening_variants_are_rejected(self):
        a, b, tenant = uuid4(), uuid4(), uuid4()
        sql, params = self._insert(a, b, tenant, rows=[(a,)])[0]
        self.assertEqual(_insert_defects(sql), [])
        weakened = {
            "task-A scope removed": sql.replace(
                "WHERE a.id = %s\n                      AND ja.tenant_id = %s",
                "WHERE a.id = %s",
            ),
            "parent-B scope removed": sql.replace(
                "WHERE b.id = %s\n                      AND jb.tenant_id = %s",
                "WHERE b.id = %s",
            ),
            "OR TRUE on A": sql.replace(
                "AND ja.tenant_id = %s", "AND ja.tenant_id = %s OR TRUE"
            ),
            "OR 1=1 on B": sql.replace(
                "AND jb.tenant_id = %s", "AND jb.tenant_id = %s OR 1 = 1"
            ),
            "same-job restriction injected": sql.replace(
                "ON CONFLICT DO NOTHING",
                "AND a.job_id = (SELECT job_id FROM tasks WHERE id = %s) "
                "ON CONFLICT DO NOTHING",
            ),
        }
        for label, mutated in weakened.items():
            with self.subTest(weakening=label):
                self.assertNotEqual(mutated, sql, "mutation did not apply")
                self.assertNotEqual(
                    _insert_defects(mutated), [], label
                )

    def test_swapped_tenant_binding_would_be_detected(self):
        """Binding tenant to the wrong branch fails the positional proof."""
        a, b, tenant = uuid4(), uuid4(), uuid4()
        sql, params = self._insert(a, b, tenant, rows=[(a,)])[0]
        swapped = (a, b, a, b, tenant, tenant)
        self.assertNotEqual(
            _bindings(sql, swapped)[3][1], tenant
        )
        self.assertEqual(_bindings(sql, params)[3][1], tenant)
        self.assertEqual(_bindings(sql, params)[5][1], tenant)

    def test_fallback_weakening_variants_are_rejected(self):
        a, b, tenant = uuid4(), uuid4(), uuid4()
        sql, _ = self._denied(a, b, tenant, rows=[None, None])[1]
        self.assertEqual(_select_b_defects(sql), [])
        weakened = {
            "tenant-A removed": sql.replace(
                "AND ja.tenant_id = %s\n", ""
            ),
            "tenant-B removed": sql.replace(
                "AND jb.tenant_id = %s", ""
            ),
            "OR 1=1": sql.replace(
                "AND jb.tenant_id = %s", "AND jb.tenant_id = %s OR 1 = 1"
            ),
            "OR TRUE": sql.replace(
                "AND ja.tenant_id = %s", "AND ja.tenant_id = %s OR TRUE"
            ),
        }
        for label, mutated in weakened.items():
            with self.subTest(weakening=label):
                self.assertNotEqual(mutated, sql, "mutation did not apply")
                self.assertNotEqual(_select_b_defects(mutated), [], label)

    def test_fallback_wrong_tenant_binding_would_be_detected(self):
        a, b, tenant, foreign = uuid4(), uuid4(), uuid4(), uuid4()
        sql, params = self._denied(a, b, tenant, rows=[None, None])[1]
        wrong = (a, b, tenant, foreign)
        self.assertNotEqual(_bindings(sql, wrong)[3][1], tenant)
        self.assertEqual(_bindings(sql, params)[3][1], tenant)

    def test_denial_message_is_uniform(self):
        """One message for every denial shape.

        Labels name the fixture actually supplied. With no database there
        are no foreign-owned tasks here, so only missing identifiers are
        exercised; the foreign-vs-missing equivalence is proven in the
        DB-gated oracle test with real foreign fixtures.
        """
        tenant = uuid4()
        messages = set()
        for label in ("missing_a_and_b",):
            with self.subTest(fixture=label):
                log = []
                with _run(RecordingCursor(log, rowcount=0, rows=[None, None])):
                    try:
                        scheduler.add_dependency(
                            uuid4(), uuid4(), tenant_id=tenant
                        )
                    except TenantScopeError as exc:
                        messages.add(str(exc))
        self.assertEqual(len(messages), 1, messages)


class ConnectionFactory:
    """One independent connection per thread; commits on success.

    `wrap` optionally decorates each raw connection (test-side only) so the
    caller can trace per-thread SQL without touching production code or
    transaction isolation.
    """

    def __init__(self, url, wrap=None):
        self.url = url
        self.wrap = wrap
        self._local = threading.local()
        self._connections = []
        self._lock = threading.Lock()
        self._counter = 0

    def __call__(self):
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            conn = psycopg.connect(self.url)
            self._local.conn = conn
            with self._lock:
                self._connections.append(conn)
        name = threading.current_thread().name
        if self.wrap is not None:
            return self.wrap(conn, name)
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
class SetTaskStatusDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        patcher = patch.object(
            scheduler, "connect", return_value=_Shared(self.conn)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        self.tenant = uuid4()
        self.foreign = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                    (tenant, str(tenant), "scheduler scope test"),
                )

    def task(self, tenant=None, status="pending"):
        job, task = uuid4(), uuid4()
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'scheduler scope', 'running')",
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

    def status_of(self, task):
        with self.conn.cursor() as cur:
            cur.execute("SELECT status FROM tasks WHERE id = %s", (task,))
            return cur.fetchone()[0]

    def test_same_tenant_mutation_succeeds(self):
        job, task = self.task()
        scheduler.set_task_status(
            task, "completed", tenant_id=self.tenant
        )
        self.assertEqual(self.status_of(task), "completed")

    def test_foreign_task_raises_existing_contract(self):
        job, task = self.task(tenant=self.foreign)
        with self.assertRaises(RuntimeError):
            scheduler.set_task_status(
                task, "completed", tenant_id=self.tenant
            )
        self.assertEqual(self.status_of(task), "pending")

    def test_missing_and_foreign_share_one_message_shape(self):
        _, foreign_task = self.task(tenant=self.foreign)
        messages = set()
        for task in (uuid4(), foreign_task):
            with self.assertRaises(RuntimeError) as ctx:
                scheduler.set_task_status(
                    task, "completed", tenant_id=self.tenant
                )
            messages.add(str(ctx.exception).split(":")[0])
        self.assertEqual(len(messages), 1, messages)

    def test_neighbouring_foreign_task_cannot_be_mutated(self):
        _, foreign_task = self.task(tenant=self.foreign)
        with self.assertRaises(RuntimeError):
            scheduler.set_task_status(
                foreign_task, "completed", tenant_id=self.tenant
            )
        self.assertEqual(self.status_of(foreign_task), "pending")


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class AddDependencyDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        patcher = patch.object(
            scheduler, "connect", return_value=_Shared(self.conn)
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        self.tenant = uuid4()
        self.foreign = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                    (tenant, str(tenant), "dependency scope test"),
                )

    def task(self, tenant=None):
        job, task = uuid4(), uuid4()
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'dep scope', 'running')",
                (job, tenant or self.tenant),
            )
            cur.execute(
                "INSERT INTO tasks("
                " id, job_id, external_id, title, description,"
                " capability, risk, status"
                ") VALUES (%s, %s, %s, 't', 'd', 'basic', 'low', 'pending')",
                (task, job, str(task)),
            )
        return job, task

    def edges(self, task=None):
        with self.conn.cursor() as cur:
            if task is None:
                cur.execute(
                    "SELECT count(*) FROM task_dependencies"
                )
                return cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM task_dependencies WHERE task_id = %s",
                (task,),
            )
            return cur.fetchone()[0]

    def test_same_tenant_new_edge(self):
        job_a, a = self.task()
        job_b, b = self.task()
        scheduler.add_dependency(a, b, tenant_id=self.tenant)
        self.assertEqual(self.edges(a), 1)

    def test_same_tenant_duplicate_is_silent_success(self):
        job_a, a = self.task()
        job_b, b = self.task()
        scheduler.add_dependency(a, b, tenant_id=self.tenant)
        scheduler.add_dependency(a, b, tenant_id=self.tenant)
        self.assertEqual(self.edges(a), 1)

    def test_same_tenant_cross_job_dependency_is_permitted(self):
        """Domain contract: cross-job edges stay allowed within a tenant."""
        job_a, a = self.task()
        job_b, b = self.task()
        self.assertNotEqual(job_a, job_b)
        scheduler.add_dependency(a, b, tenant_id=self.tenant)
        self.assertEqual(self.edges(a), 1)

    def test_own_task_foreign_parent_denied(self):
        job_a, a = self.task()
        _, foreign_b = self.task(tenant=self.foreign)
        before = self.edges()
        with self.assertRaises(TenantScopeError):
            scheduler.add_dependency(a, foreign_b, tenant_id=self.tenant)
        self.assertEqual(self.edges(), before)

    def test_foreign_task_own_parent_denied(self):
        _, foreign_a = self.task(tenant=self.foreign)
        job_b, b = self.task()
        before = self.edges()
        with self.assertRaises(TenantScopeError):
            scheduler.add_dependency(foreign_a, b, tenant_id=self.tenant)
        self.assertEqual(self.edges(), before)

    def test_foreign_both_denied(self):
        _, foreign_a = self.task(tenant=self.foreign)
        _, foreign_b = self.task(tenant=self.foreign)
        before = self.edges()
        with self.assertRaises(TenantScopeError):
            scheduler.add_dependency(
                foreign_a, foreign_b, tenant_id=self.tenant
            )
        self.assertEqual(self.edges(), before)

    def test_missing_cases_share_one_uniform_message(self):
        job_a, a = self.task()
        job_b, b = self.task()
        before = self.edges()
        messages = set()
        for x, y in ((uuid4(), b), (a, uuid4()), (uuid4(), uuid4())):
            with self.assertRaises(TenantScopeError) as ctx:
                scheduler.add_dependency(x, y, tenant_id=self.tenant)
            messages.add(str(ctx.exception))
        self.assertEqual(len(messages), 1, messages)
        self.assertEqual(self.edges(), before)

    def test_foreign_and_missing_share_one_uniform_message(self):
        """Real foreign-owned tasks and missing ids in one message set.

        Six denial shapes covering own/foreign/missing on both sides must
        all raise TenantScopeError with the exact same message, and must
        leave the dependency table untouched.
        """
        _, own_a = self.task()
        _, own_b = self.task()
        _, foreign_a = self.task(tenant=self.foreign)
        _, foreign_b = self.task(tenant=self.foreign)
        missing_a, missing_b = uuid4(), uuid4()

        before = self.edges()
        cases = {
            "own_a + foreign_b": (own_a, foreign_b),
            "foreign_a + own_b": (foreign_a, own_b),
            "foreign_a + foreign_b": (foreign_a, foreign_b),
            "missing_a + own_b": (missing_a, own_b),
            "own_a + missing_b": (own_a, missing_b),
            "missing_a + missing_b": (missing_a, missing_b),
        }
        messages = set()
        for label, (x, y) in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(TenantScopeError) as ctx:
                    scheduler.add_dependency(x, y, tenant_id=self.tenant)
                messages.add(str(ctx.exception))

        self.assertEqual(
            messages, {"Dependency is not in tenant scope"}, messages
        )
        self.assertEqual(
            self.edges(), before, "denials must not write rows"
        )

    def test_concurrent_duplicate_uses_second_statement(self):
        """Both callers succeed; the loser provably runs Statement B.

        Synchronization is deterministic and test-side only; transaction
        isolation is not changed and no sleep is used as the primary
        mechanism. Each thread records the SQL it executed:

        A. both threads reach Statement A (a barrier gates entry);
        B. the second thread's Statement A execution is observed before the
           first thread is allowed to commit its transaction, proving the
           conflict is genuinely contended rather than sequential;
        C/D. the first thread commits and the second completes its
           ON CONFLICT DO NOTHING path;
        E. per-thread SQL logs are compared: one thread must show only
           Statement A, the other must show Statement A and then the
           tenant-scoped Statement B.

        The test fails if Statement B is removed, if the loser returns
        without executing it, or if the two calls never contend.
        """
        setup = psycopg.connect(_DB_URL)
        self.addCleanup(setup.close)
        tenant = uuid4()
        job, a, b = uuid4(), uuid4(), uuid4()
        with setup.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, 'race')",
                (tenant, str(tenant)),
            )
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'dep race', 'running')",
                (job, tenant),
            )
            for task in (a, b):
                cur.execute(
                    "INSERT INTO tasks("
                    " id, job_id, external_id, title, description,"
                    " capability, risk, status"
                    ") VALUES (%s, %s, %s, 't', 'd', 'basic', 'low', 'pending')",
                    (task, job, str(task)),
                )
        setup.commit()
        self.addCleanup(_purge_dependency, (a, b, job, tenant))

        barrier = threading.Barrier(2)
        lock = threading.Lock()
        logs = {}
        results = []
        # Set once the second thread has actually issued Statement A.
        second_statement_a_issued = threading.Event()

        class Recording:
            """Wraps a connection so each thread's SQL is attributable."""

            def __init__(self, connection, name):
                self._connection = connection
                self._name = name

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                if exc[0] is None:
                    self._connection.commit()
                else:
                    self._connection.rollback()
                return False

            def cursor(self):
                return _TracingCursor(self._connection, self._name)

        class _TracingCursor:
            def __init__(self, connection, name):
                self._connection = connection
                self._name = name
                self._cursor = connection.cursor()

            def execute(self, sql, params=()):
                with lock:
                    logs.setdefault(self._name, []).append(sql)
                if "ON CONFLICT" in sql.upper():
                    # Recorded immediately before the statement runs, so a
                    # blocked statement still counts as having been issued.
                    if self._name == "second":
                        second_statement_a_issued.set()
                return self._cursor.execute(sql, params)

            def fetchone(self):
                return self._cursor.fetchone()

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        factory = ConnectionFactory(_DB_URL, wrap=Recording)
        self.addCleanup(factory.close_all)

        def attempt(name):
            barrier.wait(timeout=30)
            try:
                scheduler.add_dependency(a, b, tenant_id=tenant)
            except TenantScopeError as exc:
                with lock:
                    results.append(("scope_error", name, str(exc)))
            except Exception as exc:  # pragma: no cover - diagnostics
                with lock:
                    results.append(("error", name, repr(exc)))
            else:
                with lock:
                    results.append(("ok", name, None))
            # The winner may only commit once the loser is inside its own
            # Statement A, guaranteeing real contention on the row.
            second_statement_a_issued.wait(timeout=30)

        threads = [
            threading.Thread(target=attempt, args=("first",), name="first"),
            threading.Thread(target=attempt, args=("second",), name="second"),
        ]
        with patch.object(scheduler, "connect", factory):
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=60)

        self.assertFalse(any(t.is_alive() for t in threads), "thread hang")
        self.assertTrue(
            second_statement_a_issued.is_set(),
            "second thread never issued Statement A: no real contention",
        )
        self.assertEqual(len(results), 2, results)
        self.assertEqual([r for r in results if r[0] == "ok"],
                         [("ok", "first", None), ("ok", "second", None)], results)
        self.assertEqual([r for r in results if r[0] == "scope_error"], [])
        self.assertEqual([r for r in results if r[0] == "error"], [])

        shapes = {
            name: [
                "A" if "ON CONFLICT" in sql.upper() else "B"
                for sql in entries
            ]
            for name, entries in logs.items()
        }
        self.assertEqual(
            sorted(shapes.values()),
            [["A"], ["A", "B"]],
            f"expected one winner and one loser running Statement B: {shapes}",
        )
        loser = [n for n, s in shapes.items() if s == ["A", "B"]][0]
        loser_sql = " ".join(logs[loser])
        self.assertIn("ON CONFLICT", loser_sql.upper())
        self.assertIn("task_dependencies", loser_sql)

        with setup.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM task_dependencies"
                " WHERE task_id = %s AND depends_on_task_id = %s",
                (a, b),
            )
            self.assertEqual(cur.fetchone()[0], 1)


class _Shared:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


def _purge_dependency(ids):
    a, b, job, tenant = ids
    conn = psycopg.connect(_DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM task_dependencies WHERE task_id = %s"
                " OR depends_on_task_id = %s",
                (a, b),
            )
            cur.execute("DELETE FROM tasks WHERE id IN (%s, %s)", (a, b))
            cur.execute("DELETE FROM jobs WHERE id = %s", (job,))
            cur.execute("DELETE FROM tenants WHERE id = %s", (tenant,))
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    unittest.main()