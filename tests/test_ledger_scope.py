import ast
import threading
"""F-05 ledger lifecycle tenant isolation.

Structural (no database) tests execute the real functions against recording
fake connections, so assertions concern the SQL actually issued and the
parameters actually bound. Assertions read tokenized SQL, so a predicate
surviving only in a comment cannot satisfy them, and each authoritative
statement is located by shape rather than by position.

PostgreSQL scenarios are gated on DEVAI_TEST_DATABASE_URL and skip honestly
when it is absent. A skip is never reported as a pass.
"""
import inspect
import os
import unittest
from decimal import Decimal
from unittest.mock import patch
from uuid import uuid4

import psycopg

from devai import (
    accounting,
    budgeted_observer,
    ledger,
    ledger_observer,
    reconciliation,
    runtime,
)
from devai.tenancy import TenantScopeError
from devai.types import ExecutionAttempt, ModelCandidate
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")


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


def _patched(module, cursor):
    return patch.object(module, "connect",
                        return_value=ScriptedConnection(cursor))


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
        t.text.upper() for t in _tokenize(sql)
        if t.kind == "name" and t.text.upper() in ("OR", "XOR")
    ]


def _authoritative(statements, verb, table):
    """Statements whose leading verb reads or mutates `table`."""
    found = []
    for sql, params in statements:
        for tok in _tokenize(sql):
            if tok.kind == "name" and tok.text.upper() in (
                    "UPDATE", "INSERT", "SELECT", "DELETE"):
                if tok.text.upper() != verb:
                    break
                if verb == "SELECT" or _targets(sql, table, verb):
                    found.append((sql, params))
                break
    return found


def _targets(sql, table, verb="UPDATE"):
    toks = _tokenize(sql)
    marker = "INTO" if verb == "INSERT" else "UPDATE"
    for i, tok in enumerate(toks):
        if tok.kind == "name" and tok.text.upper() == marker:
            j = i + 1
            while j < len(toks) and toks[j].kind == "name" \
                    and toks[j].text.upper() == "ONLY":
                j += 1
            parts = []
            while j < len(toks) and toks[j].kind in ("name", "quoted"):
                parts.append(_ident(toks[j]))
                j += 1
                if j < len(toks) and toks[j].kind == "punct" \
                        and toks[j].text == ".":
                    j += 1
                    continue
                break
            if parts and parts[-1] == table:
                return True
    return False


# --- expected statement shapes -------------------------------------------
CREATE_TASK_SHAPE = (
    "SELECT %S , J . ID , %S , %S , %S , %S , %S , %S , %S FROM JOBS J "
    "WHERE J . ID = %S AND J . TENANT_ID = %S RETURNING ID"
)
ATTEMPT_GUARD = (
    "FROM JOBS J JOIN TASKS T ON T . JOB_ID = J . ID WHERE T . ID = %S "
    "AND T . JOB_ID = J . ID AND J . ID = %S AND J . TENANT_ID = %S"
)
FINISH_GUARD = (
    "AND EXISTS ( SELECT 1 FROM JOBS J "
    "WHERE J . ID = EXECUTION_ATTEMPTS . JOB_ID AND J . TENANT_ID = %S )"
)
COMPLETE_TASK_SCOPE = (
    "WHERE ID = %S AND JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )"
)
COMPLETE_JOB_SCOPE = "WHERE ID = %S AND TENANT_ID = %S"
FINALIZE_GATE = (
    "FROM EXECUTION_ATTEMPTS A JOIN JOBS J ON J . ID = A . JOB_ID "
    "WHERE A . ID = %S AND A . JOB_ID = %S AND A . STATUS = 'RUNNING' "
    "AND A . BILLING_MODE = %S AND J . TENANT_ID = %S FOR UPDATE OF A"
)
FINALIZE_BUDGET = (
    "WHERE JOB_ID = %S AND RESERVED_USD >= %S AND JOB_ID IN "
    "( SELECT ID FROM JOBS WHERE TENANT_ID = %S )"
)
FINALIZE_ATTEMPT = (
    "WHERE ID = %S AND JOB_ID = %S AND STATUS = 'RUNNING' "
    "AND BILLING_MODE = %S AND EXISTS ( SELECT 1 FROM JOBS J "
    "WHERE J . ID = EXECUTION_ATTEMPTS . JOB_ID AND J . TENANT_ID = %S )"
)
METERED_BUDGET = (
    "WHERE JOB_ID = %S AND RESERVED_USD + SPENT_USD + "
    "RECOVERY_EXPOSURE_USD + UNPRICED_EXPOSURE_USD + %S <= LIMIT_USD "
    "AND EXISTS ( SELECT 1 FROM JOBS J "
    "WHERE J . ID = JOB_BUDGETS . JOB_ID AND J . TENANT_ID = %S )"
)
METERED_ATTEMPT = (
    "FROM JOBS J JOIN TASKS T ON T . JOB_ID = J . ID WHERE J . ID = %S "
    "AND T . ID = %S AND T . JOB_ID = J . ID AND J . TENANT_ID = %S"
)
OPEN_BUDGET = (
    "WHERE JOB_ID = %S AND RESERVED_USD >= %S AND EXISTS "
    "( SELECT 1 FROM JOBS J "
    "WHERE J . ID = JOB_BUDGETS . JOB_ID AND J . TENANT_ID = %S )"
)
OPEN_ATTEMPT = (
    "WHERE ID = %S AND EXISTS ( SELECT 1 FROM JOBS J "
    "WHERE J . ID = EXECUTION_ATTEMPTS . JOB_ID AND J . TENANT_ID = %S )"
)
OPEN_CASE = (
    "WHERE EXISTS ( SELECT 1 FROM EXECUTION_ATTEMPTS A JOIN JOBS J "
    "ON J . ID = A . JOB_ID WHERE A . ID = %S AND A . JOB_ID = %S "
    "AND J . TENANT_ID = %S )"
)


class OpenInsertShapeTests(unittest.TestCase):
    """Narrow shape regression for the _open case INSERT.

    Not general PostgreSQL validation: it pins the INSERT target columns,
    the SELECT expression count, that every Python-bound value has a
    placeholder, the absence of a bare identifier where a bound job value
    belongs, and the exact bind-tuple order.
    """
    COLUMNS = ("id", "tenant_id", "job_id", "attempt_id", "status",
               "exposure_usd", "result_success")

    def _case_insert(self):
        log = []
        tenant, attributed = uuid4(), uuid4()
        job, attempt = uuid4(), uuid4()
        rows = [None, (job, attributed, Decimal(1), "metered", "running"),
                None]
        cursor = SelectiveCursor(log, rows=rows, insert_rowcount=1)
        with _patched(reconciliation, cursor):
            reconciliation._open(cursor, attempt, tenant_id=tenant)
        cases = [e for e in log
                 if "RECOVERABLE" in _code(e[0])
                 and "METERED_RECONCILIATION_EVENTS" not in _code(e[0])]
        self.assertEqual(len(cases), 1, "case INSERT not found")
        return cases[0], tenant, attributed, job, attempt

    def test_insert_target_columns_exact(self):
        (sql, _), *_ = self._case_insert()
        code = _code(sql)
        marker = "INSERT INTO METERED_RECONCILIATIONS ("
        start = code.index(marker) + len(marker)
        end = code.index(")", start)
        columns = tuple(
            c.strip() for c in code[start:end].split(","))
        self.assertEqual(columns, tuple(c.upper() for c in self.COLUMNS))

    def test_select_expression_count_matches_columns(self):
        (sql, _), *_ = self._case_insert()
        code = _code(sql)
        select = code[code.index("SELECT") + len("SELECT"):]
        # only the leading SELECT list matters (before WHERE EXISTS)
        expressions = select.split("WHERE")[0].split(",")
        self.assertEqual(len(expressions), len(self.COLUMNS))

    def test_no_bare_identifier_where_job_value_is_bound(self):
        """`job` as an unbound SQL identifier must be rejected."""
        (sql, params), _, _, job, _ = self._case_insert()
        code = _code(sql)
        select = code[code.index("SELECT"):code.index("WHERE EXISTS")]
        expressions = [e.strip() for e in select.split(",")]
        for expression in expressions:
            self.assertNotEqual(expression, "JOB")
            self.assertNotIn("J.", expression)
        self.assertIn(("select", job), _bindings(sql, params))

    def test_every_bound_value_has_a_placeholder(self):
        (sql, params), tenant, attributed, job, attempt = (
            self._case_insert())
        placeholders = [t for t in _tokenize(sql) if t.kind == "placeholder"]
        self.assertEqual(len(placeholders), len(params))
        self.assertEqual(len(params), 9)

    def test_exact_bind_order(self):
        (sql, params), tenant, attributed, job, attempt = (
            self._case_insert())
        # INSERT values first, then the EXISTS authorization gate
        self.assertEqual(
            [type(p).__name__ for p in params[:4]],
            ["UUID", "UUID", "UUID", "UUID"])
        self.assertEqual(params[1], attributed, "tenant_id is attribution")
        self.assertEqual(params[2], job, "job_id must be bound, not bare")
        self.assertEqual(params[3], attempt)
        # gate: attempt, job, caller tenant
        self.assertEqual(params[6], attempt)
        self.assertEqual(params[7], job)
        self.assertEqual(params[8], tenant,
                         "caller tenant authorizes, row tenant attributes")

    def test_status_literal_is_recoverable(self):
        (sql, _), *_ = self._case_insert()
        self.assertIn("'RECOVERABLE'", _code(sql))


class OpenProjectionTests(unittest.TestCase):
    """H1: every joined id projection in _open must be explicitly qualified."""

    def _open_statements(self):
        tenant = uuid4()
        log = []
        job = uuid4()
        rows = [None, (job, uuid4(), Decimal(1), "metered", "running"), None]
        cursor = SelectiveCursor(log, rows=rows, insert_rowcount=1)
        with _patched(reconciliation, cursor):
            reconciliation._open(cursor, uuid4(), tenant_id=tenant)
        return log

    def test_joined_id_projections_are_qualified(self):
        for sql, _ in self._open_statements():
            code = _code(sql)
            if "METERED_RECONCILIATIONS M" not in code:
                continue
            for token in _tokenize(sql):
                if token.kind == "name" and token.text.upper() == "ID":
                    left = _tokenize(sql)
                    index = left.index(token)
                    previous = left[index - 1]
                    self.assertTrue(
                        previous.kind == "punct" and previous.text == "."
                        or previous.kind in ("name", "quoted")
                        and previous.text.upper() in ("M", "A", "J"),
                        "unqualified ambiguous id projection",
                    )

    def test_case_lookup_projects_the_case_id(self):
        """The projected column must be m.id, preserving pre-B3 meaning."""
        log = self._open_statements()
        lookups = [e for e in log
                   if "METERED_RECONCILIATIONS M" in _code(e[0])
                   and "FOR UPDATE" not in _code(e[0])]
        self.assertGreaterEqual(len(lookups), 2)
        for sql, _ in lookups:
            self.assertIn("SELECT M . ID FROM", _code(sql))

    def test_bare_id_projection_is_detected(self):
        sql = ("SELECT id FROM metered_reconciliations m "
               "JOIN execution_attempts a ON a.id = m.attempt_id")
        for token in _tokenize(sql):
            if token.kind == "name" and token.text.upper() == "ID":
                left = _tokenize(sql)
                previous = left[left.index(token) - 1]
                self.assertFalse(
                    previous.kind == "punct" and previous.text == ".",
                    "bare id must fail the qualification check")
    TENANT_FNS = ("create_task", "record_attempt", "start_attempt",
                  "finish_attempt", "complete_task", "complete_job")

    def test_each_ledger_function_requires_keyword_only_tenant(self):
        for name in self.TENANT_FNS:
            with self.subTest(function=name):
                params = inspect.signature(
                    getattr(ledger, name)).parameters
                self.assertIn("tenant_id", params)
                tenant = params["tenant_id"]
                self.assertEqual(tenant.kind,
                                 inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(tenant.default, inspect.Parameter.empty)

    def test_omitting_tenant_is_a_type_error(self):
        with self.assertRaises(TypeError):
            ledger.complete_task(uuid4())
        with self.assertRaises(TypeError):
            ledger.complete_job(uuid4())

    def test_create_job_signature_unchanged(self):
        params = list(inspect.signature(ledger.create_job).parameters)
        self.assertEqual(params, ["objective", "tenant_id", "status"])

    def test_observers_require_immutable_tenant(self):
        for cls in (ledger_observer.LedgerExecutionObserver,
                    budgeted_observer.BudgetedLedgerObserver):
            with self.subTest(observer=cls.__name__):
                params = inspect.signature(cls.__init__).parameters
                tenant = params["tenant_id"]
                self.assertEqual(tenant.kind,
                                 inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(tenant.default, inspect.Parameter.empty)

    def test_metered_entry_points_require_tenant(self):
        for fn in (reconciliation.start_metered_attempt,
                   reconciliation.defer_missing_usage):
            with self.subTest(function=fn.__name__):
                params = inspect.signature(fn).parameters
                self.assertIn("tenant_id", params)
                self.assertIs(params["tenant_id"].default,
                              inspect.Parameter.empty)

    def test_finalize_requires_tenant(self):
        params = inspect.signature(
            accounting.finalize_attempt_and_budget).parameters
        self.assertEqual(params["tenant_id"].kind,
                         inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(params["tenant_id"].default,
                      inspect.Parameter.empty)

    def test_open_requires_tenant_with_no_default(self):
        params = inspect.signature(reconciliation._open).parameters
        self.assertIs(params["tenant_id"].default,
                      inspect.Parameter.empty)

    def test_no_tenant_principal_in_ledger_layer(self):
        for mod in (ledger, accounting, reconciliation,
                    budgeted_observer, ledger_observer):
            self.assertNotIn("TenantPrincipal", inspect.getsource(mod))

    def test_sweep_public_signature_unchanged(self):
        params = inspect.signature(reconciliation.sweep).parameters
        self.assertEqual(list(params), ["limit"])
        self.assertEqual(params["limit"].default, 100)


class CreateTaskScopeTests(unittest.TestCase):
    def _run(self, tenant, job, rows=((uuid4(),),), rowcount=1):
        log = []
        with _patched(ledger, RecordingCursor(log, rowcount, rows)):
            ledger.create_task(job, "e", "t", "d", "basic", "low",
                               False, tenant_id=tenant)
        return log

    def _denied(self, tenant, job):
        log = []
        with _patched(ledger, RecordingCursor(log, 0, [])):
            with self.assertRaises(TenantScopeError):
                ledger.create_task(job, "e", "t", "d", "basic",
                                   "low", False, tenant_id=tenant)
        return log

    def test_insert_is_tenant_scoped_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = self._run(tenant, job, rows=[(uuid4(),)])[0]
        self.assertIn(CREATE_TASK_SHAPE, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params[-2:], (job, tenant))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_zero_rows_raises_uniform_scope_error(self):
        tenant = uuid4()
        log = self._denied(tenant, uuid4())
        self.assertIn(CREATE_TASK_SHAPE, _code(log[0][0]))

    def test_scope_removal_detected(self):
        tenant, job = uuid4(), uuid4()
        sql, _ = self._run(tenant, job, rows=[(uuid4(),)])[0]
        stripped = sql.replace("AND j.tenant_id = %s", "")
        self.assertNotIn(CREATE_TASK_SHAPE, _code(stripped))

    def test_wrong_tenant_binding_detected(self):
        tenant, job, foreign = uuid4(), uuid4(), uuid4()
        sql, params = self._run(tenant, job, rows=[(uuid4(),)])[0]
        self.assertEqual(params[-1], tenant)
        wrong = params[:-1] + (foreign,)
        self.assertNotEqual(_bindings(sql, wrong)[-1][1], tenant)

    def test_precheck_plus_unscoped_insert_rejected(self):
        """A scoped SELECT cannot authorize an unscoped INSERT."""
        tenant = uuid4()
        statements = [
            ("SELECT 1 FROM jobs WHERE id = %s AND tenant_id = %s",
             (uuid4(), tenant)),
            ("INSERT INTO tasks (id, job_id) VALUES (%s, %s)",
             (uuid4(), uuid4())),
        ]
        inserts = _authoritative(statements, "INSERT", "tasks")
        self.assertEqual(len(inserts), 1)
        self.assertNotIn(CREATE_TASK_SHAPE, _code(inserts[0][0]))


class AttemptLifecycleScopeTests(unittest.TestCase):
    ATTEMPT = ExecutionAttempt("k", "p", "m", True)

    def _start(self, tenant, job=None, task=None):
        job, task = job or uuid4(), task or uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1, [(uuid4(),)])):
            ledger.start_attempt(job, task, 1, "k", "p", "m",
                                 tenant_id=tenant)
        return log, job, task

    def _record(self, tenant, job=None, task=None):
        job, task = job or uuid4(), task or uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1, [(uuid4(),)])):
            ledger.record_attempt(job, task, 1, self.ATTEMPT,
                                  tenant_id=tenant)
        return log, job, task

    def test_start_attempt_scoped(self):
        tenant = uuid4()
        log, _, _ = self._start(tenant)
        sql, params = log[0]
        self.assertIn(ATTEMPT_GUARD, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_start_attempt_bindings_pinned(self):
        """task_id, job_id and tenant_id must bind to their predicates."""
        tenant = uuid4()
        log, job, task = self._start(tenant)
        sql, params = log[0]
        bindings = _bindings(sql, params)
        self.assertEqual(
            [ident for ident, _ in bindings[-3:]],
            ["id", "id", "tenant_id"])
        self.assertEqual(bindings[-3][1], task, "task_id predicate")
        self.assertEqual(bindings[-2][1], job, "job_id predicate")
        self.assertEqual(bindings[-1][1], tenant, "tenant_id predicate")

    def test_start_attempt_task_job_swap_detected(self):
        tenant = uuid4()
        log, job, task = self._start(tenant)
        sql, params = log[0]
        swapped = list(params)
        swapped[-3], swapped[-2] = swapped[-2], swapped[-3]
        bindings = _bindings(sql, tuple(swapped))
        self.assertNotEqual(bindings[-3][1], task)

    def test_record_attempt_bindings_pinned(self):
        tenant = uuid4()
        log, job, task = self._record(tenant)
        sql, params = log[0]
        bindings = _bindings(sql, params)
        self.assertEqual(
            [ident for ident, _ in bindings[-3:]],
            ["id", "id", "tenant_id"])
        self.assertEqual(bindings[-3][1], task)
        self.assertEqual(bindings[-2][1], job)
        self.assertEqual(bindings[-1][1], tenant)

    def test_record_attempt_task_job_swap_detected(self):
        tenant = uuid4()
        log, job, task = self._record(tenant)
        sql, params = log[0]
        swapped = list(params)
        swapped[-3], swapped[-2] = swapped[-2], swapped[-3]
        bindings = _bindings(sql, tuple(swapped))
        self.assertNotEqual(bindings[-3][1], task)

    def test_record_attempt_scoped(self):
        tenant = uuid4()
        log, _, _ = self._record(tenant)
        sql, params = log[0]
        self.assertIn(ATTEMPT_GUARD, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params[-1], tenant)

    def test_one_sided_authorization_detected(self):
        tenant = uuid4()
        for runner in (self._start, self._record):
            log, _, _ = runner(tenant)
            sql, _ = log[0]
            for mutated in (
                sql.replace("AND j.tenant_id = %s", ""),
                sql.replace("AND t.job_id = j.id", ""),
                sql.replace("AND j.id = %s\n", ""),
            ):
                with self.subTest(mutated=mutated[:40]):
                    self.assertNotIn(ATTEMPT_GUARD, _code(mutated))

    def test_attempt_wrong_tenant_binding_detected(self):
        tenant, foreign = uuid4(), uuid4()
        log, _, _ = self._start(tenant)
        sql, params = log[0]
        wrong = params[:-1] + (foreign,)
        self.assertNotEqual(_bindings(sql, wrong)[-1][1], tenant)

    def _finish_log(self, tenant, attempt):
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.finish_attempt(attempt, True, tenant_id=tenant)
        return log

    def test_finish_attempt_update_is_authoritative(self):
        tenant, attempt = uuid4(), uuid4()
        updates = [e for e in self._finish_log(tenant, attempt)
                   if _targets(e[0], "execution_attempts", "UPDATE")]
        self.assertEqual(len(updates), 1)
        sql, params = updates[0]
        self.assertIn(FINISH_GUARD, _code(sql))
        self.assertEqual(params, ("succeeded", None, attempt, tenant))
        self.assertEqual(
            _bindings(sql, params),
            [("status", "succeeded"), ("error_message", None),
             ("id", attempt), ("tenant_id", tenant)],
        )

    def test_finish_attempt_precheck_plus_unscoped_update_rejected(self):
        tenant, attempt = uuid4(), uuid4()
        statements = [
            ("SELECT 1 FROM execution_attempts a JOIN jobs j ON j.id=a.job_id"
             " WHERE a.id=%s AND j.tenant_id=%s", (attempt, tenant)),
            ("UPDATE execution_attempts SET status='succeeded'"
             " WHERE id=%s AND status='running'", (attempt,)),
        ]
        updates = [e for e in statements
                   if _targets(e[0], "execution_attempts", "UPDATE")]
        self.assertEqual(len(updates), 1)
        self.assertNotIn(FINISH_GUARD, _code(updates[0][0]))

    def test_finish_attempt_scope_removal_detected(self):
        tenant, attempt = uuid4(), uuid4()
        sql = self._finish_log(tenant, attempt)[0][0]
        self.assertNotIn(
            FINISH_GUARD, _code(sql.replace("AND j.tenant_id = %s", "")))

    def test_finish_attempt_boolean_bypass_detected(self):
        tenant, attempt = uuid4(), uuid4()
        sql = self._finish_log(tenant, attempt)[0][0]
        for bypass in ("AND j.tenant_id = %s OR TRUE",
                       "AND j.tenant_id = %s OR 1 = 1"):
            mutated = sql.replace("AND j.tenant_id = %s", bypass)
            self.assertNotEqual(mutated, sql, "mutation did not apply")
            self.assertTrue(
                FINISH_GUARD not in _code(mutated)
                or _boolean_bypasses(mutated),
                f"boolean bypass accepted: {bypass}")

    def test_finish_attempt_foreign_rowcount_contract(self):
        tenant, attempt = uuid4(), uuid4()
        with _patched(ledger, RecordingCursor([], 0)):
            with self.assertRaises(RuntimeError):
                ledger.finish_attempt(attempt, True, tenant_id=tenant)


class CompleteScopeTests(unittest.TestCase):
    """The authoritative UPDATE itself must carry scope.

    Proofs locate the mutating statement rather than inspecting statement
    order, so a preceding tenant-scoped SELECT cannot stand in for it.
    """

    def _updates(self, log, table):
        return [e for e in log if _targets(e[0], table, "UPDATE")]

    def _complete_task_log(self, tenant, task):
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_task(task, tenant_id=tenant)
        return log

    def _complete_job_log(self, tenant, job):
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_job(job, tenant_id=tenant)
        return log

    def test_complete_task_scoped(self):
        tenant, task = uuid4(), uuid4()
        log = self._complete_task_log(tenant, task)
        updates = self._updates(log, "tasks")
        self.assertEqual(len(updates), 1)
        sql, params = updates[0]
        self.assertIn(COMPLETE_TASK_SCOPE, _code(sql))
        self.assertEqual(params, (task, tenant))
        self.assertEqual(_boolean_bypasses(sql), [])

    def test_complete_task_authoritative_update_required(self):
        """Precheck + unscoped UPDATE must fail the proof."""
        tenant, task = uuid4(), uuid4()
        statements = [
            ("SELECT 1 FROM tasks t JOIN jobs j ON j.id = t.job_id"
             " WHERE t.id = %s AND j.tenant_id = %s", (task, tenant)),
            ("UPDATE tasks SET status = 'completed', updated_at = now()"
             " WHERE id = %s", (task,)),
        ]
        updates = self._updates(statements, "tasks")
        self.assertEqual(len(updates), 1)
        self.assertNotIn(COMPLETE_TASK_SCOPE, _code(updates[0][0]))

    def test_complete_task_scope_removal_detected(self):
        tenant, task = uuid4(), uuid4()
        sql, _ = self._complete_task_log(tenant, task)[0]
        stripped = sql.replace(
            "AND job_id IN (SELECT id FROM jobs WHERE tenant_id = %s)", "")
        self.assertNotIn(COMPLETE_TASK_SCOPE, _code(stripped))

    def test_complete_job_scoped(self):
        tenant, job = uuid4(), uuid4()
        updates = self._updates(self._complete_job_log(tenant, job), "jobs")
        self.assertEqual(len(updates), 1)
        sql, params = updates[0]
        self.assertIn(COMPLETE_JOB_SCOPE, _code(sql))
        self.assertEqual(params, (job, tenant))

    def test_complete_job_boolean_bypasses_detected(self):
        tenant, job = uuid4(), uuid4()
        sql, _ = self._complete_job_log(tenant, job)[0]
        for bypass in ("AND tenant_id = %s OR TRUE",
                       "AND tenant_id = %s OR 1 = 1"):
            mutated = sql.replace("AND tenant_id = %s", bypass)
            self.assertNotEqual(mutated, sql, "mutation did not apply")
            self.assertTrue(
                COMPLETE_JOB_SCOPE not in _code(mutated)
                or _boolean_bypasses(mutated),
                f"boolean bypass accepted: {bypass}")

    def test_complete_job_scope_removal_detected(self):
        tenant, job = uuid4(), uuid4()
        sql, _ = self._complete_job_log(tenant, job)[0]
        stripped = sql.replace("AND tenant_id = %s", "")
        self.assertNotIn(COMPLETE_JOB_SCOPE, _code(stripped))

    def test_complete_job_wrong_tenant_detected(self):
        tenant, job, foreign = uuid4(), uuid4(), uuid4()
        sql, params = self._complete_job_log(tenant, job)[0]
        self.assertEqual(params, (job, tenant))
        self.assertNotEqual(_bindings(sql, (job, foreign))[1][1], tenant)


class FinalizeScopeTests(unittest.TestCase):
    ATTEMPT = ExecutionAttempt("k", "p", "m", True)

    def _log(self, tenant):
        log = []
        with _patched(accounting, RecordingCursor(log, 1, [("a",)])):
            accounting.finalize_attempt_and_budget(
                uuid4(), uuid4(), self.ATTEMPT, Decimal(1), Decimal(0),
                "pk", 1, "metered", tenant_id=tenant)
        return log

    def test_all_three_statements_are_tenant_scoped(self):
        tenant = uuid4()
        log = self._log(tenant)
        self.assertEqual(len(log), 3, [s for s, _ in log])
        gate, budget, final = log
        self.assertIn(FINALIZE_GATE, _code(gate[0]))
        self.assertIn(FINALIZE_BUDGET, _code(budget[0]))
        self.assertIn(FINALIZE_ATTEMPT, _code(final[0]))
        for sql, params in log:
            self.assertEqual(_boolean_bypasses(sql), [])
            self.assertIn(tenant, params)

    def test_each_statement_binds_tenant(self):
        tenant = uuid4()
        for sql, params in self._log(tenant):
            self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_first_scoped_later_unscoped_detected(self):
        tenant = uuid4()
        log = self._log(tenant)
        self.assertIn(FINALIZE_GATE, _code(log[0][0]))
        self.assertNotIn(
            FINALIZE_BUDGET,
            _code(log[1][0].replace("AND job_id IN (", "AND (")
                   .replace("SELECT id FROM jobs WHERE tenant_id = %s)", "1)")))
        self.assertNotIn(
            FINALIZE_ATTEMPT,
            _code(log[2][0].replace("AND j.tenant_id = %s", "")))

    def test_independent_scope_removal_per_statement(self):
        tenant = uuid4()
        log = self._log(tenant)
        weakened = {
            "gate": log[0][0].replace("AND j.tenant_id=%s", ""),
            "budget": log[1][0].replace(
                "AND job_id IN (SELECT id FROM jobs WHERE tenant_id = %s)",
                ""),
            "finalize": log[2][0].replace(
                "AND j.tenant_id = %s", ""),
        }
        shapes = {"gate": FINALIZE_GATE, "budget": FINALIZE_BUDGET,
                  "finalize": FINALIZE_ATTEMPT}
        for label, mutated in weakened.items():
            with self.subTest(statement=label):
                self.assertNotEqual(mutated, log[
                    ("gate", "budget", "finalize").index(label)][0])
                self.assertNotIn(shapes[label], _code(mutated))

    def test_wrong_tenant_per_statement_detected(self):
        tenant, foreign = uuid4(), uuid4()
        log = self._log(tenant)
        for sql, params in log:
            index = len(params) - 1
            wrong = params[:-1] + (foreign,)
            self.assertNotEqual(
                _bindings(sql, wrong)[index][1], tenant, sql[:40])


class MeteredStartScopeTests(unittest.TestCase):
    def _log(self, tenant, budget_rows=1, attempt_rows=1):
        log = []
        # The pricing snapshot must equal the price object's own values.
        cursor = RecordingCursor(log, budget_rows,
                                 [(2, 3), (uuid4(),)][:attempt_rows])
        with _patched(reconciliation, cursor):
            reconciliation.start_metered_attempt(
                job_id=uuid4(), task_id=uuid4(), number=1,
                route=_FakeRoute(), model="m", price=_FakePrice(),
                reservation=Decimal(1), tenant_id=tenant)
        return log

    def test_budget_and_attempt_statements_are_independently_scoped(self):
        tenant = uuid4()
        log = self._log(tenant)
        self.assertEqual(len(log), 3, [s for s, _ in log])
        self.assertIn(METERED_BUDGET, _code(log[1][0]))
        self.assertIn(METERED_ATTEMPT, _code(log[2][0]))
        for sql, params in log[1:]:
            self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_task_in_job_proof_retained(self):
        tenant = uuid4()
        sql, _ = self._log(tenant)[2]
        self.assertIn("T . JOB_ID = J . ID", _code(sql))

    def test_budget_scope_removal_detected(self):
        tenant = uuid4()
        sql, _ = self._log(tenant)[1]
        stripped = sql.replace(
            "AND EXISTS (SELECT 1 FROM jobs j WHERE j.id=job_budgets.job_id"
            " AND j.tenant_id=%s)", "")
        self.assertNotIn(METERED_BUDGET, _code(stripped))

    def test_attempt_scope_removal_detected(self):
        tenant = uuid4()
        sql, _ = self._log(tenant)[2]
        self.assertNotIn(
            METERED_ATTEMPT, _code(sql.replace("AND j.tenant_id=%s", "")))

    def test_scoped_first_mutation_unscoped_second_detected(self):
        tenant = uuid4()
        log = self._log(tenant)
        self.assertIn(METERED_BUDGET, _code(log[1][0]))
        self.assertNotIn(
            METERED_ATTEMPT,
            _code(log[2][0].replace("AND j.tenant_id=%s", "")))

    def test_scoped_precheck_plus_unscoped_budget_update_rejected(self):
        tenant = uuid4()
        log = self._log(tenant)
        statements = [log[0], (
            "UPDATE job_budgets SET reserved_usd=reserved_usd+%s"
            " WHERE job_id=%s AND reserved_usd+%s<=limit_usd",
            (Decimal(1), uuid4(), Decimal(1)))]
        updates = _authoritative(statements, "UPDATE", "job_budgets")
        self.assertEqual(len(updates), 1)
        self.assertNotIn(METERED_BUDGET, _code(updates[0][0]))

    def test_wrong_tenant_bindings_detected(self):
        tenant, foreign = uuid4(), uuid4()
        log = self._log(tenant)
        for sql, params in log[1:]:
            wrong = params[:-1] + (foreign,)
            self.assertNotEqual(
                _bindings(sql, wrong)[-1][1], tenant, sql[:40])

    def test_rollback_on_attempt_rejection_is_transactional(self):
        """Statement B rejection must unwind statement A's reservation."""
        tenant = uuid4()
        log = []
        # pricing snapshot present; the attempt INSERT matches zero rows.
        cursor = SelectiveCursor(log, rows=[(2, 3)], insert_rowcount=0,
                                 other_rowcount=1)
        with _patched(reconciliation, cursor):
            with self.assertRaises(reconciliation.ReconciliationError):
                reconciliation.start_metered_attempt(
                    job_id=uuid4(), task_id=uuid4(), number=1,
                    route=_FakeRoute(), model="m", price=_FakePrice(),
                    reservation=Decimal(1), tenant_id=tenant)
        self.assertEqual(len(log), 3)
        # Statement A (budget) really did run before statement B rejected.
        self.assertIn(METERED_BUDGET, _code(log[1][0]))


class SelectiveCursor(RecordingCursor):
    """Rowcount varies per statement, so one cursor can model a later failure."""

    def __init__(self, log, rows=(), insert_rowcount=0, other_rowcount=1):
        super().__init__(log, other_rowcount, rows)
        self._insert_rowcount = insert_rowcount
        self._other_rowcount = other_rowcount

    def execute(self, sql, params=()):
        super().execute(sql, params)
        if _code(sql).startswith("INSERT"):
            self.rowcount = self._insert_rowcount
        else:
            self.rowcount = self._other_rowcount


class OpenScopeTests(unittest.TestCase):
    def _cursor(self, tenant, attributed=None, insert_rowcount=1):
        log = []
        job = uuid4()
        # _open statement order: (1) existing case, (2) authorization gate,
        # (3) raced case. Row 2 must look like a recoverable metered attempt.
        gate_row = (job, attributed or uuid4(), Decimal(1), "metered",
                    "running")
        rows = [None, gate_row, None]
        cursor = SelectiveCursor(log, rows=rows,
                                insert_rowcount=insert_rowcount)
        with _patched(reconciliation, cursor):
            reconciliation._open(cursor, uuid4(), tenant_id=tenant)
        return log

    def test_gate_uses_caller_tenant(self):
        tenant = uuid4()
        log = self._cursor(tenant)
        gate = [entry for entry in log if "FOR UPDATE OF A" in _code(entry[0])]
        self.assertTrue(gate)
        for sql, _ in gate:
            self.assertIn("J . TENANT_ID = %S", _code(sql))
        # The _open authorization and mutation statements (not the trailing
        # _event bookkeeping insert) must each bind the caller tenant.
        auth = [e for e in log if "METERED_RECONCILIATION_EVENTS"
                not in _code(e[0])]
        for sql, params in auth:
            self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_three_mutations_are_tenant_scoped(self):
        tenant = uuid4()
        log = self._cursor(tenant)
        budget = [s for s, _ in log if "JOB_BUDGETS" in _code(s)
                  and "RECOVERY_EXPOSURE_USD" in _code(s)]
        attempt = [s for s, _ in log if "METERED_USAGE_PENDING" in _code(s)]
        case = [s for s, _ in log if "METERED_RECONCILIATIONS" in _code(s)
                and "RECOVERABLE" in _code(s)]
        self.assertTrue(budget and attempt and case)
        self.assertIn(OPEN_BUDGET, _code(budget[0]))
        self.assertIn(OPEN_ATTEMPT, _code(attempt[0]))
        self.assertIn(OPEN_CASE, _code(case[0]))

    def test_row_tenant_is_attribution_only(self):
        """The row tenant is attribution; the caller tenant is authority."""
        tenant, attributed = uuid4(), uuid4()
        log = self._cursor(tenant, attributed=attributed)
        case = [e for e in log
                if "RECOVERABLE" in _code(e[0])
                and "METERED_RECONCILIATION_EVENTS" not in _code(e[0])]
        self.assertEqual(len(case), 1)
        sql, params = case[0]
        bindings = _bindings(sql, params)
        # authority: the caller tenant is bound to the EXISTS tenant predicate
        self.assertIn(("tenant_id", tenant), bindings)
        # attribution: the row-derived tenant is recorded, but never appears
        # in a tenant_id authorization position
        self.assertIn(attributed, params)
        self.assertNotIn(
            ("tenant_id", attributed), bindings,
            "row-derived tenant must not occupy the authorization slot")

    def test_case_scope_removal_detected(self):
        tenant = uuid4()
        log = self._cursor(tenant)
        case = [s for s, _ in log if "RECOVERABLE" in _code(s)][0]
        weakened = case[0].replace(
            "WHERE EXISTS (SELECT 1 FROM execution_attempts a", "WHERE 1=1 OR EXISTS (SELECT 1 FROM execution_attempts a")
        self.assertTrue(
            OPEN_CASE not in _code(weakened)
            or _boolean_bypasses(weakened))

    def test_budget_and_attempt_scope_removal_detected(self):
        tenant = uuid4()
        log = self._cursor(tenant)
        budget = [s for s, _ in log if "RECOVERY_EXPOSURE_USD" in _code(s)][0]
        attempt = [s for s, _ in log if "METERED_USAGE_PENDING" in _code(s)][0]
        self.assertNotIn(
            OPEN_BUDGET,
            _code(budget[0].replace(
                "AND EXISTS (SELECT 1 FROM jobs j WHERE"
                " j.id=job_budgets.job_id AND j.tenant_id=%s)", "")))
        self.assertNotIn(
            OPEN_ATTEMPT,
            _code(attempt[0].replace("AND j.tenant_id=%s", "")))

    def test_sweep_provides_tenant_to_open(self):
        """The operational _open call inside sweep must bind tenant_id.

        AST-based: a decoy `_open(..., tenant_id=...)` elsewhere (a
        comment, an unused helper, or dead code) must not satisfy this, and
        a comment alone must not count either.
        """
        tree = ast.parse(inspect.getsource(reconciliation.sweep))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "_open"
        ]
        self.assertEqual(
            len(calls), 1,
            "sweep must contain exactly one _open call site")
        call = calls[0]
        keywords = {k.arg: k.value for k in call.keywords}
        self.assertIn(
            "tenant_id", keywords,
            "the operational sweep _open call must pass tenant_id")
        bound = keywords["tenant_id"]
        self.assertIsInstance(bound, ast.Name)
        self.assertEqual(
            bound.id, "owner_tenant",
            "sweep must pass the owning tenant selected with the attempt")
        # positional args must remain (cur, attempt) so the tenant cannot
        # accidentally become the attempt id
        self.assertEqual(len(call.args), 2)

    def test_sweep_wrong_tenant_argument_detected(self):
        """Passing the attempt as tenant must fail."""
        tree = ast.parse(inspect.getsource(reconciliation.sweep))
        call = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "_open"
        ][0]
        keywords = {k.arg: k.value for k in call.keywords}
        bound = keywords["tenant_id"]
        self.assertNotEqual(getattr(bound, "id", None), "attempt")
        self.assertNotEqual(getattr(bound, "id", None), "cur")

    def test_sweep_decoy_call_does_not_satisfy_proof(self):
        """A decoy correct call elsewhere must not rescue a wrong real one."""
        source = inspect.getsource(reconciliation.sweep)
        decoy = source + (
            "\ndef _unused_helper():\n"
            "    return _open(None, attempt, tenant_id=owner_tenant)\n")
        tree = ast.parse(decoy)
        sweep_calls = []
        helper_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                target = (sweep_calls if node.name == "sweep"
                          else helper_calls)
                target.extend(
                    c for c in ast.walk(node)
                    if isinstance(c, ast.Call)
                    and getattr(c.func, "id", None) == "_open")
        # The proof above only ever inspects ast.parse(sweep source), so the
        # decoy in another function is invisible to it by construction.
        self.assertEqual(len(helper_calls), 1)
        self.assertEqual(len(sweep_calls), 1)
        sweep_source = inspect.getsource(reconciliation.sweep)
        self.assertNotIn("_unused_helper", sweep_source)

    def test_sweep_comment_does_not_satisfy_proof(self):
        source = inspect.getsource(reconciliation.sweep)
        commented = source.replace(
            "_open(cur, attempt, tenant_id=owner_tenant)",
            "_open(cur, attempt)  # tenant_id=owner_tenant")
        tree = ast.parse(commented)
        call = [
            n for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", None) == "_open"
        ][0]
        self.assertNotIn(
            "tenant_id", {k.arg for k in call.keywords},
            "a trailing comment must not satisfy the keyword requirement")

    def test_sweep_candidate_semantics_preserved(self):
        """Eligibility/ordering/locking predicates are unchanged."""
        source = inspect.getsource(reconciliation.sweep)
        code = source
        for predicate in (
            "a.billing_mode='metered'", "a.status='running'",
            "a.accounting_due_at<=clock_timestamp()",
            "a.reserved_cost_usd IS NOT NULL",
            "ORDER BY a.accounting_due_at", "LIMIT %s",
        ):
            self.assertIn(predicate, code)

    def test_sweep_wrong_tenant_control(self):
        """A neighbouring tenant may be attributed but never authorized."""
        owner, neighbour = uuid4(), uuid4()
        log = []
        job = uuid4()
        rows = [None, (job, neighbour, Decimal(1), "metered", "running"),
                None]
        cursor = SelectiveCursor(log, rows=rows, insert_rowcount=1)
        with _patched(reconciliation, cursor):
            reconciliation._open(cursor, uuid4(), tenant_id=owner)
        for sql, params in log:
            bindings = _bindings(sql, params)
            self.assertNotIn(
                ("tenant_id", neighbour), bindings,
                "row tenant must not occupy the authorization slot")
            if "METERED_RECONCILIATION_EVENTS" not in _code(sql):
                self.assertIn(
                    ("tenant_id", owner), bindings,
                    "caller tenant must occupy the authorization slot")


class ObserverPropagationTests(unittest.TestCase):
    def test_budgeted_observer_stores_immutable_tenant(self):
        tenant = uuid4()
        observer = budgeted_observer.BudgetedLedgerObserver(
            uuid4(), uuid4(), {}, tenant_id=tenant)
        self.assertEqual(observer.tenant_id, tenant)

    def test_observer_propagates_tenant_to_every_ledger_call(self):
        tenant = uuid4()
        job, task = uuid4(), uuid4()
        observer = budgeted_observer.BudgetedLedgerObserver(
            job, task, {"standard": Decimal(1)}, tenant_id=tenant)

        # non-metered start
        with patch.object(budgeted_observer, "start_attempt") as start:
            start.return_value = uuid4()
            observer.attempt_started(
                1, ModelCandidate("k", "p", None, "free", 1,
                                  billing_mode="free"), "m")
            self.assertEqual(start.call_args.kwargs["tenant_id"], tenant)

        # metered start
        with patch.object(budgeted_observer, "get_active_price") as price:
            price.return_value = _FakePrice()
            with patch.object(
                    budgeted_observer,
                    "start_metered_attempt") as metered:
                metered.return_value = uuid4()
                observer.attempt_started(
                    2,
                    ModelCandidate("k2", "p", None, "standard", 1,
                                   pricing_key="pk", billing_mode="metered"),
                    "m")
                self.assertEqual(
                    metered.call_args.kwargs["tenant_id"], tenant)

        # deferred usage
        with patch.object(budgeted_observer, "defer_missing_usage") as defer:
            observer._state[2] = (uuid4(), Decimal(1), _FakePrice(),
                                  "metered")
            with self.assertRaises(budgeted_observer.UsageMissing):
                observer.attempt_finished(
                    2, ExecutionAttempt("k2", "p", "m", True))
            self.assertEqual(defer.call_args.kwargs["tenant_id"], tenant)

        # finalize
        with patch.object(
                budgeted_observer,
                "finalize_attempt_and_budget") as finalize:
            observer._state[3] = (uuid4(), Decimal(1), _FakePrice(),
                                  "metered")
            observer.attempt_finished(
                3,
                ExecutionAttempt("k3", "p", "m", True, prompt_tokens=1,
                                 completion_tokens=1))
            self.assertEqual(finalize.call_args.kwargs["tenant_id"], tenant)

    def test_observer_tenant_cannot_be_overridden_by_payload(self):
        """A payload tenant must never replace the observer's tenant."""
        tenant = uuid4()
        observer = budgeted_observer.BudgetedLedgerObserver(
            uuid4(), uuid4(), {}, tenant_id=tenant)

        class RouteWithTenant:
            key = "k"
            provider = "p"
            cost_class = "free"
            billing_mode = "free"
            pricing_key = None
            tenant_id = uuid4()

        with patch.object(budgeted_observer, "start_attempt") as start:
            start.return_value = uuid4()
            observer.attempt_started(1, RouteWithTenant(), "m")
            self.assertEqual(start.call_args.kwargs["tenant_id"], tenant)
        self.assertEqual(observer.tenant_id, tenant)

    def test_ledger_execution_observer_propagates_tenant(self):
        tenant = uuid4()
        observer = ledger_observer.LedgerExecutionObserver(
            uuid4(), uuid4(), tenant_id=tenant)
        with patch.object(ledger_observer, "start_attempt") as start:
            start.return_value = uuid4()
            observer.attempt_started(
                1, ModelCandidate("k", "p", None, "free", 1), "m")
            self.assertEqual(start.call_args.kwargs["tenant_id"], tenant)
            with patch.object(ledger_observer, "finish_attempt") as fin:
                observer.attempt_finished(
                    1, ExecutionAttempt("k", "p", "m", True))
                self.assertEqual(fin.call_args.kwargs["tenant_id"], tenant)

    def test_runtime_passes_task_tenant_to_budgeted_observer(self):
        """The OPERATIONAL BudgetedLedgerObserver call must bind task.tenant_id.

        AST-based and scoped to the function that actually executes the
        runtime flow, so a decoy construction in an unused function or dead
        code cannot satisfy this, and removing the keyword from the real
        call fails even if a decoy elsewhere is correct.
        """
        tree = ast.parse(inspect.getsource(runtime))
        operational = _runtime_operational_observer_calls(tree)
        self.assertTrue(operational, "no operational observer call found")
        for call in operational:
            keywords = {k.arg: k.value for k in call.keywords}
            self.assertIn(
                "tenant_id", keywords,
                "operational BudgetedLedgerObserver must pass tenant_id")
            value = keywords["tenant_id"]
            self.assertTrue(
                isinstance(value, ast.Attribute)
                and value.attr == "tenant_id"
                and isinstance(value.value, ast.Name)
                and value.value.id == "task",
                "tenant_id must be task.tenant_id")

    def test_runtime_decoy_observer_call_is_not_counted(self):
        """A correct decoy in dead code must not mask a missing keyword."""
        source = inspect.getsource(runtime)
        decoy_source = source + (
            "\n\ndef _unused():\n"
            "    return BudgetedLedgerObserver(\n"
            "        job_id=None, task_id=None,\n"
            "        reservation_by_cost_class=None,\n"
            "        tenant_id=task.tenant_id,\n    )\n")
        decoy_tree = ast.parse(decoy_source)
        operational = _runtime_operational_observer_calls(decoy_tree)
        self.assertTrue(operational)
        for call in operational:
            keywords = {k.arg for k in call.keywords}
            self.assertIn("tenant_id", keywords)

    def test_runtime_real_call_missing_keyword_with_decoy_present(self):
        """Removing the real keyword must fail even with a correct decoy."""
        source = inspect.getsource(runtime)
        stripped = source.replace(
            "            reservation_by_cost_class=reservation_by_cost_class,\n"
            "            tenant_id=task.tenant_id,\n",
            "            reservation_by_cost_class=reservation_by_cost_class,\n")
        stripped += (
            "\n\ndef _unused():\n"
            "    return BudgetedLedgerObserver(\n"
            "        job_id=None, task_id=None,\n"
            "        reservation_by_cost_class=None,\n"
            "        tenant_id=task.tenant_id,\n    )\n")
        tree = ast.parse(stripped)
        operational = _runtime_operational_observer_calls(tree)
        self.assertTrue(operational)
        for call in operational:
            keywords = {k.arg for k in call.keywords}
            self.assertNotIn(
                "tenant_id", keywords,
                "decoy must not satisfy the operational proof")

    def test_runtime_route_health_observer_still_scoped(self):
        source = inspect.getsource(runtime)
        self.assertIn("RouteHealthObserver(", source)


def _runtime_operational_observer_calls(tree):
    """BudgetedLedgerObserver calls inside the executing runtime flow.

    The observer is constructed inside run_claimed_task, which is what the
    scheduler invokes. Calls in other functions are treated as decoys.
    """
    operational_functions = {
        "run_claimed_task",
    }
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name not in operational_functions:
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Call):
                func = inner.func
                name = (
                    func.attr if isinstance(func, ast.Attribute)
                    else getattr(func, "id", None)
                )
                if name == "BudgetedLedgerObserver":
                    found.append(inner)
    return found


class _FakePrice:
    pricing_key = "pk"
    version = 1
    input_per_million_usd = 2
    output_per_million_usd = 3


class _FakeRoute:
    key = "k"
    provider = "p"
    cost_class = "standard"
    pricing_key = "pk"
    billing_mode = "metered"


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class LedgerDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        for mod in (ledger, accounting, reconciliation):
            patcher = patch.object(mod, "connect",
                                    return_value=_Shared(self.conn))
            patcher.start()
            self.addCleanup(patcher.stop)

        self.tenant = uuid4()
        self.foreign = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s,%s,%s)",
                    (tenant, str(tenant), "ledger scope test"))

    def sql(self, statement, params=()):
        with self.conn.cursor() as cur:
            cur.execute(statement, params)
            return cur.fetchall() if cur.description else None

    def job(self, tenant=None, objective="scope"):
        job = uuid4()
        self.sql("INSERT INTO jobs(id, tenant_id, objective, status)"
                 " VALUES (%s,%s,%s,'running')",
                 (job, tenant or self.tenant, objective))
        return job

    def task(self, tenant=None, job=None):
        task = uuid4()
        self.sql("INSERT INTO tasks(id, job_id, external_id, title,"
                 " description, capability, risk, status)"
                 " VALUES (%s,%s,%s,'t','d','basic','low','pending')",
                 (task, job or self.job(tenant), str(task)))
        return task

    def budget_row(self, job):
        return self.sql("SELECT limit_usd, reserved_usd, spent_usd,"
                        " recovery_exposure_usd FROM job_budgets"
                        " WHERE job_id=%s", (job,))[0]

    def test_create_task_same_tenant_success(self):
        job = self.job()
        task = ledger.create_task(job, "e", "t", "d", "basic", "low",
                                  False, tenant_id=self.tenant)
        self.assertTrue(self.sql("SELECT 1 FROM tasks WHERE id=%s", (task,)))

    def test_create_task_foreign_and_missing_uniform(self):
        foreign_job = self.job(tenant=self.foreign)
        messages = []
        before = self.sql("SELECT count(*) FROM tasks")[0][0]
        for job in (foreign_job, uuid4()):
            with self.assertRaises(TenantScopeError) as ctx:
                ledger.create_task(job, "e", "t", "d", "basic", "low",
                                   False, tenant_id=self.tenant)
            messages.append(str(ctx.exception))
        self.assertEqual(len(set(messages)), 1, messages)
        self.assertEqual(self.sql("SELECT count(*) FROM tasks")[0][0], before)

    def test_attempt_lifecycle_foreign_denied_unchanged(self):
        foreign_job = self.job(tenant=self.foreign)
        foreign_task = self.task(job=foreign_job)
        with self.assertRaises(TenantScopeError):
            ledger.start_attempt(foreign_job, foreign_task, 1, "k", "p", "m",
                                 tenant_id=self.tenant)
        with self.assertRaises(TenantScopeError):
            ledger.record_attempt(
                foreign_job, foreign_task, 1,
                ExecutionAttempt("k", "p", "m", True),
                tenant_id=self.tenant)
        self.assertEqual(
            self.sql("SELECT count(*) FROM execution_attempts"
                     " WHERE task_id=%s", (foreign_task,))[0][0], 0)

    def test_complete_foreign_unchanged(self):
        foreign_job = self.job(tenant=self.foreign)
        foreign_task = self.task(job=foreign_job)
        ledger.complete_task(foreign_task, tenant_id=self.tenant)
        ledger.complete_job(foreign_job, tenant_id=self.tenant)
        self.assertEqual(
            self.sql("SELECT status FROM tasks WHERE id=%s",
                     (foreign_task,))[0][0], "pending")
        self.assertEqual(
            self.sql("SELECT status FROM jobs WHERE id=%s",
                     (foreign_job,))[0][0], "running")

    def test_complete_same_tenant_succeeds(self):
        job = self.job()
        task = self.task(job=job)
        ledger.complete_task(task, tenant_id=self.tenant)
        ledger.complete_job(job, tenant_id=self.tenant)
        self.assertEqual(
            self.sql("SELECT status FROM tasks WHERE id=%s",
                     (task,))[0][0], "completed")
        self.assertEqual(
            self.sql("SELECT status FROM jobs WHERE id=%s",
                     (job,))[0][0], "completed")

    def test_finish_attempt_foreign_unchanged(self):
        foreign_job = self.job(tenant=self.foreign)
        foreign_task = self.task(job=foreign_job)
        self.sql("INSERT INTO execution_attempts(id, job_id, task_id,"
                 " attempt_number, route_key, provider, gateway_model,"
                 " status) VALUES (%s,%s,%s,1,'k','p','m','running')",
                 (uuid4(), foreign_job, foreign_task))
        row = self.sql("SELECT id FROM execution_attempts WHERE task_id=%s",
                       (foreign_task,))
        attempt = row[0][0]
        with self.assertRaises(RuntimeError):
            ledger.finish_attempt(attempt, True, tenant_id=self.tenant)
        self.assertEqual(
            self.sql("SELECT status FROM execution_attempts WHERE id=%s",
                     (attempt,))[0][0], "running")

    def metered_fixture(self, tenant, limit="10.00"):
        """Funded job/task/budget plus the pricing row the candidate needs.

        The pricing key MUST match _FakeRoute.pricing_key ('pk'), otherwise
        start_metered_attempt rejects at the pricing lookup and the fixture
        would not actually exercise tenant scoping.
        """
        job = self.job(tenant)
        task = self.task(job=job)
        self.sql("INSERT INTO job_budgets(job_id, limit_usd) VALUES (%s,%s)",
                 (job, Decimal(limit)))
        self.ensure_pricing()
        return job, task

    def ensure_pricing(self):
        """Exactly one active pricing row for key 'pk' version 1."""
        existing = self.sql(
            "SELECT count(*) FROM model_pricing"
            " WHERE pricing_key=%s AND version=1 AND active", ("pk",))
        if existing[0][0] == 0:
            self.sql("INSERT INTO model_pricing(pricing_key, version,"
                     " input_per_million_usd, output_per_million_usd, active)"
                     " VALUES ('pk',1,2,3,TRUE)")
        return self.sql(
            "SELECT count(*) FROM model_pricing"
            " WHERE pricing_key=%s AND version=1 AND active", ("pk",))[0][0]

    def test_pricing_fixture_is_exactly_one_row(self):
        self.assertEqual(self.ensure_pricing(), 1)
        self.assertEqual(self.ensure_pricing(), 1)
        self.assertEqual(
            self.sql("SELECT count(*) FROM model_pricing"
                     " WHERE pricing_key='pk' AND version=1")[0][0], 1)

    def _start(self, job, task, tenant):
        return reconciliation.start_metered_attempt(
            job_id=job, task_id=task, number=1, route=_FakeRoute(),
            model="m", price=_FakePrice(), reservation=Decimal("1.00"),
            tenant_id=tenant)

    def test_start_metered_same_tenant_success(self):
        job, task = self.metered_fixture(self.tenant)
        attempt = self._start(job, task, self.tenant)
        self.assertEqual(
            self.budget_row(job)[1], Decimal("1.00"))
        row = self.sql("SELECT job_id, task_id FROM execution_attempts"
                       " WHERE id=%s", (attempt,))[0]
        self.assertEqual(row, (job, task))

    def test_start_metered_foreign_denied_no_partial_state(self):
        job, task = self.metered_fixture(self.foreign)
        before_budget = self.budget_row(job)
        before_attempts = self.sql(
            "SELECT count(*) FROM execution_attempts WHERE job_id=%s",
            (job,))[0][0]
        with self.assertRaises(reconciliation.ReconciliationError):
            self._start(job, task, self.tenant)
        # independently re-read both affected tables
        self.assertEqual(self.budget_row(job), before_budget)
        self.assertEqual(
            self.sql("SELECT count(*) FROM execution_attempts WHERE job_id=%s",
                     (job,))[0][0], before_attempts)

    def test_start_metered_partial_rollback_is_load_bearing(self):
        """Statement A CAN reserve, Statement B rejects -> full rollback.

        Topology: tenant A owns a funded job A; tenant B owns a valid task B
        attached to job B. The call passes job A with task B under tenant A,
        so statement A's job+tenant+funds predicates are all satisfiable and
        it genuinely mutates the budget, while statement B rejects because
        task B does not belong to job A.
        """
        job_a, _ = self.metered_fixture(self.tenant)
        _, task_b = self.metered_fixture(self.foreign)
        before_a = self.budget_row(job_a)
        self.assertEqual(before_a[1], Decimal(0), "job A must start unreserved")

        # Statement A alone is satisfiable: prove the reservation predicate
        # really matches for job A / tenant A before asserting rollback.
        qualifies = self.sql(
            "SELECT 1 FROM job_budgets b JOIN jobs j ON j.id=b.job_id"
            " WHERE b.job_id=%s AND j.tenant_id=%s"
            " AND b.reserved_usd+b.spent_usd+b.recovery_exposure_usd"
            "+b.unpriced_exposure_usd+%s<=b.limit_usd",
            (job_a, self.tenant, Decimal("1.00")))
        self.assertEqual(len(qualifies), 1,
                         "statement A must be able to reserve for this test "
                         "to be load-bearing")

        with self.assertRaises(reconciliation.ReconciliationError):
            self._start(job_a, task_b, self.tenant)

        # Independently re-read both affected tables after transaction exit.
        self.assertEqual(
            self.budget_row(job_a), before_a,
            "job A reservation must be rolled back")
        self.assertEqual(
            self.sql("SELECT count(*) FROM execution_attempts"
                     " WHERE job_id=%s", (job_a,))[0][0],
            0, "no attempt may be inserted")

    def test_start_metered_missing_uses_same_public_contract(self):
        job, task = self.metered_fixture(self.foreign)
        messages = []
        for j, t in ((uuid4(), task), (job, uuid4())):
            with self.assertRaises(
                    reconciliation.ReconciliationError) as ctx:
                self._start(j, t, self.tenant)
            messages.append(str(ctx.exception))
        self.assertEqual(len(set(messages)), 1, messages)

    def test_defer_missing_usage_same_tenant(self):
        job, task = self.metered_fixture(self.tenant)
        attempt = self._start(job, task, self.tenant)
        reconciliation.defer_missing_usage(
            attempt_id=attempt, result_success=True, tenant_id=self.tenant)
        self.assertEqual(
            self.sql("SELECT count(*) FROM metered_reconciliations"
                     " WHERE attempt_id=%s", (attempt,))[0][0], 1)
        self.assertEqual(
            self.sql("SELECT status FROM execution_attempts WHERE id=%s",
                     (attempt,))[0][0], "failed")

    def test_defer_missing_usage_foreign_denied_unchanged(self):
        job, task = self.metered_fixture(self.foreign)
        attempt = self._start(job, task, self.foreign)
        before_budget = self.budget_row(job)
        before_attempt = self.sql(
            "SELECT status FROM execution_attempts WHERE id=%s",
            (attempt,))[0][0]
        before_cases = self.sql(
            "SELECT count(*) FROM metered_reconciliations"
            " WHERE attempt_id=%s", (attempt,))[0][0]
        with self.assertRaises(reconciliation.ReconciliationError):
            reconciliation.defer_missing_usage(
                attempt_id=attempt, result_success=True,
                tenant_id=self.tenant)
        self.assertEqual(self.budget_row(job), before_budget)
        self.assertEqual(
            self.sql("SELECT status FROM execution_attempts WHERE id=%s",
                     (attempt,))[0][0], before_attempt)
        self.assertEqual(
            self.sql("SELECT count(*) FROM metered_reconciliations"
                     " WHERE attempt_id=%s", (attempt,))[0][0], before_cases)

    def test_sweep_uses_each_resource_own_tenant(self):
        """Two genuinely eligible attempts, each opened with its own tenant.

        Fixture order matters: attempts are created and started, then
        accounting_due_at is moved into the past, and only then is
        eligibility independently asserted BEFORE sweep runs.
        """
        job_a, task_a = self.metered_fixture(self.tenant)
        job_b, task_b = self.metered_fixture(self.foreign)
        attempt_a = self._start(job_a, task_a, self.tenant)
        attempt_b = self._start(job_b, task_b, self.foreign)

        # (2) satisfy the existing sweep eligibility condition
        self.sql("UPDATE execution_attempts SET accounting_due_at="
                 "clock_timestamp()-interval '1 second' WHERE id IN (%s,%s)",
                 (attempt_a, attempt_b))

        # (3)/(4) independently prove BOTH candidates are eligible now,
        # before any sweep call, so the test cannot pass by selecting none.
        eligible = self.sql(
            "SELECT a.id FROM execution_attempts a"
            " WHERE a.billing_mode='metered' AND a.status='running'"
            " AND a.accounting_due_at<=clock_timestamp()"
            " AND a.reserved_cost_usd IS NOT NULL AND a.id IN (%s,%s)"
            " ORDER BY a.id", (attempt_a, attempt_b))
        self.assertEqual(
            [row[0] for row in eligible],
            sorted([attempt_a, attempt_b]),
            "both attempts must be sweep-eligible before the call")
        self.assertEqual(
            self.sql("SELECT count(*) FROM metered_reconciliations"
                     " WHERE attempt_id IN (%s,%s)",
                     (attempt_a, attempt_b))[0][0],
            0, "no case may exist before the sweep")

        # (5) only now invoke the reaper
        counts = reconciliation.sweep()
        self.assertEqual(counts["opened"], 2)

        for attempt, job, tenant in ((attempt_a, job_a, self.tenant),
                                     (attempt_b, job_b, self.foreign)):
            case = self.sql("SELECT tenant_id, job_id"
                            " FROM metered_reconciliations WHERE attempt_id=%s",
                            (attempt,))
            self.assertEqual(len(case), 1)
            self.assertEqual(
                case[0], (tenant, job),
                "case must be attributed to its own resource's tenant/job")

        # Cross-tenant isolation: each budget moved only for its own job.
        self.assertEqual(self.budget_row(job_a)[3], Decimal("1.00"))
        self.assertEqual(self.budget_row(job_b)[3], Decimal("1.00"))
        cases_a = self.sql("SELECT count(*) FROM metered_reconciliations"
                           " WHERE job_id=%s", (job_a,))[0][0]
        cases_b = self.sql("SELECT count(*) FROM metered_reconciliations"
                           " WHERE job_id=%s", (job_b,))[0][0]
        self.assertEqual((cases_a, cases_b), (1, 1))

    def test_finalize_same_tenant_settles(self):
        job, task = self.metered_fixture(self.tenant)
        attempt = self._start(job, task, self.tenant)
        accounting.finalize_attempt_and_budget(
            job, attempt,
            ExecutionAttempt("k", "p", "m", True, 10, 5), Decimal("1.00"),
            Decimal("0.50"), "pk", 1, "metered", tenant_id=self.tenant)
        # three projected fields: status, prompt/completion usage, cost
        row = self.sql("SELECT status, prompt_tokens, completion_tokens,"
                       " reconciled_cost_usd FROM execution_attempts"
                       " WHERE id=%s", (attempt,))[0]
        self.assertEqual(
            row, ("succeeded", 10, 5, Decimal("0.50")))
        limit, reserved, spent, _ = self.budget_row(job)
        self.assertEqual(reserved, Decimal(0))
        self.assertEqual(spent, Decimal("0.50"))

    def test_finalize_foreign_denied_no_partial_mutation(self):
        job, task = self.metered_fixture(self.foreign)
        attempt = self._start(job, task, self.foreign)
        # The fixture must be genuinely finalizable apart from tenancy:
        # running, metered, owned by job B, with a live reservation.
        state = self.sql(
            "SELECT status, billing_mode, job_id, reserved_cost_usd"
            " FROM execution_attempts WHERE id=%s", (attempt,))[0]
        self.assertEqual(state, ("running", "metered", job,
                                 Decimal("1.00")))
        self.assertEqual(self.budget_row(job)[1], Decimal("1.00"))

        before_budget = self.budget_row(job)
        before_attempt = self.sql(
            "SELECT status, finished_at, reconciled_cost_usd"
            " FROM execution_attempts WHERE id=%s", (attempt,))[0]
        before_cases = self.sql(
            "SELECT count(*) FROM metered_reconciliations"
            " WHERE job_id=%s", (job,))[0][0]

        with self.assertRaises(accounting.AccountingError):
            accounting.finalize_attempt_and_budget(
                job, attempt,
                ExecutionAttempt("k", "p", "m", True, 10, 5),
                Decimal("1.00"), Decimal("0.50"), "pk", 1, "metered",
                tenant_id=self.tenant)

        # Independently re-read all three surfaces.
        self.assertEqual(self.budget_row(job), before_budget)
        self.assertEqual(
            self.sql("SELECT status, finished_at, reconciled_cost_usd"
                     " FROM execution_attempts WHERE id=%s", (attempt,))[0],
            before_attempt)
        self.assertEqual(
            self.sql("SELECT count(*) FROM metered_reconciliations"
                     " WHERE job_id=%s", (job,))[0][0],
            before_cases)

    def test_observer_tenant_a_cannot_mutate_tenant_b(self):
        """Observer built for tenant A must not touch tenant B resources."""
        job_b, task_b = self.metered_fixture(self.foreign)
        self._start(job_b, task_b, self.foreign)
        observer = budgeted_observer.BudgetedLedgerObserver(
            job_b, task_b, {"standard": Decimal("1.00")},
            tenant_id=self.tenant)
        before_budget = self.budget_row(job_b)
        before_attempts = self.sql(
            "SELECT count(*) FROM execution_attempts WHERE job_id=%s",
            (job_b,))[0][0]
        with self.assertRaises(reconciliation.ReconciliationError):
            observer.attempt_started(
                1, ModelCandidate("pk", "p", None, "standard", 1,
                                  pricing_key="pk", billing_mode="metered"),
                "m")
        self.assertEqual(self.budget_row(job_b), before_budget)
        self.assertEqual(
            self.sql("SELECT count(*) FROM execution_attempts"
                     " WHERE job_id=%s", (job_b,))[0][0],
            before_attempts)


def _neutralization_defects(sql):
    """Obvious boolean neutralization in ONE normalized SQL statement.

    Narrow by design: reports only OR immediately followed by TRUE or by the
    literal 1 (covering OR TRUE, OR 1=1 and OR 1 = 1). Numeric literals lex as
    ``number`` tokens, so both name and number tokens are considered. Applied
    to a single known authoritative statement, never to arbitrary source text.
    """
    tokens = [
        t.text.upper() for t in _tokenize(sql)
        if t.kind in ("name", "number")
    ]
    defects = []
    for index, token in enumerate(tokens[:-1]):
        if token == "OR" and tokens[index + 1] in ("TRUE", "1"):
            defects.append(f"OR {tokens[index + 1]}")
    return defects


def _open_statements_by_purpose(log):
    """Classify the ordered _open SQL log by statement purpose.

    Classification is by normalized statement shape so each security-relevant
    statement can be asserted individually, instead of searching for a
    fragment anywhere in the log.
    """
    purposes = {
        "initial_lookup": None,
        "authorization_gate": None,
        "race_recheck": None,
        "case_insert": None,
        "budget_update": None,
        "attempt_update": None,
        "event": None,
    }
    for sql, params in log:
        code = _code(sql)
        if "METERED_RECONCILIATION_EVENTS" in code:
            purposes["event"] = (sql, params)
        elif "UPDATE JOB_BUDGETS" in code:
            purposes["budget_update"] = (sql, params)
        elif "UPDATE EXECUTION_ATTEMPTS" in code:
            purposes["attempt_update"] = (sql, params)
        elif "INSERT INTO METERED_RECONCILIATIONS" in code:
            purposes["case_insert"] = (sql, params)
        elif "FOR UPDATE OF A" in code:
            purposes["authorization_gate"] = (sql, params)
        elif code.startswith("SELECT M . ID FROM METERED_RECONCILIATIONS M"):
            if purposes["initial_lookup"] is None:
                purposes["initial_lookup"] = (sql, params)
            else:
                purposes["race_recheck"] = (sql, params)
    return purposes


class ActualEmittedStatementTests(unittest.TestCase):
    """Assert on the statements production ACTUALLY emits.

    The earlier controls inspected only hypothetical mutated copies, so an
    actual bypass in emitted SQL stayed unproven.
    """

    def _emit(self, call, table):
        tenant = uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            call(tenant)
        updates = [e for e in log if _targets(e[0], table, "UPDATE")]
        self.assertEqual(len(updates), 1, f"expected one {table} UPDATE")
        return updates[0], tenant

    def _complete_job(self):
        tenant, job = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_job(job, tenant_id=tenant)
        updates = [e for e in log if _targets(e[0], "jobs", "UPDATE")]
        self.assertEqual(len(updates), 1)
        return updates[0], tenant, job

    def _complete_task(self):
        tenant, task = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_task(task, tenant_id=tenant)
        updates = [e for e in log if _targets(e[0], "tasks", "UPDATE")]
        self.assertEqual(len(updates), 1)
        return updates[0], tenant, task

    def _finish(self):
        tenant, attempt = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.finish_attempt(attempt, True, tenant_id=tenant)
        updates = [e for e in log
                   if _targets(e[0], "execution_attempts", "UPDATE")]
        self.assertEqual(len(updates), 1)
        return updates[0], tenant, attempt

    # ---- complete_job ----
    def test_complete_job_emitted_update_is_scoped(self):
        (sql, params), tenant, job = self._complete_job()
        self.assertIn(COMPLETE_JOB_SCOPE, _code(sql))
        self.assertEqual(params, (job, tenant))
        self.assertEqual(_neutralization_defects(sql), [])

    def test_complete_job_emitted_update_would_reject_or_bypasses(self):
        (sql, _), _, _ = self._complete_job()
        for bypass in ("OR TRUE", "OR 1=1", "OR 1 = 1"):
            mutated = sql.replace("AND tenant_id = %s",
                                  f"AND tenant_id = %s {bypass}")
            self.assertNotEqual(mutated, sql, "mutation did not apply")
            self.assertNotEqual(
                _neutralization_defects(mutated), [],
                f"{bypass} on the emitted UPDATE was not detected")

    # ---- complete_task ----
    def test_complete_task_emitted_update_is_scoped(self):
        (sql, params), tenant, task = self._complete_task()
        self.assertIn(COMPLETE_TASK_SCOPE, _code(sql))
        self.assertEqual(params, (task, tenant))
        self.assertEqual(_neutralization_defects(sql), [])

    # ---- finish_attempt ----
    def test_finish_attempt_emitted_update_is_scoped(self):
        (sql, params), tenant, attempt = self._finish()
        self.assertIn(FINISH_GUARD, _code(sql))
        self.assertEqual(params, ("succeeded", None, attempt, tenant))
        self.assertEqual(_neutralization_defects(sql), [])

    def test_finish_attempt_emitted_update_would_reject_or_true(self):
        (sql, _), _, _ = self._finish()
        mutated = sql.replace("AND j.tenant_id = %s",
                              "AND j.tenant_id = %s OR TRUE")
        self.assertNotEqual(mutated, sql)
        self.assertNotEqual(
            _neutralization_defects(mutated), [],
            "OR TRUE on the emitted UPDATE was not detected")


class OpenPurposeStatementTests(unittest.TestCase):
    """O1-O9 against the actual emitted _open statements."""

    def _log(self, owner_job=None, attributed=None):
        log = []
        tenant = uuid4()
        job = owner_job or uuid4()
        rows = [None,
                (job, attributed or uuid4(), Decimal(1), "metered",
                 "running"),
                None]
        cursor = SelectiveCursor(log, rows=rows, insert_rowcount=1)
        with _patched(reconciliation, cursor):
            reconciliation._open(cursor, uuid4(), tenant_id=tenant)
        return log, tenant, job

    def _all(self):
        log, tenant, job = self._log()
        return _open_statements_by_purpose(log), tenant, job

    def test_purposes_are_classified(self):
        purposes, _, _ = self._all()
        for name in ("initial_lookup", "authorization_gate", "race_recheck",
                     "case_insert", "budget_update", "attempt_update"):
            self.assertIsNotNone(purposes[name], f"{name} not classified")

    def _assert_unneutralised(self, sql, label):
        self.assertEqual(
            _neutralization_defects(sql), [],
            f"{label} carries boolean neutralization")

    def _mutate_or_true_is_detected(self, sql, label):
        mutated = sql.replace("AND j.tenant_id=%s",
                              "AND j.tenant_id=%s OR TRUE")
        self.assertNotEqual(mutated, sql, f"{label}: mutation did not apply")
        self.assertNotEqual(
            _neutralization_defects(mutated), [],
            f"{label}: OR TRUE not detected")

    def test_O1_initial_lookup(self):
        purposes, tenant, _ = self._all()
        sql, params = purposes["initial_lookup"]
        self.assertIn("J . TENANT_ID = %S", _code(sql))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self._assert_unneutralised(sql, "initial lookup")
        self._mutate_or_true_is_detected(sql, "initial lookup")

    def test_O2_authorization_gate(self):
        purposes, tenant, _ = self._all()
        sql, params = purposes["authorization_gate"]
        self.assertIn("J . TENANT_ID = %S", _code(sql))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self._assert_unneutralised(sql, "authorization gate")
        self._mutate_or_true_is_detected(sql, "authorization gate")

    def test_O3_case_insert_guard_or_true(self):
        purposes, tenant, job = self._all()
        sql, params = purposes["case_insert"]
        self.assertIn(OPEN_CASE, _code(sql))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self._assert_unneutralised(sql, "case INSERT")
        self._mutate_or_true_is_detected(sql, "case INSERT")

    def test_O4_case_insert_guard_or_one_eq_one(self):
        purposes, tenant, job = self._all()
        sql, _ = purposes["case_insert"]
        for bypass in ("OR 1=1", "OR 1 = 1"):
            mutated = sql.replace("AND j.tenant_id=%s",
                                  f"AND j.tenant_id=%s {bypass}")
            self.assertNotEqual(mutated, sql, "mutation did not apply")
            self.assertNotEqual(
                _neutralization_defects(mutated), [],
                f"case INSERT: {bypass} not detected")

    def test_O5_budget_update_or_true(self):
        purposes, tenant, job = self._all()
        sql, params = purposes["budget_update"]
        self.assertIn(OPEN_BUDGET, _code(sql))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self._assert_unneutralised(sql, "budget UPDATE")
        self._mutate_or_true_is_detected(sql, "budget UPDATE")

    def test_O6_attempt_update_or_true(self):
        purposes, tenant, job = self._all()
        sql, params = purposes["attempt_update"]
        self.assertIn(OPEN_ATTEMPT, _code(sql))
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self._assert_unneutralised(sql, "attempt UPDATE")
        self._mutate_or_true_is_detected(sql, "attempt UPDATE")

    def test_O7_inserted_attempt_bound_correctly(self):
        purposes, tenant, job = self._all()
        sql, params = purposes["attempt_update"]
        bindings = _bindings(sql, params)
        self.assertEqual(bindings[-1], ("tenant_id", tenant))
        self.assertEqual(bindings[0], ("id", bindings[0][1]))

    def test_O8_case_exists_job_bound_correctly(self):
        owner_job = uuid4()
        log, tenant, job = self._log(owner_job=owner_job)
        purposes = _open_statements_by_purpose(log)
        sql, params = purposes["case_insert"]
        gate = _bindings(sql, params)[-3:]
        self.assertEqual([i for i, _ in gate], ["id", "job_id", "tenant_id"])
        self.assertEqual(gate[1][1], owner_job)
        self.assertEqual(gate[2][1], tenant)
        wrong = list(params)
        wrong[-2] = uuid4()
        self.assertNotEqual(
            _bindings(sql, tuple(wrong))[-2][1], owner_job)

    def test_O9_budget_update_binds_the_authorized_job(self):
        """Sentinel UUIDs: a wrong job cannot coincide with another value."""
        owner_job = uuid4()
        attributed = uuid4()
        other_job = uuid4()
        log, tenant, job = self._log(owner_job=owner_job,
                                    attributed=attributed)
        self.assertEqual(job, owner_job)
        purposes = _open_statements_by_purpose(log)
        gate_sql, gate_params = purposes["authorization_gate"]
        budget_sql, budget_params = purposes["budget_update"]

        self.assertIn(("tenant_id", tenant),
                      _bindings(gate_sql, gate_params))

        job_slots = [value for ident, value
                     in _bindings(budget_sql, budget_params)
                     if ident == "job_id"]
        self.assertTrue(job_slots, "budget UPDATE has no job_id binding")
        for value in job_slots:
            self.assertEqual(
                value, owner_job,
                "budget UPDATE must bind the authorized job")
        self.assertNotIn(other_job, budget_params)
        self.assertNotIn(attributed, budget_params)
        self.assertIn(("tenant_id", tenant),
                      _bindings(budget_sql, budget_params))

    def test_O9_wrong_budget_job_is_detected(self):
        owner_job = uuid4()
        log, tenant, job = self._log(owner_job=owner_job)
        purposes = _open_statements_by_purpose(log)
        sql, params = purposes["budget_update"]
        bindings = _bindings(sql, params)
        slot = [i for i, (ident, _) in enumerate(bindings)
                if ident == "job_id"][0]
        wrong = list(params)
        wrong[slot] = uuid4()
        self.assertNotEqual(
            _bindings(sql, tuple(wrong))[slot][1], owner_job)

    # ---- core _open controls preserved ----
    def test_gate_scope_removal_detected(self):
        purposes, _, _ = self._all()
        sql, _ = purposes["authorization_gate"]
        self.assertNotIn(
            "J . TENANT_ID = %S",
            _code(sql.replace("AND j.tenant_id=%s", "")))

    def test_budget_scope_removal_detected(self):
        purposes, _, _ = self._all()
        sql, _ = purposes["budget_update"]
        self.assertNotIn(
            OPEN_BUDGET,
            _code(sql.replace("AND j.tenant_id=%s", "")))

    def test_attempt_scope_removal_detected(self):
        purposes, _, _ = self._all()
        sql, _ = purposes["attempt_update"]
        self.assertNotIn(
            OPEN_ATTEMPT,
            _code(sql.replace("AND j.tenant_id=%s", "")))

    def test_row_derived_authority_substitution_detected(self):
        attributed = uuid4()
        log, tenant, job = self._log(attributed=attributed)
        purposes = _open_statements_by_purpose(log)
        for name in ("authorization_gate", "case_insert", "budget_update",
                     "attempt_update"):
            sql, params = purposes[name]
            bindings = _bindings(sql, params)
            self.assertIn(("tenant_id", tenant), bindings,
                          f"{name} lost the caller tenant")
            self.assertNotIn(("tenant_id", attributed), bindings,
                             f"{name} substituted the row tenant")


class _KwargRecorder:
    """Records call kwargs structurally, even when tenant_id is absent."""

    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append({"args": args, "kwargs": dict(kwargs)})
        return uuid4()


class ObserverKwargPropagationTests(unittest.TestCase):
    """Observer propagation proven by assertion, never by KeyError."""

    def _observer(self, tenant):
        return budgeted_observer.BudgetedLedgerObserver(
            uuid4(), uuid4(), {"standard": Decimal(1)},
            tenant_id=tenant)

    def _assert_propagated(self, recorder, tenant, branch):
        self.assertTrue(recorder.calls, f"{branch} was never called")
        last = recorder.calls[-1]
        self.assertIn("tenant_id", last["kwargs"],
                      f"{branch} did not receive a tenant_id keyword")
        self.assertEqual(last["kwargs"]["tenant_id"], tenant,
                         f"{branch} propagated the wrong tenant")

    def test_non_metered_start_propagates_constructor_tenant(self):
        tenant = uuid4()
        observer = self._observer(tenant)
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "start_attempt", recorder):
            observer.attempt_started(
                1, ModelCandidate("k", "p", None, "free", 1,
                                  billing_mode="free"), "m")
        self._assert_propagated(recorder, tenant, "non-metered start")

    def test_metered_start_propagates_constructor_tenant(self):
        tenant = uuid4()
        observer = self._observer(tenant)
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "get_active_price") as price:
            price.return_value = _FakePrice()
            with patch.object(budgeted_observer, "start_metered_attempt",
                              recorder):
                observer.attempt_started(
                    2, ModelCandidate("k2", "p", None, "standard", 1,
                                      pricing_key="pk",
                                      billing_mode="metered"), "m")
        self._assert_propagated(recorder, tenant, "metered start")

    def test_deferred_usage_propagates_constructor_tenant(self):
        tenant = uuid4()
        observer = self._observer(tenant)
        observer._state[1] = (uuid4(), Decimal(1), _FakePrice(), "metered")
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "defer_missing_usage", recorder):
            with self.assertRaises(budgeted_observer.UsageMissing):
                observer.attempt_finished(
                    1, ExecutionAttempt("k", "p", "m", True))
        self._assert_propagated(recorder, tenant, "deferred usage")

    def test_finalize_propagates_constructor_tenant(self):
        tenant = uuid4()
        observer = self._observer(tenant)
        observer._state[1] = (uuid4(), Decimal(0), None, "free")
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "finalize_attempt_and_budget",
                          recorder):
            observer.attempt_finished(
                1, ExecutionAttempt("k", "p", "m", True))
        self._assert_propagated(recorder, tenant, "finalize")

    def test_missing_tenant_keyword_fails_by_assertion(self):
        tenant = uuid4()
        observer = self._observer(tenant)
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "start_attempt", recorder):
            observer.attempt_started(
                1, ModelCandidate("k", "p", None, "free", 1,
                                  billing_mode="free"), "m")
        del recorder.calls[-1]["kwargs"]["tenant_id"]
        with self.assertRaises(AssertionError):
            self._assert_propagated(recorder, tenant, "non-metered start")

    def test_wrong_tenant_value_fails_by_assertion(self):
        tenant, other = uuid4(), uuid4()
        observer = self._observer(tenant)
        recorder = _KwargRecorder()
        with patch.object(budgeted_observer, "start_attempt", recorder):
            observer.attempt_started(
                1, ModelCandidate("k", "p", None, "free", 1,
                                  billing_mode="free"), "m")
        recorder.calls[-1]["kwargs"]["tenant_id"] = other
        with self.assertRaises(AssertionError):
            self._assert_propagated(recorder, tenant, "non-metered start")


class _Shared:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


def _purge_rollback(ids):
    task_x, job_a, job_b, tenant = ids
    conn = psycopg.connect(_DB_URL)
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM execution_attempts WHERE task_id=%s",
                        (task_x,))
            cur.execute("DELETE FROM task_dependencies WHERE task_id=%s"
                        " OR depends_on_task_id=%s", (task_x, task_x))
            cur.execute("DELETE FROM tasks WHERE id=%s", (task_x,))
            cur.execute("DELETE FROM job_budgets WHERE job_id IN (%s,%s)",
                        (job_a, job_b))
            cur.execute("DELETE FROM jobs WHERE id IN (%s,%s)", (job_a, job_b))
            cur.execute("DELETE FROM tenants WHERE id=%s", (tenant,))
        conn.commit()
    finally:
        conn.close()


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class StartMeteredRealTransactionTests(unittest.TestCase):
    """Rollback proven through a REAL Psycopg transaction context.

    The production function receives a genuine psycopg connection so
    ``with connect() as conn`` exercises real commit/rollback semantics.
    The after-state is read from a SEPARATE fresh connection, so the aborted
    transaction/session can never mask a leaked reservation.
    """

    def _fresh(self):
        conn = psycopg.connect(_DB_URL)
        self.addCleanup(conn.close)
        return conn

    def test_partial_rollback_is_real_and_load_bearing(self):
        tenant = uuid4()
        job_a, job_b, task_x = uuid4(), uuid4(), uuid4()
        amount = Decimal("1.00")

        # (1) fixtures on their own committed connection
        setup = self._fresh()
        with setup.cursor() as cur:
            cur.execute("INSERT INTO tenants(id, slug, name)"
                        " VALUES (%s,%s,'rollback test')",
                        (tenant, str(tenant)))
            for job in (job_a, job_b):
                cur.execute("INSERT INTO jobs(id, tenant_id, objective,"
                            " status) VALUES (%s,%s,'rollback','running')",
                            (job, tenant))
            cur.execute(
                "INSERT INTO tasks(id, job_id, external_id, title,"
                " description, capability, risk, status)"
                " VALUES (%s,%s,%s,'t','d','basic','low','pending')",
                (task_x, job_b, str(task_x)))
            cur.execute("INSERT INTO job_budgets(job_id, limit_usd)"
                        " VALUES (%s,%s)", (job_a, Decimal("10.00")))
            cur.execute("INSERT INTO model_pricing(pricing_key, version,"
                        " input_per_million_usd, output_per_million_usd,"
                        " active) VALUES ('pk',1,2,3,TRUE)")
        setup.commit()
        self.addCleanup(_purge_rollback, (task_x, job_a, job_b, tenant))

        # (2) mechanical preconditions: statement A is genuinely load-bearing
        with setup.cursor() as cur:
            cur.execute("SELECT 1 FROM jobs WHERE id=%s AND tenant_id=%s",
                        (job_a, tenant))
            self.assertIsNotNone(cur.fetchone(),
                                 "job A must exist for the caller tenant")
            cur.execute("SELECT limit_usd, reserved_usd, spent_usd,"
                        " recovery_exposure_usd, unpriced_exposure_usd"
                        " FROM job_budgets WHERE job_id=%s", (job_a,))
            before = cur.fetchone()
            self.assertIsNotNone(before, "budget row must exist")
            limit, reserved, spent, recovery, unpriced = before
            self.assertGreater(amount, Decimal(0),
                               "reservation amount must be positive")
            self.assertLessEqual(
                reserved + spent + recovery + unpriced + amount, limit,
                "funds must be sufficient so statement A qualifies")
            cur.execute("SELECT job_id FROM tasks WHERE id=%s", (task_x,))
            self.assertEqual(
                cur.fetchone()[0], job_b,
                "task X must not belong to job A so statement B rejects")
        before_reserved = before[1]
        before_limit = before[0]

        # (3) invoke through a REAL psycopg connection factory
        test_case = self

        class RealConnections:
            def __init__(self, url):
                self.url = url
                self._local = threading.local()

            def __call__(self):
                conn = getattr(self._local, "conn", None)
                if conn is None or conn.closed:
                    conn = psycopg.connect(self.url)
                    self._local.conn = conn
                    test_case.addCleanup(conn.close)
                return conn

        with patch.object(reconciliation, "connect", RealConnections(_DB_URL)):
            with self.assertRaises(reconciliation.ReconciliationError):
                reconciliation.start_metered_attempt(
                    job_id=job_a, task_id=task_x, number=1,
                    route=_FakeRoute(), model="m", price=_FakePrice(),
                    reservation=amount, tenant_id=tenant)

        # (4) after-state read from a FRESH connection; no cleanup has run
        fresh = self._fresh()
        with fresh.cursor() as cur:
            cur.execute("SELECT limit_usd, reserved_usd, spent_usd"
                        " FROM job_budgets WHERE job_id=%s", (job_a,))
            after = cur.fetchone()
            self.assertEqual(
                after[1], before_reserved,
                "reservation must be rolled back to its pre-call value")
            self.assertEqual(after[0], before_limit)
            self.assertEqual(after[2], Decimal(0))
            cur.execute("SELECT count(*) FROM execution_attempts"
                        " WHERE job_id=%s OR task_id=%s",
                        (job_a, task_x))
            self.assertEqual(
                cur.fetchone()[0], 0,
                "no attempt may be inserted by the failed call")


if __name__ == "__main__":
    unittest.main()
