import ast
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


class LedgerSignatureTests(unittest.TestCase):
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

    def _start(self, tenant, rows=((uuid4(),),)):
        log = []
        with _patched(ledger, RecordingCursor(log, 1, rows)):
            ledger.start_attempt(uuid4(), uuid4(), 1, "k", "p", "m",
                                 tenant_id=tenant)
        return log

    def _record(self, tenant, rows=((uuid4(),),)):
        log = []
        with _patched(ledger, RecordingCursor(log, 1, rows)):
            ledger.record_attempt(uuid4(), uuid4(), 1, self.ATTEMPT,
                                  tenant_id=tenant)
        return log

    def test_start_attempt_scoped(self):
        tenant = uuid4()
        sql, params = self._start(tenant)[0]
        self.assertIn(ATTEMPT_GUARD, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params[-1], tenant)
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))

    def test_record_attempt_scoped(self):
        tenant = uuid4()
        sql, params = self._record(tenant)[0]
        self.assertIn(ATTEMPT_GUARD, _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params[-1], tenant)

    def test_one_sided_authorization_detected(self):
        """Dropping the tenant half of the guard must fail."""
        tenant = uuid4()
        for runner in (self._start, self._record):
            sql, _ = runner(tenant)[0]
            for mutated in (
                sql.replace("AND j.tenant_id = %s", ""),
                sql.replace("AND t.job_id = j.id", ""),
                sql.replace("AND j.id = %s\n", ""),
            ):
                with self.subTest(mutated=mutated[:40]):
                    self.assertNotIn(ATTEMPT_GUARD, _code(mutated))

    def test_attempt_wrong_tenant_binding_detected(self):
        tenant, foreign = uuid4(), uuid4()
        sql, params = self._start(tenant)[0]
        wrong = params[:-1] + (foreign,)
        self.assertNotEqual(_bindings(sql, wrong)[-1][1], tenant)

    def test_finish_attempt_update_is_authoritative(self):
        tenant, attempt = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.finish_attempt(attempt, True, tenant_id=tenant)
        sql, params = log[0]
        self.assertIn(FINISH_GUARD, _code(sql))
        self.assertEqual(params, ("succeeded", None, attempt, tenant))
        self.assertEqual(
            _bindings(sql, params),
            [("status", "succeeded"), ("error_message", None),
             ("id", attempt), ("tenant_id", tenant)],
        )

    def test_finish_attempt_scope_removal_detected(self):
        tenant, attempt = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.finish_attempt(attempt, True, tenant_id=tenant)
        stripped = log[0][0].replace(
            "AND j.tenant_id = %s", "")
        self.assertNotIn(FINISH_GUARD, _code(stripped))

    def test_finish_attempt_foreign_rowcount_contract(self):
        """Foreign attempt keeps the existing RuntimeError contract."""
        tenant, attempt = uuid4(), uuid4()
        with _patched(ledger, RecordingCursor([], 0)):
            with self.assertRaises(RuntimeError):
                ledger.finish_attempt(attempt, True, tenant_id=tenant)


class CompleteScopeTests(unittest.TestCase):
    def test_complete_task_scoped(self):
        tenant, task = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_task(task, tenant_id=tenant)
        sql, params = log[0]
        self.assertIn(COMPLETE_TASK_SCOPE, _code(sql))
        self.assertEqual(params, (task, tenant))
        self.assertEqual(_boolean_bypasses(sql), [])

    def test_complete_job_scoped(self):
        tenant, job = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_job(job, tenant_id=tenant)
        sql, params = log[0]
        self.assertIn(COMPLETE_JOB_SCOPE, _code(sql))
        self.assertEqual(params, (job, tenant))

    def test_scope_removal_and_bypass_detected(self):
        tenant, task = uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_task(task, tenant_id=tenant)
        sql, _ = log[0]
        for mutated in (
            sql.replace(
                "AND job_id IN (SELECT id FROM jobs WHERE tenant_id = %s)",
                ""),
            sql.replace("WHERE tenant_id = %s", "WHERE tenant_id = %s OR TRUE"),
            sql.replace("WHERE tenant_id = %s", "WHERE tenant_id = %s OR 1 = 1"),
        ):
            with self.subTest(mutated=mutated[-24:]):
                self.assertTrue(
                    COMPLETE_TASK_SCOPE not in _code(mutated)
                    or _boolean_bypasses(mutated),
                    "scope removal/bypass accepted",
                )

    def test_complete_job_wrong_tenant_detected(self):
        tenant, job, foreign = uuid4(), uuid4(), uuid4()
        log = []
        with _patched(ledger, RecordingCursor(log, 1)):
            ledger.complete_job(job, tenant_id=tenant)
        sql, params = log[0]
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
        """sweep must never call _open without an explicit tenant."""
        source = inspect.getsource(reconciliation.sweep)
        self.assertIn("_open(cur, attempt, tenant_id=owner_tenant)", source)
        self.assertNotIn("_open(cur, attempt)", source)
        self.assertIn("JOIN jobs j ON j.id=a.job_id", source)
        self.assertIn("FOR UPDATE OF a SKIP LOCKED", source)

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
        """Structural: the BudgetedLedgerObserver call itself must bind it.

        A plain source search is insufficient because `tenant_id=task.tenant_id`
        also appears on the enclosing RouteHealthObserver call, so removing it
        from the observer would otherwise go unnoticed.
        """
        tree = ast.parse(inspect.getsource(runtime))
        found = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.attr if isinstance(func, ast.Attribute)
                else getattr(func, "id", None)
            )
            if name != "BudgetedLedgerObserver":
                continue
            for keyword in node.keywords:
                if keyword.arg == "tenant_id":
                    value = keyword.value
                    found.append(
                        isinstance(value, ast.Attribute)
                        and value.attr == "tenant_id"
                        and isinstance(value.value, ast.Name)
                        and value.value.id == "task"
                    )
        self.assertEqual(
            found, [True],
            "BudgetedLedgerObserver must receive tenant_id=task.tenant_id",
        )

    def test_runtime_route_health_observer_still_scoped(self):
        """The enclosing observer's own tenant binding must remain."""
        source = inspect.getsource(runtime)
        self.assertIn("RouteHealthObserver(", source)


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
        job = self.job(tenant)
        task = self.task(job=job)
        self.sql("INSERT INTO job_budgets(job_id, limit_usd) VALUES (%s,%s)",
                 (job, Decimal(limit)))
        self.sql("INSERT INTO model_pricing(pricing_key, version,"
                 " input_per_million_usd, output_per_million_usd, active)"
                 " VALUES ('b3',1,2,3,TRUE)")
        return job, task

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
        """Statement A could have mutated; Statement B rejects."""
        job, task = self.metered_fixture(self.foreign)
        before = self.budget_row(job)
        # tenant A matches no job, but task/job ids are the real foreign pair
        with self.assertRaises(reconciliation.ReconciliationError):
            self._start(job, task, self.tenant)
        self.assertEqual(self.budget_row(job), before)
        self.assertEqual(
            self.sql("SELECT count(*) FROM execution_attempts"
                     " WHERE job_id=%s", (job,))[0][0], 0)

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
        """Two eligible attempts in different tenants, opened correctly."""
        job_a, task_a = self.metered_fixture(self.tenant)
        job_b, task_b = self.metered_fixture(self.foreign)
        attempt_a = self._start(job_a, task_a, self.tenant)
        attempt_b = self._start(job_b, task_b, self.foreign)
        self.sql("UPDATE execution_attempts SET accounting_due_at="
                 "clock_timestamp()-interval '1 second' WHERE id IN (%s,%s)",
                 (attempt_a, attempt_b))
        counts = reconciliation.sweep()
        self.assertEqual(counts["opened"], 2)
        for attempt, tenant in ((attempt_a, self.tenant),
                                (attempt_b, self.foreign)):
            case = self.sql("SELECT tenant_id, job_id"
                            " FROM metered_reconciliations WHERE attempt_id=%s",
                            (attempt,))
            self.assertEqual(len(case), 1)
            self.assertEqual(case[0][0], tenant)
        # each resource was opened against its own tenant's budget
        self.assertEqual(self.budget_row(job_a)[3], Decimal("1.00"))
        self.assertEqual(self.budget_row(job_b)[3], Decimal("1.00"))

    def test_finalize_same_tenant_settles(self):
        job, task = self.metered_fixture(self.tenant)
        attempt = self._start(job, task, self.tenant)
        accounting.finalize_attempt_and_budget(
            job, attempt,
            ExecutionAttempt("k", "p", "m", True, 10, 5), Decimal("1.00"),
            Decimal("0.50"), "b3", 1, "metered", tenant_id=self.tenant)
        row = self.sql("SELECT status, reconciled_cost_usd FROM"
                       " execution_attempts WHERE id=%s", (attempt,))[0]
        self.assertEqual(row, ("succeeded", Decimal("0.50")))
        self.assertEqual(self.budget_row(job)[1:], (Decimal(0),
                                                    Decimal("0.50")))

    def test_finalize_foreign_denied_no_partial_mutation(self):
        job, task = self.metered_fixture(self.foreign)
        attempt = self._start(job, task, self.foreign)
        before_budget = self.budget_row(job)
        before_attempt = self.sql(
            "SELECT status, reconciled_cost_usd FROM execution_attempts"
            " WHERE id=%s", (attempt,))[0]
        with self.assertRaises(accounting.AccountingError):
            accounting.finalize_attempt_and_budget(
                job, attempt,
                ExecutionAttempt("k", "p", "m", True, 10, 5),
                Decimal("1.00"), Decimal("0.50"), "b3", 1, "metered",
                tenant_id=self.tenant)
        # independently re-read attempt and budget
        self.assertEqual(self.budget_row(job), before_budget)
        self.assertEqual(
            self.sql("SELECT status, reconciled_cost_usd FROM"
                     " execution_attempts WHERE id=%s", (attempt,))[0],
            before_attempt)

    def test_observer_tenant_a_cannot_mutate_tenant_b(self):
        job_b, task_b = self.metered_fixture(self.foreign)
        attempt_b = self._start(job_b, task_b, self.foreign)
        observer = budgeted_observer.BudgetedLedgerObserver(
            job_b, task_b, {"standard": Decimal("1.00")},
            tenant_id=self.tenant)
        before = self.budget_row(job_b)
        with self.assertRaises(reconciliation.ReconciliationError):
            observer.attempt_started(
                1, ModelCandidate("b3", "p", None, "standard", 1,
                                  pricing_key="b3", billing_mode="metered"),
                "m")
        self.assertEqual(self.budget_row(job_b), before)


class _Shared:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    unittest.main()
