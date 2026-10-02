"""F-02 budget tenant-scope coverage.

Two layers, following the accepted Group-A pattern:

* Structural tests that need no database. They execute the real budget
  functions against a recording fake connection, so assertions concern the
  SQL actually issued and the parameters actually bound -- never source text.
  Assertions read tokenized SQL, so a predicate that survives only inside a
  comment cannot satisfy them.
* PostgreSQL integration tests gated on DEVAI_TEST_DATABASE_URL, which skip
  honestly when it is absent. A skip is never reported as a pass.
"""
import inspect
import os
import unittest
from decimal import Decimal
from unittest.mock import MagicMock, patch
from uuid import uuid4

import psycopg

from devai import budget
from devai.tenancy import JOB_SCOPE
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

OPERATIONS = (
    ("configure_budget", ("job", Decimal("1")), {}),
    ("reserve_budget", ("job", Decimal("1")), {}),
    ("release_budget", ("job", Decimal("1")), {}),
    ("settle_budget", ("job", Decimal("1"), Decimal("1")), {}),
    ("get_budget", ("job",), {}),
)


class RecordingCursor:
    def __init__(self, log, rowcount=1, row=None):
        self._log = log
        self.rowcount = rowcount
        self._row = row

    def execute(self, sql, params=()):
        self._log.append((sql, tuple(params or ())))

    def fetchone(self):
        return self._row

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class RecordingConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


def _record(func, *args, rowcount=1, row=None, **kwargs):
    """Run a budget function against a recording fake; return statements."""
    log = []
    conn = RecordingConnection(RecordingCursor(log, rowcount, row))
    with patch.object(budget, "connect", return_value=conn):
        func(*args, **kwargs)
    return log


def _code(sql):
    """Canonical token form, case-folded for stable comparison.

    Comments and literal payloads cannot appear here, so a predicate that
    exists only inside a comment can never satisfy an assertion.
    """
    return canonical(_tokenize(sql)).upper()


def _ident(tok):
    return tok.text.replace('""', '"').strip('"').lower().split(".")[-1]


def _bindings(sql, params):
    """Pair each executed placeholder with the value actually bound to it."""
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


JOB_SCOPE_CODE = _code(f"SELECT 1 FROM job_budgets WHERE {JOB_SCOPE}")


class BudgetSignatureTests(unittest.TestCase):
    """All five operations require a keyword-only tenant_id."""

    def test_every_operation_requires_keyword_only_tenant_id(self):
        for name, _, _ in OPERATIONS:
            with self.subTest(function=name):
                params = inspect.signature(getattr(budget, name)).parameters
                self.assertIn("tenant_id", params)
                tenant = params["tenant_id"]
                self.assertEqual(tenant.kind, inspect.Parameter.KEYWORD_ONLY)
                self.assertIs(
                    tenant.default, inspect.Parameter.empty
                )

    def test_tenant_id_has_no_default_or_none_bypass(self):
        for name, _, _ in OPERATIONS:
            with self.subTest(function=name):
                params = inspect.signature(getattr(budget, name)).parameters
                self.assertIs(
                    params["tenant_id"].default, inspect.Parameter.empty
                )

    def test_omitting_tenant_id_is_a_type_error(self):
        for name, args, _ in OPERATIONS:
            with self.subTest(function=name):
                with self.assertRaises(TypeError):
                    getattr(budget, name)(*args)

    def test_positional_tenant_id_is_rejected(self):
        """tenant_id must be keyword-only, not positionally bindable."""
        for name, _, _ in OPERATIONS:
            with self.subTest(function=name):
                params = inspect.signature(getattr(budget, name)).parameters
                self.assertEqual(
                    params["tenant_id"].kind,
                    inspect.Parameter.KEYWORD_ONLY,
                )
                positional = [
                    p.name
                    for p in params.values()
                    if p.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
                ]
                self.assertNotIn("tenant_id", positional)

    def test_no_operation_imports_a_principal(self):
        """F-02 keeps budget free of principal/TenantPrincipal coupling."""
        source = inspect.getsource(budget)
        self.assertNotIn("TenantPrincipal", source)
        self.assertNotIn("from .principal", source)


class BudgetSqlScopeTests(unittest.TestCase):
    """Executed SQL must carry the tenant scope, with the right bound value."""

    def test_configure_scope_is_atomic_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = _record(
            budget.configure_budget,
            job,
            Decimal("1"),
            tenant_id=tenant,
        )[0]
        code = _code(sql)
        self.assertIn("SELECT ID , %S FROM JOBS", code)
        self.assertIn("TENANT_ID = %S", code)
        self.assertIn("ON CONFLICT ( JOB_ID ) DO UPDATE SET", code)
        self.assertEqual(_boolean_bypasses(sql), [])
        # the tenant value must be bound to the tenant predicate
        self.assertIn(("tenant_id", tenant), _bindings(sql, params))
        self.assertEqual(params, (Decimal("1"), job, tenant))
        self.assertEqual(
            _bindings(sql, params),
            [("id", Decimal("1")), ("id", job), ("tenant_id", tenant)],
        )

    def test_get_scope_is_atomic_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = _record(
            budget.get_budget,
            job,
            tenant_id=tenant,
            row=(Decimal("1"), Decimal("0"), Decimal("0")),
        )[0]
        self.assertIn("JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )", _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params, (job, tenant))

    def test_reserve_scope_is_atomic_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = _record(
            budget.reserve_budget,
            job,
            Decimal("1"),
            tenant_id=tenant,
            row=(job,),
        )[0]
        code = _code(sql)
        self.assertIn("JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )", code)
        self.assertIn("RETURNING JOB_ID", code)
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params, (Decimal("1"), job, tenant, Decimal("1")))

    def test_reserve_fallback_is_tenant_scoped(self):
        """The exceeded/not-configured probe must also be tenant scoped."""
        tenant, job = uuid4(), uuid4()
        log = []
        conn = RecordingConnection(RecordingCursor(log, rowcount=0, row=None))
        with patch.object(budget, "connect", return_value=conn):
            with self.assertRaises(budget.BudgetNotConfigured):
                budget.reserve_budget(job, Decimal("1"), tenant_id=tenant)
        self.assertEqual(len(log), 2, "expected mutation then fallback probe")
        fallback_sql, fallback_params = log[1]
        self.assertIn(
            "JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )",
            _code(fallback_sql),
        )
        self.assertEqual(fallback_params, (job, tenant))

    def test_release_scope_is_atomic_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = _record(
            budget.release_budget, job, Decimal("1"), tenant_id=tenant
        )[0]
        self.assertIn("JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )", _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(params, (Decimal("1"), job, Decimal("1"), tenant))

    def test_settle_scope_is_atomic_and_bound(self):
        tenant, job = uuid4(), uuid4()
        sql, params = _record(
            budget.settle_budget,
            job,
            Decimal("1"),
            Decimal("1"),
            tenant_id=tenant,
        )[0]
        self.assertIn("JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )", _code(sql))
        self.assertEqual(_boolean_bypasses(sql), [])
        self.assertEqual(
            params,
            (Decimal("1"), Decimal("1"), job, Decimal("1"), tenant),
        )

    def test_every_statement_carries_the_scope_fragment(self):
        tenant, job = uuid4(), uuid4()
        executed = []
        executed += _record(budget.configure_budget, job, Decimal("1"), tenant_id=tenant)
        executed += _record(budget.get_budget, job, tenant_id=tenant, row=(Decimal("1"), Decimal("0"), Decimal("0")))
        executed += _record(budget.reserve_budget, job, Decimal("1"), tenant_id=tenant, row=(job,))
        executed += _record(budget.release_budget, job, Decimal("1"), tenant_id=tenant)
        executed += _record(budget.settle_budget, job, Decimal("1"), Decimal("1"), tenant_id=tenant)
        for sql, params in executed:
            with self.subTest(sql=sql[:48]):
                code = _code(sql)
                self.assertTrue(
                    "TENANT_ID = %S" in code,
                    "statement is not tenant scoped",
                )
                self.assertIn(tenant, params)
                self.assertEqual(_boolean_bypasses(sql), [])

    def test_comment_only_scope_cannot_satisfy_assertions(self):
        tenant, job = uuid4(), uuid4()
        sql, _ = _record(
            budget.get_budget,
            job,
            tenant_id=tenant,
            row=(Decimal("1"), Decimal("0"), Decimal("0")),
        )[0]
        self.assertIn(
            "JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )",
            _code(sql),
        )
        mutated = sql.replace(
            f"AND {JOB_SCOPE}", "AND 1 = 1 /* AND jobs.tenant_id = %s */"
        )
        self.assertNotEqual(mutated, sql, "mutation did not apply")
        self.assertNotIn(
            "JOB_ID IN ( SELECT ID FROM JOBS WHERE TENANT_ID = %S )",
            _code(mutated),
        )

    def test_boolean_bypass_variants_are_rejected(self):
        tenant, job = uuid4(), uuid4()
        sql, _ = _record(
            budget.get_budget,
            job,
            tenant_id=tenant,
            row=(Decimal("1"), Decimal("0"), Decimal("0")),
        )[0]
        for bypass in (f"AND {JOB_SCOPE} OR TRUE", f"AND {JOB_SCOPE} OR 1 = 1"):
            mutated = sql.replace(f"AND {JOB_SCOPE}", bypass)
            self.assertNotEqual(mutated, sql, "bypass not applied")
            self.assertNotEqual(
                _boolean_bypasses(mutated), [], f"not rejected: {bypass}"
            )

    def test_wrong_tenant_value_would_be_detected(self):
        tenant, job, foreign = uuid4(), uuid4(), uuid4()
        sql, params = _record(
            budget.get_budget,
            job,
            tenant_id=tenant,
            row=(Decimal("1"), Decimal("0"), Decimal("0")),
        )[0]
        wrong = (job, foreign)
        self.assertNotEqual(_bindings(sql, wrong)[1][1], tenant)
        self.assertEqual(_bindings(sql, params)[1][1], tenant)

    def test_zero_row_mutations_raise_uniform_error(self):
        tenant, job = uuid4(), uuid4()
        with self.assertRaises(budget.BudgetNotConfigured):
            _record(budget.configure_budget, job, Decimal("1"), tenant_id=tenant,
                    rowcount=0)


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class BudgetTenantScopeDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        self._patch = patch.object(
            budget, "connect", return_value=_Shared(self.conn)
        )
        self._patch.start()
        self.addCleanup(self._patch.stop)

        self.tenant = uuid4()
        self.foreign = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s, %s, %s)",
                    (tenant, str(tenant), "budget scope test"),
                )

    def job(self, tenant=None):
        job = uuid4()
        with self.conn.cursor() as cur:
            cur.execute(
                "INSERT INTO jobs(id, tenant_id, objective, status)"
                " VALUES (%s, %s, 'budget scope', 'running')",
                (job, tenant or self.tenant),
            )
        return job

    def budget_row(self, job):
        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT limit_usd, reserved_usd, spent_usd FROM job_budgets"
                " WHERE job_id = %s",
                (job,),
            )
            return cur.fetchone()

    def count_budgets(self):
        with self.conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM job_budgets")
            return cur.fetchone()[0]

    def test_configure_same_tenant_succeeds(self):
        job = self.job()
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)
        self.assertEqual(self.budget_row(job)[0], Decimal("1.00"))

    def test_configure_foreign_denied_and_no_row(self):
        job = self.job(tenant=self.foreign)
        before = self.count_budgets()
        with self.assertRaises(budget.BudgetNotConfigured):
            budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)
        self.assertEqual(self.count_budgets(), before)

    def test_configure_missing_job_denied_and_no_row(self):
        before = self.count_budgets()
        with self.assertRaises(budget.BudgetNotConfigured):
            budget.configure_budget(uuid4(), Decimal("1.00"), tenant_id=self.tenant)
        self.assertEqual(self.count_budgets(), before)

    def test_get_same_tenant_succeeds(self):
        job = self.job()
        budget.configure_budget(job, Decimal("2.00"), tenant_id=self.tenant)
        self.assertEqual(
            budget.get_budget(job, tenant_id=self.tenant)[0], Decimal("2.00")
        )

    def test_get_foreign_matches_missing_behaviour(self):
        foreign_job = self.job(tenant=self.foreign)
        budget.configure_budget(foreign_job, Decimal("2.00"), tenant_id=self.foreign)
        missing = uuid4()
        messages = {}
        for label, job in (("foreign", foreign_job), ("missing", missing)):
            with self.assertRaises(budget.BudgetNotConfigured) as ctx:
                budget.get_budget(job, tenant_id=self.tenant)
            messages[label] = str(ctx.exception)
        self.assertEqual(
            messages["foreign"],
            messages["missing"],
            f"foreign vs missing must be indistinguishable: {messages}",
        )

    def test_reserve_same_tenant_succeeds(self):
        job = self.job()
        budget.configure_budget(job, Decimal("2.00"), tenant_id=self.tenant)
        budget.reserve_budget(job, Decimal("0.50"), tenant_id=self.tenant)
        self.assertEqual(self.budget_row(job)[1], Decimal("0.50"))

    def test_reserve_insufficient_same_tenant_is_budget_exceeded(self):
        job = self.job()
        budget.configure_budget(job, Decimal("1.00"), tenant_id=self.tenant)
        with self.assertRaises(budget.BudgetExceeded):
            budget.reserve_budget(job, Decimal("5.00"), tenant_id=self.tenant)
        self.assertEqual(self.budget_row(job)[1], Decimal(0))

    def test_reserve_foreign_configured_is_not_budget_exceeded(self):
        foreign_job = self.job(tenant=self.foreign)
        budget.configure_budget(
            foreign_job, Decimal("0.01"), tenant_id=self.foreign
        )
        # Amount far above the foreign limit: if scope leaked, this would
        # surface as BudgetExceeded and disclose the configured budget.
        with self.assertRaises(budget.BudgetNotConfigured):
            budget.reserve_budget(
                foreign_job, Decimal("5.00"), tenant_id=self.tenant
            )
        self.assertEqual(self.budget_row(foreign_job)[1], Decimal(0))

    def test_release_same_tenant_mutates(self):
        job = self.job()
        budget.configure_budget(job, Decimal("2.00"), tenant_id=self.tenant)
        budget.reserve_budget(job, Decimal("0.50"), tenant_id=self.tenant)
        budget.release_budget(job, Decimal("0.20"), tenant_id=self.tenant)
        self.assertEqual(self.budget_row(job)[1], Decimal("0.30"))

    def test_release_foreign_leaves_row_unchanged(self):
        foreign_job = self.job(tenant=self.foreign)
        budget.configure_budget(foreign_job, Decimal("2.00"), tenant_id=self.foreign)
        before = self.budget_row(foreign_job)
        with self.assertRaises(budget.BudgetError):
            budget.release_budget(
                foreign_job, Decimal("0.20"), tenant_id=self.tenant
            )
        self.assertEqual(self.budget_row(foreign_job), before)

    def test_settle_same_tenant_mutates(self):
        job = self.job()
        budget.configure_budget(job, Decimal("2.00"), tenant_id=self.tenant)
        budget.reserve_budget(job, Decimal("1.00"), tenant_id=self.tenant)
        budget.settle_budget(job, Decimal("1.00"), Decimal("0.60"),
                             tenant_id=self.tenant)
        row = self.budget_row(job)
        self.assertEqual((row[1], row[2]), (Decimal(0), Decimal("0.60")))

    def test_settle_foreign_leaves_row_unchanged(self):
        foreign_job = self.job(tenant=self.foreign)
        budget.configure_budget(foreign_job, Decimal("2.00"), tenant_id=self.foreign)
        budget.reserve_budget(foreign_job, Decimal("1.00"), tenant_id=self.foreign)
        before = self.budget_row(foreign_job)
        with self.assertRaises(budget.BudgetError):
            budget.settle_budget(
                foreign_job, Decimal("1.00"), Decimal("0.60"),
                tenant_id=self.tenant,
            )
        self.assertEqual(self.budget_row(foreign_job), before)

    def test_neighbouring_object_id_is_not_usable(self):
        """A valid UUID owned by another tenant is still out of scope."""
        foreign_job = self.job(tenant=self.foreign)
        for call in (
            lambda: budget.configure_budget(
                foreign_job, Decimal("1.00"), tenant_id=self.tenant
            ),
            lambda: budget.get_budget(foreign_job, tenant_id=self.tenant),
            lambda: budget.reserve_budget(
                foreign_job, Decimal("1.00"), tenant_id=self.tenant
            ),
            lambda: budget.release_budget(
                foreign_job, Decimal("1.00"), tenant_id=self.tenant
            ),
            lambda: budget.settle_budget(
                foreign_job, Decimal("1.00"), Decimal("0.50"),
                tenant_id=self.tenant,
            ),
        ):
            with self.subTest(call=call):
                with self.assertRaises(budget.BudgetError):
                    call()


class _Shared:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_):
        return False


if __name__ == "__main__":
    unittest.main()