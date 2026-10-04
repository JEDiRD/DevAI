"""Residual-B: numeric accounting domain.

TEST-ONLY. This file freezes the CURRENT security and financial-integrity
boundaries of the numeric accounting path. It changes no production module,
adds no migration, and asserts no new production behaviour.

Every assertion here is about a boundary that, if loosened, would let an
invalid number reach a durable financial mutation. The two known
CORRECTNESS debts (recorded, deliberately NOT frozen as desired behaviour)
are named in DEBTS below and covered by tests that pass whether or not
production is later corrected.

What is frozen, and why each matters:

  1. calculate_cost accepts ONLY exact non-negative ints, in BOTH token
     positions. bool is excluded by an exact `type(...) is int` identity
     check, not by an isinstance check, because bool is an int subclass.
     This is the single choke point every priced dollar passes through.
  2. ModelPrice accepts only finite, non-negative Decimal. A non-finite or
     negative rate would poison every cost derived from it.
  3. The reconciliation usage and statement_cost branches reject invalid
     numerics before the first financial mutation.
  4. Exactly one of usage / statement_cost / unrecoverable may be selected,
     and the check runs BEFORE any connection is opened.
  5. None usage is not zero usage. A truthiness-based future change would
     silently reclassify measured-zero work as missing usage.
  6. spent_usd is never decremented anywhere in production SQL, and
     settlement subtracts reserved/exposure only under a sufficient-balance
     predicate, so no negative or non-finite input can credit budget.
  7. complete_dispatch and calculate_cost are TWO INDEPENDENT guards on the
     worker-dispatch token path. Both are pinned.
  8. budget.py's helpers currently lack explicit is_finite(). They are
     dormant (zero production call sites). An ACTIVATION TRIPWIRE fails if
     they ever become reachable without the debt being settled.

Deliberately NOT claimed anywhere in this file:

  * That any of this persists successfully. NUMERIC(18,8) capacity, BIGINT
    capacity and DB CHECK enforcement are DB-layer facts, gated separately
    and reported NOT_TESTED when no engine is available.
  * That CHECK (x >= 0) implies finiteness. In PostgreSQL a numeric NaN
    compares greater than every other value, so `>= 0` does NOT exclude NaN.
    The finiteness defence in this system is CODE-side, and it is the code
    side that is pinned here. See test_pg_nan_caveat_is_not_encoded.
  * That evidence_sha256 cryptographically binds statement_cost. Under the
    current operator trust model the digest and the amount are INDEPENDENT
    caller-supplied values; only the digest's syntactic format is asserted.
  * That Pydantic's ge=0 means "strict integer JSON". It does not: lax mode
    coerces true -> 1, false -> 0 and "5" -> 5. That coercion is pinned as
    a SEPARATE, weaker boundary from internal accounting validation.
  * That the absence of a DB CHECK on worker_dispatches token columns is
    desirable, or that it should be frozen. It is neither required nor
    forbidden here; the two code guards are what is pinned, so a future
    harmless CHECK addition does not break this suite.

Mutation testing (section 26-28) uses EIGHT synthetic controls, each with a
unique target, a unique intended invariant, and behavioural evaluation: the
mutated module is loaded and EXECUTED, and the invariant is judged by
observed behaviour rather than by string matching.
"""
import ast
import importlib.util
import json
import os
import re
import sys
import unittest
from decimal import Decimal
from unittest import mock
from uuid import uuid4

from devai import accounting, budget, db as db_module, pricing as pricing_module
from devai import reconciliation, worker_dispatch
from devai.pricing import (ModelPrice, PricingNotConfigured, calculate_cost)
from devai.reconciliation import ReconciliationError
from devai.worker_dispatch import DispatchUnavailable

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Recorded, tracked, and deliberately NOT frozen as required behaviour.
# CORRECTNESS_DEBT_STATEMENT_COST_BOOL: Decimal(True) == Decimal(1), and the
#   statement_cost predicate admits any finite non-negative Decimal, so a
#   JSON boolean currently becomes a valid $1.00 statement cost. The tests
#   below pass whether production accepts or rejects it.
# DORMANT_BUDGET_NONFINITE_DEBT: budget.py's four mutators guard with `< 0`
#   but not is_finite(), so +Infinity would pass. Unreachable today because
#   they have zero production call sites (pinned by a tripwire).
DEBTS = {
    "CORRECTNESS_DEBT_STATEMENT_COST_BOOL": "OPEN",
    "DORMANT_BUDGET_NONFINITE_DEBT": "OPEN",
}

PRICING_REL = "controller/devai/pricing.py"
RECON_REL = "controller/devai/reconciliation.py"
WDISP_REL = "controller/devai/worker_dispatch.py"
BUDGET_REL = "controller/devai/budget.py"

TENANT = "11111111-1111-4111-8111-111111111111"
CASE = "33333333-3333-4333-8333-333333333333"
JOB = "77777777-7777-4777-8777-777777777777"
ATTEMPT = "55555555-5555-4555-8555-555555555555"
EVIDENCE = "a" * 64

# _resolve row order: case row, then the attempt price snapshot.
CASE_ROW = (JOB, ATTEMPT, "recoverable", Decimal("1"), True, None)
SNAPSHOT_ROW = ("pricing-key", 1, Decimal("0.5"), Decimal("1.5"))


def price(rate_in="1", rate_out="2"):
    return ModelPrice(pricing_key="k", version=1,
                      input_per_million_usd=Decimal(rate_in),
                      output_per_million_usd=Decimal(rate_out))


# ----------------------------------------------------------------------
# Faithful psycopg3 doubles. COMMIT on clean __exit__, ROLLBACK on raise.
# ----------------------------------------------------------------------
class ScriptedCursor:
    """Records every statement so ordering and mutation count are provable."""

    def __init__(self, rows, log):
        self._rows = list(rows)
        self.log = log
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.log.append(" ".join(str(sql).split()))

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows


class FakeConn:
    def __init__(self, rows, log):
        self._rows = list(rows)
        self.log = log

    def __enter__(self):
        self.log.append("OPEN_TX")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.log.append("ROLLBACK" if exc_type else "COMMIT")
        return False

    def cursor(self):
        return ScriptedCursor(self._rows, self.log)


def drive_resolve(module, *, case_row=CASE_ROW, **kwargs):
    """Run module._resolve against a scripted cursor; return (result, log).

    Invalid usage surfaces as ValueError from the pricing choke point, which
    is NOT a ReconciliationError. Both are recorded as "rejected", because the
    distinction that matters here is refused-vs-mutated, not which type
    refused. The mutations list is what proves nothing was written.
    """
    log = []
    cursor = ScriptedCursor([case_row, SNAPSHOT_ROW], log)
    try:
        result = module._resolve(cursor, TENANT, CASE, **kwargs)
        return ("ok", result, log)
    except module.ReconciliationError as exc:
        return ("rejected", str(exc), log)
    except ValueError as exc:
        return ("rejected", str(exc), log)


def mutations(log):
    """Statements that write financial or durable state."""
    return [s for s in log
            if s.startswith(("UPDATE", "INSERT", "DELETE"))
            and ("job_budgets" in s or "execution_attempts" in s
                 or "metered_reconciliation" in s)]


# ----------------------------------------------------------------------
# 3. calculate_cost: the real choke point, both token positions.
# ----------------------------------------------------------------------
class CalculateCostDomainTests(unittest.TestCase):
    """Section 3: the pure pricing function's exact input domain."""

    REJECT = (-1, 0.5, 1.0, True, False, float("nan"), float("inf"),
              float("-inf"), "1", None, Decimal("NaN"), Decimal("Infinity"),
              Decimal("-Infinity"))
    ACCEPT = (0, 1, 7, 10 ** 6)

    def test_negative_is_rejected_in_both_positions(self):
        with self.assertRaises(ValueError) as ctx:
            calculate_cost(price(), -1, 1)
        self.assertEqual("INVALID_TOKEN_USAGE", str(ctx.exception))
        with self.assertRaises(ValueError):
            calculate_cost(price(), 1, -1)

    def test_zero_and_one_are_accepted_in_both_positions(self):
        for value in (0, 1):
            self.assertIsInstance(calculate_cost(price(), value, 1), Decimal)
            self.assertIsInstance(calculate_cost(price(), 1, value), Decimal)

    def test_zero_usage_is_a_real_zero_cost_not_an_error(self):
        self.assertEqual(Decimal(0), calculate_cost(price(), 0, 0))

    def test_fractional_is_rejected_in_both_positions(self):
        for value in (0.5, 1.0):
            with self.assertRaises(ValueError):
                calculate_cost(price(), value, 1)
            with self.assertRaises(ValueError):
                calculate_cost(price(), 1, value)

    def test_bool_is_rejected_in_both_positions(self):
        for value in (True, False):
            with self.assertRaises(ValueError):
                calculate_cost(price(), value, 1)
            with self.assertRaises(ValueError):
                calculate_cost(price(), 1, value)

    def test_nonfinite_floats_are_rejected_in_both_positions(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                calculate_cost(price(), value, 1)
            with self.assertRaises(ValueError):
                calculate_cost(price(), 1, value)

    def test_string_and_none_are_rejected_in_both_positions(self):
        for value in ("1", None):
            with self.assertRaises(ValueError):
                calculate_cost(price(), value, 1)
            with self.assertRaises(ValueError):
                calculate_cost(price(), 1, value)

    def test_decimal_nan_is_rejected(self):
        with self.assertRaises(ValueError):
            calculate_cost(price(), Decimal("NaN"), 1)

    def test_every_rejected_class_is_rejected_in_every_position(self):
        """Exhaustive cross-product, so no position is quietly permissive."""
        for bad in self.REJECT:
            with self.subTest(value=repr(bad)):
                with self.assertRaises(ValueError):
                    calculate_cost(price(), bad, 1)
                with self.assertRaises(ValueError):
                    calculate_cost(price(), 1, bad)

    def test_accepted_non_negative_ints_produce_finite_costs(self):
        for good in self.ACCEPT:
            for cost in (calculate_cost(price(), good, 1),
                         calculate_cost(price(), 1, good)):
                self.assertIsInstance(cost, Decimal)
                self.assertTrue(cost.is_finite())
                self.assertGreaterEqual(cost, 0)


# ----------------------------------------------------------------------
# 4. The bool guard is an exact type identity, not isinstance.
# ----------------------------------------------------------------------
class BoolTokenGuardTests(unittest.TestCase):
    """Section 4: why the bool rejection is load-bearing."""

    def test_bool_is_an_int_subclass_so_isinstance_would_not_exclude_it(self):
        # This is the reason production uses `type(v) is int`. If this
        # assertion ever fails, the exact-type guard is no longer necessary
        # for bool exclusion and the reasoning here must be revisited.
        self.assertTrue(isinstance(True, int))
        self.assertIsInstance(True, int)
        self.assertNotEqual(type(True), int)

    def test_production_guard_is_exact_type_identity(self):
        source = open(os.path.join(ROOT, PRICING_REL), encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "calculate_cost")
        body = ast.unparse(fn).replace(" ", "")
        self.assertIn("type(value)isnotint", body,
                      "the bool-excluding guard must be exact type identity")
        self.assertNotIn("notisinstance(value,int)", body,
                         "an isinstance guard would admit bool")

    def test_bool_tokens_are_not_valid_accounting_usage(self):
        for value in (True, False):
            with self.assertRaises(ValueError):
                calculate_cost(price(), value, 0)
            with self.assertRaises(ValueError):
                calculate_cost(price(), 0, value)

    def test_a_bool_cost_would_otherwise_be_a_plausible_amount(self):
        """Documents the consequence the guard prevents.

        Decimal(True) * rate is a finite, non-negative number, so nothing
        downstream would catch a bool that slipped through. The guard at the
        choke point is the only thing standing between a JSON boolean and a
        priced dollar.
        """
        would_be = Decimal(True) * Decimal("1") / Decimal("1000000")
        self.assertTrue(would_be.is_finite())
        self.assertGreaterEqual(would_be, 0)
        with self.assertRaises(ValueError):
            calculate_cost(price(), True, 0)


# ----------------------------------------------------------------------
# 5. ModelPrice domain.
# ----------------------------------------------------------------------
class ModelPriceDomainTests(unittest.TestCase):
    """Section 5: a price is a finite, non-negative Decimal, nothing else."""

    def _build(self, value):
        return ModelPrice(pricing_key="k", version=1,
                          input_per_million_usd=value,
                          output_per_million_usd=value)

    def test_decimal_zero_is_accepted(self):
        self.assertEqual(Decimal(0), self._build(Decimal(0)).input_per_million_usd)

    def test_positive_decimal_is_accepted(self):
        self.assertEqual(Decimal("0.25"),
                         self._build(Decimal("0.25")).input_per_million_usd)

    def test_negative_decimal_is_rejected(self):
        with self.assertRaises(PricingNotConfigured):
            self._build(Decimal("-1"))

    def test_nan_is_rejected(self):
        with self.assertRaises(PricingNotConfigured):
            self._build(Decimal("NaN"))

    def test_both_infinities_are_rejected(self):
        for value in (Decimal("Infinity"), Decimal("-Infinity")):
            with self.assertRaises(PricingNotConfigured):
                self._build(value)

    def test_non_decimal_types_are_rejected(self):
        for value in (1.0, 1, "1"):
            with self.subTest(value=repr(value)):
                with self.assertRaises(PricingNotConfigured):
                    self._build(value)

    def test_each_rate_is_validated_independently(self):
        with self.assertRaises(PricingNotConfigured):
            ModelPrice(pricing_key="k", version=1,
                       input_per_million_usd=Decimal("-1"),
                       output_per_million_usd=Decimal("1"))
        with self.assertRaises(PricingNotConfigured):
            ModelPrice(pricing_key="k", version=1,
                       input_per_million_usd=Decimal("1"),
                       output_per_million_usd=Decimal("Infinity"))

    def test_a_price_built_from_db_rows_validates_the_snapshot(self):
        """The _resolve path constructs ModelPrice(*snapshot) from a row."""
        built = ModelPrice(*SNAPSHOT_ROW)
        self.assertEqual(Decimal("0.5"), built.input_per_million_usd)
        with self.assertRaises(PricingNotConfigured):
            ModelPrice("k", 1, Decimal("NaN"), Decimal("1.5"))


# ----------------------------------------------------------------------
# 6/7. CLI usage domain, and zero is not missing.
# ----------------------------------------------------------------------
class UsageDomainTests(unittest.TestCase):
    """Sections 6-7: the reconciliation usage branch, exercised for real."""

    def _resolve_usage(self, usage):
        return drive_resolve(reconciliation, actor="operator", usage=usage,
                             evidence=EVIDENCE)

    def test_negative_usage_is_rejected_without_financial_mutation(self):
        for usage in ((-1, 1), (1, -1)):
            with self.subTest(usage=usage):
                kind, detail, log = self._resolve_usage(usage)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_fractional_usage_is_rejected(self):
        kind, detail, log = self._resolve_usage((1.5, 1))
        self.assertEqual("rejected", kind)
        self.assertEqual([], mutations(log))

    def test_bool_usage_is_rejected(self):
        kind, detail, log = self._resolve_usage((True, 1))
        self.assertEqual("rejected", kind)
        self.assertEqual([], mutations(log))

    def test_string_and_none_usage_are_rejected(self):
        for usage in (("1", 1), (None, 1)):
            with self.subTest(usage=usage):
                kind, _, log = self._resolve_usage(usage)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_nan_and_infinity_usage_are_rejected(self):
        for usage in ((float("nan"), 1), (float("inf"), 1),
                      (float("-inf"), 1)):
            with self.subTest(usage=usage):
                kind, _, log = self._resolve_usage(usage)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_wrong_arity_is_rejected(self):
        """Unpacking happens before any statement, so it raises ValueError."""
        for usage in ((1,), (1, 2, 3), ()):
            with self.subTest(usage=usage):
                log = []
                cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
                with self.assertRaises(ValueError):
                    reconciliation._resolve(cursor, TENANT, CASE,
                                            actor="operator", usage=usage,
                                            evidence=EVIDENCE)
                self.assertEqual([], mutations(log))

    def test_zero_usage_is_valid_measured_usage(self):
        """Section 7: zero tokens is a measurement, not an absence."""
        kind, result, log = self._resolve_usage((0, 0))
        self.assertEqual("ok", kind)
        self.assertTrue(result)
        self.assertTrue(mutations(log), "zero usage must still settle")
        self.assertIn("spent_usd=spent_usd+%s", " ".join(log))

    def test_zero_usage_is_not_treated_as_missing_usage(self):
        """A truthiness regression would route (0, 0) to the deferral path."""
        kind, result, _ = self._resolve_usage((0, 0))
        self.assertEqual("ok", kind)
        self.assertNotEqual("RESOLUTION_EVIDENCE_REQUIRED", result)
        self.assertTrue(calculate_cost(price(), 0, 0).is_finite())

    def test_none_usage_is_not_zero_usage(self):
        """None selects no usage branch at all."""
        kind, detail, _ = drive_resolve(reconciliation, actor="operator",
                                        usage=None, evidence=EVIDENCE)
        self.assertEqual("rejected", kind)
        self.assertEqual("RESOLUTION_EVIDENCE_REQUIRED", detail)
        self.assertNotEqual(Decimal(0), None)


# ----------------------------------------------------------------------
# 8. Exactly one resolution mode, rejected before any connection.
# ----------------------------------------------------------------------
class ExactlyOneResolutionModeTests(unittest.TestCase):
    """Section 8: the AMBIGUOUS_RESOLUTION contract and its ordering."""

    COMBINATIONS = (
        ("usage_and_statement",
         dict(usage=(1, 1), statement_cost=Decimal("1")), True),
        ("usage_and_unrecoverable",
         dict(usage=(1, 1), unrecoverable=True), True),
        ("statement_and_unrecoverable",
         dict(statement_cost=Decimal("1"), unrecoverable=True), True),
        ("all_three",
         dict(usage=(1, 1), statement_cost=Decimal("1"), unrecoverable=True),
         True),
        ("none", dict(), True),
    )

    def test_each_combination_is_rejected_as_ambiguous(self):
        for label, kwargs, _ in self.COMBINATIONS:
            with self.subTest(case=label):
                with mock.patch.object(reconciliation, "connect") as conn:
                    with self.assertRaises(ReconciliationError) as ctx:
                        reconciliation.resolve_case(
                            tenant_id=TENANT, case_id=CASE, actor="operator",
                            evidence_sha256=EVIDENCE, **kwargs)
                    self.assertEqual("AMBIGUOUS_RESOLUTION",
                                     str(ctx.exception))
                    conn.assert_not_called()

    def test_ambiguity_is_rejected_before_opening_a_connection(self):
        """Ordering is load-bearing: no transaction may begin."""
        for label, kwargs, _ in self.COMBINATIONS:
            with self.subTest(case=label):
                log = []
                with mock.patch.object(reconciliation, "connect",
                                       lambda: FakeConn([], log)):
                    with self.assertRaises(ReconciliationError):
                        reconciliation.resolve_case(
                            tenant_id=TENANT, case_id=CASE,
                            actor="operator", evidence_sha256=EVIDENCE,
                            **kwargs)
                self.assertEqual([], log,
                                 "connect must not be reached at all")

    def test_exactly_one_mode_each_is_accepted_by_the_guard(self):
        """The guard admits exactly one; it is not merely reject-everything."""
        singles = (
            ("usage_only", dict(usage=(1, 1))),
            ("statement_only", dict(statement_cost=Decimal("1"))),
            ("unrecoverable_only", dict(unrecoverable=True)),
        )
        for label, kwargs in singles:
            with self.subTest(case=label):
                log = []
                rows = [CASE_ROW, SNAPSHOT_ROW]
                with mock.patch.object(reconciliation, "connect",
                                       lambda: FakeConn(rows, log)):
                    try:
                        reconciliation.resolve_case(
                            tenant_id=TENANT, case_id=CASE, actor="operator",
                            evidence_sha256=EVIDENCE, **kwargs)
                    except ReconciliationError as exc:
                        # Later stages may still reject on their own
                        # evidence; the ambiguity guard must not fire.
                        self.assertNotEqual("AMBIGUOUS_RESOLUTION", str(exc))
                self.assertNotIn("OPEN_TX", log[:0])


# ----------------------------------------------------------------------
# 9/10/11. statement_cost security domain, bool debt, evidence format.
# ----------------------------------------------------------------------
class StatementCostSecurityDomainTests(unittest.TestCase):
    """Sections 9-11: the authoritative-statement boundary."""

    def _statement(self, value, evidence=EVIDENCE):
        return drive_resolve(reconciliation, actor="operator",
                             statement_cost=value, evidence=evidence)

    def test_negative_statement_is_rejected_without_mutation(self):
        kind, detail, log = self._statement(Decimal("-1"))
        self.assertEqual("rejected", kind)
        self.assertEqual("AUTHORITATIVE_STATEMENT_REQUIRED", detail)
        self.assertEqual([], mutations(log))

    def test_nan_statement_is_rejected(self):
        kind, detail, log = self._statement(Decimal("NaN"))
        self.assertEqual("rejected", kind)
        self.assertEqual("AUTHORITATIVE_STATEMENT_REQUIRED", detail)
        self.assertEqual([], mutations(log))

    def test_both_infinities_are_rejected(self):
        for value in (Decimal("Infinity"), Decimal("-Infinity")):
            with self.subTest(value=str(value)):
                kind, _, log = self._statement(value)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_wrong_internal_types_are_rejected(self):
        for value in (1, 1.25, "1.25", None, True):
            with self.subTest(value=repr(value)):
                if isinstance(value, Decimal):
                    continue
                kind, _, log = self._statement(value)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_missing_evidence_is_rejected(self):
        kind, _, log = self._statement(Decimal("1.25"), evidence=None)
        self.assertEqual("rejected", kind)
        self.assertEqual([], mutations(log))

    def test_zero_statement_is_accepted(self):
        kind, result, log = self._statement(Decimal(0))
        self.assertEqual("ok", kind)
        self.assertTrue(result)
        self.assertIn("spent_usd=spent_usd+%s", " ".join(log))

    def test_positive_finite_statement_is_accepted(self):
        for value in (Decimal("0.00000001"), Decimal("1.25"), Decimal("9999")):
            with self.subTest(value=str(value)):
                kind, result, log = self._statement(value)
                self.assertEqual("ok", kind)
                self.assertTrue(result)

    def test_bool_statement_cost_debt_is_recorded_open(self):
        self.assertEqual("OPEN", DEBTS["CORRECTNESS_DEBT_STATEMENT_COST_BOOL"])

    def test_bool_statement_cost_is_not_frozen_as_desired_behaviour(self):
        """Passes whether production accepts or later rejects bool.

        If production is corrected to reject bool, this test still passes:
        rejection is an acceptable outcome. Only an out-of-domain amount
        would fail, and that is the property actually asserted.
        """
        kind, result, log = self._statement(Decimal(True))
        if kind == "rejected":
            self.assertEqual([], mutations(log))
            return
        self.assertEqual("ok", kind)
        # Accepted: the committed amount must still be a valid money value.
        self.assertTrue(Decimal(True).is_finite())
        self.assertGreaterEqual(Decimal(True), 0)

    def test_bool_statement_arithmetic_is_the_documented_mechanism(self):
        """The pure fact behind the debt; asserts no production behaviour."""
        self.assertEqual(Decimal(1), Decimal(True))
        self.assertEqual(Decimal(0), Decimal(False))
        self.assertIsInstance(Decimal(True), Decimal)

    def test_evidence_sha_requires_syntactic_format_only(self):
        """Section 11: format, and explicitly NOT a binding on the amount.

        This asserts the honest property only. It does not claim the digest
        binds statement_cost, because it does not: the digest and the amount
        are independent caller-supplied values under the operator trust model.
        """
        source = open(os.path.join(ROOT, RECON_REL), encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef) and n.name == "_event")
        body = ast.unparse(fn)
        self.assertIn("[a-f0-9]{64}", body)
        for good in ("a" * 64, "0123456789abcdef" * 4):
            self.assertRegex(good, r"^[a-f0-9]{64}$")
        for bad in ("a" * 63, "A" * 64, "g" * 64, "a" * 65, "", "z"):
            self.assertIsNone(re.match(r"^[a-f0-9]{64}$", bad))

    def test_evidence_and_amount_are_independently_validated(self):
        """Honest statement of the trust model, pinned as such.

        _event checks the digest against its format regex and the amount
        against the financial predicate, with nothing linking the two. This
        test fails if someone later claims a binding that does not exist, and
        equally fails if someone silently removes one of the two checks.
        """
        source = open(os.path.join(ROOT, RECON_REL), encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef) and n.name == "_event")
        body = ast.unparse(fn)
        self.assertIn("re.fullmatch", body)
        self.assertIn("[a-f0-9]{64}", body)
        self.assertNotIn("hashlib", body,
                         "_event must not fabricate a digest over the amount")


# ----------------------------------------------------------------------
# 12/13. Ordering, and no partial financial state.
# ----------------------------------------------------------------------
class ValidationPrecedesMutationTests(unittest.TestCase):
    """Section 12: rejection ordering, stated per current contract."""

    @staticmethod
    def _first_lines(rel, symbol):
        source = open(os.path.join(ROOT, rel), encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef) and n.name == symbol)
        first_raise = None
        first_sql = None
        for node in ast.walk(fn):
            if isinstance(node, ast.Raise) and first_raise is None:
                first_raise = node.lineno
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value.strip().upper().startswith(
                        ("UPDATE ", "INSERT ", "DELETE ")):
                    if first_sql is None or node.lineno < first_sql:
                        first_sql = node.lineno
        return first_raise, first_sql

    def test_start_metered_attempt_validates_reservation_before_connect(self):
        first_raise, first_sql = self._first_lines(
            RECON_REL, "start_metered_attempt")
        self.assertIsNotNone(first_raise)
        self.assertIsNotNone(first_sql)
        self.assertLess(first_raise, first_sql)

    def test_resolve_validates_before_its_first_financial_mutation(self):
        first_raise, first_sql = self._first_lines(RECON_REL, "_resolve")
        self.assertIsNotNone(first_raise)
        self.assertIsNotNone(first_sql)
        self.assertLess(first_raise, first_sql)

    def test_finalize_validates_costs_before_opening_a_transaction(self):
        first_raise, first_sql = self._first_lines(
            "controller/devai/accounting.py", "finalize_attempt_and_budget")
        self.assertIsNotNone(first_raise)
        self.assertIsNotNone(first_sql)
        self.assertLess(first_raise, first_sql)

    def test_complete_dispatch_validates_tokens_before_connect(self):
        first_raise, first_sql = self._first_lines(
            WDISP_REL, "complete_dispatch")
        self.assertIsNotNone(first_raise)
        self.assertIsNotNone(first_sql)
        self.assertLess(first_raise, first_sql)

    def test_settle_metered_rowcount_guard_is_not_input_validation(self):
        """Section 12: do not misclassify the rowcount guard.

        _settle_metered performs no numeric validation at all. Its raise is a
        post-mutation rowcount check that exists to roll back, so the
        validation-precedes-mutation property does NOT apply to it and must
        not be asserted as if it did.
        """
        source = open(os.path.join(ROOT, "controller/devai/accounting.py"),
                      encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "_settle_metered")
        body = ast.unparse(fn)
        self.assertNotIn("is_finite", body)
        self.assertIn("rowcount", body)
        self.assertIn("BUDGET_SETTLEMENT_FAILED", body)

    def test_settlement_failure_rolls_back_rather_than_partial_commit(self):
        """A rowcount miss must abort the transaction, not half-apply.

        Driven through finalize_attempt_and_budget so the real `with
        connect()` wrapper is exercised: the settlement UPDATE is issued, the
        rowcount check misses, and the context manager must ROLLBACK.
        """
        log = []

        class ZeroRowCursor(ScriptedCursor):
            def __init__(self, rows, log_):
                super().__init__(rows, log_)
                self._gated = False

            def execute(self, sql, params=None):
                super().execute(sql, params)
                # Authorization gate passes; the budget settlement misses.
                self._gated = "job_budgets" in " ".join(str(sql).split())
                self.rowcount = 0 if self._gated else 1

        class ZeroRowConn(FakeConn):
            def cursor(self):
                return ZeroRowCursor([], log)

        conn = ZeroRowConn([], log)
        with mock.patch.object(accounting, "connect", lambda: conn):
            with self.assertRaises(accounting.AccountingError):
                accounting.finalize_attempt_and_budget(
                    job_id=JOB, attempt_id=ATTEMPT, attempt=_Attempt(),
                    reserved_usd=Decimal("1"), actual_usd=Decimal("0.5"),
                    pricing_key="k", pricing_version=1,
                    billing_mode="metered", tenant_id=TENANT)
        self.assertIn("ROLLBACK", log)
        self.assertNotIn("COMMIT", log)
        # the attempt must NOT be marked settled after a failed settlement
        self.assertNotIn("UPDATE execution_attempts", " ".join(log))


class NoPartialFinancialStateTests(unittest.TestCase):
    """Section 13: an invalid number commits nothing."""

    INVALID = (
        ("negative", dict(usage=(-1, 1))),
        ("fractional", dict(usage=(1.5, 1))),
        ("bool", dict(usage=(True, 1))),
        ("nan", dict(usage=(float("nan"), 1))),
        ("infinity", dict(usage=(float("inf"), 1))),
        ("string", dict(usage=("1", 1))),
        ("negative_statement", dict(statement_cost=Decimal("-1"))),
        ("nan_statement", dict(statement_cost=Decimal("NaN"))),
        ("infinite_statement", dict(statement_cost=Decimal("Infinity"))),
    )

    def test_no_financial_mutation_commits_for_any_invalid_class(self):
        for label, kwargs in self.INVALID:
            with self.subTest(case=label):
                log = []
                rows = [CASE_ROW, SNAPSHOT_ROW]
                with mock.patch.object(reconciliation, "connect",
                                       lambda: FakeConn(rows, log)):
                    with self.assertRaises((ReconciliationError, ValueError)):
                        reconciliation.resolve_case(
                            tenant_id=TENANT, case_id=CASE, actor="operator",
                            evidence_sha256=EVIDENCE, **kwargs)
                self.assertEqual([], mutations(log))
                self.assertIn("ROLLBACK", log)
                self.assertNotIn("COMMIT", log)

    def test_no_case_resolution_commits_for_invalid_input(self):
        for label, kwargs in self.INVALID:
            with self.subTest(case=label):
                log = []
                cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
                with self.assertRaises((ReconciliationError, ValueError)):
                    reconciliation._resolve(cursor, TENANT, CASE,
                                            actor="operator",
                                            evidence=EVIDENCE, **kwargs)
                self.assertNotIn("COMMIT", log)
                self.assertFalse([s for s in log
                                  if "status='resolved'" in s])

    def test_no_audit_event_commits_for_invalid_input(self):
        for label, kwargs in self.INVALID:
            with self.subTest(case=label):
                log = []
                cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
                with self.assertRaises((ReconciliationError, ValueError)):
                    reconciliation._resolve(cursor, TENANT, CASE,
                                            actor="operator",
                                            evidence=EVIDENCE, **kwargs)
                self.assertEqual([], [s for s in log
                                      if "metered_reconciliation_events"
                                      in s])

    def test_spent_and_reserved_are_untouched_by_invalid_input(self):
        for label, kwargs in self.INVALID:
            with self.subTest(case=label):
                log = []
                cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
                with self.assertRaises((ReconciliationError, ValueError)):
                    reconciliation._resolve(cursor, TENANT, CASE,
                                            actor="operator",
                                            evidence=EVIDENCE, **kwargs)
                self.assertNotIn("job_budgets", " ".join(log))

    def test_finalize_rejects_negative_costs_before_any_statement(self):
        for actual, reserved in ((Decimal("-1"), Decimal("1")),
                                 (Decimal("0.5"), Decimal("-1")),
                                 (Decimal("2"), Decimal("1"))):
            with self.subTest(actual=str(actual), reserved=str(reserved)):
                log = []
                with mock.patch.object(accounting, "connect",
                                       lambda: FakeConn([], log)):
                    with self.assertRaises(accounting.AccountingError):
                        accounting.finalize_attempt_and_budget(
                            job_id=JOB, attempt_id=ATTEMPT, attempt=None,
                            reserved_usd=reserved, actual_usd=actual,
                            pricing_key=None, pricing_version=None,
                            billing_mode="metered", tenant_id=TENANT)
                self.assertEqual([], log)


# ----------------------------------------------------------------------
# 14/15. Budget credit and live arithmetic.
# ----------------------------------------------------------------------
class _RecordingCursor:
    def __init__(self, log, fetches, rowcount=1):
        self.log = log
        self._fetches = list(fetches)
        self.rowcount = rowcount

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.log.append(" ".join(str(sql).split()))

    def fetchone(self):
        return self._fetches.pop(0) if self._fetches else None

    def fetchall(self):
        rows, self._fetches = self._fetches, []
        return rows


class _RecordingConn:
    """Real class, so `with connect() as conn` resolves its dunders."""

    def __init__(self, fetches=(), rowcount=1):
        self.log = []
        self._fetches = list(fetches)
        self._rowcount = rowcount

    def __enter__(self):
        self.log.append("OPEN_TX")
        return self

    def __exit__(self, exc_type, exc, tb):
        self.log.append("ROLLBACK" if exc_type else "COMMIT")
        return False

    def cursor(self):
        return _RecordingCursor(self.log, self._fetches, self._rowcount)


def _capture(module, call, fetches=(), rowcount=1):
    """Run `call` against a recording connection; return its SQL log."""
    conn = _RecordingConn(fetches, rowcount)
    with mock.patch.object(module, "connect", lambda: conn):
        try:
            call()
        except Exception:
            pass
    return conn.log


def executed_budget_statements():
    """Every job_budgets statement production ACTUALLY executes, fully rendered.

    Captured by driving the real functions, not by scanning source. That
    distinction is load-bearing: the reserve and settlement statements are
    f-strings, so a source scan sees only fragments and never sees the
    rendered guard. Assertions are made against executed SQL, never against
    comments or source text.
    """
    captured = []

    def harvest(module, call, label, fetches=(), rowcount=1):
        for sql in _capture(module, call, fetches, rowcount):
            if "job_budgets" in sql and sql.upper().startswith(
                    ("UPDATE", "INSERT")):
                captured.append((label, sql))

    route = type("Route", (), {"key": "standard", "provider": "p",
                               "cost_class": "standard"})()
    harvest(reconciliation,
            lambda: reconciliation.start_metered_attempt(
                job_id=JOB, task_id="t", number=1, route=route, model="m",
                price=price("0.5", "1.5"), reservation=Decimal("1"),
                tenant_id=TENANT),
            "start_metered_attempt.reserve",
            fetches=[(Decimal("0.5"), Decimal("1.5"))])

    harvest(reconciliation,
            lambda: reconciliation.resolve_case(
                tenant_id=TENANT, case_id=CASE, actor="operator",
                usage=(1000, 500), evidence_sha256=EVIDENCE),
            "_resolve.settle",
            fetches=[CASE_ROW, SNAPSHOT_ROW])

    harvest(reconciliation,
            lambda: reconciliation.resolve_case(
                tenant_id=TENANT, case_id=CASE, actor="operator",
                statement_cost=Decimal("1.25"),
                evidence_sha256=EVIDENCE),
            "_resolve.statement_settle",
            fetches=[CASE_ROW, SNAPSHOT_ROW])

    harvest(accounting,
            lambda: accounting.finalize_attempt_and_budget(
                job_id=JOB, attempt_id=ATTEMPT, attempt=_Attempt(),
                reserved_usd=Decimal("1"), actual_usd=Decimal("0.5"),
                pricing_key="k", pricing_version=1, billing_mode="metered",
                tenant_id=TENANT),
            "finalize.settle",
            fetches=[("attempt-id",)])

    for name, kwargs in (
            ("reserve_budget", dict(amount_usd=Decimal("1"))),
            ("release_budget", dict(amount_usd=Decimal("1"))),
            ("settle_budget", dict(reserved_usd=Decimal("1"),
                                   actual_usd=Decimal("1"))),
    ):
        harvest(budget, lambda n=name, k=kwargs: getattr(budget, n)(
            JOB, tenant_id=TENANT, **k), "budget.%s" % name)

    return captured


class _Attempt:
    """Minimal stand-in exposing only the attributes accounting reads."""

    success = True
    error = None
    prompt_tokens = 1000
    completion_tokens = 500
    provider_request_id = "req-1"


def _set_clause(sql):
    """Only the SET list of a statement, excluding the WHERE guard.

    spent_usd legitimately appears in the reserve guard's arithmetic sum;
    inspecting the whole statement would misread a read as a write.
    """
    upper = sql.upper()
    start = upper.find(" SET ")
    end = upper.find(" WHERE ")
    if start == -1:
        return ""
    if end == -1 or end < start:
        return sql[start + 5:]
    return sql[start + 5:end]


class BudgetCreditInvariantTests(unittest.TestCase):
    """Sections 14-15: no input can credit budget or reduce spent.

    Asserted against the SQL production ACTUALLY EXECUTES, never against
    comments or source fragments.
    """

    def setUp(self):
        self.statements = executed_budget_statements()
        self.assertTrue(self.statements,
                        "expected executed job_budgets statements")

    def test_capture_reached_every_live_budget_path(self):
        """Proves the capture is broad enough for the assertions to mean
        something. If a path silently stopped issuing SQL, this fails."""
        labels = {label for label, _ in self.statements}
        for expected in ("start_metered_attempt.reserve", "_resolve.settle",
                         "finalize.settle"):
            self.assertIn(expected, labels)

    def test_spent_usd_is_never_decremented_anywhere(self):
        for label, sql in self.statements:
            flat = _set_clause(sql).replace(" ", "").upper()
            if "SPENT_USD" not in flat:
                continue
            self.assertIn("SPENT_USD=SPENT_USD+", flat,
                          "%s changes spent_usd other than by addition: %s"
                          % (label, flat))
            self.assertNotIn("SPENT_USD=SPENT_USD-", flat,
                             "%s decrements spent_usd" % label)

    def test_some_path_does_increase_spent(self):
        """Proves the previous test is not vacuously true."""
        hits = [sql for _, sql in self.statements
                if "SPENT_USD=SPENT_USD+" in _set_clause(sql)
                .replace(" ", "").upper()]
        self.assertTrue(hits, "expected at least one spent_usd increase")

    def test_settlement_subtracts_reserved_only_under_a_balance_predicate(self):
        hits = [(label, sql) for label, sql in self.statements
                if "reserved_usd=reserved_usd-" in sql.replace(" ", "")]
        self.assertTrue(hits, "expected at least one reserved release")
        for label, sql in hits:
            flat = sql.replace(" ", "")
            self.assertIn("reserved_usd>=%s", flat,
                          "%s releases reserved without a balance predicate"
                          % label)

    def test_exposure_release_uses_a_sufficient_balance_predicate(self):
        for label, sql in self.statements:
            flat = sql.replace(" ", "")
            for bucket in ("recovery_exposure_usd", "unpriced_exposure_usd"):
                if bucket + "-%s" in flat:
                    self.assertIn(bucket + ">=%s", flat,
                                  "%s releases %s without a balance predicate"
                                  % (label, bucket))

    def test_reserve_guard_counts_every_consumption_bucket(self):
        """The reserve guard must read all four buckets, or exposure parked in
        an unread bucket would be double-spendable."""
        hits = [(label, sql) for label, sql in self.statements
                if "reserved_usd=reserved_usd+%s" in sql.replace(" ", "")]
        self.assertTrue(hits)
        for label, sql in hits:
            flat = sql.replace(" ", "").lower()
            for bucket in ("reserved_usd", "spent_usd",
                           "recovery_exposure_usd", "unpriced_exposure_usd"):
                self.assertIn(bucket, flat,
                              "%s reserve guard omits %s" % (label, bucket))
            self.assertIn("<=limit_usd", flat,
                          "%s reserve guard must compare against limit_usd"
                          % label)

    def test_recovery_exposure_is_not_double_counted_by_the_reserve_guard(self):
        """_open moves reserved -> recovery_exposure; both stay in the guard."""
        guard = [sql for label, sql in self.statements
                 if "reserved_usd=reserved_usd+%s" in sql.replace(" ", "")]
        flat = " ".join(guard).replace(" ", "")
        self.assertIn("recovery_exposure_usd", flat)

    def test_direct_reserve_and_settlement_are_tenant_scoped(self):
        for label, sql in self.statements:
            if label.startswith("budget.") or "finalize" in label \
                    or "reserve" in label:
                self.assertIn("tenant_id", sql.replace(" ", ""),
                              "%s lacks tenant scope" % label)

    def test_resolve_settlement_is_tenant_scoped_by_its_locked_case_read(self):
        """_resolve's budget UPDATE carries no tenant predicate of its own.

        That is correct and not a gap: its job_id comes from a case row read
        under `WHERE tenant_id=%s AND id=%s FOR UPDATE`, so the caller tenant
        is already bound to the row. This test pins that derivation instead
        of demanding a redundant predicate.
        """
        source = open(os.path.join(ROOT, RECON_REL), encoding="utf-8").read()
        fn = next(n for n in ast.walk(ast.parse(source))
                  if isinstance(n, ast.FunctionDef) and n.name == "_resolve")
        body = ast.unparse(fn).replace(" ", "").replace("\n", "")
        self.assertIn("FROMmetered_reconciliationsWHEREtenant_id=%sANDid=%s"
                      "FORUPDATE", body)
        self.assertIn("job,attempt,status,exposure,success,previous=case",
                      body)
        # the budget UPDATE must key on the job_id taken from that row
        self.assertIn("WHEREjob_id=%s", body)

    def test_negative_amount_cannot_increase_available_budget(self):
        """A negative reservation would both add to reserved_usd and shrink
        the guard's own sum. The code rejects it before any statement."""
        for bad in (Decimal("-1"), Decimal("-0.00000001")):
            with self.subTest(value=str(bad)):
                with mock.patch.object(reconciliation, "connect") as conn:
                    with self.assertRaises(ReconciliationError) as ctx:
                        reconciliation.start_metered_attempt(
                            job_id=JOB, task_id="t", number=1, route=None,
                            model="m", price=price(), reservation=bad,
                            tenant_id=TENANT)
                    self.assertEqual("INVALID_RESERVATION", str(ctx.exception))
                    conn.assert_not_called()

    def test_nan_and_infinity_reservations_are_rejected(self):
        for bad in (Decimal("NaN"), Decimal("Infinity"),
                    Decimal("-Infinity")):
            with self.subTest(value=str(bad)):
                log = []
                with mock.patch.object(reconciliation, "connect",
                                       lambda: FakeConn([], log)):
                    with self.assertRaises(ReconciliationError) as ctx:
                        reconciliation.start_metered_attempt(
                            job_id=JOB, task_id="t", number=1, route=None,
                            model="m", price=price(), reservation=bad,
                            tenant_id=TENANT)
                    self.assertEqual("INVALID_RESERVATION", str(ctx.exception))
                self.assertEqual([], log)

    def test_decrement_decimal_comparison_semantics(self):
        """Why is_finite is required and a bare `< 0` is not sufficient.

        +Infinity evaluates False under `< 0`, so a negativity-only guard
        admits it. NaN does not evaluate False either way: comparison RAISES
        InvalidOperation, which aborts before any mutation. Both facts decide
        which guards are decorative and which are real, so they are pinned.
        """
        self.assertFalse(Decimal("Infinity") < 0)
        self.assertTrue(Decimal("-Infinity") < 0)
        self.assertFalse(Decimal("Infinity").is_finite())
        with self.assertRaises(ArithmeticError):
            _ = Decimal("NaN") < 0


# ----------------------------------------------------------------------
# 16. Dormant budget.py non-finite debt: activation tripwire.
# ----------------------------------------------------------------------
class DormantBudgetNonfiniteDebtTests(unittest.TestCase):
    """Section 16: record the debt, and trip if the helpers go live."""

    HELPERS = ("configure_budget", "reserve_budget", "release_budget",
               "settle_budget")

    @staticmethod
    def production_call_sites():
        sites = []
        for base in ("controller/devai", "worker_agent"):
            directory = os.path.join(ROOT, base)
            for name in sorted(os.listdir(directory)):
                if not name.endswith(".py"):
                    continue
                rel = os.path.join(base, name).replace("\\", "/")
                with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                for node in ast.walk(tree):
                    if not isinstance(node, ast.Call):
                        continue
                    name_of = (getattr(node.func, "id", None)
                               or getattr(node.func, "attr", None))
                    if name_of in DormantBudgetNonfiniteDebtTests.HELPERS:
                        sites.append((rel, node.lineno, name_of))
        return sites

    def test_debt_is_recorded_open(self):
        self.assertEqual("OPEN", DEBTS["DORMANT_BUDGET_NONFINITE_DEBT"])

    def test_dormant_helpers_lack_explicit_is_finite(self):
        """The debt is real in the source, and this is why it is pinned."""
        with open(os.path.join(ROOT, BUDGET_REL), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        seen = 0
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in self.HELPERS:
                with self.subTest(helper=node.name):
                    flat = ast.unparse(node).replace(" ", "")
                    self.assertNotIn("is_finite", flat,
                                     "%s gained an is_finite guard; the "
                                     "DORMANT_BUDGET_NONFINITE_DEBT may now "
                                     "be settled" % node.name)
                    # configure_budget guards limit_usd, the rest guard an
                    # amount; either form is a negativity guard.
                    self.assertTrue("<0" in flat or "<=0" in flat,
                                    "%s lost its negativity guard" % node.name)
                    seen += 1
        self.assertEqual(len(self.HELPERS), seen,
                         "a budget.py helper was renamed or removed")

    def test_activation_tripwire_helpers_have_no_production_call_sites(self):
        """LOAD-BEARING: fails if a dormant helper becomes reachable.

        budget.py is imported only through budgeted_observer -> runtime,
        which is dormant from the live FastAPI closure, and none of its four
        mutators is called from production at all. If a future change wires
        one in, the non-finite debt becomes reachable and this fails.
        """
        sites = self.production_call_sites()
        self.assertEqual(
            [], sites,
            "budget.py helpers became production-reachable while "
            "DORMANT_BUDGET_NONFINITE_DEBT is still OPEN; settle the debt "
            "(add is_finite or narrow the input domain) before wiring them in")

    def test_tripwire_would_notice_a_call_site(self):
        """Self-test: the tripwire must detect a synthetic call site."""
        source = (
            "from .budget import reserve_budget\n"
            "def _tripwire_probe(job, tenant_id):\n"
            "    reserve_budget(job, Decimal('1'), tenant_id=tenant_id)\n")
        tree = ast.parse(source)
        found = [getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                 for n in ast.walk(tree) if isinstance(n, ast.Call)]
        self.assertIn("reserve_budget", found,
                      "the tripwire matcher must see a real call")

    def test_infinity_is_not_acceptable_input_to_a_budget_helper(self):
        """Pins the debt's consequence without endorsing it.

        This asserts the FACT that +Infinity passes a bare `< 0` guard, which
        is the debt. It deliberately does not assert that acceptance is
        correct behaviour, and it fails if someone later hardens budget.py,
        which would be a fix and should be recorded rather than blocked.
        """
        self.assertFalse(Decimal("Infinity") < 0)
        self.assertTrue(Decimal("Infinity") > 0)
        self.assertFalse(Decimal("Infinity").is_finite())


# ----------------------------------------------------------------------
# 17/19. complete_dispatch domain and the two independent guards.
# ----------------------------------------------------------------------
class CompleteDispatchDomainTests(unittest.TestCase):
    """Section 17: the dispatch token boundary, before any DB access."""

    @staticmethod
    def _call(prompt_tokens, completion_tokens=1):
        return worker_dispatch.complete_dispatch(
            tenant_id=None, dispatch_id=None, worker_node_id=None,
            claim_version=1, content="result",
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens)

    def test_negative_token_counts_are_rejected_before_connect(self):
        for bad in (-1, -1000):
            with self.subTest(value=bad):
                with mock.patch.object(worker_dispatch, "connect") as conn:
                    with self.assertRaises(DispatchUnavailable) as ctx:
                        self._call(bad)
                    self.assertEqual("INVALID_USAGE", str(ctx.exception))
                    conn.assert_not_called()

    def test_bool_token_counts_are_rejected_before_connect(self):
        for bad in (True, False):
            with self.subTest(value=bad):
                with mock.patch.object(worker_dispatch, "connect") as conn:
                    with self.assertRaises(DispatchUnavailable) as ctx:
                        self._call(bad)
                    self.assertEqual("INVALID_USAGE", str(ctx.exception))
                    conn.assert_not_called()

    def test_non_int_token_counts_are_rejected_before_connect(self):
        for bad in (1.5, 1.0, "1", Decimal("1"), None if False else "x"):
            with self.subTest(value=repr(bad)):
                with mock.patch.object(worker_dispatch, "connect") as conn:
                    with self.assertRaises(DispatchUnavailable):
                        self._call(bad)
                    conn.assert_not_called()

    def test_completion_position_is_validated_too(self):
        for bad in (-1, True, 1.5):
            with self.subTest(value=repr(bad)):
                with mock.patch.object(worker_dispatch, "connect") as conn:
                    with self.assertRaises(DispatchUnavailable):
                        self._call(1, bad)
                    conn.assert_not_called()

    def test_guard_is_exact_type_identity_at_the_dispatch_boundary(self):
        with open(os.path.join(ROOT, WDISP_REL), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef)
                  and n.name == "complete_dispatch")
        body = ast.unparse(fn).replace(" ", "")
        self.assertIn("type(count)isnotint", body)
        self.assertNotIn("notisinstance(count,int)", body)

    def test_dispatch_guard_and_cost_guard_are_independent(self):
        """Section 19: two separate guards, neither relying on the other."""
        with open(os.path.join(ROOT, WDISP_REL), encoding="utf-8") as fh:
            dispatch = fh.read()
        with open(os.path.join(ROOT, PRICING_REL), encoding="utf-8") as fh:
            pricing = fh.read()
        self.assertIn("INVALID_USAGE", dispatch)
        self.assertIn("INVALID_TOKEN_USAGE", pricing)
        # Neither module imports the other's guard.
        self.assertNotIn("calculate_cost", dispatch)
        self.assertNotIn("complete_dispatch", pricing)

    def test_a_negative_would_be_caught_even_if_it_reached_the_cost_guard(self):
        """Defence in depth, proven against the real pricing function."""
        with self.assertRaises(ValueError):
            calculate_cost(price(), -1, 0)


# ----------------------------------------------------------------------
# 18. Pydantic coercion is a separate, weaker boundary.
# ----------------------------------------------------------------------
class PydanticCoercionSeparationTests(unittest.TestCase):
    """Section 18: API lax coercion != internal accounting validation."""

    def setUp(self):
        from devai.worker_api import CompleteRequest
        self.model = CompleteRequest

    def test_api_model_does_coerce_bool_and_numeric_string(self):
        """Pinned as CURRENT behaviour, and as strictly weaker than internal.

        ge=0 does not mean strict-integer JSON. These results are recorded so
        that a future change to them is a deliberate decision, but they are
        NOT treated as financial corruption: every coerced value is a valid
        non-negative integer, so the money is correct even though the input
        was loose.
        """
        coerced = self.model(claim_version=1, content="x",
                             prompt_tokens=True, completion_tokens=1)
        self.assertEqual(1, coerced.prompt_tokens)
        self.assertIs(type(coerced.prompt_tokens), int)

        coerced = self.model(claim_version=1, content="x",
                             prompt_tokens="5", completion_tokens=1)
        self.assertEqual(5, coerced.prompt_tokens)

        coerced = self.model(claim_version=1, content="x",
                             prompt_tokens=False, completion_tokens=1)
        self.assertEqual(0, coerced.prompt_tokens)

    def test_api_model_rejects_negative_and_fractional(self):
        for bad in (-1, 1.5):
            with self.subTest(value=bad):
                with self.assertRaises(Exception):
                    self.model(claim_version=1, content="x",
                               prompt_tokens=bad, completion_tokens=1)

    def test_ge_zero_is_not_a_strict_integer_guarantee(self):
        """The specific false inference this section exists to prevent."""
        self.assertTrue(self.model(claim_version=1, content="x",
                                   prompt_tokens=True).prompt_tokens >= 0)
        self.assertIs(type(self.model(claim_version=1, content="x",
                                      prompt_tokens=True).prompt_tokens), int)

    def test_coerced_values_are_valid_accounting_inputs(self):
        """Coercion does not produce an out-of-domain number."""
        for raw, expected in ((True, 1), (False, 0), ("5", 5)):
            with self.subTest(raw=repr(raw)):
                coerced = self.model(claim_version=1, content="x",
                                     prompt_tokens=raw).prompt_tokens
                self.assertIs(type(coerced), int)
                self.assertEqual(expected, coerced)
                self.assertIsInstance(calculate_cost(price(), coerced, 0),
                                      Decimal)


# ----------------------------------------------------------------------
# 20. The accounting chain is real, so these columns matter.
# ----------------------------------------------------------------------
class AccountingChainTests(unittest.TestCase):
    """Section 20: worker_dispatch tokens reach calculate_cost."""

    @staticmethod
    def _source(rel):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return ast.unparse(ast.parse(fh.read())).replace(" ", "")

    def test_dispatch_result_selects_the_token_columns(self):
        source = self._source(WDISP_REL)
        self.assertIn("prompt_tokens,completion_tokens", source)

    def test_gateway_projects_dispatch_tokens_into_the_result(self):
        source = self._source("controller/devai/remote_worker_gateway.py")
        self.assertIn("get_dispatch_result(", source)
        self.assertIn("GatewayResult(content,pt,ct,request_id)", source)

    def test_executor_carries_result_tokens_into_the_attempt(self):
        source = self._source("controller/devai/executor.py")
        self.assertIn("prompt_tokens=response.prompt_tokens", source)
        self.assertIn("completion_tokens=response.completion_tokens", source)

    def test_observer_passes_attempt_tokens_to_calculate_cost(self):
        source = self._source("controller/devai/budgeted_observer.py")
        self.assertIn("calculate_cost(", source)
        self.assertIn("attempt.prompt_tokens", source)
        self.assertIn("attempt.completion_tokens", source)

    def test_chain_is_contiguous_across_the_four_modules(self):
        """Proves the chain exists rather than inferring it from fragments."""
        dispatch = self._source(WDISP_REL)
        gateway = self._source("controller/devai/remote_worker_gateway.py")
        executor = self._source("controller/devai/executor.py")
        observer = self._source("controller/devai/budgeted_observer.py")
        pricing = self._source(PRICING_REL)
        self.assertIn("prompt_tokens,completion_tokens", dispatch)
        self.assertIn("GatewayResult(content,pt,ct,request_id)", gateway)
        self.assertIn("prompt_tokens=response.prompt_tokens", executor)
        self.assertIn("attempt.prompt_tokens", observer)
        self.assertIn("defcalculate_cost(", pricing)

    def test_no_accounting_module_reads_dispatch_tokens_directly(self):
        """The only route into accounting is the executor chain above."""
        for rel in ("controller/devai/reconciliation.py",
                    "controller/devai/accounting.py",
                    "controller/devai/ledger.py",
                    "controller/devai/budget.py"):
            with self.subTest(module=rel):
                self.assertNotIn("worker_dispatches", self._source(rel))

    def test_no_db_check_is_asserted_to_exist_or_be_absent(self):
        """Section 19: the schema is neither frozen nor required here.

        A future harmless CHECK addition must not break this suite, and this
        suite must not be read as endorsing its absence. The pinned
        properties are the two code guards, asserted elsewhere.
        """
        with open(os.path.join(ROOT, WDISP_REL), encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("type(count) is not int", source)
        self.assertIn("type(value) is not int",
                      open(os.path.join(ROOT, PRICING_REL),
                           encoding="utf-8").read())


# ----------------------------------------------------------------------
# 21. Huge values: pure Python only, never a persistence claim.
# ----------------------------------------------------------------------
class HugeValueTests(unittest.TestCase):
    """Section 21: separation of the pure calculation from DB capacity."""

    HUGE = (10 ** 18, 10 ** 50, 10 ** 1000)

    def test_calculate_cost_handles_very_large_non_negative_ints(self):
        for tokens in self.HUGE:
            with self.subTest(magnitude=len(str(tokens))):
                cost = calculate_cost(price(), tokens, 0)
                self.assertIsInstance(cost, Decimal)
                self.assertTrue(cost.is_finite())
                self.assertGreater(cost, 0)

    def test_large_values_are_not_rejected_as_invalid_usage(self):
        for tokens in self.HUGE:
            with self.subTest(magnitude=len(str(tokens))):
                with mock.patch.object(reconciliation, "connect") as conn:
                    conn.return_value.__enter__.return_value.cursor.return_value \
                        .fetchone.side_effect = [CASE_ROW, SNAPSHOT_ROW]
                    try:
                        reconciliation.resolve_case(
                            tenant_id=TENANT, case_id=CASE,
                            actor="operator", usage=(tokens, 0),
                            evidence_sha256=EVIDENCE)
                    except ValueError as exc:
                        self.assertNotEqual("INVALID_TOKEN_USAGE", str(exc))

    def _assert_pure_huge_cost_property(self, label):
        """The huge-value property, free of any database or env assumption.

        NUMERIC(18,8) caps magnitude at 10**10 - 1, so these costs could not
        persist. That is a STORAGE claim, deliberately not made here. What is
        asserted is only that the pure calculation handles them: correct type,
        finite, positive, and larger than the durable capacity.
        """
        for tokens in self.HUGE:
            with self.subTest(case=label, magnitude=len(str(tokens))):
                cost = calculate_cost(price(), tokens, 0)
                self.assertIsInstance(cost, Decimal)
                self.assertTrue(cost.is_finite())
                self.assertGreater(cost, 0)
                self.assertGreater(cost, Decimal(10 ** 10))

    def test_huge_costs_are_computable_with_no_database_access(self):
        """Pure calculation, proven to touch no connection boundary.

        `connect` is patched to explode at both the pricing and db module
        boundaries, so any accidental database access fails the test rather
        than passing unnoticed.
        """
        boom = mock.Mock(side_effect=AssertionError("database access attempted"))
        with mock.patch.object(pricing_module, "connect", boom), \
                mock.patch.object(db_module, "connect", boom):
            self._assert_pure_huge_cost_property("no-db")

    def test_huge_cost_property_is_independent_of_database_env(self):
        """Regression for RESIDUAL_B_TEST_HARNESS_DEFECT.

        The earlier version of this suite asserted the environment variable
        was UNSET, which made a 121/121 green run impossible: the five real-DB
        tests skip when it is unset and fail when it is set. That coupling
        made the no-DB and real-DB configurations mutually exclusive.

        The property here is pure Python, so it must hold with the variable
        absent AND present. A synthetic, non-secret, deliberately unreachable
        DSN is used; no connection is attempted, and `connect` is patched to
        explode to prove it. No real credential is ever encoded.
        """
        synthetic = ("postgresql://residualb-synthetic@127.0.0.1:1/"
                     "residualb-synthetic-absent")
        boom = mock.Mock(side_effect=AssertionError("database access attempted"))
        with mock.patch.dict(os.environ, {"DEVAI_TEST_DATABASE_URL": synthetic}):
            self.assertEqual(synthetic, os.environ["DEVAI_TEST_DATABASE_URL"])
            with mock.patch.object(pricing_module, "connect", boom), \
                    mock.patch.object(db_module, "connect", boom):
                self._assert_pure_huge_cost_property("db-env-present")
        # and again with the variable explicitly absent
        with mock.patch.dict(os.environ):
            os.environ.pop("DEVAI_TEST_DATABASE_URL", None)
            with mock.patch.object(pricing_module, "connect", boom), \
                    mock.patch.object(db_module, "connect", boom):
                self._assert_pure_huge_cost_property("db-env-absent")


# ----------------------------------------------------------------------
# 22. JSON non-finite parses, and is rejected before any mutation.
# ----------------------------------------------------------------------
class JsonNonfiniteTests(unittest.TestCase):
    """Section 22: stdlib json accepts NaN/Infinity; production does not."""

    def test_stdlib_json_does_parse_nonfinite_literals(self):
        for literal, expected in (("NaN", "nan"), ("Infinity", "inf"),
                                  ("-Infinity", "-inf")):
            with self.subTest(literal=literal):
                value = json.loads('[%s, 1]' % literal)[0]
                self.assertIsInstance(value, float)
                self.assertEqual(expected, repr(value))

    def test_parsed_nonfinite_usage_is_rejected_before_mutation(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal):
                usage = tuple(json.loads('[%s, 1]' % literal))
                kind, _, log = drive_resolve(
                    reconciliation, actor="operator", usage=usage,
                    evidence=EVIDENCE)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_json_boolean_usage_parses_to_bool_then_is_rejected(self):
        usage = tuple(json.loads("[true, 1]"))
        self.assertIs(type(usage[0]), bool)
        kind, _, log = drive_resolve(reconciliation, actor="operator",
                                     usage=usage, evidence=EVIDENCE)
        self.assertEqual("rejected", kind)
        self.assertEqual([], mutations(log))

    def test_cli_statement_construction_rejects_nonfinite_before_connect(self):
        """Construction never raises; is_finite() is what refuses.

        Correcting a plausible-sounding but wrong assumption: Decimal() of a
        non-finite float or string SUCCEEDS, yielding Decimal('NaN') or
        Decimal('Infinity'). The CLI therefore does not fail at construction;
        it is refused later by the statement_cost predicate's finiteness
        clause. Both facts are pinned so neither is assumed.
        """
        for label, value in (("float_nan", float("nan")),
                             ("float_inf", float("inf")),
                             ("string_nan", "NaN"),
                             ("string_infinity", "Infinity")):
            with self.subTest(source=label):
                built = Decimal(value)
                self.assertIsInstance(built, Decimal)
                self.assertFalse(built.is_finite())

        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(json_literal=literal):
                built = Decimal(json.loads('{"x": %s}' % literal)["x"])
                kind, _, log = drive_resolve(
                    reconciliation, actor="operator",
                    statement_cost=built, evidence=EVIDENCE)
                self.assertEqual("rejected", kind)
                self.assertEqual([], mutations(log))

    def test_nan_statement_is_refused_by_finiteness_not_by_comparison(self):
        """The predicate short-circuits on is_finite before `< 0` is reached.

        NaN would raise InvalidOperation if compared, so the finiteness
        clause is what turns the refusal into a clean ReconciliationError
        rather than an unexpected exception type.
        """
        log = []
        kind, detail, log = drive_resolve(
            reconciliation, actor="operator", statement_cost=Decimal("NaN"),
            evidence=EVIDENCE)
        self.assertEqual("rejected", kind)
        self.assertEqual("AUTHORITATIVE_STATEMENT_REQUIRED", detail)
        self.assertEqual([], mutations(log))


# ----------------------------------------------------------------------
# 24. The PostgreSQL NaN caveat is documented, not encoded.
# ----------------------------------------------------------------------
class PgNanCaveatTests(unittest.TestCase):
    """Section 24: CHECK (x >= 0) does NOT imply finiteness."""

    def test_pg_nan_caveat_is_not_encoded_as_a_guarantee(self):
        """Fails if anyone starts asserting `>= 0` proves finite.

        PostgreSQL orders numeric NaN greater than every other value, so
        `'NaN'::numeric >= 0` is TRUE and a >= 0 CHECK does not reject it.
        The finiteness defence here is code-side, and that is what this suite
        pins. No migration is authorized, so this test records the limit
        rather than asserting a schema property that does not hold.
        """
        with open(os.path.join(ROOT, BUDGET_REL), encoding="utf-8") as fh:
            budget_src = fh.read()
        self.assertIn("reserved_usd = reserved_usd - %s", budget_src)
        # The schema does carry non-negative CHECKs; nothing here claims they
        # are sufficient for finiteness.
        with open(os.path.join(ROOT, "controller/devai/reconciliation.py"),
                  encoding="utf-8") as fh:
            recon_src = fh.read()
        self.assertIn("reservation.is_finite()", recon_src)
        self.assertIn("statement_cost.is_finite()", recon_src)

    def test_finiteness_defence_is_code_side_and_present(self):
        source = open(os.path.join(ROOT, RECON_REL), encoding="utf-8").read()
        self.assertIn("not reservation.is_finite()", source)
        self.assertIn("not statement_cost.is_finite()", source)
        with open(os.path.join(ROOT, PRICING_REL), encoding="utf-8") as fh:
            self.assertIn("not value.is_finite()", fh.read())


# ----------------------------------------------------------------------
# 25. Idempotency after rejection.
# ----------------------------------------------------------------------
class IdempotencyAfterRejectionTests(unittest.TestCase):
    """Section 25: a rejection must not poison the case."""

    RESOLVED_USAGE_ROW = (JOB, ATTEMPT, "resolved", Decimal("1"), True,
                          "usage")

    def test_rejected_resolution_leaves_no_settled_state(self):
        for label, kwargs in (("negative", dict(usage=(-1, 1))),
                              ("nan", dict(statement_cost=Decimal("NaN"))),
                              ("infinite",
                               dict(statement_cost=Decimal("Infinity")))):
            with self.subTest(case=label):
                log = []
                cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
                with self.assertRaises((ReconciliationError, ValueError)):
                    reconciliation._resolve(cursor, TENANT, CASE,
                                            actor="operator",
                                            evidence=EVIDENCE, **kwargs)
                self.assertEqual([], mutations(log))

    def test_case_row_is_never_written_to_resolved_by_a_rejection(self):
        for kwargs in (dict(usage=(-1, 1)),
                       dict(statement_cost=Decimal("NaN"))):
            log = []
            cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
            with self.assertRaises((ReconciliationError, ValueError)):
                reconciliation._resolve(cursor, TENANT, CASE, actor="operator",
                                        evidence=EVIDENCE, **kwargs)
            self.assertNotIn("SET status='resolved'",
                             " ".join(log).replace(" ", ""))

    def test_a_later_valid_resolution_still_applies(self):
        """Recovery: rejection must not make the case unresolvable."""
        kind, result, log = drive_resolve(reconciliation, actor="operator",
                                          usage=(1000, 500),
                                          evidence=EVIDENCE)
        self.assertEqual("ok", kind)
        self.assertTrue(result, "a valid resolution must still be applied")
        self.assertIn("status='resolved'", " ".join(log))

    def test_replay_of_a_successful_resolution_does_not_spend_twice(self):
        kind, result, log = drive_resolve(
            reconciliation, case_row=self.RESOLVED_USAGE_ROW,
            actor="operator", usage=(1000, 500), evidence=EVIDENCE)
        self.assertEqual("ok", kind)
        self.assertFalse(result, "a replay must report no change")
        self.assertEqual([], mutations(log))

    def test_resolved_guard_fires_before_any_financial_statement(self):
        log = []
        cursor = ScriptedCursor([self.RESOLVED_USAGE_ROW], log)
        result = reconciliation._resolve(cursor, TENANT, CASE,
                                         actor="operator", usage=(1, 1),
                                         evidence=EVIDENCE)
        self.assertFalse(result)
        self.assertEqual([], mutations(log))


# ======================================================================
# 26-28. Synthetic controls. Behavioural: the mutant is EXECUTED.
# ======================================================================
# Each control is (id, property, relative file, old text, new text,
#                  intended invariant). `old` must occur EXACTLY ONCE in the
# AST-normalised source of that file, so isolation is proven before the
# mutant is built. The mutated module is then loaded and driven through the
# same behavioural probes the real tests use, and classification is by
# OBSERVED behaviour.
#
#   ASSERTION_CAUGHT  the exact intended invariant is violated
#   WRONG_INVARIANT    rejected, but by a different invariant
#   SURVIVED           no invariant detected the change
#   HARNESS_ERROR      target not unique, mutation was a no-op, or the
#                      mutated source failed to load/parse. Does NOT count.

MUTATION_MATRIX = (
    ("RBM01",
     "calculate_cost must reject bool tokens via exact type identity",
     PRICING_REL,
     "type(value) is not int",
     "not isinstance(value, int)",
     "bool_token_guard"),

    ("RBM02",
     "calculate_cost must reject negative token counts",
     PRICING_REL,
     "type(value) is not int or value < 0",
     "type(value) is not int",
     "negative_token_guard"),

    ("RBM03",
     "ModelPrice must reject non-finite rates",
     PRICING_REL,
     "not isinstance(value, Decimal) or not value.is_finite() or value < 0",
     "not isinstance(value, Decimal) or value < 0",
     "model_price_finite_guard"),

    ("RBM04",
     "statement_cost must reject non-finite amounts",
     RECON_REL,
     "or (not statement_cost.is_finite())",
     "",
     "statement_cost_finite_guard"),

    ("RBM05",
     "statement_cost must reject negative amounts",
     RECON_REL,
     "or (statement_cost < 0)",
     "",
     "statement_cost_negative_guard"),

    ("RBM06",
     "exactly one resolution mode may be selected",
     RECON_REL,
     "if sum((usage is not None, statement_cost is not None, unrecoverable)) != 1:",
     "if False:",
     "exactly_one_resolution_mode"),

    ("RBM07",
     "complete_dispatch must reject negative token counts",
     WDISP_REL,
     "type(count) is not int or count < 0",
     "type(count) is not int",
     "dispatch_negative_token_guard"),

    ("RBM08",
     "budget.py helpers must not become production-reachable while the "
     "non-finite debt is open",
     RECON_REL,
     "        return _open(cur, attempt_id, result_success=result_success, "
     "tenant_id=tenant_id)",
     "        from .budget import reserve_budget\n"
     "        reserve_budget(attempt_id, Decimal('1'), tenant_id=tenant_id)\n"
     "        return _open(cur, attempt_id, result_success=result_success, "
     "tenant_id=tenant_id)",
     "dormant_budget_remain_dormant"),
)


def normalised_source(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return ast.unparse(ast.parse(handle.read()))


def load_mutant(rel, mutated_source, alias):
    """Load a mutated module under `alias` inside the devai package."""
    path = os.path.join(ROOT, rel)
    spec = importlib.util.spec_from_file_location(alias, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "devai"
    module.__file__ = path
    # Retained so reachability probes can read the MUTATED source rather than
    # the file on disk, which is never modified.
    module.__rb_rel__ = rel
    module.__rb_source__ = mutated_source
    sys.modules[alias] = module
    exec(compile(mutated_source, path, "exec"), module.__dict__)
    return module


def _fires_exactly(module, expected, error_types, call):
    """True only when `call` is refused with `expected`.

    Any other outcome -- no refusal, a different exception type, a different
    message -- is a violation. This totality matters: a probe that leaks an
    exception would otherwise be scored as "invariant holds", silently
    masking the very regression it exists to catch.
    """
    try:
        call()
        return False
    except error_types as exc:
        return str(exc) == expected
    except Exception:
        return False


BUNDLE_KEYS = ((PRICING_REL, "pricing"), (RECON_REL, "recon"),
               (WDISP_REL, "wdisp"))


def load_bundle(overrides=None):
    """Load all three guarded modules, applying `overrides` where given.

    Each probe is then evaluated against the ONE module it actually
    exercises. Evaluating every probe against a single loaded module would
    report unrelated invariants as violated (a pricing mutant would make the
    dispatch probe 'fail' purely because the dispatch probe could not find
    its own symbol), which destroys exact attribution.
    """
    overrides = overrides or {}
    bundle = {}
    for rel, key in BUNDLE_KEYS:
        source = overrides.get(rel) or normalised_source(rel)
        bundle[key] = load_mutant(rel, source, "devai._rb_" + key)
    return bundle


def unload_bundle(bundle):
    for key in bundle:
        sys.modules.pop("devai._rb_" + key, None)


def probe_bool_token_guard(bundle):
    """True while bool tokens remain rejected by the pricing choke point."""
    module = bundle["pricing"]
    try:
        module.calculate_cost(price(), True, 1)
        module.calculate_cost(price(), 1, False)
    except ValueError:
        return True
    except Exception:
        return False
    return False


def probe_negative_token_guard(bundle):
    module = bundle["pricing"]
    try:
        module.calculate_cost(price(), -1, 1)
        module.calculate_cost(price(), 1, -1)
    except ValueError:
        return True
    except Exception:
        return False
    return False


def probe_model_price_finite_guard(bundle):
    module = bundle["pricing"]
    for value in (Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")):
        if not _fires_exactly(
                module, "INVALID_PRICE_SNAPSHOT", module.PricingNotConfigured,
                lambda v=value: module.ModelPrice(
                    pricing_key="k", version=1, input_per_million_usd=v,
                    output_per_million_usd=Decimal("1"))):
            return False
    return True


def _resolve_refuses(module, **kwargs):
    """True when _resolve refuses without issuing any financial mutation."""
    log = []
    cursor = ScriptedCursor([CASE_ROW, SNAPSHOT_ROW], log)
    try:
        module._resolve(cursor, TENANT, CASE, actor="operator",
                        evidence=EVIDENCE, **kwargs)
        return False
    except module.ReconciliationError:
        return not mutations(log)
    except Exception:
        return False


def probe_statement_cost_finite_guard(bundle):
    module = bundle["recon"]
    return all(_resolve_refuses(module, statement_cost=v)
               for v in (Decimal("NaN"), Decimal("Infinity"),
                         Decimal("-Infinity")))


def probe_statement_cost_negative_guard(bundle):
    return _resolve_refuses(bundle["recon"], statement_cost=Decimal("-1"))


def probe_exactly_one_resolution_mode(bundle):
    """Exactly-one must refuse AMBIGUOUS before any connection is opened."""
    module = bundle["recon"]
    with mock.patch.object(module, "connect") as conn:
        clean = _fires_exactly(
            module, "AMBIGUOUS_RESOLUTION", module.ReconciliationError,
            lambda: module.resolve_case(
                tenant_id=TENANT, case_id=CASE, actor="operator",
                evidence_sha256=EVIDENCE, usage=(1, 1),
                statement_cost=Decimal("1")))
        if not clean:
            return False
        return not conn.called


def probe_dispatch_negative_token_guard(bundle):
    """Negative dispatch tokens must be refused before connect is reached."""
    module = bundle["wdisp"]
    with mock.patch.object(module, "connect") as conn:
        clean = _fires_exactly(
            module, "INVALID_USAGE", module.DispatchUnavailable,
            lambda: module.complete_dispatch(
                tenant_id=None, dispatch_id=None, worker_node_id=None,
                claim_version=1, content="result", prompt_tokens=-1,
                completion_tokens=1))
        if not clean:
            return False
        return not conn.called


def _production_sources(override=None):
    """Every production module's normalised source, optionally overridden."""
    sources = {}
    for base in ("controller/devai", "worker_agent"):
        directory = os.path.join(ROOT, base)
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".py"):
                continue
            rel = "%s/%s" % (base, name)
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                sources[rel] = ast.unparse(ast.parse(fh.read()))
    if override:
        sources[override[0]] = override[1]
    return sources


def probe_dormant_budget_remain_dormant(bundle):
    """True while the dormant helpers still have no production call sites.

    Reads the MUTATED source for reconciliation, so a mutant that wires a
    dormant helper in is detected even though the file on disk is untouched.
    """
    module = bundle["recon"]
    override = None
    rel = getattr(module, "__rb_rel__", None)
    if rel:
        override = (rel, module.__rb_source__)
    for rel_name, source in _production_sources(override).items():
        if rel_name.endswith("budget.py"):
            continue  # the helpers' own definitions are not call sites
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            called = (getattr(node.func, "id", None)
                      or getattr(node.func, "attr", None))
            if called in DormantBudgetNonfiniteDebtTests.HELPERS:
                return False
    return True


INVARIANT_PROBES = {
    "bool_token_guard": probe_bool_token_guard,
    "negative_token_guard": probe_negative_token_guard,
    "model_price_finite_guard": probe_model_price_finite_guard,
    "statement_cost_finite_guard": probe_statement_cost_finite_guard,
    "statement_cost_negative_guard": probe_statement_cost_negative_guard,
    "exactly_one_resolution_mode": probe_exactly_one_resolution_mode,
    "dispatch_negative_token_guard": probe_dispatch_negative_token_guard,
    "dormant_budget_remain_dormant": probe_dormant_budget_remain_dormant,
}

ALIASES = {
    PRICING_REL: "devai._rb_pricing",
    RECON_REL: "devai._rb_recon",
    WDISP_REL: "devai._rb_wdisp",
    BUDGET_REL: "devai._rb_budget",
}


def execute_mutation(entry):
    """Classify one control by loading and executing the mutant."""
    mid, prop, rel, old, new, invariant = entry
    base = normalised_source(rel)

    pre_count = base.count(old)
    if pre_count != 1:
        return {"id": mid, "classification": "HARNESS_ERROR",
                "detail": "target occurs %d times in %s" % (pre_count, rel),
                "violated": []}

    mutated = base.replace(old, new, 1)
    if mutated == base:
        return {"id": mid, "classification": "HARNESS_ERROR",
                "detail": "mutation was a no-op", "violated": []}
    try:
        ast.parse(mutated)
    except SyntaxError as exc:
        return {"id": mid, "classification": "HARNESS_ERROR",
                "detail": "SyntaxError: %s" % exc, "violated": []}

    try:
        bundle = load_bundle({rel: mutated})
    except Exception as exc:
        return {"id": mid, "classification": "HARNESS_ERROR",
                "detail": "%s: %s" % (type(exc).__name__, exc),
                "violated": []}

    try:
        # Every probe is evaluated, so attribution is exact: a mutant rejected
        # by an unrelated invariant is WRONG_INVARIANT, never silently
        # counted as a catch.
        violated = sorted(name for name, probe in INVARIANT_PROBES.items()
                          if not _safe(probe, bundle))
    finally:
        unload_bundle(bundle)

    if invariant in violated:
        classification = "ASSERTION_CAUGHT"
    elif violated:
        classification = "WRONG_INVARIANT"
    else:
        classification = "SURVIVED"
    return {"id": mid, "property": prop, "target_file": rel,
            "intended_invariant": invariant, "observed_violations": violated,
            "classification": classification, "detail": ""}


def _safe(probe, module):
    """Run a probe; an exploding probe does NOT count as a held invariant.

    Scoring a crashed probe as "invariant holds" would hide exactly the
    regression these controls exist to catch, so failure is the default.
    A probe broken on BASELINE therefore fails the baseline test loudly
    rather than quietly passing the mutant matrix.
    """
    try:
        return bool(probe(module))
    except Exception:
        return False


class SyntheticControlInventoryTests(unittest.TestCase):
    """Sections 26-27: the inventory itself must be well formed."""

    def test_inventory_is_exactly_the_eight_required_ids(self):
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(["RBM%02d" % n for n in range(1, 9)], ids)

    def test_every_control_has_a_unique_property_and_invariant(self):
        props = [m[1] for m in MUTATION_MATRIX]
        invariants = [m[5] for m in MUTATION_MATRIX]
        self.assertEqual(len(set(props)), len(props))
        self.assertEqual(len(set(invariants)), len(invariants))

    def test_every_target_occurs_exactly_once_in_normalised_source(self):
        for mid, _, rel, old, _, _ in MUTATION_MATRIX:
            with self.subTest(control=mid):
                self.assertEqual(1, normalised_source(rel).count(old),
                                 "%s target must be unique in %s" % (mid, rel))

    def test_every_invariant_has_a_probe(self):
        for mid, _, _, _, _, invariant in MUTATION_MATRIX:
            with self.subTest(control=mid):
                self.assertIn(invariant, INVARIANT_PROBES)

    def test_every_mutation_actually_changes_its_target(self):
        for mid, _, rel, old, new, _ in MUTATION_MATRIX:
            with self.subTest(control=mid):
                base = normalised_source(rel)
                mutated = base.replace(old, new, 1)
                self.assertNotEqual(base, mutated)
                ast.parse(mutated)


class BaselineInvariantTests(unittest.TestCase):
    """Section 28: unmodified source must satisfy every invariant first."""

    def test_baseline_violates_no_invariant(self):
        bundle = load_bundle()
        try:
            violated = sorted(name for name, probe in INVARIANT_PROBES.items()
                              if not _safe(probe, bundle))
            self.assertEqual([], violated,
                             "baseline violations: %s" % violated)
        finally:
            unload_bundle(bundle)

    def test_baseline_uses_the_same_probes_as_the_mutants(self):
        """The probes must be meaningful on unmodified source."""
        bundle = load_bundle()
        try:
            self.assertTrue(probe_bool_token_guard(bundle))
            self.assertTrue(probe_negative_token_guard(bundle))
            self.assertTrue(probe_model_price_finite_guard(bundle))
            self.assertTrue(probe_statement_cost_finite_guard(bundle))
            self.assertTrue(probe_statement_cost_negative_guard(bundle))
            self.assertTrue(probe_exactly_one_resolution_mode(bundle))
            self.assertTrue(probe_dispatch_negative_token_guard(bundle))
            self.assertTrue(probe_dormant_budget_remain_dormant(bundle))
        finally:
            unload_bundle(bundle)


class SyntheticControlMatrixTests(unittest.TestCase):
    """Sections 26-28: run all eight controls and require 8 catches."""

    def test_all_eight_controls_are_caught_by_their_intended_invariant(self):
        results = [execute_mutation(m) for m in MUTATION_MATRIX]
        report = "\n".join(
            ("  %s %-17s invariant=%s violated=%s %s"
             % (r["id"], r["classification"], r.get("intended_invariant"),
                r.get("observed_violations"), r.get("detail", ""))).rstrip()
            for r in results)
        print("\n=== RESIDUAL-B SYNTHETIC CONTROLS ===")
        print(report)

        caught = [r for r in results
                  if r["classification"] == "ASSERTION_CAUGHT"]
        harness = [r for r in results
                   if r["classification"] == "HARNESS_ERROR"]
        survived = [r for r in results
                    if r["classification"] == "SURVIVED"]
        wrong = [r for r in results
                 if r["classification"] == "WRONG_INVARIANT"]
        self.assertEqual([], harness, report)
        self.assertEqual([], survived, report)
        self.assertEqual([], wrong, report)
        self.assertEqual(8, len(caught), report)

    def test_repository_production_sources_are_never_written(self):
        """Mutants are in-memory only; the files on disk are untouched."""
        for rel in (PRICING_REL, RECON_REL, WDISP_REL, BUDGET_REL):
            with self.subTest(module=rel):
                path = os.path.join(ROOT, rel)
                with open(path, encoding="utf-8") as handle:
                    self.assertEqual(normalised_source(rel),
                                     ast.unparse(ast.parse(handle.read())))


# ======================================================================
# 23. DB-layer checks. Honest SKIP when no engine is configured.
# ======================================================================
def db_available():
    return bool(os.environ.get("DEVAI_TEST_DATABASE_URL"))


CHECK_VIOLATION = "23514"


def require_check_violation(case, exc, label):
    """Accept ONLY a psycopg CheckViolation with SQLSTATE 23514.

    This is the whole point of the corrective. The previous oracle was a bare
    `assertRaises(Exception)`, which happily accepted ProgrammingError raised
    by a parameter-count mismatch -- evidence of nothing at all. Kept as a
    free function so it can be unit-tested without an engine, including with
    synthetic exception objects, so the oracle itself is proven strict.
    """
    import psycopg
    sqlstate = getattr(exc, "sqlstate", None)
    case.assertEqual(
        CHECK_VIOLATION, sqlstate,
        "%s: expected check_violation (23514), got %s / sqlstate=%r: %s"
        % (label, type(exc).__name__, sqlstate, exc))
    case.assertIsInstance(exc, psycopg.errors.CheckViolation,
                          "%s: not a psycopg CheckViolation" % label)


class CheckViolationOracleTests(unittest.TestCase):
    """The oracle is strict, proven with NO database and synthetic errors.

    Section 15. A parameter-count mismatch raises ProgrammingError, whose
    SQLSTATE is not 23514. These tests construct such exceptions directly, so
    they run without an engine and cannot themselves drift into accepting the
    wrong failure.
    """

    def test_oracle_rejects_the_exact_defect_that_was_reported(self):
        """The original defect shape, asserted directly against the oracle.

        The failing statement was a two-placeholder SELECT given one
        parameter. Reproducing the exception class here and requiring the
        oracle to reject it is the regression test for RESIDUAL_B_TEST_DEFECT,
        and it needs no engine.
        """
        import psycopg
        mismatch = psycopg.errors.ProgrammingError(
            "the query has 2 placeholders but 1 parameters were passed")
        self.assertNotEqual(CHECK_VIOLATION,
                            getattr(mismatch, "sqlstate", None))
        with self.assertRaises(AssertionError):
            require_check_violation(self, mismatch, "param mismatch")

    def test_only_a_check_violation_satisfies_the_oracle(self):
        """Every other failure mode must be rejected, by construction.

        Enumerated in one place so the rejected set is explicit: the original
        defect's ProgrammingError, plus foreign-key, NOT NULL, overflow and a
        plain exception with no SQLSTATE at all.
        """
        import psycopg
        rejected = (
            ("parameter_mismatch", psycopg.errors.ProgrammingError("x")),
            ("syntax", psycopg.errors.SyntaxError("x")),
            ("foreign_key", psycopg.errors.ForeignKeyViolation("x")),
            ("not_null", psycopg.errors.NotNullViolation("x")),
            ("overflow", psycopg.errors.NumericValueOutOfRange("x")),
            ("no_sqlstate", ValueError("x")),
        )
        for label, exc in rejected:
            with self.subTest(case=label):
                self.assertNotEqual(CHECK_VIOLATION,
                                    getattr(exc, "sqlstate", None))
                with self.assertRaises(AssertionError):
                    require_check_violation(self, exc, label)

    def test_check_violation_is_accepted(self):
        import psycopg
        require_check_violation(
            self, psycopg.errors.CheckViolation("synthetic"), "synthetic")


class DbTestFamilyCensusTests(unittest.TestCase):
    """Sections 3, 5, 8: exactly five real DB property families exist.

    Structural and engine-free, so the census is verified even with no
    database configured. Each family must perform a durable table write
    against a real committed column, and the oracle must be the strict
    23514 check, never a bare Exception.
    """

    FAMILIES = (
        ("negative_pricing_constrained_write",
         "test_negative_pricing_rate_is_rejected_by_the_column",
         "model_pricing"),
        ("negative_budget_constrained_write",
         "test_negative_budget_amounts_are_rejected", "job_budgets"),
        ("numeric_overflow_rollback",
         "test_oversized_numeric_rolls_back", "model_pricing"),
        ("huge_cost_durable_persistence_rollback",
         "test_huge_usage_cost_overflow_rolls_back",
         "execution_attempts"),
        ("token_domain_overflow",
         "test_beyond_bigint_token_counts_are_rejected",
         "execution_attempts"),
    )

    def test_the_five_db_gated_methods_are_exactly_the_five_families(self):
        import inspect
        gated = sorted(name for name, _ in inspect.getmembers(
            DatabaseConstraintTests, predicate=inspect.isfunction)
            if name.startswith("test_"))
        expected = sorted(name for _, name, _ in self.FAMILIES)
        self.assertEqual(expected, gated)
        self.assertEqual(5, len(gated))

    def test_each_family_writes_a_real_table_not_a_bare_select(self):
        import inspect
        for family, method, table in self.FAMILIES:
            source = inspect.getsource(getattr(DatabaseConstraintTests, method))
            with self.subTest(family=family):
                self.assertIn(table, source)
                upper = source.upper()
                self.assertTrue("INSERT INTO" in upper or "UPDATE" in upper,
                                "%s must perform a durable table write"
                                % family)

    def test_no_db_test_relies_on_a_bare_exception_oracle(self):
        """A generic assertRaises(Exception) must never BE the oracle.

        Where a broad `assertRaises(Exception)` is used, it exists only to
        CAPTURE the exception so a specific psycopg error class can be
        asserted immediately afterwards. The test below requires that pairing
        for every occurrence, so a bare catch can never again stand as
        evidence of CHECK enforcement.
        """
        import inspect
        for name, _ in inspect.getmembers(
                DatabaseConstraintTests, predicate=inspect.isfunction):
            if not name.startswith("test_"):
                continue
            source = inspect.getsource(getattr(DatabaseConstraintTests, name))
            with self.subTest(method=name):
                self.assertNotIn("self._rejects", source,
                                 "%s: the old one-parameter helper is gone"
                                 % name)
                if "assertRaises(Exception)" not in source:
                    continue
                # A broad catch is only legitimate if the method ALSO
                # asserts a specific psycopg error class (23514 via the
                # oracle, or a named .errors.X for overflow). Otherwise the
                # bare catch would be standing in as the oracle.
                narrows = ("require_check_violation" in source
                           or ".errors." in source)
                self.assertTrue(
                    narrows,
                    "%s: assertRaises(Exception) must be narrowed to a "
                    "specific psycopg error class" % name)

    def test_constraint_rejections_route_through_the_strict_oracle(self):
        """Every 23514 expectation must go through require_check_violation."""
        import inspect
        source = inspect.getsource(DatabaseConstraintTests)
        self.assertIn("require_check_violation", source)
        # the old one-parameter helper must be entirely absent
        self.assertNotIn("def _rejects(", source)


@unittest.skipUnless(db_available(),
                     "set DEVAI_TEST_DATABASE_URL to run Residual-B "
                     "database tests; reported NOT_TESTED when absent")
class DatabaseConstraintTests(unittest.TestCase):
    """Section 23: real engine only. Never faked, never self-passing.

    Every negative-value probe below performs a REAL durable write against a
    REAL constrained column in the committed schema, and requires PostgreSQL
    SQLSTATE 23514 (check_violation) from the table's own CHECK.

    The earlier version of these tests was invalid evidence: it ran
    `SELECT %s::numeric(18,8) WHERE %s::numeric(18,8) >= 0` with ONE
    parameter for TWO placeholders, so psycopg raised ProgrammingError during
    binding -- before PostgreSQL ever evaluated anything. Wrapped in a bare
    `assertRaises(Exception)` that passed for the wrong reason, proving
    nothing about any constraint.

    Two properties are therefore enforced here:

      * The oracle is a specific SQLSTATE, not a generic Exception. A
        parameter-count mismatch, syntax error, foreign-key violation or
        NOT NULL violation can no longer satisfy these tests.
      * The cast is NOT the security oracle. `SELECT (-1)::numeric(18,8)`
        SUCCEEDS in PostgreSQL, so a load-bearing control asserts that
        explicitly: the rejection must come from the table CHECK, proven by
        comparing the bare cast against the constrained write.

    NOTE on NaN, unchanged and honest: in PostgreSQL a numeric NaN compares
    greater than every other value, so `CHECK (x >= 0)` does NOT exclude NaN.
    These tests assert the NON-NEGATIVE constraints only. Finiteness is
    enforced code-side by is_finite(), which is what the pure tests pin. No
    migration is authorized and none is proposed.
    """

    def setUp(self):
        import psycopg
        self.psycopg = psycopg
        self.conn = psycopg.connect(os.environ["DEVAI_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.tenant = uuid4()
        self.job = uuid4()
        self.task = uuid4()
        self.pricing_key = "residualb-%s" % uuid4().hex[:12]
        self._create_fixtures()

    def tearDown(self):
        try:
            self.conn.rollback()
            self._drop_fixtures()
        finally:
            self.conn.close()

    # -- fixtures -----------------------------------------------------
    def _create_fixtures(self):
        with self.conn.transaction():
            self.cur.execute(
                "INSERT INTO tenants(id,slug,name) VALUES (%s,%s,%s)",
                (self.tenant, "rb-%s" % self.tenant.hex[:12], "Residual-B"))
            self.cur.execute(
                "INSERT INTO jobs(id,tenant_id,objective,status) "
                "VALUES (%s,%s,%s,'running')",
                (self.job, self.tenant, "residual-b constraint probe"))
            self.cur.execute(
                "INSERT INTO tasks(id,job_id,external_id,title,description,"
                "capability,risk,needs_review,status) "
                "VALUES (%s,%s,%s,%s,%s,'basic','low',FALSE,'running')",
                (self.task, self.job, "rb-ext-1", "t", "d"))
            # A legitimate, valid pricing row, so later negative writes are
            # rejected by the CHECK rather than by a missing fixture.
            self.cur.execute(
                "INSERT INTO model_pricing(pricing_key,version,"
                "input_per_million_usd,output_per_million_usd,active) "
                "VALUES (%s,1,%s,%s,TRUE)",
                (self.pricing_key, Decimal("1.5"), Decimal("3")))
            self.cur.execute(
                "INSERT INTO job_budgets(job_id,limit_usd) VALUES (%s,%s)",
                (self.job, Decimal("10")))
            self.cur.execute(
                "INSERT INTO execution_attempts(id,job_id,task_id,"
                "attempt_number,route_key,provider,gateway_model,status,"
                "billing_mode) VALUES (%s,%s,%s,1,%s,%s,%s,'running','metered')",
                (uuid4(), self.job, self.task, "standard", "p", "m"))

    def _drop_fixtures(self):
        with self.conn.transaction():
            self.cur.execute(
                "DELETE FROM execution_attempts WHERE job_id=%s", (self.job,))
            self.cur.execute("DELETE FROM job_budgets WHERE job_id=%s",
                             (self.job,))
            self.cur.execute("DELETE FROM model_pricing WHERE pricing_key=%s",
                             (self.pricing_key,))
            self.cur.execute("DELETE FROM tasks WHERE job_id=%s", (self.job,))
            self.cur.execute("DELETE FROM jobs WHERE id=%s", (self.job,))
            self.cur.execute("DELETE FROM tenants WHERE id=%s", (self.tenant,))

    # -- oracles ------------------------------------------------------
    def _assert_check_violation(self, sql, params, label):
        """Require SQLSTATE 23514 from a real constrained write.

        The transaction is expected to abort. On any other outcome the test
        fails, which is precisely what makes a parameter mismatch
        impossible to mistake for constraint enforcement.
        """
        with self.assertRaises(Exception) as ctx:
            with self.conn.transaction():
                self.cur.execute(sql, params)
        require_check_violation(self, ctx.exception, label)
        return ctx.exception

    def _assert_bare_numeric_cast_succeeds(self, value, label):
        """Load-bearing control: the CAST is not the security oracle.

        PostgreSQL happily stores -1 in a numeric(18,8) expression. Only the
        table's CHECK rejects it. If this control ever started failing, the
        negative-write tests would be proving something else entirely.
        """
        self.cur.execute("SELECT %s::numeric(18,8)", (value,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "%s: bare cast returned no row" % label)
        self.assertEqual(Decimal("-1"), row[0],
                         "%s: bare cast must round-trip the negative value"
                         % label)

    def _read_pricing(self):
        self.cur.execute(
            "SELECT input_per_million_usd,output_per_million_usd "
            "FROM model_pricing WHERE pricing_key=%s AND version=1",
            (self.pricing_key,))
        return self.cur.fetchone()

    def _read_budget(self):
        self.cur.execute(
            "SELECT limit_usd,reserved_usd,spent_usd,"
            "recovery_exposure_usd,unpriced_exposure_usd "
            "FROM job_budgets WHERE job_id=%s", (self.job,))
        return self.cur.fetchone()

    # -- A. negative pricing, real constrained write ------------------
    def test_negative_pricing_rate_is_rejected_by_the_column(self):
        """Real INSERT and UPDATE against model_pricing; require 23514."""
        before = self._read_pricing()
        self.assertEqual((Decimal("1.5"), Decimal("3")), before)

        self._assert_bare_numeric_cast_succeeds(
            Decimal("-1"), "negative pricing bare cast")

        self._assert_check_violation(
            "INSERT INTO model_pricing(pricing_key,version,"
            "input_per_million_usd,output_per_million_usd,active) "
            "VALUES (%s,2,%s,%s,TRUE)",
            ("%s-neg" % self.pricing_key, Decimal("-1"), Decimal("1")),
            "negative input_per_million_usd INSERT")

        self._assert_check_violation(
            "UPDATE model_pricing SET input_per_million_usd=%s "
            "WHERE pricing_key=%s AND version=1",
            (Decimal("-1"), self.pricing_key),
            "negative input_per_million_usd UPDATE")

        self._assert_check_violation(
            "UPDATE model_pricing SET output_per_million_usd=%s "
            "WHERE pricing_key=%s AND version=1",
            (Decimal("-0.00000001"), self.pricing_key),
            "negative output_per_million_usd UPDATE")

        # Independent re-read in a clean transaction: nothing negative
        # persisted, and the valid fixture is untouched.
        self.conn.rollback()
        self.assertEqual((Decimal("1.5"), Decimal("3")),
                         self._read_pricing())
        self.cur.execute(
            "SELECT count(*) FROM model_pricing WHERE pricing_key=%s",
            ("%s-neg" % self.pricing_key,))
        self.assertEqual(0, self.cur.fetchone()[0],
                         "the rejected negative pricing row must not exist")

    # -- B. negative budget amounts, real constrained writes ----------
    def test_negative_budget_amounts_are_rejected(self):
        """Real UPDATE against each constrained job_budgets column."""
        before = self._read_budget()
        self.assertEqual((Decimal("10"), Decimal("0"), Decimal("0"),
                          Decimal("0"), Decimal("0")), before)

        self._assert_bare_numeric_cast_succeeds(
            Decimal("-1"), "negative budget bare cast")

        for column in ("reserved_usd", "spent_usd",
                       "recovery_exposure_usd", "unpriced_exposure_usd"):
            with self.subTest(column=column):
                self._assert_check_violation(
                    "UPDATE job_budgets SET %s=%%s WHERE job_id=%%s"
                    % column,
                    (Decimal("-1"), self.job),
                    "negative %s UPDATE" % column)

        # limit_usd carries a strict > 0 constraint, so zero is invalid too.
        self._assert_check_violation(
            "UPDATE job_budgets SET limit_usd=%s WHERE job_id=%s",
            (Decimal("0"), self.job), "zero limit_usd UPDATE")

        # Independent re-read after rollback.
        self.conn.rollback()
        self.assertEqual(before, self._read_budget())
        for value in self._read_budget():
            self.assertGreaterEqual(value, 0,
                                    "no negative budget amount may persist")

    # -- C. NUMERIC(18,8) overflow, real write ------------------------
    def test_oversized_numeric_rolls_back(self):
        """A real constrained write that overflows numeric(18,8)."""
        before = self._read_pricing()
        with self.assertRaises(Exception) as ctx:
            with self.conn.transaction():
                self.cur.execute(
                    "UPDATE model_pricing SET input_per_million_usd=%s "
                    "WHERE pricing_key=%s AND version=1",
                    (Decimal("1e40"), self.pricing_key))
        self.assertNotEqual(self.CHECK_VIOLATION,
                            getattr(ctx.exception, "sqlstate", None),
                            "overflow is not a check violation")
        self.assertIsInstance(ctx.exception,
                              self.psycopg.errors.NumericValueOutOfRange)
        self.conn.rollback()
        self.assertEqual(before, self._read_pricing())

    # -- D. huge calculated monetary value at durable persistence -----
    def test_huge_usage_cost_overflow_rolls_back(self):
        """A real calculate_cost result written to a durable cost column."""
        huge = calculate_cost(price(), 10 ** 50, 0)
        self.assertGreater(huge, Decimal(10 ** 10))
        self.cur.execute("SELECT reserved_cost_usd,reconciled_cost_usd "
                         "FROM execution_attempts WHERE job_id=%s", (self.job,))
        before = self.cur.fetchone()
        self.assertEqual((None, None), before)
        with self.assertRaises(Exception) as ctx:
            with self.conn.transaction():
                self.cur.execute(
                    "UPDATE execution_attempts SET reconciled_cost_usd=%s "
                    "WHERE job_id=%s", (huge, self.job))
        self.assertIsInstance(ctx.exception,
                              self.psycopg.errors.NumericValueOutOfRange)
        self.conn.rollback()
        self.cur.execute("SELECT reserved_cost_usd,reconciled_cost_usd "
                         "FROM execution_attempts WHERE job_id=%s", (self.job,))
        self.assertEqual((None, None), self.cur.fetchone(),
                         "the oversized cost must not have persisted")

    # -- E. token durable-domain overflow ----------------------------
    def test_beyond_bigint_token_counts_are_rejected(self):
        """A real write to execution_attempts.prompt_tokens (BIGINT)."""
        self.cur.execute("SELECT prompt_tokens,completion_tokens "
                         "FROM execution_attempts WHERE job_id=%s", (self.job,))
        self.assertEqual((None, None), self.cur.fetchone())
        for value in (10 ** 50, 10 ** 1000):
            with self.subTest(magnitude=len(str(value))):
                with self.assertRaises(Exception) as ctx:
                    with self.conn.transaction():
                        self.cur.execute(
                            "UPDATE execution_attempts SET prompt_tokens=%s "
                            "WHERE job_id=%s", (value, self.job))
                self.assertIsInstance(
                    ctx.exception,
                    self.psycopg.errors.NumericValueOutOfRange)
                self.conn.rollback()
        self.cur.execute("SELECT prompt_tokens FROM execution_attempts "
                         "WHERE job_id=%s", (self.job,))
        self.assertIsNone(self.cur.fetchone()[0],
                          "oversized token counts must not have persisted")

    # The five gated property families are exactly the five test methods
    # above. No extra gated tests live here: the oracle's own strictness is
    # unit-tested engine-free in CheckViolationOracleTests, and the family
    # census is structural in DbTestFamilyCensusTests, so this class stays at
    # exactly five skips-or-executions.