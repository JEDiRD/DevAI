"""Group C1 -- claim and lease tenant authority.

C1 hardens the three claim/lease entry points: ``checkpoint.claim_task``,
``checkpoint.renew_lease`` and ``scheduler.claim_next_ready_task``. In each,
the CALLER tenant is the authority and ownership is proven atomically inside
the authoritative statement by following tasks -> jobs -> jobs.tenant_id.

Deliberately NOT in C1 (owned by C2): ``save_checkpoint``,
``load_latest_checkpoint``, ``release_task``, ``defer_task_for_route``,
``load_runtime_task`` and ``run_claimed_task``. No migration is introduced; the
ownership join already exists via tasks.job_id.

DB tests exercise production through its REAL connection factories. Fixtures
are committed before production runs, so ``connect()`` opens genuine
independent connections; nothing is patched onto a shared uncommitted
connection. After-state is read from a further independent connection, and
every foreign-denial test first proves its target resource exists and belongs
to the foreign tenant, so a denial cannot be an invisibility artefact.

This file also carries an EXECUTED structural mutation matrix. It mutates real
production source, re-runs the same invariant checker used against the
authoritative source, and classifies each mutant as ASSERTION_CAUGHT,
HARNESS_ERROR or SURVIVED. That matrix is distinct from the structural
negative controls below; the two are reported separately and never conflated.
"""

import ast
import dataclasses
import inspect
import os
import re
import unittest
from datetime import datetime, timezone
from uuid import uuid4

import psycopg

from devai import checkpoint, runtime, scheduler
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

DEVAI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CK_PATH = os.path.join(DEVAI_ROOT, "controller", "devai", "checkpoint.py")
SC_PATH = os.path.join(DEVAI_ROOT, "controller", "devai", "scheduler.py")

EXPECTED_DENIAL_MESSAGE = "Task <task_id> is not claimable"


def _code(sql):
    """Canonical uppercase form of one SQL statement."""
    return canonical(_tokenize(sql)).upper()


def _body(func):
    return inspect.getsource(func)


def _literal_strings(tree):
    """Every string constant in a function, uppercased canonically."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            out.append(_code(node.value))
    return out


def _neutralization_defects(sql):
    """Boolean neutralization in one normalized SQL statement.

    Reports OR immediately followed by TRUE or by the literal 1, covering
    OR TRUE, OR 1=1 and OR 1 = 1. Numeric literals lex as ``number`` tokens, so
    both name and number tokens are considered.
    """
    toks = [t.text.upper() for t in _tokenize(sql)
            if t.kind in ("name", "number")]
    defects = []
    for i, tok in enumerate(toks[:-1]):
        if tok == "OR" and toks[i + 1] in ("TRUE", "1"):
            defects.append(f"OR {toks[i + 1]}")
    return defects


def _exec_params(tree):
    """The parameter tuple passed to cur.execute, in binding order."""
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "execute"):
            for arg in node.args:
                if isinstance(arg, ast.Tuple):
                    names = []
                    for el in arg.elts:
                        if isinstance(el, ast.Name):
                            names.append(el.id)
                        elif isinstance(el, ast.Attribute):
                            names.append(el.attr)
                        else:
                            names.append(type(el).__name__)
                    return names
    return None


_PLACEHOLDER = re.compile(r"([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*\Z")


def _placeholder_order(tree):
    """What each %s binds to, in SQL order.

    Returns the column expression each placeholder is compared against, or
    "(expr)" for a bare value such as an interval multiplier. Binding by role
    -- not by placeholder count -- is what lets a swapped job/tenant binding be
    detected.
    """
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "execute"):
            sql = node.args[0]
            if not (isinstance(sql, ast.Constant)
                    and isinstance(sql.value, str)):
                continue
            out, rest = [], sql.value
            while "%s" in rest:
                idx = rest.index("%s")
                match = _PLACEHOLDER.search(rest[:idx])
                out.append(match.group(1) if match else "(expr)")
                rest = rest[idx + 2:]
            return out
    return None


def _find_func(source, name):
    """Parse `source` and return the FunctionDef called `name`."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _mutate_in_function(source, func_name, old, new):
    """Apply `old` -> `new` ONLY inside `func_name`'s own source slice.

    Plain str.replace() is unsafe here: claim_task and renew_lease contain the
    byte-identical line 'AND j.tenant_id = %s', so a global first-match
    replacement would silently mutate the wrong function and the checker would
    then report the untouched one as conforming.
    """
    func = _find_func(source, func_name)
    if func is None:
        raise AssertionError(f"{func_name} not found in source")
    lines = source.splitlines(keepends=True)
    start, end = func.lineno - 1, func.end_lineno
    segment = "".join(lines[start:end])
    if old not in segment:
        raise AssertionError(f"mutant does not apply in {func_name}: {old!r}")
    mutated = segment.replace(old, new, 1)
    return "".join(lines[:start]) + mutated + "".join(lines[end:])


def _sql_of(func_def):
    return "\n".join(_literal_strings(func_def))


# ===========================================================================
# SHARED INVARIANT CHECKER
#
# This is the single authority used both against the real production source
# and against every mutant. The authoritative source must produce zero
# violations; a mutant that also produces zero is SURVIVED.
# ===========================================================================


def _c1_invariants(source, func_name):
    """Invariant violations for `func_name` in `source`.

    Returns a list of short labels; an empty list means the variant satisfies
    every C1 claim/lease invariant.
    """
    func = _find_func(source, func_name)
    if func is None:
        return [f"{func_name}:absent"]

    sql = _sql_of(func)
    params = _exec_params(func)
    order = _placeholder_order(func)
    bad = []

    is_claim_next = func_name == "claim_next_ready_task"

    # -- ownership join --
    if is_claim_next:
        if "JOIN JOBS J" not in sql:
            bad.append("no_jobs_join")
        if "J . ID = T . JOB_ID" not in sql:
            bad.append("join_not_on_job_id")
    else:
        if "FROM JOBS J" not in sql:
            bad.append("no_jobs_from")
        if "J . ID = T . JOB_ID" not in sql:
            bad.append("from_not_on_job_id")

    # -- tenant predicate present --
    if "J . TENANT_ID = %S" not in sql:
        bad.append("tenant_predicate_missing")

    # -- no boolean neutralization --
    if _neutralization_defects(sql):
        bad.append("boolean_neutralized")

    # -- tenant supplied and bound by role --
    if not params or "tenant_id" not in params:
        bad.append("tenant_not_supplied")
    elif order and "j.tenant_id" not in order:
        bad.append("tenant_not_bound_to_tenant_placeholder")

    if is_claim_next:
        # -- tenant scope inside the candidate CTE, before contention --
        try:
            cte = sql.index("WITH CANDIDATE AS")
            tenant = sql.index("J . TENANT_ID = %S")
        except ValueError:
            bad.append("cte_or_tenant_missing")
        else:
            if tenant < cte:
                bad.append("tenant_outside_cte")
            for marker, label in (("ORDER BY T . EXTERNAL_ID", "after_order"),
                                  ("LIMIT 1", "after_limit")):
                if marker in sql and tenant > sql.index(marker):
                    bad.append(f"tenant_{label}")
            # -- task-only lock target --
            if "FOR UPDATE OF T SKIP LOCKED" not in sql:
                bad.append("lock_target_not_task_only")
            if ("FOR UPDATE SKIP LOCKED" in sql
                    or "FOR UPDATE OF T, J" in sql
                    or "FOR UPDATE J" in sql):
                bad.append("lock_target_includes_joined_rows")
            # -- job and tenant are distinct bindings --
            if order and order[:2] != ["t.job_id", "j.tenant_id"]:
                bad.append("job_tenant_binding_not_distinct")
    else:
        # -- the existing lease fence must survive --
        if func_name == "renew_lease":
            # renew_lease PRESERVES the version; it must not increment it.
            for needed in ("T . LEASE_OWNER = %S",
                           "T . LEASE_VERSION = %S",
                           "T . LEASE_EXPIRES_AT > NOW ( )"):
                if needed not in sql:
                    bad.append(f"renew_fence_missing:{needed}")
            if "LEASE_VERSION = T . LEASE_VERSION + 1" in sql:
                bad.append("renew_lease_incorrectly_bumps_version")
        elif "LEASE_VERSION = T . LEASE_VERSION + 1" not in sql:
            bad.append("lease_version_fence_lost")

    return bad


# ===========================================================================
# SECTION 1: SIGNATURE CONTRACT (static)
# ===========================================================================


class ClaimSignatureTests(unittest.TestCase):
    """tenant_id is mandatory keyword-only on every claim/lease entry point."""

    def test_claim_task_tenant_is_keyword_only_and_required(self):
        p = inspect.signature(checkpoint.claim_task).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)

    def test_renew_lease_tenant_is_keyword_only_and_required(self):
        p = inspect.signature(checkpoint.renew_lease).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)

    def test_claim_next_ready_task_tenant_is_keyword_only_and_required(self):
        p = inspect.signature(
            scheduler.claim_next_ready_task).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)

    def test_worker_once_tenant_is_keyword_only_and_required(self):
        p = inspect.signature(runtime.worker_once).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)

    def test_no_tenant_default_anywhere_in_claim_surface(self):
        """No default tenant, no tenant_id=None, no row-derived fallback."""
        for func in (checkpoint.claim_task, checkpoint.renew_lease,
                     scheduler.claim_next_ready_task, runtime.worker_once):
            src = _body(func)
            self.assertNotIn("tenant_id=None", src, func.__name__)
            self.assertNotIn("tenant_id: UUID =", src, func.__name__)
            self.assertNotIn("tenant_id: UUID | None", src, func.__name__)

    def test_tasklease_carries_tenant_and_preserves_existing_fields(self):
        fields = list(checkpoint.TaskLease.__dataclass_fields__)
        self.assertEqual(
            fields,
            ["task_id", "owner_id", "version", "expires_at", "tenant_id"])

    def test_tasklease_remains_frozen(self):
        lease = checkpoint.TaskLease(
            task_id=uuid4(), owner_id=uuid4(), version=1,
            expires_at=None, tenant_id=uuid4())
        with self.assertRaises(Exception):
            lease.tenant_id = uuid4()

    def test_tasklease_tenant_has_no_default(self):
        """Construction without tenant must fail; authority is never optional."""
        with self.assertRaises(TypeError):
            checkpoint.TaskLease(
                task_id=uuid4(), owner_id=uuid4(), version=1,
                expires_at=None)


# ===========================================================================
# SECTION 2: STRUCTURAL NEGATIVE CONTROLS (static)
# ===========================================================================


class ClaimStatementScopeTests(unittest.TestCase):
    """Structural controls pinning the C1 claim/lease shape.

    These are direct assertions against the authoritative source. The executed
    mutation matrix in C1MutationMatrixTests is reported separately.
    """

    def _claim_sql(self, func):
        tree = ast.parse(inspect.cleandoc(_body(func)))
        return "\n".join(_literal_strings(tree))

    def test_claim_task_proves_ownership_through_jobs(self):
        sql = self._claim_sql(checkpoint.claim_task)
        self.assertIn("FROM JOBS J", sql)
        self.assertIn("J . ID = T . JOB_ID", sql)
        self.assertIn("J . TENANT_ID = %S", sql)

    def test_claim_task_ownership_predicate_is_in_the_update(self):
        sql = self._claim_sql(checkpoint.claim_task)
        self.assertIn("UPDATE TASKS T", sql)
        self.assertLess(sql.index("UPDATE TASKS T"),
                        sql.index("J . TENANT_ID = %S"))

    def test_renew_lease_proves_ownership_through_jobs(self):
        sql = self._claim_sql(checkpoint.renew_lease)
        self.assertIn("FROM JOBS J", sql)
        self.assertIn("J . ID = T . JOB_ID", sql)
        self.assertIn("J . TENANT_ID = %S", sql)

    def test_renew_lease_keeps_its_existing_fence(self):
        sql = self._claim_sql(checkpoint.renew_lease)
        self.assertIn("T . LEASE_OWNER = %S", sql)
        self.assertIn("T . LEASE_VERSION = %S", sql)
        self.assertIn("T . LEASE_EXPIRES_AT > NOW ( )", sql)

    def test_claim_next_joins_jobs_for_authorization(self):
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        self.assertIn("JOIN JOBS J", sql)
        self.assertIn("J . ID = T . JOB_ID", sql)

    def test_claim_next_tenant_predicate_is_inside_the_candidate_cte(self):
        """The whole point of C1: scope precedes ordering, locking and limit."""
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        cte = sql.index("WITH CANDIDATE AS")
        tenant = sql.index("J . TENANT_ID = %S")
        order = sql.index("ORDER BY T . EXTERNAL_ID")
        lock = sql.index("FOR UPDATE OF T SKIP LOCKED")
        limit = sql.index("LIMIT 1")
        self.assertLess(cte, tenant, "tenant scope must follow the CTE head")
        self.assertLess(tenant, order, "tenant scope must precede ORDER BY")
        self.assertLess(tenant, lock,
                        "tenant scope must precede FOR UPDATE/SKIP LOCKED")
        self.assertLess(tenant, limit, "tenant scope must precede LIMIT")

    def test_claim_next_lock_target_is_task_only(self):
        """The joined jobs rows must stay outside the contention lock set."""
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        self.assertIn("FOR UPDATE OF T SKIP LOCKED", sql)
        for bad in ("FOR UPDATE SKIP LOCKED", "FOR UPDATE OF T, J SKIP LOCKED",
                    "FOR UPDATE OF T, J", "FOR UPDATE J"):
            self.assertNotIn(bad, sql, f"lock target must not be {bad!r}")

    def test_claim_next_preserves_ordering_and_dependency_predicate(self):
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        self.assertIn("ORDER BY T . EXTERNAL_ID", sql)
        self.assertIn("NOT EXISTS", sql)
        self.assertIn("PARENT . STATUS <> 'COMPLETED'", sql)

    def test_claim_next_outer_update_still_claims(self):
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        self.assertIn("UPDATE TASKS T", sql)
        self.assertIn("FROM CANDIDATE C", sql)
        self.assertIn("LEASE_VERSION = T . LEASE_VERSION + 1", sql)
        self.assertIn("LEASE_OWNER = %S", sql)
        self.assertIn("STATUS = 'RUNNING'", sql)

    def test_lease_tenant_comes_from_caller_not_returning_clause(self):
        """Authority is the argument, never a value read back from a row."""
        for func in (checkpoint.claim_task, checkpoint.renew_lease,
                     scheduler.claim_next_ready_task):
            src = inspect.cleandoc(_body(func))
            tree = ast.parse(src)
            returned_tenant = False
            for node in ast.walk(tree):
                if (isinstance(node, ast.keyword)
                        and node.arg == "tenant_id"):
                    v = node.value
                    if isinstance(v, ast.Subscript):
                        returned_tenant = True
                    if isinstance(v, ast.Constant) and v.value is None:
                        self.fail(f"{func.__name__} binds tenant_id=None")
            self.assertFalse(
                returned_tenant,
                f"{func.__name__} must not take tenant from a row subscript")

    def test_returning_clauses_do_not_carry_tenant(self):
        for func in (checkpoint.claim_task, checkpoint.renew_lease,
                     scheduler.claim_next_ready_task):
            sql = self._claim_sql(func)
            ret = sql[sql.rindex("RETURNING"):]
            self.assertNotIn("TENANT_ID", ret,
                             f"{func.__name__} RETURNING must not adopt a row tenant")

    def test_tenant_predicate_is_never_boolean_neutralized(self):
        """OR TRUE / OR 1=1 / OR 1 = 1 would erase the tenant scope."""
        for func in (checkpoint.claim_task, checkpoint.renew_lease,
                     scheduler.claim_next_ready_task):
            tree = ast.parse(inspect.cleandoc(_body(func)))
            for sql in _literal_strings(tree):
                defects = _neutralization_defects(sql)
                self.assertEqual(
                    defects, [],
                    f"{func.__name__} neutralizes its tenant scope: {defects}")

    def test_neutralization_forms_are_individually_rejected(self):
        """Each bypass form must be rejected, not just the spelling used."""
        sql = self._claim_sql(scheduler.claim_next_ready_task)
        self.assertIn("J . TENANT_ID = %S", sql)
        for bypass in ("OR TRUE", "OR 1=1", "OR 1 = 1"):
            mutated = sql.replace("J . TENANT_ID = %S",
                                  f"J . TENANT_ID = %S {bypass}")
            self.assertNotEqual(mutated, sql, "mutation did not apply")
            self.assertNotEqual(_neutralization_defects(mutated), [],
                                f"bypass {bypass} not rejected")

    def test_claim_task_binds_tenant_to_the_tenant_placeholder(self):
        """job/task, duration, owner and tenant must bind by role."""
        params = _exec_params(ast.parse(
            inspect.cleandoc(_body(checkpoint.claim_task))))
        self.assertEqual(params, ["owner_id", "lease_seconds",
                                  "task_id", "tenant_id"])
        order = _placeholder_order(ast.parse(
            inspect.cleandoc(_body(checkpoint.claim_task))))
        self.assertEqual(order, ["lease_owner", "(expr)", "t.id",
                                 "j.tenant_id"])

    def test_renew_lease_binds_tenant_to_the_tenant_placeholder(self):
        params = _exec_params(ast.parse(
            inspect.cleandoc(_body(checkpoint.renew_lease))))
        self.assertEqual(params, ["lease_seconds", "task_id",
                                  "tenant_id", "owner_id", "version"])
        order = _placeholder_order(ast.parse(
            inspect.cleandoc(_body(checkpoint.renew_lease))))
        self.assertEqual(order, ["(expr)", "t.id", "j.tenant_id",
                                 "t.lease_owner", "t.lease_version"])

    def test_claim_next_binds_job_then_tenant_distinctly(self):
        """job_id and tenant_id must be separate placeholders, in that order."""
        params = _exec_params(ast.parse(
            inspect.cleandoc(_body(scheduler.claim_next_ready_task))))
        self.assertEqual(params, ["job_id", "tenant_id", "owner_id",
                                  "lease_seconds"])
        order = _placeholder_order(ast.parse(
            inspect.cleandoc(_body(scheduler.claim_next_ready_task))))
        self.assertEqual(order, ["t.job_id", "j.tenant_id",
                                 "lease_owner", "(expr)"])
        self.assertNotEqual(order[0], order[1],
                            "job and tenant must not share a placeholder")

    def test_tenant_placeholder_count_matches_supplied_params(self):
        """Placeholder count alone is not trusted, but must still agree."""
        for func in (checkpoint.claim_task, checkpoint.renew_lease,
                     scheduler.claim_next_ready_task):
            tree = ast.parse(inspect.cleandoc(_body(func)))
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and getattr(node.func, "attr", None) == "execute"):
                    sql = node.args[0].value
                    self.assertEqual(
                        sql.count("%s"), len(node.args[1].elts),
                        f"{func.__name__} placeholder/param arity mismatch")


# ===========================================================================
# SECTION 3: EXECUTED MUTATION MATRIX
# ===========================================================================

CK_CLAIM_TASK_TENANT = "                  AND j.tenant_id = %s\n"
CK_RENEW_TENANT = "                  AND j.tenant_id = %s\n"
SC_TENANT = "                      AND j.tenant_id = %s\n"

# (id, label, source file, function under test, old, new)
MUTATION_MATRIX = [
    ("M01", "claim_task tenant predicate removed",
     CK_PATH, "claim_task", CK_CLAIM_TASK_TENANT, ""),
    ("M02", "claim_task tenant binding wrong",
     CK_PATH, "claim_task", CK_CLAIM_TASK_TENANT,
     "                  AND j.id = %s\n"),
    ("M03", "claim_task boolean neutralization OR TRUE",
     CK_PATH, "claim_task", CK_CLAIM_TASK_TENANT,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("M04", "claim_task tenant dropped from params",
     CK_PATH, "claim_task",
     "                    task_id,\n                    tenant_id,\n",
     "                    task_id,\n"),
    ("M05", "renew_lease tenant predicate removed",
     CK_PATH, "renew_lease", CK_RENEW_TENANT, ""),
    ("M06", "renew_lease tenant binding wrong",
     CK_PATH, "renew_lease", CK_RENEW_TENANT,
     "                  AND j.id = %s\n"),
    ("M07", "renew_lease boolean neutralization OR TRUE",
     CK_PATH, "renew_lease", CK_RENEW_TENANT,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("M08", "claim_next tenant predicate removed",
     SC_PATH, "claim_next_ready_task", SC_TENANT, ""),
    ("M09", "claim_next tenant binding wrong",
     SC_PATH, "claim_next_ready_task", SC_TENANT,
     "                      AND j.id = %s\n"),
    ("M10", "claim_next job/tenant swapped",
     SC_PATH, "claim_next_ready_task", SC_TENANT,
     "                      AND t.id = %s\n"),
    ("M11", "claim_next boolean neutralization OR TRUE",
     SC_PATH, "claim_next_ready_task", SC_TENANT,
     "                      AND j.tenant_id = %s OR TRUE\n"),
    ("M12", "claim_next boolean neutralization OR 1=1",
     SC_PATH, "claim_next_ready_task", SC_TENANT,
     "                      AND j.tenant_id = %s OR 1=1\n"),
    ("M13", "claim_next tenant scope moved to outer UPDATE only",
     SC_PATH, "claim_next_ready_task",
     SC_TENANT + "                      AND t.status = 'pending'\n",
     "                      AND t.status = 'pending'\n"),
    ("M14", "claim_next task-only lock removed (joined rows locked)",
     SC_PATH, "claim_next_ready_task",
     "FOR UPDATE OF t SKIP LOCKED", "FOR UPDATE SKIP LOCKED"),
    ("M15", "claim_next authorization join dropped",
     SC_PATH, "claim_next_ready_task",
     "                    JOIN jobs j\n                      ON j.id = t.job_id\n",
     ""),
]


class C1MutationMatrixTests(unittest.TestCase):
    """Executed mutation matrix over real production source.

    Each mutant is applied to the real source text, must remain syntactically
    valid Python, and is then evaluated by the SAME invariant checker used
    against the authoritative source. Verdicts:

    * ASSERTION_CAUGHT -- invariants rejected it (the desired outcome)
    * HARNESS_ERROR    -- unparseable/unloadable; never counted as a catch
    * SURVIVED         -- invariants accepted it; a real evidence gap
    """

    def _source(self, path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def _verdict(self, mutant):
        _, _, path, func_name, old, new = mutant
        source = self._source(path)
        mutated = _mutate_in_function(source, func_name, old, new)
        try:
            ast.parse(mutated)
        except SyntaxError:
            return "HARNESS_ERROR", ["SyntaxError"]
        try:
            return "ASSERTION_CAUGHT", _c1_invariants(mutated, func_name)
        except Exception as exc:                      # noqa: BLE001
            return "HARNESS_ERROR", [f"{type(exc).__name__}:{exc}"]

    def test_each_mutant_lands_inside_its_target_function(self):
        """Guard against cross-function mutation, which silently survives."""
        for mutant in MUTATION_MATRIX:
            _, label, path, func_name, old, new = mutant
            source = self._source(path)
            mutated = _mutate_in_function(source, func_name, old, new)
            original_func = ast.get_source_segment(source, _find_func(
                source, func_name))
            mutated_func = ast.get_source_segment(mutated, _find_func(
                mutated, func_name))
            self.assertNotEqual(
                original_func, mutated_func,
                f"{label}: mutation did not change {func_name}")
            for other in ("claim_task", "renew_lease", "claim_next_ready_task"):
                if other == func_name:
                    continue
                a = ast.get_source_segment(source, _find_func(source, other))
                b = ast.get_source_segment(mutated, _find_func(mutated, other))
                self.assertEqual(a, b, f"{label}: {other} must be untouched")

    def test_authoritative_source_has_zero_invariant_violations(self):
        """Baseline: the real production source must fully conform."""
        for path, func_name in ((CK_PATH, "claim_task"),
                                (CK_PATH, "renew_lease"),
                                (SC_PATH, "claim_next_ready_task")):
            self.assertEqual(_c1_invariants(self._source(path), func_name), [],
                             f"{func_name} baseline violations")

    def test_matrix_is_exactly_fifteen_mutants(self):
        """The matrix size is fixed, not tuned to the outcome."""
        self.assertEqual(len(MUTATION_MATRIX), 15)
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(len(set(ids)), 15, "mutant ids must be unique")

    def _run_one(self, mutant):
        verdict, violations = self._verdict(mutant)
        self.assertNotEqual(verdict, "HARNESS_ERROR",
                            f"{mutant[0]} {mutant[1]} -> harness error: {violations}")
        self.assertNotEqual(
            verdict, "SURVIVED",
            f"{mutant[0]} {mutant[1]} SURVIVED: invariants found no violation")
        self.assertTrue(violations,
                        f"{mutant[0]} {mutant[1]} produced no violation detail")

    def test_M01_claim_task_tenant_predicate_removed(self):
        self._run_one(MUTATION_MATRIX[0])

    def test_M02_claim_task_tenant_binding_wrong(self):
        self._run_one(MUTATION_MATRIX[1])

    def test_M03_claim_task_boolean_neutralization(self):
        self._run_one(MUTATION_MATRIX[2])

    def test_M04_claim_task_tenant_dropped_from_params(self):
        self._run_one(MUTATION_MATRIX[3])

    def test_M05_renew_lease_tenant_predicate_removed(self):
        self._run_one(MUTATION_MATRIX[4])

    def test_M06_renew_lease_tenant_binding_wrong(self):
        self._run_one(MUTATION_MATRIX[5])

    def test_M07_renew_lease_boolean_neutralization(self):
        self._run_one(MUTATION_MATRIX[6])

    def test_M08_claim_next_tenant_predicate_removed(self):
        self._run_one(MUTATION_MATRIX[7])

    def test_M09_claim_next_tenant_binding_wrong(self):
        self._run_one(MUTATION_MATRIX[8])

    def test_M10_claim_next_job_tenant_swapped(self):
        self._run_one(MUTATION_MATRIX[9])

    def test_M11_claim_next_boolean_neutralization_or_true(self):
        self._run_one(MUTATION_MATRIX[10])

    def test_M12_claim_next_boolean_neutralization_or_1eq1(self):
        self._run_one(MUTATION_MATRIX[11])

    def test_M13_claim_next_tenant_scope_moved_to_outer_update(self):
        self._run_one(MUTATION_MATRIX[12])

    def test_M14_claim_next_task_only_lock_removed(self):
        self._run_one(MUTATION_MATRIX[13])

    def test_M15_claim_next_authorization_join_dropped(self):
        self._run_one(MUTATION_MATRIX[14])


# ===========================================================================
# SECTION 4: LIVE REACHABILITY SENTINEL (static)
# ===========================================================================


def _module_deps(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                out.add(node.module)
            elif node.module and node.module.startswith("devai"):
                out.add(node.module.split(".")[-1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                out.add(alias.name.split(".")[-1])
    return out


def _live_closure(entry):
    """Transitive relative-import closure from a production module."""
    root = os.path.join(DEVAI_ROOT, "controller", "devai")
    seen, stack = set(), [entry]
    while stack:
        mod = stack.pop()
        if mod in seen:
            continue
        seen.add(mod)
        path = os.path.join(root, mod + ".py")
        if os.path.exists(path):
            for dep in _module_deps(path):
                if os.path.exists(os.path.join(root, dep + ".py")):
                    stack.append(dep)
    return seen


class LiveReachabilitySentinelTests(unittest.TestCase):
    """Group C must not silently activate the dormant execution cluster."""

    ACCEPTED_LIVE_CLOSURE = {
        "db", "worker_api", "worker_dispatch",
        "worker_identity", "worker_registry",
    }

    DORMANT = ("runtime", "scheduler", "checkpoint", "executor")

    def test_live_closure_is_exactly_the_accepted_baseline(self):
        self.assertEqual(_live_closure("worker_api"),
                         self.ACCEPTED_LIVE_CLOSURE)

    def test_dormant_cluster_excluded_from_live_closure(self):
        closure = _live_closure("worker_api")
        for mod in self.DORMANT:
            self.assertNotIn(mod, closure,
                             f"{mod} must not be reachable from worker_api")

    def test_worker_api_still_has_no_import_of_dormant_cluster(self):
        src = open(os.path.join(
            DEVAI_ROOT, "controller", "devai", "worker_api.py"),
            encoding="utf-8").read()
        for mod in self.DORMANT:
            self.assertNotIn(f".{mod} import", src)
            self.assertNotIn(f"devai.{mod} import", src)

    def test_live_worker_subsystem_frozen(self):
        """C1 may not touch the live dispatch subsystem."""
        import subprocess
        base = "ab21619fccd83af2f18576133934e7f696cbf3af"
        for name in ("worker_api", "worker_dispatch", "worker_identity",
                     "worker_registry"):
            rel = f"controller/devai/{name}.py"
            out = subprocess.run(
                ["git", "diff", "--name-only", base, "--", rel],
                cwd=DEVAI_ROOT, capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), "",
                             f"{rel} must be unchanged by Group C1")

    def test_worker_once_has_no_production_caller(self):
        """C1 adds tenant context, never a new caller."""
        hits = []
        root = os.path.join(DEVAI_ROOT, "controller")
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for n in names:
                if not n.endswith(".py"):
                    continue
                path = os.path.join(base, n)
                tree = ast.parse(open(path, encoding="utf-8").read())
                for node in ast.walk(tree):
                    if (isinstance(node, ast.Call)
                            and getattr(node.func, "id", None) == "worker_once"):
                        hits.append(path)
        self.assertEqual(hits, [], "worker_once must stay uncalled")


# ===========================================================================
# SECTION 5: C2 BOUNDARY NOT CROSSED (static)
# ===========================================================================


class C2BoundaryTests(unittest.TestCase):
    """C1 must not pre-empt C2's checkpoint read/write hardening."""

    C2_OWNED = ("save_checkpoint", "load_latest_checkpoint",
                "release_task", "defer_task_for_route")

    def test_c2_owned_signatures_have_no_tenant_yet(self):
        """C1->C2 handoff marker: records the C2 authority model.

        This began as an absence marker asserting the C2 APIs had gained no
        tenant_id yet. Group C2 implements exactly that, so it now records the
        resulting authority classification instead. The LEASE versus EXPLICIT
        distinction is the contract and must not be flattened into "all four
        take tenant_id": the three lease-taking APIs must NOT grow a redundant
        explicit argument, and only the lease-free API may take one.

        The authoritative detailed proof lives in
        tests/test_group_c_checkpoint_scope.py; this stays a narrow marker.
        """
        lease_apis = ("save_checkpoint", "release_task",
                      "defer_task_for_route")
        for name in lease_apis:
            params = inspect.signature(getattr(checkpoint, name)).parameters
            self.assertIn("lease", params, f"{name} must receive the lease")
            self.assertNotIn(
                "tenant_id", params,
                f"{name} takes authority from lease.tenant_id and must not "
                "gain a redundant explicit tenant_id")
            src = inspect.cleandoc(inspect.getsource(getattr(checkpoint, name)))
            self.assertIn("lease.tenant_id", src,
                          f"{name} must read authority from the lease")

        explicit = inspect.signature(
            checkpoint.load_latest_checkpoint).parameters["tenant_id"]
        self.assertEqual(explicit.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(explicit.default, inspect.Parameter.empty,
                      "load_latest_checkpoint tenant_id must be mandatory")
        self.assertNotIn("None", str(explicit.annotation))

    def test_c2_owned_statements_have_no_tenant_predicate(self):
        """C1->C2 handoff marker: the C2 surfaces are now tenant scoped.

        Was an absence marker asserting no C2 statement carried a tenant
        predicate. Group C2 adds one to every authoritative statement, and
        converts both checkpoint writes to INSERT ... SELECT rather than an
        unscoped VALUES insert.

        Detailed proof, including the full invariant checker and the executed
        mutation matrix, lives in tests/test_group_c_checkpoint_scope.py.
        """
        def statements(func):
            tree = ast.parse(inspect.cleandoc(inspect.getsource(func)))
            out = []
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and getattr(node.func, "attr", None) == "execute"
                        and node.args
                        and isinstance(node.args[0], ast.Constant)
                        and isinstance(node.args[0].value, str)):
                    out.append(node.args[0].value)
            return out

        for name in self.C2_OWNED:
            joined = "\n".join(_code(s) for s in statements(
                getattr(checkpoint, name)))
            self.assertIn("J . TENANT_ID = %S", joined,
                          f"{name} must carry a tenant predicate")
            self.assertIn("J . ID = T . JOB_ID", joined,
                          f"{name} must prove ownership via tasks -> jobs")

        # Both checkpoint writes must be INSERT ... SELECT, never VALUES.
        for name in ("save_checkpoint", "defer_task_for_route"):
            inserts = [s for s in statements(getattr(checkpoint, name))
                       if "INSERT INTO task_checkpoints" in s]
            self.assertEqual(len(inserts), 1, name)
            self.assertIn("SELECT", inserts[0].upper(), name)
            self.assertNotIn("VALUES", inserts[0].upper(),
                             f"{name} must not use an unscoped VALUES insert")

    def test_load_runtime_task_and_run_claimed_task_unchanged(self):
        self.assertEqual(
            list(inspect.signature(runtime.load_runtime_task).parameters),
            ["task_id"])
        self.assertEqual(
            list(inspect.signature(runtime.run_claimed_task).parameters),
            ["lease", "reservation_by_cost_class", "gateway"])

    def test_no_new_migration_introduced(self):
        import subprocess
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", "migrations"],
            cwd=DEVAI_ROOT, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "",
                         "C1 must not add or modify migrations")


# ===========================================================================
# SECTION 6: DB SECURITY (requires PostgreSQL)
# ===========================================================================


def _canonical_message(message, known_ids):
    """Replace only the specific caller-supplied task identifiers.

    Deliberately exact-match on str(known_id): no regex, no blanket UUID
    normalization. Any other textual difference between two denials would
    survive and fail the comparison.
    """
    out = message
    for known in known_ids:
        out = out.replace(str(known), "<task_id>")
    return out


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class ClaimScopeDatabaseTests(unittest.TestCase):
    """Cross-tenant claim/lease denial against a real database.

    Fixtures are COMMITTED, then production runs through its own real
    connections. Nothing is patched onto this test's connection, so each
    production call exercises genuine transaction and connection boundaries.
    After-state and pre-existence proofs are read from independent
    connections, so neither can be satisfied by this test's session state.
    """

    def setUp(self):
        self.setup = psycopg.connect(_DB_URL)
        self.addCleanup(self.setup.close)
        self.tenant = uuid4()
        self.foreign = uuid4()
        self._owned_tasks, self._owned_jobs = [], []
        with self.setup.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s,%s,%s)",
                    (tenant, f"c1-{tenant}", "c1 claim scope"))
        self.setup.commit()
        self.addCleanup(self._purge)

    # ---- fixture ownership and cleanup ----

    def _purge(self):
        """Remove exactly this test's rows, using only guaranteed cascades."""
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                if self._owned_tasks:
                    cur.execute(
                        "DELETE FROM tasks WHERE id = ANY(%s)",
                        (self._owned_tasks,))
                if self._owned_jobs:
                    cur.execute(
                        "DELETE FROM jobs WHERE id = ANY(%s)",
                        (self._owned_jobs,))
                cur.execute("DELETE FROM tenants WHERE id = ANY(%s)",
                            ([self.tenant, self.foreign],))
            conn.commit()
        finally:
            conn.close()

    def job(self, tenant=None):
        """Create and COMMIT a job owned by `tenant`."""
        job = uuid4()
        self._owned_jobs.append(job)
        with self.setup.cursor() as cur:
            cur.execute("INSERT INTO jobs(id, tenant_id, objective, status)"
                        " VALUES (%s,%s,'c1','running')",
                        (job, tenant or self.tenant))
        self.setup.commit()
        return job

    def task(self, job, status="pending"):
        """Create and COMMIT a pending task attached to `job`."""
        task = uuid4()
        self._owned_tasks.append(task)
        with self.setup.cursor() as cur:
            cur.execute(
                "INSERT INTO tasks(id, job_id, external_id, title,"
                " description, capability, risk, status)"
                " VALUES (%s,%s,%s,'t','d','basic','low',%s)",
                (task, job, f"ext-{task}", status))
        self.setup.commit()
        return task

    # ---- independent authoritative reads ----

    def _fresh(self, sql, params=()):
        """Read from a brand-new connection with no test session state."""
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall() if cur.description else None
        finally:
            conn.close()

    def task_state(self, task):
        """status, lease_owner, lease_version, lease_expires_at, checkpoint_seq."""
        return self._fresh(
            "SELECT status, lease_owner, lease_version, lease_expires_at,"
            " checkpoint_seq FROM tasks WHERE id=%s", (task,))[0]

    def prove_task_visible_and_owned_by(self, task, expected_tenant):
        """R5/R7: the target must really exist and really belong elsewhere.

        Without this, a 'foreign' denial could be an invisibility artefact
        and the test would prove nothing.
        """
        rows = self._fresh(
            "SELECT t.id, j.tenant_id, t.status FROM tasks t"
            " JOIN jobs j ON j.id = t.job_id WHERE t.id = %s", (task,))
        self.assertEqual(len(rows), 1,
                         "target task must exist and be independently visible")
        self.assertEqual(rows[0][1], expected_tenant,
                         "target task must belong to the expected foreign tenant")
        return rows[0]

    def prove_job_visible_and_owned_by(self, job, expected_tenant):
        rows = self._fresh(
            "SELECT id, tenant_id FROM jobs WHERE id = %s", (job,))
        self.assertEqual(len(rows), 1,
                         "target job must exist and be independently visible")
        self.assertEqual(rows[0][1], expected_tenant)
        return rows[0]

    def prove_task_eligible(self, task):
        """The foreign task must be an eligible candidate, not merely present."""
        row = self._fresh(
            "SELECT status, next_attempt_at, lease_expires_at"
            " FROM tasks WHERE id=%s", (task,))[0]
        self.assertEqual(row[0], "pending", "candidate must be READY")
        self.assertTrue(row[1] is None or row[1] <= datetime.now(timezone.utc),
                        "candidate must not be deferred into the future")
        self.assertTrue(row[2] is None, "candidate must hold no live lease")
        return row

    # ---- claim_task ----

    def test_claim_task_same_tenant_succeeds(self):
        """R4: production really runs, sees the fixture, and claims."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.tenant_id, self.tenant)
        self.assertEqual(lease.task_id, task)
        state = self.task_state(task)
        self.assertEqual(state[0], "running", "status must be claimed")
        self.assertEqual(state[1], lease.owner_id, "lease owner must be set")
        self.assertEqual(state[2], 1, "lease_version must increment once")
        self.assertIsNotNone(state[3], "lease_expires_at must be set")

    def test_claim_task_foreign_tenant_denied_and_task_unchanged(self):
        """R5/R3: non-vacuous denial with fresh after-state."""
        job = self.job(self.tenant)
        task = self.task(job)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.TaskAlreadyClaimed):
            checkpoint.claim_task(task, uuid4(), tenant_id=self.foreign)
        self.assertEqual(self.task_state(task), before)

    def test_claim_task_missing_and_foreign_are_uniform(self):
        """R6: canonicalize only the specific supplied id, then exact-compare."""
        job = self.job(self.tenant)
        task = self.task(job)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        missing = uuid4()
        messages, classes = [], set()
        for target, tenant in ((missing, self.tenant), (task, self.foreign)):
            with self.assertRaises(checkpoint.TaskAlreadyClaimed) as ctx:
                checkpoint.claim_task(target, uuid4(), tenant_id=tenant)
            messages.append(
                _canonical_message(str(ctx.exception), [target]))
            classes.add(type(ctx.exception))
        self.assertEqual(len(classes), 1, "exception class must be identical")
        for message in messages:
            self.assertEqual(message, EXPECTED_DENIAL_MESSAGE)
        self.assertEqual(messages[0], messages[1],
                         "missing and foreign must be externally identical")

    # ---- renew_lease ----

    def test_renew_lease_same_tenant_succeeds(self):
        """R4/R8: correct owner and version, caller tenant carried."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        before_expiry = self.task_state(task)[3]
        renewed = checkpoint.renew_lease(lease, tenant_id=self.tenant)
        self.assertEqual(renewed.tenant_id, self.tenant)
        self.assertEqual(renewed.version, lease.version)
        state = self.task_state(task)
        self.assertEqual(state[1], lease.owner_id, "owner must be preserved")
        self.assertEqual(state[2], lease.version, "version must be preserved")
        self.assertGreaterEqual(state[3], before_expiry,
                                "expiry must not move backwards")

    def test_renew_lease_foreign_tenant_denied_and_state_unchanged(self):
        """R5/R3: owner, version, expiry and status all unchanged."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(lease, tenant_id=self.foreign)
        self.assertEqual(self.task_state(task), before)

    def test_renew_lease_lease_tenant_is_not_authority(self):
        """A lease that knows the owner tenant is not self-authorizing."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        self.assertEqual(lease.tenant_id, self.tenant)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(lease, tenant_id=self.foreign)
        self.assertEqual(self.task_state(task), before)

    def test_renew_lease_stale_version_rejected_and_state_unchanged(self):
        """R8: the lease-version fence must survive tenant scoping."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        stale = dataclasses.replace(lease, version=lease.version + 5)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(stale, tenant_id=self.tenant)
        self.assertEqual(self.task_state(task), before)

    def test_renew_lease_wrong_owner_rejected_and_state_unchanged(self):
        """R8: the owner fence must survive tenant scoping."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        impostor = dataclasses.replace(lease, owner_id=uuid4())
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(impostor, tenant_id=self.tenant)
        self.assertEqual(self.task_state(task), before)

    # ---- claim_next_ready_task ----

    def test_claim_next_same_tenant_succeeds(self):
        """R4: real PostgreSQL executes the JOIN and the task-only lock."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.tenant)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.task_id, task)
        self.assertEqual(lease.tenant_id, self.tenant)
        state = self.task_state(task)
        self.assertEqual(state[0], "running")
        self.assertEqual(state[1], lease.owner_id)
        self.assertEqual(state[2], 1)

    def test_claim_next_foreign_tenant_cannot_claim(self):
        """R5/R3: foreign job proven to exist and be tenant-eligible first."""
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        self.prove_job_visible_and_owned_by(foreign_job, self.foreign)
        self.prove_task_visible_and_owned_by(foreign_task, self.foreign)
        self.prove_task_eligible(foreign_task)
        before = self.task_state(foreign_task)
        self.assertIsNone(scheduler.claim_next_ready_task(
            foreign_job, uuid4(), tenant_id=self.tenant))
        self.assertEqual(self.task_state(foreign_task), before,
                         "foreign candidate must be untouched")

    def test_claim_next_foreign_job_id_under_own_tenant_cannot_claim(self):
        """Own tenant but a foreign job id is still outside the scope."""
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        self.prove_job_visible_and_owned_by(foreign_job, self.foreign)
        self.prove_task_eligible(foreign_task)
        before = self.task_state(foreign_task)
        self.assertIsNone(scheduler.claim_next_ready_task(
            foreign_job, uuid4(), tenant_id=self.tenant))
        self.assertEqual(self.task_state(foreign_task), before)

    def test_claim_next_missing_and_foreign_job_are_uniform(self):
        """R7: both unavailable cases give the identical None contract."""
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        self.prove_job_visible_and_owned_by(foreign_job, self.foreign)
        self.prove_task_eligible(foreign_task)
        missing = uuid4()
        outcomes = set()
        for target, tenant in ((missing, self.tenant),
                               (foreign_job, self.tenant)):
            outcomes.add(scheduler.claim_next_ready_task(
                target, uuid4(), tenant_id=tenant))
        self.assertEqual(outcomes, {None},
                         "missing and foreign job must both yield no claim")

    def test_claim_next_does_not_lock_or_consume_foreign_tasks(self):
        """Repeated foreign attempts leave the foreign task claimable by its
        own tenant, proving no consumption and no permanent contention."""
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        self.prove_job_visible_and_owned_by(foreign_job, self.foreign)
        self.prove_task_eligible(foreign_task)
        before = self.task_state(foreign_task)
        for _ in range(3):
            self.assertIsNone(scheduler.claim_next_ready_task(
                foreign_job, uuid4(), tenant_id=self.tenant))
        self.assertEqual(self.task_state(foreign_task), before)
        lease = scheduler.claim_next_ready_task(
            foreign_job, uuid4(), tenant_id=self.foreign)
        self.assertIsNotNone(lease,
                             "owning tenant must still be able to claim it")
        self.assertEqual(lease.task_id, foreign_task)

    def test_lease_carries_exact_caller_tenant(self):
        job = self.job(self.tenant)
        self.task(job)
        lease = scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.tenant)
        self.assertEqual(lease.tenant_id, self.tenant)
        self.assertNotEqual(lease.tenant_id, self.foreign)


if __name__ == "__main__":
    unittest.main()
