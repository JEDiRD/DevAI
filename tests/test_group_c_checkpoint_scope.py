"""Group C2 -- checkpoint tenant hardening.

C2 hardens the four remaining checkpoint operations: ``save_checkpoint``,
``load_latest_checkpoint``, ``release_task`` and ``defer_task_for_route``.

Authority model, inherited from C1:

* the three APIs that receive a ``TaskLease`` take their authority from
  ``lease.tenant_id`` -- the caller tenant already proven at claim time. They
  gain no redundant parameter;
* ``load_latest_checkpoint`` receives no lease, so it takes a mandatory
  keyword-only ``tenant_id`` from its caller.

Authority is never re-derived from a job, task or checkpoint row.

Every effect-producing statement carries its OWN ownership proof. In
particular both ``task_checkpoints`` INSERTs are INSERT ... SELECT that
re-prove tasks -> jobs ownership inside the INSERT, rather than trusting a
tenant-scoped UPDATE that ran earlier in the same transaction.

This file also carries an EXECUTED structural mutation matrix, reported
separately from the structural controls.
"""

import ast
import dataclasses
import inspect
import os
import unittest
from uuid import uuid4

import psycopg

from devai import checkpoint, runtime, scheduler
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

DEVAI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CK_PATH = os.path.join(DEVAI_ROOT, "controller", "devai", "checkpoint.py")


def _code(sql):
    """Canonical uppercase form of one SQL statement."""
    return canonical(_tokenize(sql)).upper()


def _literal_strings(tree):
    """SQL literals only: the first argument of each cur.execute(...) call.

    Collecting every string constant would sweep in docstrings, which are not
    SQL and would corrupt every statement-shape assertion.
    """
    out = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "execute"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)):
            out.append((node.args[0].value, _code(node.args[0].value)))
    return out


def _func_source(source, name):
    """Exact source text of `name` inside `source`."""
    func = _find_func(source, name)
    return ast.get_source_segment(source, func) or ""


def _neutralization_defects(sql):
    """Boolean neutralization in one SQL statement (OR TRUE / OR 1=1)."""
    toks = [t.text.upper() for t in _tokenize(sql)
            if t.kind in ("name", "number")]
    return [f"OR {toks[i + 1]}" for i, t in enumerate(toks[:-1])
            if t == "OR" and toks[i + 1] in ("TRUE", "1")]


def _statements(func):
    """(raw, canonical) for every SQL literal in a function, in order."""
    tree = ast.parse(inspect.cleandoc(inspect.getsource(func)))
    return _literal_strings(tree)


def _find_func(source, name):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _execute_literals(func):
    """The cur.execute() SQL literals of a function, in source order."""
    return [n.args[0] for n in ast.walk(func)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", None) == "execute"
            and n.args
            and isinstance(n.args[0], ast.Constant)
            and isinstance(n.args[0].value, str)]


def _mutate_in_function(source, func_name, old, new):
    """Apply old->new ONLY inside func_name's own source slice.

    For non-SQL mutants (e.g. removing a zero-row guard). SQL mutants must use
    _mutate_in_statement instead: a guard UPDATE and its INSERT carry the
    byte-identical line 'AND j.tenant_id = %s' at the same indentation, so a
    first-match replacement inside the function silently hits the WRONG
    statement and the invariant then credits the guard for an INSERT mutant.
    """
    func = _find_func(source, func_name)
    if func is None:
        raise AssertionError(f"{func_name} not found")
    lines = source.splitlines(keepends=True)
    start, end = func.lineno - 1, func.end_lineno
    segment = "".join(lines[start:end])
    if old not in segment:
        raise AssertionError(f"mutant does not apply in {func_name}: {old!r}")
    return ("".join(lines[:start]) + segment.replace(old, new, 1)
            + "".join(lines[end:]))


def _mutate_in_statement(source, func_name, stmt_index, old, new):
    """Apply old->new ONLY inside the stmt_index-th execute() SQL literal."""
    func = _find_func(source, func_name)
    if func is None:
        raise AssertionError(f"{func_name} not found")
    literals = _execute_literals(func)
    if stmt_index >= len(literals):
        raise AssertionError(
            f"{func_name} has {len(literals)} execute() statements, "
            f"index {stmt_index} requested")
    lit = literals[stmt_index]
    lines = source.splitlines(keepends=True)
    offsets, acc = [], 0
    for line in lines:
        offsets.append(acc)
        acc += len(line)
    start = offsets[lit.lineno - 1] + lit.col_offset
    end = offsets[lit.end_lineno - 1] + lit.end_col_offset
    segment = source[start:end]
    if old not in segment:
        raise AssertionError(
            f"mutant does not apply in {func_name} stmt {stmt_index}: {old!r}")
    return source[:start] + segment.replace(old, new, 1) + source[end:]


# ===========================================================================
# SHARED INVARIANT CHECKER
# ===========================================================================


def _c2_invariants(source, func_name):
    """Invariant violations for a C2 checkpoint function.

    Empty list means the variant satisfies every C2 invariant. The SAME
    checker is applied to the authoritative source and to every mutant.
    """
    func = _find_func(source, func_name)
    if func is None:
        return [f"{func_name}:absent"]

    stmts = _literal_strings(func)
    canonical_sql = "\n".join(c for _, c in stmts)
    joined = "\n".join(raw for raw, _ in stmts)
    bad = []

    inserts = [(raw, c) for raw, c in stmts
               if c.lstrip().startswith("INSERT INTO TASK_CHECKPOINTS")]
    updates = [(raw, c) for raw, c in stmts if c.lstrip().startswith("UPDATE")]
    selects = [(raw, c) for raw, c in stmts
               if c.lstrip().startswith("SELECT")]

    # -- authority is never re-derived from a row --
    if func_name == "load_latest_checkpoint":
        params = [a.arg for a in func.args.args]
        kwonly = [a.arg for a in func.args.kwonlyargs]
        if "tenant_id" not in kwonly:
            bad.append("no_mandatory_tenant_argument")
        # tenant must not be selected FROM a row as authority
        if "J . TENANT_ID" in canonical_sql and "= %S" not in canonical_sql:
            bad.append("tenant_selected_as_authority")

    # -- the tenant predicate must live in the statement that has effect --
    scoped_statements = updates + selects + inserts
    if not any("J . TENANT_ID = %S" in c for _, c in scoped_statements):
        bad.append("no_tenant_predicate_in_any_statement")

    for _, c in scoped_statements:
        if _neutralization_defects(c):
            bad.append("boolean_neutralized")

    if func_name == "load_latest_checkpoint":
        if not selects:
            bad.append("no_select")
        else:
            sql = selects[-1][1]
            for needed, label in (("JOIN TASKS T", "join_tasks_missing"),
                                  ("ON T . ID = CP . TASK_ID", "join_tasks_wrong"),
                                  ("JOIN JOBS J", "join_jobs_missing"),
                                  ("ON J . ID = T . JOB_ID", "join_jobs_wrong"),
                                  ("CP . TASK_ID = %S", "task_binding_missing"),
                                  ("J . TENANT_ID = %S", "tenant_predicate_missing"),
                                  ("ORDER BY CP . SEQUENCE DESC", "ordering_lost"),
                                  ("LIMIT 1", "limit_lost")):
                if needed not in sql:
                    bad.append(f"load_{label}")

    if func_name == "release_task":
        if not updates:
            bad.append("no_update")
        else:
            sql = updates[-1][1]
            for needed, label in (("FROM JOBS J", "from_jobs_missing"),
                                  ("J . ID = T . JOB_ID", "join_jobs_wrong"),
                                  ("T . ID = %S", "task_binding_missing"),
                                  ("J . TENANT_ID = %S", "tenant_predicate_missing"),
                                  ("T . LEASE_OWNER = %S", "owner_fence_lost"),
                                  ("T . LEASE_VERSION = %S", "version_fence_lost"),
                                  ("T . LEASE_EXPIRES_AT > NOW ( )", "expiry_fence_lost")):
                if needed not in sql:
                    bad.append(f"release_{label}")

    if func_name in ("save_checkpoint", "defer_task_for_route"):
        # -- guard UPDATE must itself be tenant scoped --
        guard = updates[0][1] if updates else ""
        for needed, label in (("FROM JOBS J", "guard_from_jobs_missing"),
                              ("J . ID = T . JOB_ID", "guard_join_jobs_wrong"),
                              ("J . TENANT_ID = %S", "guard_tenant_predicate_missing"),
                              ("T . LEASE_OWNER = %S", "guard_owner_fence_lost"),
                              ("T . LEASE_VERSION = %S", "guard_version_fence_lost"),
                              ("T . LEASE_EXPIRES_AT > NOW ( )", "guard_expiry_fence_lost")):
            if needed not in guard:
                bad.append(f"{func_name}_{label}")

        # -- the INSERT must be INSERT ... SELECT with its OWN proof --
        if not inserts:
            bad.append("no_checkpoint_insert")
        else:
            raw, sql = inserts[0]
            if "INSERT INTO TASK_CHECKPOINTS" in raw.upper() \
                    and "VALUES" in raw.upper() and "SELECT" not in raw.upper():
                bad.append("insert_is_unscoped_values")
            for needed, label in (("SELECT", "insert_not_insert_select"),
                                  ("FROM TASKS T", "insert_source_tasks_missing"),
                                  ("JOIN JOBS J", "insert_join_jobs_missing"),
                                  ("ON J . ID = T . JOB_ID", "insert_join_jobs_wrong"),
                                  ("T . ID = %S", "insert_task_binding_missing"),
                                  ("J . TENANT_ID = %S", "insert_tenant_predicate_missing"),
                                  ("T . CHECKPOINT_SEQ = %S", "insert_seq_fence_lost")):
                if needed not in sql:
                    bad.append(f"{func_name}_{label}")
            # save_checkpoint keeps the lease held, so its INSERT must also bind
            # owner and version. defer_task_for_route releases the lease before
            # inserting and legitimately cannot.
            if func_name == "save_checkpoint":
                for needed, label in (("T . LEASE_OWNER = %S",
                                       "insert_owner_fence_lost"),
                                      ("T . LEASE_VERSION = %S",
                                       "insert_version_fence_lost")):
                    if needed not in sql:
                        bad.append(f"{func_name}_{label}")
            # the INSERT must select the task id rather than echoing a literal
            if "T . ID" not in sql:
                bad.append(f"{func_name}_insert_does_not_source_task_id")

        # -- zero-row INSERT must be detected, not treated as success --
        if "RETURNING CREATED_AT" not in joined.upper():
            bad.append(f"{func_name}_insert_no_returning")
        elif "if inserted is None" not in _func_source(source, func_name):
            bad.append(f"{func_name}_insert_zero_row_not_detected")

    return bad


# ===========================================================================
# SECTION 1: API CONTRACT (static)
# ===========================================================================


class C2SignatureTests(unittest.TestCase):
    """Lease-taking APIs keep one authority; the lease-free API gains one."""

    LEASE_APIS = ("save_checkpoint", "release_task", "defer_task_for_route")

    def test_lease_apis_take_authority_from_the_lease_not_a_new_argument(self):
        for name in self.LEASE_APIS:
            params = inspect.signature(
                getattr(checkpoint, name)).parameters
            self.assertIn("lease", params, name)
            self.assertNotIn("tenant_id", params,
                             f"{name} must not gain a redundant tenant_id")

    def test_load_latest_checkpoint_takes_mandatory_keyword_only_tenant(self):
        p = inspect.signature(checkpoint.load_latest_checkpoint
                              ).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)

    def test_no_c2_api_defaults_tenant_or_allows_none(self):
        for name in (*self.LEASE_APIS, "load_latest_checkpoint"):
            src = inspect.cleandoc(
                inspect.getsource(getattr(checkpoint, name)))
            self.assertNotIn("tenant_id=None", src, name)
            self.assertNotIn("tenant_id: UUID =", src, name)

    def test_authority_is_never_read_from_a_row(self):
        """No C2 API may SELECT jobs.tenant_id and treat it as authority."""
        for name in (*self.LEASE_APIS, "load_latest_checkpoint"):
            stmts = _statements(getattr(checkpoint, name))
            for raw, canon in stmts:
                selects_tenant = canon.lstrip().startswith("SELECT") and (
                    "J . TENANT_ID" in canon and "J . TENANT_ID = %S"
                    not in canon)
                if selects_tenant:
                    self.fail(f"{name} selects the row tenant as authority")
            if name in self.LEASE_APIS:
                self.assertIn("lease.tenant_id",
                              inspect.cleandoc(inspect.getsource(
                                  getattr(checkpoint, name))),
                              f"{name} must use lease.tenant_id")

    def test_run_claimed_task_signature_unchanged(self):
        self.assertEqual(
            list(inspect.signature(runtime.run_claimed_task).parameters),
            ["lease", "reservation_by_cost_class", "gateway"])

    def test_load_runtime_task_unchanged(self):
        self.assertEqual(
            list(inspect.signature(runtime.load_runtime_task).parameters),
            ["task_id"])


# ===========================================================================
# SECTION 2: STRUCTURAL CONTROLS (static)
# ===========================================================================


class C2StatementShapeTests(unittest.TestCase):
    """Direct assertions on the authoritative C2 source."""

    def test_save_guard_update_is_tenant_scoped(self):
        sql = "\n".join(c for _, c in _statements(checkpoint.save_checkpoint))
        guard = sql.split("INSERT")[0]
        self.assertIn("FROM JOBS J", guard)
        self.assertIn("J . TENANT_ID = %S", guard)
        self.assertIn("T . LEASE_OWNER = %S", guard)
        self.assertIn("T . LEASE_VERSION = %S", guard)

    def test_save_insert_is_insert_select_with_own_ownership_proof(self):
        raw, sql = [(r, c) for r, c in _statements(checkpoint.save_checkpoint)
                    if c.lstrip().startswith("INSERT")][0]
        self.assertIn("SELECT", raw.upper())
        self.assertIn("FROM TASKS T", sql)
        self.assertIn("JOIN JOBS J", sql)
        self.assertIn("J . ID = T . JOB_ID", sql)
        self.assertIn("J . TENANT_ID = %S", sql)
        self.assertIn("T . CHECKPOINT_SEQ = %S", sql)

    def test_defer_insert_is_insert_select_with_own_ownership_proof(self):
        raw, sql = [(r, c) for r, c in
                    _statements(checkpoint.defer_task_for_route)
                    if c.lstrip().startswith("INSERT")][0]
        self.assertIn("SELECT", raw.upper())
        self.assertIn("FROM TASKS T", sql)
        self.assertIn("JOIN JOBS J", sql)
        self.assertIn("J . ID = T . JOB_ID", sql)
        self.assertIn("J . TENANT_ID = %S", sql)

    def test_no_c2_insert_uses_unscoped_values(self):
        for name in ("save_checkpoint", "defer_task_for_route"):
            for raw, _ in _statements(getattr(checkpoint, name)):
                if "INSERT INTO TASK_CHECKPOINTS" in raw.upper():
                    self.assertNotIn("VALUES", raw.upper(),
                                     f"{name} must not use a VALUES insert")

    def test_load_select_is_tenant_scoped_and_keeps_ordering(self):
        sql = [c for _, c in _statements(checkpoint.load_latest_checkpoint)
               if c.lstrip().startswith("SELECT")][0]
        self.assertIn("JOIN TASKS T", sql)
        self.assertIn("JOIN JOBS J", sql)
        self.assertIn("J . TENANT_ID = %S", sql)
        self.assertIn("ORDER BY CP . SEQUENCE DESC", sql)
        self.assertIn("LIMIT 1", sql)

    def test_release_update_is_tenant_scoped_and_keeps_fences(self):
        sql = [c for _, c in _statements(checkpoint.release_task)][0]
        self.assertIn("FROM JOBS J", sql)
        self.assertIn("J . TENANT_ID = %S", sql)
        self.assertIn("T . LEASE_OWNER = %S", sql)
        self.assertIn("T . LEASE_VERSION = %S", sql)
        self.assertIn("T . LEASE_EXPIRES_AT > NOW ( )", sql)

    def test_c2_statements_resist_boolean_neutralization(self):
        for name in ("save_checkpoint", "load_latest_checkpoint",
                     "release_task", "defer_task_for_route"):
            for raw, canon in _statements(getattr(checkpoint, name)):
                self.assertEqual(
                    _neutralization_defects(canon), [], f"{name}: {raw[:60]}")

    def test_neutralization_forms_are_individually_rejected(self):
        for bypass in ("OR TRUE", "OR 1=1", "OR 1 = 1"):
            base = _code("SELECT 1 FROM tasks t JOIN jobs j ON j.id=t.job_id"
                         " WHERE j.tenant_id = %s")
            mutated = base.replace("J . TENANT_ID = %S",
                                   f"J . TENANT_ID = %S {bypass}")
            self.assertNotEqual(_neutralization_defects(mutated), [],
                                f"{bypass} not rejected")

    def test_zero_row_insert_is_detected_in_both_mutating_apis(self):
        for name in ("save_checkpoint", "defer_task_for_route"):
            src = inspect.cleandoc(inspect.getsource(
                getattr(checkpoint, name)))
            self.assertIn("if inserted is None", src,
                          f"{name} must detect an unauthorized zero-row insert")
            self.assertIn("RETURNING created_at", src, name)


# ===========================================================================
# SECTION 3: EXECUTED MUTATION MATRIX
# ===========================================================================

TENANT_PRED = "                  AND j.tenant_id = %s\n"

# Statement indices per function: save_checkpoint / defer_task_for_route are
# [guard UPDATE, checkpoint INSERT]; load and release are single-statement.
SAVE_GUARD, SAVE_INS = 0, 1
DEFER_GUARD, DEFER_INS = 0, 1
LOAD_SEL, RELEASE_UPD = 0, 0

# (id, label, function, stmt_index, old, new) -- stmt_index None means a
# non-SQL (function-body) mutation, applied with _mutate_in_function.
MUTATION_MATRIX = [
    # save_checkpoint -- guard UPDATE (4)
    ("C2M01", "save guard UPDATE tenant predicate removed",
     "save_checkpoint", SAVE_GUARD, TENANT_PRED, ""),
    ("C2M02", "save guard UPDATE tenant binding wrong",
     "save_checkpoint", SAVE_GUARD, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M03", "save guard UPDATE boolean neutralization",
     "save_checkpoint", SAVE_GUARD, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("C2M04", "save guard UPDATE ownership join removed",
     "save_checkpoint", SAVE_GUARD,
     "                FROM jobs j\n                WHERE j.id = t.job_id\n", ""),
    # save_checkpoint -- INSERT (7)
    ("C2M05", "save INSERT tenant predicate removed",
     "save_checkpoint", SAVE_INS, TENANT_PRED, ""),
    ("C2M06", "save INSERT tenant binding wrong",
     "save_checkpoint", SAVE_INS, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M07", "save INSERT authorization join removed",
     "save_checkpoint", SAVE_INS,
     "                JOIN jobs j\n                  ON j.id = t.job_id\n", ""),
    ("C2M08", "save INSERT converted to unscoped VALUES",
     "save_checkpoint", SAVE_INS,
     "                SELECT %s, t.id, %s, %s, %s\n",
     "                VALUES (%s, %s, %s, %s, %s)\n"),
    ("C2M09", "save INSERT boolean neutralization",
     "save_checkpoint", SAVE_INS, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("C2M10", "save INSERT sequence fence removed",
     "save_checkpoint", SAVE_INS,
     "                  AND t.checkpoint_seq = %s\n", ""),
    ("C2M11", "save INSERT lease-owner fence removed",
     "save_checkpoint", SAVE_INS,
     "                  AND t.lease_owner = %s\n", ""),
    ("C2M12", "save zero-row INSERT detection removed",
     "save_checkpoint", None,
     "            if inserted is None:\n"
     "                raise LeaseLost(\n"
     "                    \"Cannot checkpoint with a stale lease\"\n"
     "                )\n\n", ""),
    # load_latest_checkpoint (4)
    ("C2M13", "load SELECT tenant predicate removed",
     "load_latest_checkpoint", LOAD_SEL, TENANT_PRED, ""),
    ("C2M14", "load SELECT tenant binding wrong",
     "load_latest_checkpoint", LOAD_SEL, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M15", "load SELECT authorization join removed",
     "load_latest_checkpoint", LOAD_SEL,
     "                JOIN jobs j\n                  ON j.id = t.job_id\n", ""),
    ("C2M16", "load SELECT boolean neutralization",
     "load_latest_checkpoint", LOAD_SEL, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    # release_task (3)
    ("C2M17", "release tenant predicate removed",
     "release_task", RELEASE_UPD, TENANT_PRED, ""),
    ("C2M18", "release tenant binding wrong",
     "release_task", RELEASE_UPD, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M19", "release boolean neutralization",
     "release_task", RELEASE_UPD, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    # defer_task_for_route -- guard UPDATE (3)
    ("C2M20", "defer guard UPDATE tenant predicate removed",
     "defer_task_for_route", DEFER_GUARD, TENANT_PRED, ""),
    ("C2M21", "defer guard UPDATE tenant binding wrong",
     "defer_task_for_route", DEFER_GUARD, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M22", "defer guard UPDATE boolean neutralization",
     "defer_task_for_route", DEFER_GUARD, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    # defer_task_for_route -- INSERT (5)
    ("C2M23", "defer INSERT tenant predicate removed",
     "defer_task_for_route", DEFER_INS, TENANT_PRED, ""),
    ("C2M24", "defer INSERT tenant binding wrong",
     "defer_task_for_route", DEFER_INS, TENANT_PRED, "                  AND j.id = %s\n"),
    ("C2M25", "defer INSERT authorization join removed",
     "defer_task_for_route", DEFER_INS,
     "                JOIN jobs j\n                  ON j.id = t.job_id\n", ""),
    ("C2M26", "defer INSERT converted to unscoped VALUES",
     "defer_task_for_route", DEFER_INS,
     "                SELECT %s, t.id, %s, %s, %s\n",
     "                VALUES (%s, %s, %s, %s, %s)\n"),
    ("C2M27", "defer INSERT boolean neutralization",
     "defer_task_for_route", DEFER_INS, TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("C2M28", "defer INSERT sequence fence removed",
     "defer_task_for_route", DEFER_INS,
     "                  AND t.checkpoint_seq = %s\n", ""),
]


class C2MutationMatrixTests(unittest.TestCase):
    """Executed mutation matrix over real production source.

    Verdicts: ASSERTION_CAUGHT (invariants rejected it), HARNESS_ERROR
    (unparseable or unloadable, never counted as a catch), SURVIVED
    (invariants accepted it -- a real evidence gap).
    """

    def _source(self):
        with open(CK_PATH, encoding="utf-8") as handle:
            return handle.read()

    def _verdict(self, func_name, stmt_index, old, new):
        source = self._source()
        mutated = (_mutate_in_function(source, func_name, old, new)
                   if stmt_index is None
                   else _mutate_in_statement(source, func_name, stmt_index,
                                              old, new))
        try:
            ast.parse(mutated)
        except SyntaxError:
            return "HARNESS_ERROR", ["SyntaxError"]
        try:
            violations = _c2_invariants(mutated, func_name)
        except Exception as exc:                        # noqa: BLE001
            return "HARNESS_ERROR", [f"{type(exc).__name__}:{exc}"]
        return ("ASSERTION_CAUGHT" if violations else "SURVIVED"), violations

    def test_authoritative_source_has_zero_violations(self):
        """Baseline: real production must fully conform."""
        source = self._source()
        for name in ("save_checkpoint", "load_latest_checkpoint",
                     "release_task", "defer_task_for_route"):
            self.assertEqual(_c2_invariants(source, name), [],
                             f"{name} baseline violations")

    def test_matrix_is_frozen_at_its_inventory_size(self):
        """Count and ids are pinned, not tuned to the outcome."""
        self.assertEqual(len(MUTATION_MATRIX), 28)
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(len(set(ids)), 28, "mutant ids must be unique")

    def test_each_mutant_touches_only_its_intended_statement(self):
        """Isolation guard, at statement granularity.

        A guard UPDATE and its INSERT share byte-identical predicate lines, so
        this asserts the mutated statement actually differs while its sibling
        statement stays byte-identical.
        """
        source = self._source()
        others = ["save_checkpoint", "load_latest_checkpoint",
                  "release_task", "defer_task_for_route"]
        for mid, _label, func_name, stmt_index, old, new in MUTATION_MATRIX:
            mutated = (_mutate_in_function(source, func_name, old, new)
                       if stmt_index is None
                       else _mutate_in_statement(source, func_name, stmt_index,
                                                  old, new))
            if stmt_index is None:
                before = ast.get_source_segment(source,
                                                _find_func(source, func_name))
                after = ast.get_source_segment(mutated,
                                               _find_func(mutated, func_name))
                self.assertNotEqual(before, after, f"{mid} did not change target")
            else:
                b_stmts = [n.value for n in
                           _execute_literals(_find_func(source, func_name))]
                m_stmts = [n.value for n in
                           _execute_literals(_find_func(mutated, func_name))]
                self.assertEqual(len(b_stmts), len(m_stmts),
                                 f"{mid} changed statement count")
                self.assertNotEqual(b_stmts[stmt_index],
                                    m_stmts[stmt_index],
                                    f"{mid} did not change stmt {stmt_index}")
                for i, (b, m) in enumerate(zip(b_stmts, m_stmts)):
                    if i != stmt_index:
                        self.assertEqual(
                            b, m,
                            f"{mid}: stmt {i} must stay byte-identical")
            for other in others:
                if other == func_name:
                    continue
                self.assertEqual(
                    ast.get_source_segment(source, _find_func(source, other)),
                    ast.get_source_segment(mutated, _find_func(mutated, other)),
                    f"{mid}: {other} must stay byte-identical")

    def test_insert_mutants_actually_hit_the_insert_statement(self):
        """Belt-and-braces: INSERT mutants must report INSERT violations.

        Without this, a guard-hit mutant could satisfy an INSERT invariant and
        be counted as INSERT coverage while proving nothing about the INSERT.
        """
        source = self._source()
        for mid, _label, func_name, stmt_index, old, new in MUTATION_MATRIX:
            if stmt_index is None:
                continue
            mutated = _mutate_in_statement(source, func_name, stmt_index,
                                           old, new)
            b = [n.value for n in
                 _execute_literals(_find_func(source, func_name))]
            m = [n.value for n in
                 _execute_literals(_find_func(mutated, func_name))]
            self.assertNotEqual(b[stmt_index], m[stmt_index], mid)

    def _run(self, mid):
        for entry in MUTATION_MATRIX:
            if entry[0] == mid:
                # entry = (id, label, func, stmt_index, old, new)
                verdict, violations = self._verdict(*entry[2:])
                self.assertNotEqual(
                    verdict, "HARNESS_ERROR",
                    f"{mid} harness error: {violations}")
                self.assertNotEqual(
                    verdict, "SURVIVED", f"{mid} SURVIVED")
                self.assertTrue(violations, f"{mid} produced no detail")
                return
        self.fail(f"{mid} not in inventory")

    def test_matrix_execution(self):
        """Every frozen mutant is executed and must be rejected."""
        for entry in MUTATION_MATRIX:
            self._run(entry[0])


# ===========================================================================
# SECTION 4: LIVE REACHABILITY + C1/C3 BOUNDARIES (static)
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


class C2BoundaryTests(unittest.TestCase):
    ACCEPTED_LIVE_CLOSURE = {"db", "worker_api", "worker_dispatch",
                             "worker_identity", "worker_registry"}

    def test_live_closure_unchanged_and_dormant(self):
        closure = _live_closure("worker_api")
        self.assertEqual(closure, self.ACCEPTED_LIVE_CLOSURE)
        for mod in ("runtime", "scheduler", "checkpoint", "executor"):
            self.assertNotIn(mod, closure)

    def test_live_worker_subsystem_untouched_by_c2(self):
        import subprocess
        base = "b0d95f6eadb57ece278aafe63802bfec74f5d882"
        out = subprocess.run(
            ["git", "diff", "--name-only", base, "--", "controller/devai"],
            cwd=DEVAI_ROOT, capture_output=True, text=True)
        changed = [p for p in out.stdout.split()
                   if p and os.path.basename(p) in (
                       "worker_api.py", "worker_dispatch.py",
                       "worker_identity.py", "worker_registry.py")]
        self.assertEqual(changed, [], "C2 must not touch the live subsystem")

    def test_scheduler_untouched_by_c2(self):
        """C1 owns the claim surface; C2 must not change it."""
        import subprocess
        out = subprocess.run(
            ["git", "diff", "--name-only",
             "b0d95f6eadb57ece278aafe63802bfec74f5d882", "--",
             "controller/devai/scheduler.py"],
            cwd=DEVAI_ROOT, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "",
                         "C2 must not modify scheduler.py")

    def test_no_migrations_added(self):
        import subprocess
        out = subprocess.run(
            ["git", "status", "--porcelain", "--", "migrations"],
            cwd=DEVAI_ROOT, capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "", "C2 must not add migrations")

    def test_runtime_propagates_lease_tenant_only(self):
        """C3 owns runtime authority continuity; C2 only forwards the lease.

        Scoped to the checkpoint call sites only. ``tenant_id=task.tenant_id``
        legitimately appears when runtime builds the observers and resolves
        gateways; that is pre-existing code C2 must not touch, so a blanket
        substring ban would forbid the wrong thing.
        """
        src = inspect.cleandoc(inspect.getsource(runtime.run_claimed_task))
        tree = ast.parse(src)
        checkpoint_calls = {
            "load_latest_checkpoint", "save_checkpoint",
            "release_task", "defer_task_for_route",
        }
        seen = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # runtime imports these names directly, so they are ast.Name
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name not in checkpoint_calls:
                continue
            seen += 1
            for kw in node.keywords:
                if kw.arg == "tenant_id":
                    self.assertIsInstance(
                        kw.value, ast.Attribute,
                        f"{name} must take tenant from the lease, not a row")
                    self.assertEqual(kw.value.attr, "tenant_id",
                                     f"{name} must use lease.tenant_id")
        self.assertEqual(seen, 9, "all nine runtime checkpoint calls inventoried")

    def test_runtime_checkpoint_calls_take_the_lease_object(self):
        """The lease-taking APIs must receive the lease, not a re-derived id."""
        src = inspect.cleandoc(inspect.getsource(runtime.run_claimed_task))
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name in ("save_checkpoint", "release_task",
                        "defer_task_for_route"):
                self.assertTrue(node.args, f"{name} must receive the lease")
                self.assertIsInstance(node.args[0], ast.Name)
                self.assertEqual(node.args[0].id, "lease")

    def test_c1_production_surface_unchanged(self):
        self.assertEqual(
            list(inspect.signature(scheduler.claim_next_ready_task).parameters),
            ["job_id", "owner_id", "lease_seconds", "tenant_id"])
        self.assertEqual(
            list(inspect.signature(checkpoint.claim_task).parameters),
            ["task_id", "owner_id", "lease_seconds", "tenant_id"])
        self.assertEqual(
            list(inspect.signature(checkpoint.renew_lease).parameters),
            ["lease", "lease_seconds", "tenant_id"])


# ===========================================================================
# SECTION 5: DB SECURITY (requires PostgreSQL)
# ===========================================================================


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class CheckpointScopeDatabaseTests(unittest.TestCase):
    """Cross-tenant checkpoint hardening against a real database.

    Fixtures are COMMITTED before production runs, and production uses its own
    real connections. After-state and pre-existence proofs come from
    independent connections so neither can be satisfied by the setup session.
    """

    def setUp(self):
        self.setup = psycopg.connect(_DB_URL)
        self.addCleanup(self.setup.close)
        self.tenant = uuid4()
        self.foreign = uuid4()
        self._tasks, self._jobs = [], []
        with self.setup.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s,%s,%s)",
                    (tenant, f"c2-{tenant}", "c2 checkpoint scope"))
        self.setup.commit()
        self.addCleanup(self._purge)

    def _purge(self):
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                if self._tasks:
                    cur.execute("DELETE FROM tasks WHERE id = ANY(%s)",
                                (self._tasks,))
                if self._jobs:
                    cur.execute("DELETE FROM jobs WHERE id = ANY(%s)",
                                (self._jobs,))
                cur.execute("DELETE FROM tenants WHERE id = ANY(%s)",
                            ([self.tenant, self.foreign],))
            conn.commit()
        finally:
            conn.close()

    def job(self, tenant=None):
        job = uuid4()
        self._jobs.append(job)
        with self.setup.cursor() as cur:
            cur.execute("INSERT INTO jobs(id, tenant_id, objective, status)"
                        " VALUES (%s,%s,'c2','running')",
                        (job, tenant or self.tenant))
        self.setup.commit()
        return job

    def task(self, job, status="pending"):
        task = uuid4()
        self._tasks.append(task)
        with self.setup.cursor() as cur:
            cur.execute(
                "INSERT INTO tasks(id, job_id, external_id, title,"
                " description, capability, risk, status)"
                " VALUES (%s,%s,%s,'t','d','basic','low',%s)",
                (task, job, f"ext-{task}", status))
        self.setup.commit()
        return task

    def _fresh(self, sql, params=()):
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall() if cur.description else None
        finally:
            conn.close()

    def task_state(self, task):
        return self._fresh(
            "SELECT status, lease_owner, lease_version, lease_expires_at,"
            " checkpoint_seq FROM tasks WHERE id=%s", (task,))[0]

    def checkpoint_count(self, task):
        return self._fresh(
            "SELECT count(*) FROM task_checkpoints WHERE task_id=%s",
            (task,))[0][0]

    def prove_task_visible_and_owned_by(self, task, expected_tenant):
        rows = self._fresh(
            "SELECT t.id, j.tenant_id FROM tasks t JOIN jobs j"
            " ON j.id = t.job_id WHERE t.id = %s", (task,))
        self.assertEqual(len(rows), 1, "target must exist independently")
        self.assertEqual(rows[0][1], expected_tenant)
        return rows[0]

    def claim(self, task, tenant):
        """Put a real, fence-valid lease on `task` as `tenant`."""
        return checkpoint.claim_task(task, uuid4(), tenant_id=tenant)

    # ---- same tenant ----

    def test_save_checkpoint_same_tenant_succeeds(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        cp = checkpoint.save_checkpoint(lease, {"phase": "unit"})
        self.assertEqual(cp.payload["phase"], "unit")
        self.assertEqual(cp.lease_version, lease.version)
        self.assertEqual(self.checkpoint_count(task), 1)
        self.assertEqual(self.task_state(task)[4], 1, "checkpoint_seq bumped")

    def test_load_latest_checkpoint_same_tenant_returns_latest(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        checkpoint.save_checkpoint(lease, {"n": 1})
        checkpoint.save_checkpoint(lease, {"n": 2})
        latest = checkpoint.load_latest_checkpoint(
            task, tenant_id=self.tenant)
        self.assertIsNotNone(latest)
        self.assertEqual(latest.payload["n"], 2, "must return the latest")

    def test_release_task_same_tenant_succeeds(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        checkpoint.release_task(lease, "completed")
        status, owner, _, expires, _ = self.task_state(task)
        self.assertEqual(status, "completed")
        self.assertIsNone(owner)
        self.assertIsNone(expires)

    def test_defer_task_for_route_same_tenant_succeeds(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        cp = checkpoint.defer_task_for_route(lease, retry_seconds=30)
        self.assertEqual(cp.payload["phase"], "waiting_for_route")
        status, owner, _, _, seq = self.task_state(task)
        self.assertEqual(status, "pending", "defer returns the task to pending")
        self.assertIsNone(owner, "defer releases the lease")
        self.assertEqual(seq, 1)
        self.assertEqual(self.checkpoint_count(task), 1)

    # ---- foreign tenant ----

    def test_save_checkpoint_foreign_denied_and_nothing_mutated(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        before_state = self.task_state(task)
        before_cp = self.checkpoint_count(task)
        forged = dataclasses.replace(lease, tenant_id=self.foreign)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(forged, {"phase": "intruder"})
        self.assertEqual(self.task_state(task), before_state)
        self.assertEqual(self.checkpoint_count(task), before_cp)

    def test_load_latest_checkpoint_foreign_matches_missing(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        checkpoint.save_checkpoint(lease, {"n": 1})
        self.prove_task_visible_and_owned_by(task, self.tenant)
        foreign = checkpoint.load_latest_checkpoint(
            task, tenant_id=self.foreign)
        missing = checkpoint.load_latest_checkpoint(
            uuid4(), tenant_id=self.tenant)
        self.assertIsNone(foreign)
        self.assertEqual(foreign, missing,
                         "foreign and missing must be externally identical")

    def test_release_task_foreign_denied_and_state_unchanged(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        before = self.task_state(task)
        forged = dataclasses.replace(lease, tenant_id=self.foreign)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.release_task(forged, "completed")
        self.assertEqual(self.task_state(task), before)

    def test_defer_task_for_route_foreign_denied_and_nothing_mutated(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        before_state = self.task_state(task)
        before_cp = self.checkpoint_count(task)
        forged = dataclasses.replace(lease, tenant_id=self.foreign)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(forged)
        self.assertEqual(self.task_state(task), before_state)
        self.assertEqual(self.checkpoint_count(task), before_cp)

    # ---- forged lease authority ----

    def test_lease_tenant_is_load_bearing_not_ignored(self):
        """A lease whose task/owner/version are valid for tenant B must still
        be refused when its tenant_id says tenant A. If authority were
        re-derived from the DB, this forged lease would succeed."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        self.prove_task_visible_and_owned_by(task, self.tenant)
        forged = dataclasses.replace(lease, tenant_id=self.foreign)
        # task_id, owner_id and version are all genuinely valid right now
        self.assertEqual(forged.task_id, task)
        self.assertEqual(forged.owner_id, lease.owner_id)
        self.assertEqual(forged.version, lease.version)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.release_task(forged, "failed")
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(forged, {"x": 1})
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(forged)
        self.assertEqual(self.task_state(task), before)
        self.assertEqual(self.checkpoint_count(task), 0)

    # ---- fencing preserved ----

    def test_wrong_owner_denied_for_all_mutating_apis(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        impostor = dataclasses.replace(lease, owner_id=uuid4())
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(impostor, {"x": 1})
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.release_task(impostor, "completed")
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(impostor)
        self.assertEqual(self.task_state(task), before)
        self.assertEqual(self.checkpoint_count(task), 0)

    def test_stale_version_denied_for_all_mutating_apis(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        stale = dataclasses.replace(lease, version=lease.version + 3)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(stale, {"x": 1})
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.release_task(stale, "completed")
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(stale)
        self.assertEqual(self.task_state(task), before)
        self.assertEqual(self.checkpoint_count(task), 0)

    def test_expired_lease_denied_for_mutating_apis(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant, lease_seconds=1)
        with self._fresh(
                "UPDATE tasks SET lease_expires_at = now() - interval '1 hour'"
                " WHERE id=%s", (task,)):
            pass
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(lease, {"x": 1})
        self.assertEqual(self.task_state(task), before)
        self.assertEqual(self.checkpoint_count(task), 0)

    # ---- transactional rollback ----

    def test_save_checkpoint_rolls_back_when_insert_fails(self):
        """The guard UPDATE is eligible, the INSERT then fails on the
        UNIQUE(task_id, sequence) constraint, and nothing may persist."""
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        # Pre-create a checkpoint at the sequence the next save will compute.
        checkpoint.save_checkpoint(lease, {"pre": True})
        # Force the internal counter out of step with task_checkpoints so the
        # next INSERT collides on UNIQUE(task_id, sequence).
        with self._fresh(
                "UPDATE tasks SET checkpoint_seq = checkpoint_seq + 5"
                " WHERE id=%s", (task,)):
            pass
        fresh_lease = self.claim(task, self.tenant)
        before_state = self.task_state(task)
        before_cp = self.checkpoint_count(task)
        # The UPDATE is eligible, but the INSERT selects nothing because the
        # lease is stale, so the whole transaction must leave no trace.
        self.assertGreaterEqual(before_state[4], 5)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.save_checkpoint(fresh_lease, {"boom": True})
        after = self.task_state(task)
        self.assertEqual(self.checkpoint_count(task), before_cp,
                         "no partial checkpoint may persist")
        self.assertEqual(after[0], before_state[0], "status must be unchanged")

    def test_defer_rolls_back_when_insert_fails(self):
        job = self.job(self.tenant)
        task = self.task(job)
        lease = self.claim(task, self.tenant)
        before_cp = self.checkpoint_count(task)
        stale = dataclasses.replace(lease, version=lease.version + 9)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.defer_task_for_route(stale)
        self.assertEqual(self.checkpoint_count(task), before_cp)
        self.assertEqual(self.task_state(task)[0], "running",
                         "a failed defer must not return the task to pending")


if __name__ == "__main__":
    unittest.main()
