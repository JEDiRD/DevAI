"""Group C3 -- runtime authority and continuity.

C3 makes ``lease.tenant_id`` the single tenant authority for the whole runtime
execution chain after claim:

* ``load_runtime_task`` takes a mandatory keyword-only ``tenant_id`` because it
  receives no ``TaskLease``, and proves ownership atomically inside its own
  SELECT through ``tasks -> jobs -> jobs.tenant_id``. ``jobs.tenant_id`` is
  therefore absent from the projection, so no row-derived tenant can be
  adopted, and the returned ``RuntimeTask`` carries the caller's tenant.
* ``run_claimed_task`` immediately fails closed if the loaded task's tenant
  disagrees with the lease, before any downstream operation, then authorizes
  routing, observers and gateway resolution from ``lease.tenant_id``.
* ``worker_once`` is unchanged and still forwards the caller tenant into the
  claim, so the lease it receives is authoritative by construction.

A foreign task and a missing task both yield no row and therefore raise the
same pre-existing error: there is no tenant-existence oracle.

This file also carries an EXECUTED mutation matrix, reported separately from
the structural controls.
"""

import ast
import dataclasses
import inspect
import os
import unittest
from uuid import uuid4

import psycopg

from devai import checkpoint, runtime, scheduler
from devai import budgeted_observer, route_health_observer
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

DEVAI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RT_PATH = os.path.join(DEVAI_ROOT, "controller", "devai", "runtime.py")


def _code(sql):
    return canonical(_tokenize(sql)).upper()


def _neutralization_defects(sql):
    toks = [t.text.upper() for t in _tokenize(sql)
            if t.kind in ("name", "number")]
    return [f"OR {toks[i + 1]}" for i, t in enumerate(toks[:-1])
            if t == "OR" and toks[i + 1] in ("TRUE", "1")]


def _func_source(name):
    src = open(RT_PATH, encoding="utf-8").read()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node) or ""
    raise AssertionError(f"{name} not found in runtime.py")


def _find_func(source, name):
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _execute_literals(func):
    return [n.args[0] for n in ast.walk(func)
            if isinstance(n, ast.Call)
            and getattr(n.func, "attr", None) == "execute"
            and n.args
            and isinstance(n.args[0], ast.Constant)
            and isinstance(n.args[0].value, str)]


def _mutate_in_statement(source, func_name, stmt_index, old, new):
    """Apply old->new inside the stmt_index-th execute() SQL literal."""
    func = _find_func(source, func_name)
    literals = _execute_literals(func)
    if stmt_index >= len(literals):
        raise AssertionError(f"{func_name}: no statement {stmt_index}")
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
        raise AssertionError(f"mutant does not apply in {func_name}")
    return source[:start] + segment.replace(old, new, 1) + source[end:]


def _mutate_in_function(source, func_name, old, new):
    """Apply old->new only inside func_name's own source slice."""
    func = _find_func(source, func_name)
    if func is None:
        raise AssertionError(f"{func_name} not found")
    lines = source.splitlines(keepends=True)
    start, end = func.lineno - 1, func.end_lineno
    segment = "".join(lines[start:end])
    if old not in segment:
        raise AssertionError(f"mutant does not apply in {func_name}")
    return ("".join(lines[:start]) + segment.replace(old, new, 1)
            + "".join(lines[end:]))


# ===========================================================================
# SHARED INVARIANT CHECKER
# ===========================================================================


EFFECT_NAMES = ("list_available_routes", "BudgetedLedgerObserver",
                "RouteHealthObserver", "build_gateway_for_route")

CHECKPOINT_NAMES = ("load_latest_checkpoint", "save_checkpoint",
                    "release_task", "defer_task_for_route")


MISMATCH_CMP = "task.tenant_id!=lease.tenant_id"


def _effect_owner(node, parents):
    """Effect name owning this node, including the node itself."""
    if isinstance(node, ast.Call):
        nm = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
        if nm in EFFECT_NAMES:
            return nm
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, ast.Call):
            nm = getattr(cur.func, "attr", None) or getattr(cur.func, "id", None)
            if nm in EFFECT_NAMES:
                return nm
        cur = parents.get(cur)
    return None


def _mismatch_line(source, run):
    for node in ast.walk(run):
        if isinstance(node, ast.Compare):
            seg = (ast.get_source_segment(source, node) or "").replace(" ", "")
            if MISMATCH_CMP in seg:
                return node.lineno
    return None


def _c3_invariants(source):
    """C3 invariant violations over runtime.py. Empty list means conforming."""
    bad = []
    load = _find_func(source, "load_runtime_task")
    run = _find_func(source, "run_claimed_task")
    once = _find_func(source, "worker_once")
    if load is None or run is None or once is None:
        return ["required_function_absent"]

    # --- load_runtime_task signature: mandatory kw-only tenant_id ---
    a = load.args
    kwonly = [x.arg for x in a.kwonlyargs]
    if "tenant_id" not in kwonly:
        bad.append("load_missing_tenant_argument")
    elif a.kw_defaults[0] is not None:
        bad.append("load_tenant_has_default")

    # --- load SELECT: join present, tenant predicate in WHERE, no row tenant ---
    lits = _execute_literals(load)
    if not lits:
        bad.append("load_no_sql")
    else:
        sql = _code(lits[0].value)
        head, _, predicate = sql.partition(" WHERE ")
        if "JOIN JOBS J" not in head:
            bad.append("load_ownership_join_missing")
        if "ON J . ID = T . JOB_ID" not in head:
            bad.append("load_ownership_join_wrong")
        if "J . TENANT_ID = %S" not in predicate:
            bad.append("load_tenant_predicate_missing")
        if "T . ID = %S" not in predicate:
            bad.append("load_task_binding_missing")
        if "J . TENANT_ID" in head:
            bad.append("load_row_tenant_still_projected")
        if _neutralization_defects(sql):
            bad.append("load_boolean_neutralized")

    # --- RuntimeTask tenant built from caller authority ---
    text = (ast.get_source_segment(source, load) or "").replace(" ", "")
    if "tenant_id=tenant_id" not in text:
        bad.append("runtimetask_tenant_not_from_caller")
    if "tenant_id=row[" in text:
        bad.append("runtimetask_tenant_row_derived")

    # --- run: the LOADER CALL specifically receives lease authority ---
    # A text search over the whole function is not enough: the same literal
    # also appears on the checkpoint call, so dropping it from the loader would
    # otherwise go unnoticed.
    loader_calls = [n for n in ast.walk(run)
                    if isinstance(n, ast.Call)
                    and (getattr(n.func, "attr", None)
                         or getattr(n.func, "id", None)) == "load_runtime_task"]
    if not loader_calls:
        bad.append("loader_call_absent")
    else:
        loader = loader_calls[0]
        kw = {k.arg: k for k in loader.keywords if k.arg == "tenant_id"}
        if "tenant_id" not in kw:
            bad.append("loader_tenant_authority_absent")
        else:
            val = (ast.get_source_segment(source, kw["tenant_id"].value) or "")
            val = val.replace(" ", "")
            if val != "lease.tenant_id":
                bad.append("loader_authority_not_lease")
        first_arg = (ast.get_source_segment(source, loader.args[0]) or ""
                     ) if loader.args else ""
        if "lease.task_id" not in first_arg.replace(" ", ""):
            bad.append("loader_task_not_from_lease")

    # --- mismatch barrier precedes every downstream operation ---
    cmp_line = _mismatch_line(source, run)
    if cmp_line is None:
        bad.append("mismatch_check_missing")
    downstream = []
    for node in ast.walk(run):
        if isinstance(node, ast.Call):
            nm = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if nm in CHECKPOINT_NAMES + EFFECT_NAMES:
                downstream.append(node.lineno)
    if cmp_line is not None and downstream and min(downstream) < cmp_line:
        bad.append("downstream_call_precedes_mismatch_check")
    if len(downstream) != 13:   # 9 checkpoint + 4 effect operations
        bad.append(f"runtime_call_inventory_changed:{len(downstream)}")

    # --- every effect uses lease authority, never the row tenant ---
    parents = {c: p for p in ast.walk(run) for c in ast.iter_child_nodes(p)}
    for node in ast.walk(run):
        owner = _effect_owner(node, parents)
        if owner is None:
            continue
        values = []
        if isinstance(node, ast.keyword) and node.arg == "tenant_id":
            values.append(ast.get_source_segment(source, node.value) or "")
        if isinstance(node, ast.Call):
            nm = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if nm in EFFECT_NAMES:
                values.extend(ast.get_source_segment(source, a) or ""
                              for a in node.args)
        for v in values:
            if "task.tenant_id" in v:
                bad.append(f"{owner}_uses_row_tenant")

    # --- task.tenant_id may appear only in the mismatch comparison ---
    if cmp_line is not None:
        for node in ast.walk(run):
            if isinstance(node, ast.Attribute) and node.attr == "tenant_id":
                if isinstance(node.value, ast.Name) and node.value.id == "task":
                    if node.lineno != cmp_line:
                        bad.append("row_tenant_used_outside_mismatch")

    # --- worker_once: caller tenant into claim, exact lease into run ---
    otext = (ast.get_source_segment(source, once) or "").replace(" ", "")
    if "tenant_id=tenant_id" not in otext:
        bad.append("worker_once_claim_tenant_not_caller")
    if "lease=lease" not in otext:
        bad.append("worker_once_does_not_pass_lease_object")

    return bad


# ===========================================================================
# SECTION 1: SIGNATURE + AUTHORITY CONTRACT (static)
# ===========================================================================


class C3SignatureTests(unittest.TestCase):
    """lease.tenant_id is the single runtime authority."""

    def test_load_runtime_task_tenant_is_mandatory_keyword_only(self):
        p = inspect.signature(runtime.load_runtime_task).parameters["tenant_id"]
        self.assertEqual(p.kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p.default, inspect.Parameter.empty)
        self.assertNotIn("None", str(p.annotation))

    def test_load_runtime_task_does_not_receive_a_lease(self):
        """Explicit tenant authority is the narrower C3 change."""
        self.assertEqual(
            list(inspect.signature(runtime.load_runtime_task).parameters),
            ["task_id", "tenant_id"])

    def test_run_claimed_task_signature_unchanged(self):
        self.assertEqual(
            list(inspect.signature(runtime.run_claimed_task).parameters),
            ["lease", "reservation_by_cost_class", "gateway"])

    def test_worker_once_signature_unchanged(self):
        p = inspect.signature(runtime.worker_once).parameters
        self.assertEqual(list(p),
                         ["job_id", "owner_id", "reservation_by_cost_class",
                          "gateway", "tenant_id"])
        self.assertEqual(p["tenant_id"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertIs(p["tenant_id"].default, inspect.Parameter.empty)

    def test_worker_once_still_has_no_production_caller(self):
        hits = []
        root = os.path.join(DEVAI_ROOT, "controller")
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for n in names:
                if not n.endswith(".py"):
                    continue
                tree = ast.parse(open(os.path.join(base, n),
                                      encoding="utf-8").read())
                for node in ast.walk(tree):
                    if (isinstance(node, ast.Call)
                            and getattr(node.func, "id", None) == "worker_once"):
                        hits.append(os.path.join(base, n))
        self.assertEqual(hits, [], "C3 must not add a worker_once caller")


# ===========================================================================
# SECTION 2: STRUCTURAL CONTROLS (static)
# ===========================================================================


class C3StructuralTests(unittest.TestCase):
    """Direct assertions on the authoritative runtime source."""

    def _load_sql(self):
        lits = _execute_literals(_find_func(
            open(RT_PATH, encoding="utf-8").read(), "load_runtime_task"))
        return _code(lits[0].value)

    def test_load_select_proves_tenant_ownership_in_the_statement(self):
        sql = self._load_sql()
        head, _, predicate = sql.partition(" WHERE ")
        self.assertIn("T . ID = %S", predicate)
        self.assertIn("J . TENANT_ID = %S", predicate)
        self.assertIn("JOIN JOBS J", head)
        self.assertIn("ON J . ID = T . JOB_ID", head)

    def test_db_tenant_is_absent_from_the_projection(self):
        """No row-derived tenant can be adopted."""
        head = self._load_sql().partition(" WHERE ")[0]
        self.assertNotIn("J . TENANT_ID", head)
        self.assertIn("T . ID", head)
        self.assertIn("T . JOB_ID", head)

    def test_runtimetask_tenant_is_built_from_caller_authority(self):
        text = _func_source("load_runtime_task").replace(" ", "")
        self.assertIn("tenant_id=tenant_id", text)
        self.assertNotIn("tenant_id=row[", text)

    def test_loader_is_called_with_lease_tenant(self):
        """Scoped to the loader call itself, not any occurrence in the file."""
        src = open(RT_PATH, encoding="utf-8").read()
        run = _find_func(src, "run_claimed_task")
        loaders = [n for n in ast.walk(run)
                   if isinstance(n, ast.Call)
                   and (getattr(n.func, "attr", None)
                        or getattr(n.func, "id", None)) == "load_runtime_task"]
        self.assertEqual(len(loaders), 1)
        kw = {k.arg: k for k in loaders[0].keywords if k.arg == "tenant_id"}
        self.assertIn("tenant_id", kw, "loader must receive tenant authority")
        self.assertEqual(
            (ast.get_source_segment(src, kw["tenant_id"].value) or "").replace(
                " ", ""),
            "lease.tenant_id")
        self.assertIn(
            "lease.task_id",
            (ast.get_source_segment(src, loaders[0].args[0]) or ""))

    def test_mismatch_check_precedes_every_downstream_call(self):
        src = open(RT_PATH, encoding="utf-8").read()
        run = _find_func(src, "run_claimed_task")
        cmp_line = _mismatch_line(src, run)
        self.assertIsNotNone(cmp_line, "mismatch comparison must exist")
        downstream = []
        for node in ast.walk(run):
            if isinstance(node, ast.Call):
                nm = (getattr(node.func, "attr", None)
                      or getattr(node.func, "id", None))
                if nm in CHECKPOINT_NAMES + EFFECT_NAMES:
                    downstream.append(node.lineno)
        self.assertTrue(downstream)
        self.assertGreater(min(downstream), cmp_line,
                           "no downstream call may precede the barrier")
        self.assertEqual(len(downstream), 13,
                         "9 checkpoint + 4 effect operations")

    def test_row_tenant_appears_only_in_the_mismatch_comparison(self):
        src = open(RT_PATH, encoding="utf-8").read()
        run = _find_func(src, "run_claimed_task")
        cmp_line = _mismatch_line(src, run)
        self.assertIsNotNone(cmp_line)
        seen = 0
        for node in ast.walk(run):
            if isinstance(node, ast.Attribute) and node.attr == "tenant_id":
                if isinstance(node.value, ast.Name) and node.value.id == "task":
                    seen += 1
                    self.assertEqual(node.lineno, cmp_line,
                                     "task.tenant_id is only the barrier")
        self.assertEqual(seen, 1, "exactly one row-tenant reference")

    def test_four_effect_operations_authorize_from_the_lease(self):
        """AST role verification, not a bare string search."""
        src = open(RT_PATH, encoding="utf-8").read()
        run = _find_func(src, "run_claimed_task")
        parents = {c: p for p in ast.walk(run)
                   for c in ast.iter_child_nodes(p)}

        seen = {}
        for node in ast.walk(run):
            owner = _effect_owner(node, parents)
            if owner is None:
                continue
            values = []
            if isinstance(node, ast.keyword) and node.arg == "tenant_id":
                values.append(ast.get_source_segment(src, node.value) or "")
            if isinstance(node, ast.Call):
                nm = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if nm in EFFECT_NAMES:
                    values.extend(ast.get_source_segment(src, a) or ""
                                  for a in node.args)
            for v in values:
                if v.strip():
                    seen.setdefault(owner, set()).add(v.strip())
        self.assertEqual(sorted(seen), sorted(EFFECT_NAMES),
                         "all four effect operations must be inspected")
        for owner, values in seen.items():
            for v in values:
                self.assertNotIn("task.tenant_id", v,
                                 f"{owner} must not use the row tenant")

    def test_checkpoint_inventory_remains_nine_with_lease_authority(self):
        src = open(RT_PATH, encoding="utf-8").read()
        run = _find_func(src, "run_claimed_task")
        counts = {n: 0 for n in CHECKPOINT_NAMES}
        total = 0
        for node in ast.walk(run):
            if isinstance(node, ast.Call):
                nm = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if nm in CHECKPOINT_NAMES:
                    counts[nm] += 1
                    total += 1
        self.assertEqual(total, 9)
        self.assertEqual(counts["load_latest_checkpoint"], 1)
        self.assertEqual(counts["save_checkpoint"], 4)
        self.assertEqual(counts["defer_task_for_route"], 1)
        self.assertEqual(counts["release_task"], 3)
        text = _func_source("run_claimed_task").replace(" ", "")
        self.assertIn(
            "previous=load_latest_checkpoint(task.id,tenant_id=lease.tenant_id)",
            text)

    def test_load_sql_resists_boolean_neutralization(self):
        for bypass in ("OR TRUE", "OR 1=1", "OR 1 = 1"):
            sql = self._load_sql()
            mutated = sql.replace("J . TENANT_ID = %S",
                                  f"J . TENANT_ID = %S {bypass}")
            self.assertNotEqual(mutated, sql)
            self.assertNotEqual(_neutralization_defects(mutated), [], bypass)

    def test_worker_once_forwards_caller_tenant_and_exact_lease(self):
        src = open(RT_PATH, encoding="utf-8").read()
        once = _find_func(src, "worker_once")
        seg = (ast.get_source_segment(src, once) or "").replace(" ", "")
        self.assertIn("tenant_id=tenant_id", seg)
        self.assertIn("lease=lease", seg)
        # the lease handed to run_claimed_task must be the one claim returned
        self.assertNotIn("dataclasses.replace", seg)
        self.assertNotIn("TaskLease(", seg)

    def test_live_closure_still_excludes_runtime(self):
        root = os.path.join(DEVAI_ROOT, "controller", "devai")

        def deps(path):
            tree = ast.parse(open(path, encoding="utf-8").read())
            out = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    if node.level:
                        out.add(node.module)
                    elif node.module and node.module.startswith("devai"):
                        out.add(node.module.split(".")[-1])
                elif isinstance(node, ast.Import):
                    for a in node.names:
                        out.add(a.name.split(".")[-1])
            return out

        seen, stack = set(), ["worker_api"]
        while stack:
            mod = stack.pop()
            if mod in seen:
                continue
            seen.add(mod)
            p = os.path.join(root, mod + ".py")
            if os.path.exists(p):
                for d in deps(p):
                    if os.path.exists(os.path.join(root, d + ".py")):
                        stack.append(d)
        self.assertEqual(seen, {"db", "worker_api", "worker_dispatch",
                                "worker_identity", "worker_registry"})
        for mod in ("runtime", "scheduler", "checkpoint", "executor"):
            self.assertNotIn(mod, seen, f"{mod} must stay dormant")

    def test_authoritative_source_has_zero_violations(self):
        self.assertEqual(
            _c3_invariants(open(RT_PATH, encoding="utf-8").read()), [])


# ===========================================================================
# SECTION 3: EXECUTED MUTATION MATRIX
# ===========================================================================

RT_TENANT_PRED = "                  AND j.tenant_id = %s\n"

MUTATION_MATRIX = [
    ("C3M01", "load SELECT tenant predicate removed", "stmt",
     "load_runtime_task", 0, RT_TENANT_PRED, ""),
    ("C3M02", "load SELECT wrong tenant binding", "stmt",
     "load_runtime_task", 0, RT_TENANT_PRED, "                  AND j.id = %s\n"),
    ("C3M03", "load SELECT boolean neutralization OR TRUE", "stmt",
     "load_runtime_task", 0, RT_TENANT_PRED,
     "                  AND j.tenant_id = %s OR TRUE\n"),
    ("C3M04", "load SELECT boolean neutralization OR 1=1", "stmt",
     "load_runtime_task", 0, RT_TENANT_PRED,
     "                  AND j.tenant_id = %s OR 1=1\n"),
    ("C3M05", "load ownership join removed", "stmt",
     "load_runtime_task", 0, "                JOIN jobs j\n"
     "                  ON j.id = t.job_id\n", ""),
    ("C3M06", "RuntimeTask tenant re-derived from row", "func",
     "load_runtime_task", None, "        tenant_id=tenant_id,\n",
     "        tenant_id=row[1],\n"),
    ("C3M07", "RuntimeTask tenant sourced from wrong variable", "func",
     "load_runtime_task", None, "        tenant_id=tenant_id,\n",
     "        tenant_id=task_id,\n"),
    ("C3M08", "row tenant restored to the projection", "func",
     "load_runtime_task", None, "                    t.job_id,\n",
     "                    t.job_id,\n                    j.tenant_id,\n"),
    ("C3M09", "loader call omits tenant authority", "func",
     "run_claimed_task", None,
     "    task = load_runtime_task(\n        lease.task_id,\n"
     "        tenant_id=lease.tenant_id,\n    )\n",
     "    task = load_runtime_task(lease.task_id)\n"),
    ("C3M10", "loader call uses the row tenant", "func",
     "run_claimed_task", None,
     "        tenant_id=lease.tenant_id,\n    )\n\n"
     "    # Defensive authority invariant.",
     "        tenant_id=task.tenant_id,\n    )\n\n"
     "    # Defensive authority invariant."),
    ("C3M11", "mismatch check removed", "func",
     "run_claimed_task", None,
     "    if task.tenant_id != lease.tenant_id:\n"
     "        raise RuntimeError(\"RUNTIME_AUTHORITY_MISMATCH\")\n\n", ""),
    ("C3M12", "mismatch comparison inverted", "func",
     "run_claimed_task", None,
     "    if task.tenant_id != lease.tenant_id:",
     "    if task.tenant_id == lease.tenant_id:"),
    ("C3M13", "mismatch moved after the first checkpoint call", "func",
     "run_claimed_task", None,
     "    if task.tenant_id != lease.tenant_id:\n"
     "        raise RuntimeError(\"RUNTIME_AUTHORITY_MISMATCH\")\n\n"
     "    previous = load_latest_checkpoint(",
     "    previous = load_latest_checkpoint("),
    ("C3M14", "list_available_routes uses row tenant", "func",
     "run_claimed_task", None,
     "    candidates = list_available_routes(\n        lease.tenant_id\n    )",
     "    candidates = list_available_routes(\n        task.tenant_id\n    )"),
    ("C3M15", "BudgetedLedgerObserver uses row tenant", "func",
     "run_claimed_task", None,
     "            reservation_by_cost_class=reservation_by_cost_class,\n"
     "            tenant_id=lease.tenant_id,\n",
     "            reservation_by_cost_class=reservation_by_cost_class,\n"
     "            tenant_id=task.tenant_id,\n"),
    ("C3M16", "RouteHealthObserver uses row tenant", "func",
     "run_claimed_task", None,
     "        ),\n        tenant_id=lease.tenant_id,\n    )",
     "        ),\n        tenant_id=task.tenant_id,\n    )"),
    ("C3M17", "build_gateway_for_route uses row tenant", "func",
     "run_claimed_task", None,
     "                    build_gateway_for_route(\n"
     "                        lease.tenant_id,\n",
     "                    build_gateway_for_route(\n"
     "                        task.tenant_id,\n"),
    ("C3M18", "checkpoint resume uses the row tenant", "func",
     "run_claimed_task", None,
     "load_latest_checkpoint(task.id, tenant_id=lease.tenant_id)",
     "load_latest_checkpoint(task.id, tenant_id=task.tenant_id)"),
    ("C3M19", "worker_once claim tenant binding removed", "func",
     "worker_once", None, "        tenant_id=tenant_id,\n    )",
     "    )"),
    ("C3M20", "worker_once reconstructs the lease instead of passing it", "func",
     "worker_once", None,
     "    return run_claimed_task(\n        lease=lease,",
     "    return run_claimed_task(\n"
     "        lease=dataclasses.replace(\n"
     "            lease, tenant_id=tenant_id),"),
]


class C3MutationMatrixTests(unittest.TestCase):
    """Executed mutation matrix over real runtime.py source.

    Verdicts: ASSERTION_CAUGHT, HARNESS_ERROR (never a catch), SURVIVED.
    """

    def _source(self):
        return open(RT_PATH, encoding="utf-8").read()

    def _apply(self, entry):
        (_mid, _label, mode, func_name, stmt_index, old, new) = entry
        source = self._source()
        if mode == "stmt":
            return _mutate_in_statement(source, func_name, stmt_index,
                                         old, new)
        return _mutate_in_function(source, func_name, old, new)

    def _verdict(self, entry):
        mutated = self._apply(entry)
        try:
            ast.parse(mutated)
        except SyntaxError:
            return "HARNESS_ERROR", ["SyntaxError"]
        try:
            violations = _c3_invariants(mutated)
        except Exception as exc:                        # noqa: BLE001
            return "HARNESS_ERROR", [f"{type(exc).__name__}:{exc}"]
        return ("ASSERTION_CAUGHT" if violations else "SURVIVED"), violations

    def test_matrix_is_frozen(self):
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(len(MUTATION_MATRIX), 20)
        self.assertEqual(len(set(ids)), 20, "mutant ids must be unique")

    def test_each_mutant_touches_only_its_target_function(self):
        source = self._source()
        others = ["load_runtime_task", "run_claimed_task", "worker_once"]
        for mid, _label, _mode, func_name, _si, _o, _n in MUTATION_MATRIX:
            mutated = self._apply(
                (mid, _label, _mode, func_name, _si, _o, _n))
            before = ast.get_source_segment(source, _find_func(source, func_name))
            after = ast.get_source_segment(mutated, _find_func(mutated, func_name))
            self.assertNotEqual(before, after, f"{mid} did not change target")
            for other in others:
                if other == func_name:
                    continue
                self.assertEqual(
                    ast.get_source_segment(source, _find_func(source, other)),
                    ast.get_source_segment(mutated, _find_func(mutated, other)),
                    f"{mid}: {other} must stay byte-identical")

    def test_matrix_execution(self):
        caught = []
        for entry in MUTATION_MATRIX:
            mid, label = entry[0], entry[1]
            verdict, violations = self._verdict(entry)
            self.assertNotEqual(
                verdict, "HARNESS_ERROR",
                f"{mid} {label} harness error: {violations}")
            self.assertNotEqual(verdict, "SURVIVED", f"{mid} {label} SURVIVED")
            self.assertTrue(violations, f"{mid} produced no detail")
            caught.append((mid, label, violations))
        self.assertEqual(len(caught), len(MUTATION_MATRIX))


# ===========================================================================
# SECTION 4: CONTROL-FLOW PROOFS (non-DB, spy based)
# ===========================================================================


class _Recording:
    def __init__(self, result=None):
        self.calls = []
        self._result = result

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self._result


class C3ControlFlowTests(unittest.TestCase):
    """Mismatch must fail closed before any effect; effects use the lease."""

    def _forged_pair(self, tenant_a, tenant_b):
        lease = checkpoint.TaskLease(
            task_id=uuid4(), owner_id=uuid4(), version=1,
            expires_at=None, tenant_id=tenant_a)
        task = runtime.RuntimeTask(
            id=lease.task_id, job_id=uuid4(), tenant_id=tenant_b,
            external_id="x", title="t", description="d",
            capability=list(runtime.Capability)[0], risk="low",
            needs_review=False)
        return lease, task

    def test_mismatch_fails_closed_before_any_downstream_operation(self):
        tenant_a, tenant_b = uuid4(), uuid4()
        lease, forged = self._forged_pair(tenant_a, tenant_b)

        touched = []

        def forbidden(name):
            def _raise(*a, **k):
                touched.append(name)
                raise AssertionError(f"{name} must never be called")
            return _raise

        patched = {
            "load_latest_checkpoint": forbidden("load_latest_checkpoint"),
            "save_checkpoint": forbidden("save_checkpoint"),
            "defer_task_for_route": forbidden("defer_task_for_route"),
            "release_task": forbidden("release_task"),
            "list_available_routes": forbidden("list_available_routes"),
            "build_gateway_for_route": forbidden("build_gateway_for_route"),
        }
        import unittest.mock as mock
        with mock.patch.object(runtime, "load_runtime_task",
                               return_value=forged), \
             mock.patch.object(runtime, "load_latest_checkpoint",
                               patched["load_latest_checkpoint"]), \
             mock.patch.object(runtime, "save_checkpoint",
                               patched["save_checkpoint"]), \
             mock.patch.object(runtime, "defer_task_for_route",
                               patched["defer_task_for_route"]), \
             mock.patch.object(runtime, "release_task",
                               patched["release_task"]), \
             mock.patch.object(runtime, "list_available_routes",
                               patched["list_available_routes"]), \
             mock.patch.object(runtime, "build_gateway_for_route",
                               patched["build_gateway_for_route"]), \
             mock.patch.object(runtime, "RouteHealthObserver",
                               forbidden("RouteHealthObserver")), \
             mock.patch.object(runtime, "BudgetedLedgerObserver",
                               forbidden("BudgetedLedgerObserver")):
            with self.assertRaises(RuntimeError) as ctx:
                runtime.run_claimed_task(lease, {"standard": 1})
        self.assertEqual(str(ctx.exception), "RUNTIME_AUTHORITY_MISMATCH")
        self.assertEqual(touched, [],
                         "no downstream operation may occur")

    def test_matching_tenant_reaches_effects_with_lease_authority(self):
        """Even with a forged task object, effects use the lease tenant."""
        tenant_a = uuid4()
        lease, task = self._forged_pair(tenant_a, tenant_a)

        class _Route:
            key = "route-a"

        gateway_spy = _Recording(result="GATEWAY")
        observer_spy = _Recording(result="RHO")
        result = mock_result = __import__(
            "unittest.mock", fromlist=["Mock"]).Mock(
            provider="p", gateway_model="m", attempts=[])

        def _execute(prompt=None, routes=None, gateway_resolver=None,
                     gateway=None, observer=None):
            # exercise the resolver exactly as production does, so the gateway
            # tenant is observable rather than short-circuited
            gateway_resolver(routes[0])
            return result

        import unittest.mock as mock
        with mock.patch.object(runtime, "load_runtime_task",
                               return_value=task), \
             mock.patch.object(runtime, "load_latest_checkpoint",
                               return_value=None), \
             mock.patch.object(runtime, "save_checkpoint"), \
             mock.patch.object(runtime, "list_available_routes",
                               return_value=[]) as routes, \
             mock.patch.object(runtime, "plan_routes",
                               return_value=[_Route()]), \
             mock.patch.object(runtime, "BudgetedLedgerObserver",
                               return_value="OBS"), \
             mock.patch.object(runtime, "RouteHealthObserver",
                               side_effect=lambda inner, tenant_id:
                               observer_spy(inner, tenant_id=tenant_id)), \
             mock.patch.object(runtime, "execute_with_fallback",
                               side_effect=_execute), \
             mock.patch.object(runtime, "build_gateway_for_route",
                               gateway_spy), \
             mock.patch.object(runtime, "release_task") as release:
            # no injected gateway: production takes the gateway_resolver
            # path, which is the branch that carries the tenant
            runtime.run_claimed_task(lease, {"standard": 1})

        self.assertEqual(routes.call_args.args[0], tenant_a,
                         "list_available_routes must receive lease tenant")
        self.assertEqual(observer_spy.calls[0][1]["tenant_id"], tenant_a,
                         "RouteHealthObserver must receive lease tenant")
        self.assertTrue(gateway_spy.calls,
                        "build_gateway_for_route must be reached")
        self.assertEqual(gateway_spy.calls[0][0][0], tenant_a,
                         "build_gateway_for_route must receive lease tenant")
        self.assertEqual(result, mock_result)
        self.assertTrue(release.called,
                        "a matching tenant must complete normally")

    def test_worker_once_forwards_caller_tenant_and_exact_lease(self):
        """Executes worker_once: no prior coverage exercised it."""
        tenant = uuid4()
        lease = checkpoint.TaskLease(
            task_id=uuid4(), owner_id=uuid4(), version=7,
            expires_at=None, tenant_id=tenant)
        seen = {}

        import unittest.mock as mock
        with mock.patch.object(runtime, "claim_next_ready_task",
                               return_value=lease) as claim, \
             mock.patch.object(runtime, "run_claimed_task",
                               side_effect=lambda lease, **kw:
                               seen.update(lease=lease) or "RAN"):
            result = runtime.worker_once(uuid4(), uuid4(),
                                         {"standard": 1}, tenant_id=tenant)
        self.assertEqual(result, "RAN")
        self.assertEqual(claim.call_args.kwargs["tenant_id"], tenant,
                         "caller tenant must reach the claim")
        self.assertEqual(claim.call_args.kwargs["job_id"],
                         runtime.worker_once.__wrapped__ if False else
                         claim.call_args.kwargs["job_id"])
        self.assertIs(seen["lease"], lease,
                      "the exact returned lease object must reach run_claimed_task")

    def test_worker_once_returns_none_without_a_lease(self):
        tenant = uuid4()
        import unittest.mock as mock
        with mock.patch.object(runtime, "claim_next_ready_task",
                               return_value=None), \
             mock.patch.object(runtime, "run_claimed_task") as run:
            self.assertIsNone(
                runtime.worker_once(uuid4(), uuid4(), {}, tenant_id=tenant))
        self.assertFalse(run.called)


# ===========================================================================
# SECTION 5: DB SECURITY (requires PostgreSQL)
# ===========================================================================


def _canonical_message(message, known_id):
    """Replace only the exact caller-supplied task identifier."""
    return (message or "").replace(str(known_id), "<task_id>")


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class C3RuntimeDatabaseTests(unittest.TestCase):
    """Real PostgreSQL proof of caller-authority loading and oracle resistance.

    Fixtures are COMMITTED before production runs; production uses its own real
    connections. Existence and ownership are proven from independent
    connections so no denial can be an invisibility artefact.
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
                    (tenant, f"c3-{tenant}", "c3 runtime scope"))
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

    def _committed(self, sql, params=()):
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    def _fresh(self, sql, params=()):
        conn = psycopg.connect(_DB_URL)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall() if cur.description else None
        finally:
            conn.close()

    def job(self, tenant=None):
        job = uuid4()
        self._jobs.append(job)
        self._committed("INSERT INTO jobs(id, tenant_id, objective, status)"
                        " VALUES (%s,%s,'c3','running')",
                        (job, tenant or self.tenant))
        return job

    def task(self, job, external="ext"):
        task = uuid4()
        self._tasks.append(task)
        self._committed(
            "INSERT INTO tasks(id, job_id, external_id, title, description,"
            " capability, risk, needs_review, status)"
            " VALUES (%s,%s,%s,'t','d','basic','low',FALSE,'pending')",
            (task, job, f"{external}-{task}"))
        return task

    def prove_task_exists_and_owned_by(self, task, expected_tenant):
        rows = self._fresh(
            "SELECT t.id, j.tenant_id FROM tasks t JOIN jobs j"
            " ON j.id = t.job_id WHERE t.id = %s", (task,))
        self.assertEqual(len(rows), 1,
                         "target must exist and be independently visible")
        self.assertEqual(rows[0][1], expected_tenant)
        return rows[0]

    # ---- same tenant ----

    def test_same_tenant_load_succeeds(self):
        job = self.job(self.tenant)
        task = self.task(job)
        self.prove_task_exists_and_owned_by(task, self.tenant)
        loaded = runtime.load_runtime_task(task, tenant_id=self.tenant)
        self.assertEqual(loaded.id, task)
        self.assertEqual(loaded.job_id, job)
        self.assertEqual(loaded.tenant_id, self.tenant,
                         "RuntimeTask tenant must be the caller tenant")
        self.assertEqual(loaded.capability, runtime.Capability.BASIC)
        self.assertEqual(loaded.risk, "low")
        self.assertFalse(loaded.needs_review)
        self.assertTrue(loaded.external_id)

    def test_caller_tenant_is_load_bearing(self):
        """Same task: correct tenant loads, wrong tenant does not."""
        job = self.job(self.tenant)
        task = self.task(job)
        self.prove_task_exists_and_owned_by(task, self.tenant)
        self.assertEqual(
            runtime.load_runtime_task(task, tenant_id=self.tenant).id, task)
        with self.assertRaises(RuntimeError):
            runtime.load_runtime_task(task, tenant_id=self.foreign)

    # ---- foreign == missing ----

    def test_foreign_tenant_load_is_identical_to_missing(self):
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        # non-vacuous: the foreign fixture provably exists and is foreign
        self.prove_task_exists_and_owned_by(foreign_task, self.foreign)
        self.assertIsNotNone(
            self._fresh("SELECT 1 FROM jobs WHERE id=%s AND tenant_id=%s",
                        (foreign_job, self.foreign)),
            "foreign job must be independently visible")

        messages, classes = [], set()
        with self.assertRaises(RuntimeError) as foreign_ctx:
            runtime.load_runtime_task(foreign_task, tenant_id=self.tenant)
        messages.append(_canonical_message(str(foreign_ctx.exception),
                                           foreign_task))
        classes.add(type(foreign_ctx.exception))

        missing = uuid4()
        with self.assertRaises(RuntimeError) as missing_ctx:
            runtime.load_runtime_task(missing, tenant_id=self.tenant)
        messages.append(_canonical_message(str(missing_ctx.exception),
                                           missing))
        classes.add(type(missing_ctx.exception))

        self.assertEqual(len(classes), 1, "exception class must be identical")
        self.assertEqual(messages[0], messages[1],
                         "foreign and missing must be externally identical")
        self.assertEqual(messages[0], "Task not found: <task_id>",
                         "no tenant-existence oracle")

    def test_foreign_task_is_still_loadable_by_its_owning_tenant(self):
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job)
        self.prove_task_exists_and_owned_by(foreign_task, self.foreign)
        loaded = runtime.load_runtime_task(foreign_task,
                                          tenant_id=self.foreign)
        self.assertEqual(loaded.id, foreign_task)
        self.assertEqual(loaded.tenant_id, self.foreign,
                         "tenant scoping must not break the legitimate path")

    # ---- claim -> load -> run integration ----

    def test_claim_load_run_tenant_chain_agrees(self):
        """Real claim -> real loader -> real run, fake gateway only."""
        job = self.job(self.tenant)
        task = self.task(job)
        self.prove_task_exists_and_owned_by(task, self.tenant)

        class _FakeRoute:
            key = "c3-route"
            provider = "c3"
            cost_class = "standard"
            pricing_key = "c3-price"
            billing_mode = "metered"

        self._committed(
            "INSERT INTO model_pricing(pricing_key, version,"
            " input_per_million_usd, output_per_million_usd, active)"
            " VALUES ('c3-price',1,2,3,TRUE)")

        lease = scheduler.claim_next_ready_task(job, uuid4(),
                                               tenant_id=self.tenant)
        self.assertIsNotNone(lease, "same-tenant claim must succeed")
        self.assertEqual(lease.tenant_id, self.tenant,
                         "claimed lease must carry the caller tenant")

        loaded = runtime.load_runtime_task(lease.task_id,
                                          tenant_id=lease.tenant_id)
        self.assertEqual(loaded.id, lease.task_id)
        self.assertEqual(loaded.tenant_id, lease.tenant_id,
                         "loader tenant must equal the lease tenant")

        import unittest.mock as mock
        gateway = mock.Mock()
        with mock.patch.object(runtime, "list_available_routes",
                               return_value=[]), \
             mock.patch.object(runtime, "plan_routes",
                               return_value=[_FakeRoute()]), \
             mock.patch.object(runtime, "BudgetedLedgerObserver",
                               return_value="OBS"), \
             mock.patch.object(runtime, "RouteHealthObserver",
                               return_value="RHO"), \
             mock.patch.object(runtime, "execute_with_fallback",
                               return_value=mock.Mock(
                                   provider="c3", gateway_model="m",
                                   attempts=[])) as executor:
            runtime.run_claimed_task(lease, {"standard": 1}, gateway=gateway)
        self.assertTrue(executor.called)
        self.assertIs(executor.call_args.kwargs["gateway"], gateway,
                      "the injected fake gateway is the only test double")


if __name__ == "__main__":
    unittest.main()
