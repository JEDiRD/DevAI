"""Group C1 -- claim and lease tenant authority.

C1 hardens the three claim/lease entry points: ``checkpoint.claim_task``,
``checkpoint.renew_lease`` and ``scheduler.claim_next_ready_task``. In each,
the CALLER tenant is the authority and ownership is proven atomically inside
the authoritative statement by following tasks -> jobs -> jobs.tenant_id.

Deliberately NOT in C1 (owned by C2): ``save_checkpoint``,
``load_latest_checkpoint``, ``release_task``, ``defer_task_for_route``,
``load_runtime_task`` and ``run_claimed_task``. No migration is introduced; the
ownership join already exists via tasks.job_id.
"""

import ast
import inspect
import os
import re
import unittest
from uuid import uuid4

import psycopg

from devai import checkpoint, runtime, scheduler
from test_tenancy_invariants import canonical, _tokenize

_DB_URL = os.environ.get("DEVAI_TEST_DATABASE_URL")

DEVAI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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


def _exec_params(func):
    """The parameter tuple passed to cur.execute, in binding order."""
    tree = ast.parse(inspect.cleandoc(_body(func)))
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


def _placeholder_order(func):
    """What each %s binds to, in SQL order.

    Returns the column expression each placeholder is compared against, or
    "(expr)" when the placeholder is a bare value such as an interval
    multiplier. Binding by role -- not by placeholder count -- is what lets a
    swapped job/tenant binding be detected.
    """
    tree = ast.parse(inspect.cleandoc(_body(func)))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call)
                and getattr(node.func, "attr", None) == "execute"):
            sql = node.args[0]
            if not (isinstance(sql, ast.Constant)
                    and isinstance(sql.value, str)):
                continue
            out = []
            rest = sql.value
            while "%s" in rest:
                idx = rest.index("%s")
                prefix = rest[:idx]
                match = _PLACEHOLDER.search(prefix)
                out.append(match.group(1) if match else "(expr)")
                rest = rest[idx + 2:]
            return out
    return None


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
# SECTION 2: AUTHORITATIVE STATEMENT SCOPE (static)
# ===========================================================================


class ClaimStatementScopeTests(unittest.TestCase):
    """Tenant ownership is proven inside the authoritative statement."""

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
        # The authoritative statement is the UPDATE; ownership must be a
        # predicate of that same statement, not a preceding probe.
        self.assertIn("UPDATE TASKS T", sql)
        self.assertLess(sql.index("UPDATE TASKS T"), sql.index("J . TENANT_ID = %S"))

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
        self.assertLess(tenant, order,
                        "tenant scope must precede ORDER BY")
        self.assertLess(tenant, lock,
                        "tenant scope must precede FOR UPDATE/SKIP LOCKED")
        self.assertLess(tenant, limit,
                        "tenant scope must precede LIMIT")

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

    # ---- neutralization ----

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

    # ---- binding order ----

    def test_claim_task_binds_tenant_to_the_tenant_placeholder(self):
        """job/task, duration, owner and tenant must bind by role."""
        params = _exec_params(checkpoint.claim_task)
        self.assertEqual(params, ["owner_id", "lease_seconds",
                                  "task_id", "tenant_id"])
        order = _placeholder_order(checkpoint.claim_task)
        self.assertEqual(order, ["lease_owner", "(expr)", "t.id",
                                 "j.tenant_id"])

    def test_renew_lease_binds_tenant_to_the_tenant_placeholder(self):
        params = _exec_params(checkpoint.renew_lease)
        self.assertEqual(params, ["lease_seconds", "task_id",
                                  "tenant_id", "owner_id", "version"])
        order = _placeholder_order(checkpoint.renew_lease)
        self.assertEqual(order, ["(expr)", "t.id", "j.tenant_id",
                                 "t.lease_owner", "t.lease_version"])

    def test_claim_next_binds_job_then_tenant_distinctly(self):
        """job_id and tenant_id must be separate placeholders, in that order."""
        params = _exec_params(scheduler.claim_next_ready_task)
        self.assertEqual(params, ["job_id", "tenant_id", "owner_id",
                                  "lease_seconds"])
        order = _placeholder_order(scheduler.claim_next_ready_task)
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
# SECTION 3: LIVE REACHABILITY SENTINEL (static)
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
    """Group C must not silently activate the dormant execution cluster.

    The accepted live closure is the worker dispatch subsystem. If a future
    change wires runtime/scheduler/checkpoint/executor into the worker API,
    this fails instead of the change passing unnoticed.
    """

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
        base = "31716362a7f07807c667ed8975192a770259adac"
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
# SECTION 4: C2 BOUNDARY NOT CROSSED (static)
# ===========================================================================


class C2BoundaryTests(unittest.TestCase):
    """C1 must not pre-empt C2's checkpoint read/write hardening."""

    C2_OWNED = ("save_checkpoint", "load_latest_checkpoint",
                "release_task", "defer_task_for_route")

    def test_c2_owned_signatures_have_no_tenant_yet(self):
        for name in self.C2_OWNED:
            func = getattr(checkpoint, name)
            self.assertNotIn(
                "tenant_id", inspect.signature(func).parameters,
                f"{name} is C2-owned and must not gain tenant_id in C1")

    def test_c2_owned_statements_have_no_tenant_predicate(self):
        for name in self.C2_OWNED:
            func = getattr(checkpoint, name)
            tree = ast.parse(inspect.cleandoc(inspect.getsource(func)))
            joined = "\n".join(_literal_strings(tree))
            self.assertNotIn("TENANT_ID", joined, name)
            self.assertNotIn("JOBS", joined, name)

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
# SECTION 5: DB SECURITY (requires PostgreSQL)
# ===========================================================================


@unittest.skipUnless(_DB_URL, "PostgreSQL integration URL required")
class ClaimScopeDatabaseTests(unittest.TestCase):
    """Cross-tenant claim/lease denial against a real database."""

    def setUp(self):
        self.conn = psycopg.connect(_DB_URL)
        self.addCleanup(self.conn.close)
        self.addCleanup(self.conn.rollback)
        self.tenant = uuid4()
        self.foreign = uuid4()
        with self.conn.cursor() as cur:
            for tenant in (self.tenant, self.foreign):
                cur.execute(
                    "INSERT INTO tenants(id, slug, name) VALUES (%s,%s,%s)",
                    (tenant, str(tenant), "c1 claim scope"))

    def sql(self, statement, params=()):
        with self.conn.cursor() as cur:
            cur.execute(statement, params)
            return cur.fetchall() if cur.description else None

    def job(self, tenant=None):
        job = uuid4()
        self.sql("INSERT INTO jobs(id, tenant_id, objective, status)"
                 " VALUES (%s,%s,'c1','running')",
                 (job, tenant or self.tenant))
        return job

    def task(self, job, external="ext"):
        task = uuid4()
        self.sql("INSERT INTO tasks(id, job_id, external_id, title,"
                 " description, capability, risk, status)"
                 " VALUES (%s,%s,%s,'t','d','basic','low','pending')",
                 (task, job, f"{external}-{task}"))
        return task

    def task_state(self, task):
        return self.sql(
            "SELECT status, lease_owner, lease_version, lease_expires_at,"
            " checkpoint_seq FROM tasks WHERE id=%s", (task,))[0]

    # ---- claim_task ----

    def test_claim_task_same_tenant_succeeds(self):
        job = self.job()
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        self.assertEqual(lease.tenant_id, self.tenant)
        self.assertEqual(lease.task_id, task)
        status, owner, version, _, _ = self.task_state(task)
        self.assertEqual(status, "running")
        self.assertEqual(owner, lease.owner_id)
        self.assertEqual(version, 1)

    def test_claim_task_foreign_tenant_denied_and_task_unchanged(self):
        job = self.job()
        task = self.task(job)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.TaskAlreadyClaimed):
            checkpoint.claim_task(task, uuid4(), tenant_id=self.foreign)
        self.assertEqual(self.task_state(task), before)

    def test_claim_task_missing_and_foreign_are_uniform(self):
        job = self.job()
        task = self.task(job)
        messages = []
        for target, tenant in ((uuid4(), self.tenant), (task, self.foreign)):
            with self.assertRaises(checkpoint.TaskAlreadyClaimed) as ctx:
                checkpoint.claim_task(target, uuid4(), tenant_id=tenant)
            messages.append(str(ctx.exception))
        self.assertEqual(len(set(messages)), 1,
                         f"missing/foreign must not form an oracle: {messages}")

    # ---- renew_lease ----

    def test_renew_lease_same_tenant_succeeds(self):
        job = self.job()
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        renewed = checkpoint.renew_lease(lease, tenant_id=self.tenant)
        self.assertEqual(renewed.tenant_id, self.tenant)
        self.assertEqual(renewed.version, lease.version)

    def test_renew_lease_foreign_tenant_denied_and_state_unchanged(self):
        job = self.job()
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(lease, tenant_id=self.foreign)
        after = self.task_state(task)
        self.assertEqual(after, before,
                         "foreign renewal must leave owner/version/expiry/status")

    def test_renew_lease_lease_tenant_is_not_authority(self):
        """A lease carrying the owner tenant cannot be renewed by a foreign
        caller merely because the lease object knows the owning tenant."""
        job = self.job()
        task = self.task(job)
        lease = checkpoint.claim_task(task, uuid4(), tenant_id=self.tenant)
        before = self.task_state(task)
        with self.assertRaises(checkpoint.LeaseLost):
            checkpoint.renew_lease(lease, tenant_id=self.foreign)
        self.assertEqual(self.task_state(task), before)

    # ---- claim_next_ready_task ----

    def test_claim_next_same_tenant_succeeds(self):
        job = self.job()
        task = self.task(job)
        lease = scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.tenant)
        self.assertIsNotNone(lease)
        self.assertEqual(lease.tenant_id, self.tenant)
        self.assertEqual(lease.task_id, task)

    def test_claim_next_foreign_tenant_cannot_claim(self):
        job = self.job()
        task = self.task(job)
        before = self.task_state(task)
        self.assertIsNone(scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.foreign))
        self.assertEqual(self.task_state(task), before,
                         "foreign claim must leave the task untouched")

    def test_claim_next_foreign_job_id_under_own_tenant_cannot_claim(self):
        """Own tenant but a job belonging to another tenant is still denied."""
        foreign_job = self.job(self.foreign)
        self.task(foreign_job)
        self.assertIsNone(scheduler.claim_next_ready_task(
            foreign_job, uuid4(), tenant_id=self.tenant))

    def test_claim_next_missing_and_foreign_job_are_uniform(self):
        job = self.job()
        self.task(job)
        foreign_job = self.job(self.foreign)
        self.task(foreign_job)
        missing = uuid4()
        outcomes = set()
        for target, tenant in ((missing, self.tenant),
                               (foreign_job, self.tenant)):
            outcomes.add(scheduler.claim_next_ready_task(
                target, uuid4(), tenant_id=tenant))
        self.assertEqual(outcomes, {None})

    def test_claim_next_does_not_lock_or_consume_foreign_tasks(self):
        """A foreign-tenant attempt must leave ordering and cardinality intact."""
        foreign_job = self.job(self.foreign)
        foreign_task = self.task(foreign_job, external="a")
        before = self.task_state(foreign_task)
        for _ in range(3):
            self.assertIsNone(scheduler.claim_next_ready_task(
                foreign_job, uuid4(), tenant_id=self.tenant))
        self.assertEqual(self.task_state(foreign_task), before)
        # the owning tenant can still claim it normally afterwards
        lease = scheduler.claim_next_ready_task(
            foreign_job, uuid4(), tenant_id=self.foreign)
        self.assertIsNotNone(lease)

    def test_lease_carries_exact_caller_tenant(self):
        job = self.job()
        self.task(job)
        lease = scheduler.claim_next_ready_task(
            job, uuid4(), tenant_id=self.tenant)
        self.assertEqual(lease.tenant_id, self.tenant)
        self.assertNotEqual(lease.tenant_id, self.foreign)


if __name__ == "__main__":
    unittest.main()
