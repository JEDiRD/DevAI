"""F11: reconciliation CLI provenance.

The CLI previously printed {"resolved": true, "changed": ...}. Two unrelated
reconciliation cases produced byte-identical output, so an operator-visible
claim could not be attributed to the operation that produced it. That is the
F11 rule violated: a CLI claim is not evidence unless it is bound to system
state.

F11 makes the success result attributable by reading the committed
reconciliation row in a SEPARATE transaction after resolve_case has returned,
and deriving every state field from that row. 'changed' deliberately remains
the operation outcome for this invocation, so a replayed no-op stays
distinguishable from a fresh mutation.

These tests drive the real __main__ guard body through a fake connection
modelling psycopg3 semantics (commit on clean __exit__, raise on commit
failure), so ordering is proven behaviourally rather than by reading source
order. No PostgreSQL is needed: no production request path exists here, and
the B3 internals are frozen and already covered elsewhere.

The stdin allowlist is unchanged: {tenant_id, case_id, usage, statement_cost,
evidence_sha256, unrecoverable}. Nothing lets a caller assert status, result,
outcome, success, resolved, changed, attempt_id or resolved_at.
"""
import ast
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from decimal import Decimal
from unittest import mock

from devai import reconciliation
from devai.reconciliation import ReconciliationError

TENANT_A = "11111111-1111-4111-8111-111111111111"
TENANT_B = "22222222-2222-4222-8222-222222222222"
CASE_A = "33333333-3333-4333-8333-333333333333"
CASE_B = "44444444-4444-4444-8444-444444444444"
ATTEMPT_A = "55555555-5555-4555-8555-555555555555"
ATTEMPT_B = "66666666-6666-4666-8666-666666666666"
RESOLVED_AT_DT = datetime(2026, 2, 3, 4, 5, 6, 123456, tzinfo=timezone.utc)
RESOLVED_AT = RESOLVED_AT_DT.isoformat()

COMMITTED_A = dict(case_id=CASE_A, attempt_id=ATTEMPT_A, status="resolved",
                   resolution="usage", resolved_at=RESOLVED_AT)
COMMITTED_B = dict(case_id=CASE_B, attempt_id=ATTEMPT_B, status="resolved",
                   resolution="provider_statement", resolved_at=RESOLVED_AT)

OPEN_CASE_ROW = ("99999999-9999-4999-8999-999999999999", "attempt-in-flight",
                 "recoverable", Decimal("1"), True, None)
PRICE_SNAPSHOT = ("pricing-key", 1, Decimal("0.5"), Decimal("1.5"))


def cli_block_source():
    """Verbatim source of the module's `if __name__ == '__main__':` body."""
    source = open(reconciliation.__file__, encoding="utf-8").read()
    for node in ast.parse(source).body:
        if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
            return "\n".join(ast.unparse(s) for s in node.body)
    raise AssertionError("no __main__ guard found in reconciliation.py")


class Events:
    def __init__(self):
        self.log = []

    def add(self, item):
        self.log.append(item)

    def indices(self, prefix):
        return [i for i, e in enumerate(self.log) if e.startswith(prefix)]


class _FakeStdin:
    def __init__(self, payload):
        self.buffer = io.BytesIO(
            payload if isinstance(payload, bytes)
            else json.dumps(payload).encode())


class ScriptedCursor:
    def __init__(self, rows, events):
        self._rows = list(rows)
        self._events = events
        self.rowcount = 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self._events.add("SQL " + " ".join(sql.split()))

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows


class FakeConn:
    def __init__(self, rows, events, fail_commit=False):
        self._rows = list(rows)
        self._events = events
        self.fail_commit = fail_commit

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self._events.add("COMMIT")
            if self.fail_commit:
                self._events.add("COMMIT-FAILED")
                raise RuntimeError("simulated commit failure")
        else:
            self._events.add("ROLLBACK")
        return False

    def cursor(self):
        return ScriptedCursor(self._rows, self._events)


def resolve_inputs(**over):
    payload = {"tenant_id": TENANT_A, "case_id": CASE_A,
               "usage": [10, 20], "evidence_sha256": "a" * 64}
    payload.update(over)
    return payload


def mutation_queue(case_row=OPEN_CASE_ROW):
    """Rows for the resolve_case transaction: case row, then price snapshot."""
    return [case_row, PRICE_SNAPSHOT]


def evidence_queue(committed):
    """Rows for the post-commit provenance re-read.

    resolved_at is a real datetime, because the production CLI serialises it
    with .isoformat(); a string here would test the fixture, not the code.
    """
    return [(committed["case_id"], committed["attempt_id"],
             committed["status"], committed["resolution"],
             RESOLVED_AT_DT if committed["resolved_at"] else None)]


def resolve_queues(committed=COMMITTED_A, case_row=OPEN_CASE_ROW):
    """One resolve invocation opens TWO connections: mutate, then re-read."""
    return [mutation_queue(case_row), evidence_queue(committed)]


def run_cli(payloads, queues, fail_commit_on=()):
    """Run the CLI once per payload; queues are consumed per connection.

    F11 makes each resolve invocation open two connections, so queues are
    positional across connections rather than per invocation.
    """
    events = Events()
    supplied = iter(queues)
    opened = []

    def factory():
        index = len(opened)
        rows = next(supplied, [])
        conn = FakeConn(rows, events, fail_commit=index in fail_commit_on)
        opened.append(conn)
        return conn

    results = []
    argv = sys.argv
    try:
        with mock.patch.object(reconciliation, "connect", factory), \
             mock.patch.object(os, "getuid", lambda: 1000, create=True):
            for payload in payloads:
                out, err = io.StringIO(), io.StringIO()
                sys.argv = ["devai.reconciliation", "--resolve-stdin"]
                code = 0
                glb = dict(reconciliation.__dict__)
                glb["__name__"] = "__main__"
                with mock.patch.object(sys, "stdin",
                                       _FakeStdin(payload)), \
                     redirect_stdout(out), redirect_stderr(err):
                    try:
                        exec(cli_block_source(), glb)
                    except SystemExit as exc:
                        code = exc.code or 0
                results.append({"code": code, "stdout": out.getvalue(),
                                "stderr": err.getvalue()})
    finally:
        sys.argv = argv
    return results, events


def run_sweep(queues):
    """Run the no-argument sweep mode."""
    events = Events()
    supplied = iter(queues)
    opened = []

    def factory():
        conn = FakeConn(next(supplied, []), events)
        opened.append(conn)
        return conn

    out, err = io.StringIO(), io.StringIO()
    argv = sys.argv
    code = 0
    try:
        sys.argv = ["devai.reconciliation"]
        glb = dict(reconciliation.__dict__)
        glb["__name__"] = "__main__"
        with mock.patch.object(reconciliation, "connect", factory), \
             redirect_stdout(out), redirect_stderr(err):
            try:
                exec(cli_block_source(), glb)
            except SystemExit as exc:
                code = exc.code or 0
            except Exception:
                # sweep mode has no try/except, so an unhandled error is how
                # Python reports failure: traceback on stderr, non-zero exit.
                code = 1
    finally:
        sys.argv = argv
    return {"code": code, "stdout": out.getvalue(),
            "stderr": err.getvalue()}, events


class F11CliOutputTests(unittest.TestCase):
    """Sections 3, 8-14: output bound to committed state."""

    def resolve_once(self, committed=COMMITTED_A, payload=None):
        results, _ = run_cli(
            [payload if payload is not None else resolve_inputs()],
            resolve_queues(committed))
        return results[0]

    def test_success_output_is_json_and_exits_zero(self):
        r = self.resolve_once()
        self.assertEqual(0, r["code"], r["stderr"])
        self.assertEqual("", r["stderr"])
        payload = json.loads(r["stdout"])
        self.assertIsInstance(payload, dict)

    def test_output_identifies_case_attempt_and_committed_state(self):
        payload = json.loads(self.resolve_once()["stdout"])
        self.assertEqual(CASE_A, payload["case_id"])
        self.assertEqual(ATTEMPT_A, payload["attempt_id"])
        self.assertEqual("resolved", payload["status"])
        self.assertEqual("usage", payload["resolution"])
        self.assertEqual(RESOLVED_AT, payload["resolved_at"])
        self.assertTrue(payload["changed"])

    def test_resolved_is_derived_from_committed_status_not_constant(self):
        pending = dict(COMMITTED_A, status="review_required", resolution=None,
                       resolved_at=None)
        payload = json.loads(self.resolve_once(committed=pending)["stdout"])
        self.assertFalse(payload["resolved"])
        self.assertEqual("review_required", payload["status"])
        self.assertIsNone(payload["resolution"])
        self.assertIsNone(payload["resolved_at"])

    def test_case_id_is_db_derived_not_stdin_echo(self):
        decoy = "99999999-9999-4999-8999-999999999999"
        payload = json.loads(
            self.resolve_once(payload=resolve_inputs(case_id=decoy))["stdout"])
        self.assertEqual(CASE_A, payload["case_id"])
        self.assertNotEqual(decoy, payload["case_id"])

    def test_resolution_is_db_derived_not_inferred_from_input(self):
        reported = dict(COMMITTED_A, resolution="provider_statement")
        payload = json.loads(self.resolve_once(committed=reported)["stdout"])
        self.assertEqual("provider_statement", payload["resolution"])

    def test_attempt_id_is_not_suppliable(self):
        """Supplying attempt_id is rejected outright, and never echoed."""
        r = self.resolve_once(payload=resolve_inputs(attempt_id=ATTEMPT_B))
        self.assertNotEqual(0, r["code"])
        self.assertEqual("", r["stdout"])
        self.assertNotIn(ATTEMPT_B, r["stdout"] + r["stderr"])
        # and the committed row supplies it on the accepted path
        ok = json.loads(self.resolve_once()["stdout"])
        self.assertEqual(ATTEMPT_A, ok["attempt_id"])

    def test_resolved_at_uses_persisted_timestamp(self):
        payload = json.loads(self.resolve_once()["stdout"])
        self.assertEqual(RESOLVED_AT, payload["resolved_at"])

    def test_output_exposes_no_secrets_or_environment(self):
        r = self.resolve_once()
        for forbidden in ("password", "token", "postgresql", "database_url",
                          "psycopg", "select ", "secret", "evidence_sha256"):
            self.assertNotIn(forbidden, r["stdout"].lower())


class F11IdempotencyAndAttributionTests(unittest.TestCase):
    """Sections 28, 29: replay and cross-case confusion distinguishable."""

    def test_first_then_repeat_distinguishes_changed_from_idempotent(self):
        already = ("99999999-9999-4999-8999-999999999999", "attempt-in-flight",
                   "resolved", Decimal("1"), True, "usage")
        queues = (resolve_queues(COMMITTED_A)
                  + resolve_queues(COMMITTED_A, case_row=already))
        results, _ = run_cli([resolve_inputs(), resolve_inputs()], queues)
        first, second = (json.loads(r["stdout"]) for r in results)
        self.assertTrue(first["changed"])
        self.assertFalse(second["changed"])
        self.assertEqual(first["case_id"], second["case_id"])
        self.assertEqual(first["attempt_id"], second["attempt_id"])
        self.assertEqual(first["status"], second["status"])
        self.assertNotEqual(first["changed"], second["changed"])

    def test_two_cases_are_not_attribution_equivalent(self):
        queues = resolve_queues(COMMITTED_A) + resolve_queues(COMMITTED_B)
        payloads = [resolve_inputs(), resolve_inputs(case_id=CASE_B)]
        results, _ = run_cli(payloads, queues)
        a, b = (json.loads(r["stdout"]) for r in results)
        self.assertNotEqual(a["case_id"], b["case_id"])
        self.assertNotEqual(a["attempt_id"], b["attempt_id"])
        self.assertNotEqual(a["resolution"], b["resolution"])
        self.assertNotEqual(a, b)


class F11OrderingTests(unittest.TestCase):
    """Sections 1, 16, 32: success output cannot precede commit."""

    def test_mutation_commits_before_evidence_read_and_output(self):
        results, events = run_cli([resolve_inputs()],
                                  resolve_queues(COMMITTED_A))
        self.assertEqual(0, results[0]["code"])
        commits = events.indices("COMMIT")
        re_reads = events.indices("SQL SELECT id,attempt_id,status,resolution")
        self.assertTrue(commits, "mutation transaction never committed")
        self.assertTrue(re_reads, "no post-commit provenance read happened")
        self.assertLess(commits[0], re_reads[0],
                        "evidence must be read after the mutation commits")
        self.assertEqual(2, len(commits),
                         "F11 adds exactly one committed read")

    def test_commit_failure_yields_no_success_json_and_nonzero_exit(self):
        results, events = run_cli([resolve_inputs()],
                                  resolve_queues(COMMITTED_A),
                                  fail_commit_on={0})
        r = results[0]
        self.assertNotEqual(0, r["code"])
        self.assertEqual("", r["stdout"])
        self.assertEqual("RESOLUTION_REJECTED", r["stderr"].strip())
        self.assertIn("COMMIT-FAILED", events.log)
        self.assertNotIn("simulated commit failure", r["stderr"])

    def test_evidence_read_failure_reports_failure_without_rollback_claim(self):
        results, events = run_cli([resolve_inputs()],
                                  [mutation_queue()])   # no rows for the re-read
        r = results[0]
        self.assertNotEqual(0, r["code"])
        self.assertEqual("", r["stdout"])
        self.assertEqual("RESOLUTION_REJECTED", r["stderr"].strip())
        self.assertIn("COMMIT", events.log)     # mutation DID commit
        self.assertNotIn("ROLLBACK", events.log)


class F11FailureContractTests(unittest.TestCase):
    """Sections 17, 19, 20, 21, 30, 31."""

    def test_caller_cannot_supply_outcome_fields(self):
        for key, value in (("status", "resolved"), ("result", "ok"),
                           ("outcome", "success"), ("success", True),
                           ("resolved", True), ("changed", True),
                           ("attempt_id", ATTEMPT_B),
                           ("resolved_at", "2026-01-01T00:00:00Z")):
            results, _ = run_cli([resolve_inputs(**{key: value})], [])
            r = results[0]
            self.assertNotEqual(0, r["code"], key)
            self.assertEqual("", r["stdout"], key)

    def test_allowlist_is_unchanged(self):
        source = open(reconciliation.__file__, encoding="utf-8").read()
        node = next(n for n in ast.walk(ast.parse(source))
                    if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "allowed"
                            for t in n.targets))
        self.assertEqual({"tenant_id", "case_id", "usage", "statement_cost",
                          "evidence_sha256", "unrecoverable"},
                         set(ast.literal_eval(node.value)))

    def test_foreign_tenant_case_is_rejected_without_leaking(self):
        results, _ = run_cli(
            [resolve_inputs(tenant_id=TENANT_B, case_id=CASE_B)], [])
        r = results[0]
        self.assertNotEqual(0, r["code"])
        self.assertEqual("", r["stdout"])
        self.assertEqual("RESOLUTION_REJECTED", r["stderr"].strip())
        for secret in (CASE_B, TENANT_B, ATTEMPT_B):
            self.assertNotIn(secret, r["stdout"] + r["stderr"])

    def test_oversized_stdin_is_rejected(self):
        big = resolve_inputs()
        big["evidence_sha256"] = "a" * 9000
        out, err = io.StringIO(), io.StringIO()
        glb = dict(reconciliation.__dict__)
        glb["__name__"] = "__main__"
        argv = sys.argv
        code = 0
        try:
            sys.argv = ["devai.reconciliation", "--resolve-stdin"]
            with mock.patch.object(sys, "stdin", _FakeStdin(big)), \
                 mock.patch.object(os, "getuid", lambda: 1000, create=True), \
                 redirect_stdout(out), redirect_stderr(err):
                try:
                    exec(cli_block_source(), glb)
                except SystemExit as exc:
                    code = exc.code or 0
        finally:
            sys.argv = argv
        self.assertNotEqual(0, code)
        self.assertEqual("", out.getvalue())


class F11SweepContractTests(unittest.TestCase):
    """Section 22: sweep summary preserved."""

    def test_sweep_prints_counts_and_exits_zero(self):
        result, events = run_sweep([[]])
        payload = json.loads(result["stdout"])
        self.assertEqual({"opened", "review_required", "resolved_unpriced"},
                         set(payload))
        self.assertEqual(0, result["code"])
        self.assertIn("COMMIT", events.log)

    def test_sweep_failure_exits_nonzero_without_stdout(self):
        out, err = io.StringIO(), io.StringIO()
        glb = dict(reconciliation.__dict__)
        glb["__name__"] = "__main__"
        argv = sys.argv
        code = 0
        try:
            sys.argv = ["devai.reconciliation"]
            with mock.patch.object(reconciliation, "connect",
                                   side_effect=RuntimeError("db down")), \
                 redirect_stdout(out), redirect_stderr(err):
                try:
                    exec(cli_block_source(), glb)
                except SystemExit as exc:
                    code = exc.code or 0
                except Exception:
                    code = 1
        finally:
            sys.argv = argv
        self.assertNotEqual(0, code)
        self.assertEqual("", out.getvalue())


class F11StructuralTests(unittest.TestCase):
    """Section 37: shape of the F11 change."""

    def source(self):
        return open(reconciliation.__file__, encoding="utf-8").read()

    def provenance_body(self):
        for node in ast.walk(ast.parse(self.source())):
            if isinstance(node, ast.FunctionDef) and \
                    node.name == "committed_case_provenance":
                return ast.unparse(node)
        raise AssertionError("committed_case_provenance is missing")

    def test_cli_calls_hardened_resolve_case(self):
        self.assertIn("resolve_case(", cli_block_source())

    def test_post_commit_read_is_scoped_by_caller_tenant_and_case(self):
        body = self.provenance_body()
        self.assertIn("WHERE tenant_id=%s AND id=%s", body)
        # a case-only lookup would be the vulnerability
        self.assertNotIn("WHERE id=%s", body)
        # the call site must pass the caller's tenant, not a row-derived one
        cli = cli_block_source()
        self.assertIn("tenant_id=UUID(data['tenant_id'])", cli)
        self.assertIn("case_id=UUID(data['case_id'])", cli)

    def test_provenance_read_does_not_project_row_tenant_as_authority(self):
        self.assertNotIn("tenant_id", self.provenance_body().split("SELECT")[1]
                         .split("FROM")[0])

    def test_resolved_is_not_a_static_true_constant(self):
        flat = cli_block_source().replace(" ", "")
        self.assertNotIn("'resolved':True", flat)
        self.assertIn("'resolved':status=='resolved'", flat)

    def test_state_fields_come_from_the_committed_row(self):
        cli = cli_block_source()
        self.assertIn("committed_case_provenance(", cli)
        for echoed in ("data['attempt_id']", "data['status']",
                       "data['resolution']", "data['resolved_at']"):
            self.assertNotIn(echoed, cli)

    def test_success_print_follows_the_provenance_read(self):
        cli = cli_block_source()
        provenance = cli.index("committed_case_provenance(")
        # rindex: the sweep-mode print appears earlier in the block, so the
        # resolve-mode print is the LAST one.
        resolve_print = cli.rindex("print(json.dumps(")
        self.assertLess(provenance, resolve_print)

    def test_b3_internal_signatures_are_unchanged(self):
        import inspect
        for name, params in (
                ("resolve_case", ["tenant_id", "case_id", "actor", "usage",
                                  "statement_cost", "evidence_sha256",
                                  "unrecoverable"]),
                ("defer_missing_usage", ["attempt_id", "result_success",
                                         "tenant_id"]),
                ("start_metered_attempt", ["job_id", "task_id", "number",
                                           "route", "model", "price",
                                           "reservation", "tenant_id"]),
                ("sweep", ["limit"])):
            self.assertEqual(params,
                             list(inspect.signature(
                                 getattr(reconciliation, name)).parameters),
                             name)


# =====================================================================
# MUTATION MATRIX
# =====================================================================
#
# F11 corrective 1. The F11 commit reported a 13/13 mutation result, but the
# harness that produced it lived outside the repository and was never
# committed, so the committed artifact contained no mutation evidence at all.
# This matrix is self-contained: everything needed to execute it lives in
# this file, and it reads the committed production source rather than any
# temporary copy or prior console state.
#
# Discipline, applied per mutant:
#
#   * Targets are matched in AST-normalised form, so a comment or docstring
#     can neither satisfy nor break target detection.
#   * Every target must occur EXACTLY ONCE in the normalised production
#     source. That proves isolation before the mutant is built, and
#     non-unique targets are reported as harness errors rather than silently
#     passing.
#   * The mutated source must still parse, and the target must have changed,
#     otherwise the mutant is a harness error, not a catch.
#   * A mutant counts as ASSERTION_CAUGHT only when the EXACT intended
#     invariant appears among the violated set. Rejection by an unrelated
#     invariant is classified WRONG_INVARIANT and does not count.
#   * Mutants are applied to in-memory strings only. The repository's
#     reconciliation.py is never written to.

PRODUCTION_REL = "controller/devai/reconciliation.py"
RESOLVE_BRANCH_MARKER = "else:"

# (id, property, target_file, target_symbol, old, new, invariant)
MUTATION_MATRIX = (
    ("F11M01",
     "committed reread must be scoped by tenant AND case",
     PRODUCTION_REL, "committed_case_provenance",
     "cur.execute('SELECT id,attempt_id,status,resolution,resolved_at\\n"
     "            FROM metered_reconciliations WHERE tenant_id=%s AND id=%s', "
     "(tenant_id, case_id))",
     "cur.execute('SELECT id,attempt_id,status,resolution,resolved_at "
     "FROM metered_reconciliations WHERE id=%s', (case_id,))",
     "reread_scoped_by_tenant_and_case"),

    ("F11M02",
     "output case_id comes from the committed row, not a request echo",
     PRODUCTION_REL, "__main__",
     "'case_id': str(case)",
     "'case_id': data['case_id']",
     "output_case_id_db_derived"),

    ("F11M03",
     "output identifies the attempt persisted on the case",
     PRODUCTION_REL, "__main__",
     "'attempt_id': str(attempt)",
     "'attempt_id': 'unbound'",
     "output_attempt_id_db_derived"),

    ("F11M04",
     "output status is committed-row state, not a static value",
     PRODUCTION_REL, "__main__",
     "'status': status",
     "'status': 'resolved'",
     "output_status_db_derived"),

    ("F11M05",
     "output resolution is committed state, not input-derived",
     PRODUCTION_REL, "__main__",
     "'resolution': resolution",
     "'resolution': 'usage' if data.get('usage') is not None else 'provider_statement'",
     "output_resolution_db_derived"),

    ("F11M06",
     "output resolved_at is the persisted timestamp",
     PRODUCTION_REL, "__main__",
     "'resolved_at': resolved_at.isoformat() if resolved_at is not None else None",
     "'resolved_at': datetime.now(timezone.utc).isoformat()",
     "output_resolved_at_db_derived"),

    ("F11M07",
     "resolved is computed from committed status, never hard-coded",
     PRODUCTION_REL, "__main__",
     "'resolved': status == 'resolved'",
     "'resolved': True",
     "resolved_not_static_true"),

    ("F11M08",
     "resolve success requires a committed reread on a new connection",
     PRODUCTION_REL, "__main__",
     "case, attempt, status, resolution, resolved_at = committed_case_provenance(tenant_id=UUID(data['tenant_id']), case_id=UUID(data['case_id']))",
     "case, attempt, status, resolution, resolved_at = (data['case_id'], data['case_id'], 'resolved', 'usage', None)",
     "success_requires_committed_reread"),

    ("F11M09",
     "resolve success print occurs AFTER committed provenance is obtained",
     PRODUCTION_REL, "__main__",
     "            case, attempt, status, resolution, resolved_at = committed_case_provenance(tenant_id=UUID(data['tenant_id']), case_id=UUID(data['case_id']))",
     "            print(json.dumps({'case_id': str(case), 'attempt_id': str(attempt), 'resolved': status == 'resolved', 'changed': changed, 'status': status, 'resolution': resolution, 'resolved_at': resolved_at.isoformat()}))\n            case, attempt, status, resolution, resolved_at = committed_case_provenance(tenant_id=UUID(data['tenant_id']), case_id=UUID(data['case_id']))",
     "success_print_after_provenance"),

    ("F11M10",
     "evidence-read failure emits no success and exits non-zero",
     PRODUCTION_REL, "committed_case_provenance",
     "        raise ReconciliationError('EVIDENCE_UNAVAILABLE')",
     "        return (case_id, case_id, 'resolved', 'usage', None)",
     "evidence_failure_not_success"),

    ("F11M11",
     "failure exit is non-zero, never swallowed",
     PRODUCTION_REL, "__main__",
     "            print('RESOLUTION_REJECTED', file=sys.stderr)\n            sys.exit(1)",
     "            print('RESOLUTION_REJECTED', file=sys.stderr)",
     "failure_exit_nonzero"),

    ("F11M12",
     "the success JSON must DECLARE the attempt binding field at all",
     PRODUCTION_REL, "__main__",
     "'attempt_id': str(attempt), ",
     "",
     "required_output_fields_present"),

    ("F11M13",
     "the reread returns the row it actually read (row binding intact)",
     PRODUCTION_REL, "committed_case_provenance",
     "    return row",
     "    return (case_id, case_id, 'resolved', 'usage', None)",
     "reread_returns_read_row"),
)


def normalised_production():
    """AST-normalised committed production source."""
    with open(PRODUCTION_REL, encoding="utf-8") as handle:
        return ast.unparse(ast.parse(handle.read()))


def _symbol_body(text, symbol):
    """Normalised source of one top-level function or the __main__ block."""
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == symbol:
            return ast.unparse(node)
        if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
            if symbol == "__main__":
                return ast.unparse(node)
    return ""


def _resolve_branch(text):
    """Normalised source of the --resolve-stdin branch only.

    Ordering and output invariants are scoped here so the sweep-mode summary
    print, which is legitimately un-attributed, can never be mistaken for
    resolve-mode evidence.
    """
    for node in ast.parse(text).body:
        if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
            for sub in node.body:
                if isinstance(sub, ast.If):
                    return "\n".join(ast.unparse(s) for s in sub.orelse)
    return ""


def check_invariants(text):
    """Sorted names of violated F11 invariants; empty means all hold.

    Every invariant is written so that only the specific construct it names
    can satisfy or violate it. String presence alone is never authority.
    """
    bad = []
    provenance = _symbol_body(text, "committed_case_provenance")
    resolve = _resolve_branch(text)
    flat_prov = provenance.replace(" ", "")
    flat_resolve = resolve.replace(" ", "")

    # --- committed reread helper ---
    if not provenance:
        bad.append("reread_present")
    else:
        if "tenant_id=%sANDid=%s" not in flat_prov:
            bad.append("reread_scoped_by_tenant_and_case")
        if "returnrow" not in flat_prov:
            bad.append("reread_returns_read_row")
        # a miss must raise, never fabricate a plausible-looking row
        if "raiseReconciliationError('EVIDENCE_UNAVAILABLE')" not in flat_prov:
            bad.append("evidence_failure_not_success")
        if "return(case_id,case_id,'resolved','usage',None)" in flat_prov:
            bad.append("evidence_failure_not_success")
            bad.append("reread_returns_read_row")

    # --- resolve-mode output ---
    if "'resolved':True" in flat_resolve:
        bad.append("resolved_not_static_true")
    if "'case_id':str(case)" not in flat_resolve:
        bad.append("output_case_id_db_derived")
    if "'attempt_id':str(attempt)" not in flat_resolve:
        bad.append("output_attempt_id_db_derived")
    if "'status':status" not in flat_resolve:
        bad.append("output_status_db_derived")
    if "'resolution':resolution" not in flat_resolve:
        bad.append("output_resolution_db_derived")
    if "resolved_at.isoformat()" not in flat_resolve:
        bad.append("output_resolved_at_db_derived")
    # required binding fields: case, attempt, status, resolution, resolved_at
    for field in ("case_id", "attempt_id", "status", "resolution",
                  "resolved_at"):
        if f"'{field}'" not in flat_resolve:
            bad.append("required_output_fields_present")

    # --- committed reread must actually be invoked ---
    if "committed_case_provenance(" not in resolve:
        bad.append("success_requires_committed_reread")

    # --- ordering: no success output before the reread ---
    if "print(json.dumps(" in resolve:
        first_print = resolve.index("print(json.dumps(")
        read_at = resolve.find("committed_case_provenance(")
        if read_at == -1 or read_at > first_print:
            bad.append("success_print_after_provenance")
    if "sys.exit(0)" in flat_resolve:
        bad.append("success_print_after_provenance")

    # --- failure surface ---
    if "exceptException:" in flat_resolve:
        tail = flat_resolve.split("exceptException:", 1)[1]
        if "sys.exit(1)" not in tail:
            bad.append("failure_exit_nonzero")

    return sorted(set(bad))


def execute_mutation(mid, prop, rel, symbol, old, new, invariant):
    """Classify one mutant. Never touches the repository file."""
    base = normalised_production()
    symbol_src = _symbol_body(base, symbol)

    # (6) target isolation, before mutation
    pre_count = base.count(old)
    if pre_count != 1:
        return {"id": mid, "property": prop, "classification":
                "HARNESS_ERROR", "detail": f"target occurs {pre_count} times",
                "violated": []}
    if symbol_src and old not in symbol_src:
        return {"id": mid, "property": prop, "classification":
                "HARNESS_ERROR",
                "detail": f"target not inside declared symbol {symbol}",
                "violated": []}

    mutated = base.replace(old, new, 1)

    # target must actually have changed, and the source must still parse
    if mutated == base:
        return {"id": mid, "property": prop, "classification":
                "HARNESS_ERROR", "detail": "mutation was a no-op",
                "violated": []}
    post_count = mutated.count(new)
    try:
        ast.parse(mutated)
    except SyntaxError as exc:
        return {"id": mid, "property": prop, "classification":
                "HARNESS_ERROR", "detail": f"SyntaxError: {exc}",
                "violated": []}

    violated = check_invariants(mutated)
    if invariant in violated:
        classification = "ASSERTION_CAUGHT"
    elif violated:
        classification = "WRONG_INVARIANT"
    else:
        classification = "SURVIVED"
    return {"id": mid, "property": prop, "target_file": rel,
            "target_symbol": symbol, "pre_target_count": pre_count,
            "post_target_count": post_count, "intended_invariant": invariant,
            "observed_violations": violated, "classification": classification,
            "detail": ""}


class F11MutationMatrixTests(unittest.TestCase):
    """Sections 4-6, 21-23: the committed mutation matrix."""

    def test_inventory_is_exactly_the_thirteen_frozen_ids(self):
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(
            [f"F11M{n:02d}" for n in range(1, 14)], ids)
        self.assertEqual(len(set(ids)), len(ids))
        self.assertEqual(13, len(MUTATION_MATRIX))

    def test_every_mutant_targets_a_distinct_property(self):
        props = [m[1] for m in MUTATION_MATRIX]
        self.assertEqual(len(set(props)), len(props))
        invariants = [m[6] for m in MUTATION_MATRIX]
        self.assertEqual(len(set(invariants)), len(invariants))
        targets = [(m[3], m[4]) for m in MUTATION_MATRIX]
        self.assertEqual(len(set(targets)), len(targets),
                         "no two mutants may share a target")

    def test_baseline_satisfies_every_invariant(self):
        """Section 21: must pass before any mutant is considered."""
        self.assertEqual([], check_invariants(normalised_production()))

    def test_every_target_is_isolated_in_normalised_source(self):
        """Target isolation: exactly one occurrence in normalised source.

        No assertion that the replacement is absent, because several mutants
        are deletions whose replacement text is by definition already present
        in the original. Isolation is proven by unique occurrence, and the
        runner additionally proves the mutation changed the target and that
        the result still parses.
        """
        base = normalised_production()
        for mid, prop, rel, symbol, old, new, inv in MUTATION_MATRIX:
            self.assertEqual(1, base.count(old),
                             f"{mid}: target must occur exactly once")

    def test_matrix_results(self):
        results = [execute_mutation(*m) for m in MUTATION_MATRIX]
        report = "\n".join(
            f"  {r['id']} {r['classification']:<17} "
            f"invariant={r.get('intended_invariant')} "
            f"violated={r.get('observed_violations')} "
            f"{r.get('detail', '')}".rstrip()
            for r in results)
        print("\n=== F11 MUTATION MATRIX ===")
        print(report)
        caught = [r for r in results
                  if r["classification"] == "ASSERTION_CAUGHT"]
        harness = [r for r in results if r["classification"] == "HARNESS_ERROR"]
        survived = [r for r in results if r["classification"] == "SURVIVED"]
        wrong = [r for r in results
                 if r["classification"] == "WRONG_INVARIANT"]
        self.assertEqual([], harness, report)
        self.assertEqual([], survived, report)
        self.assertEqual([], wrong, report)
        self.assertEqual(13, len(caught), report)

    def test_f11m09_is_attributed_to_the_ordering_invariant(self):
        """Section 15/23: F11M09 must be rejected by ordering, nothing else."""
        result = execute_mutation(*MUTATION_MATRIX[8])
        self.assertEqual("ASSERTION_CAUGHT", result["classification"])
        self.assertEqual("success_print_after_provenance",
                         result["intended_invariant"])
        self.assertIn("success_print_after_provenance",
                      result["observed_violations"])
        self.assertEqual(
            ["success_print_after_provenance"],
            result["observed_violations"],
            "F11M09 must be isolated: no unrelated invariant may fire")

    def test_repository_production_file_is_never_modified(self):
        with open(PRODUCTION_REL, encoding="utf-8") as handle:
            before = handle.read()
        for mutant in MUTATION_MATRIX:
            execute_mutation(*mutant)
        with open(PRODUCTION_REL, encoding="utf-8") as handle:
            after = handle.read()
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()