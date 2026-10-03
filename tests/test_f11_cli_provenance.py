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


if __name__ == "__main__":
    unittest.main()