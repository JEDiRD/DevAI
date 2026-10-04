"""Residual-A: reconciliation actor attribution contract.

Discovery classified this residual as TEST HARDENING ONLY: no production
defect, no migration, no production change. Bare 'operator' is NOT
production-reachable; it appears only as a test fixture value. This file
freezes the contract so a future production edit cannot silently weaken it.

What is deliberately NOT claimed here, because the code does not support it:

  * operator:<sha256(uid)> is NOT cryptographic authentication. It is audit
    attribution metadata derived from the host UID. It is not non-repudiation,
    not an identity proof, and not an authorization decision.
  * The DB CHECK is a GENERIC CHARSET check, not an actor allowlist. The
    schema accepts 'operator', 'service', 'root' and any other 1-80 character
    string from [A-Za-z0-9_.:-]. Only the CODE enforces the actor allowlist.
    Schema validation is therefore not actor authenticity, and these tests
    pin that fact rather than papering over it.
  * resolve_case(actor=...) accepts any allowlisted value from trusted
    internal code. Arbitrary actor values require trusted-code invocation;
    they are not currently production caller-controlled, and this file does
    not claim arbitrary spoofing is impossible.

The append-only trigger is pinned STRUCTURALLY from the migration text. No
PostgreSQL exists on this host, so no test here claims live enforcement.
"""
import ast
import os
import re
import unittest
from decimal import Decimal

from devai import reconciliation, principal
from devai.reconciliation import ReconciliationError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")
PRODUCTION_REL = "controller/devai/reconciliation.py"
PRINCIPAL_REL = "controller/devai/principal.py"

# The only three actor sources production can produce today.
PRODUCTION_ACTOR_LITERALS = {"controller", "accounting-timer"}
FAKE_UID = 1000
EXPECTED_CLI_ACTOR = (
    "operator:" +
    __import__("hashlib").sha256(f"uid:{FAKE_UID}".encode()).hexdigest())


def normalised(path=PRODUCTION_REL):
    with open(os.path.join(ROOT, path), encoding="utf-8") as handle:
        return ast.unparse(ast.parse(handle.read()))


def migration_text():
    parts = []
    for name in sorted(os.listdir(MIGRATIONS)):
        if name.endswith(".sql"):
            with open(os.path.join(MIGRATIONS, name), encoding="utf-8") as fh:
                parts.append(fh.read())
    return "\n".join(parts)


def cli_block():
    """Normalised source of the module's __main__ guard."""
    for node in ast.parse(normalised()).body:
        if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
            return ast.unparse(node)
    raise AssertionError("no __main__ guard")


def stdin_allowlist():
    for node in ast.walk(ast.parse(normalised())):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "allowed"
                for t in node.targets):
            return set(ast.literal_eval(node.value))
    raise AssertionError("stdin allowlist not found")


def function_body(name):
    for node in ast.parse(normalised()).body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.unparse(node)
    raise AssertionError(f"{name} not found")


class RecordingCursor:
    """Minimal cursor: records the INSERT and never touches a database."""

    def __init__(self):
        self.statements = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def execute(self, sql, params=None):
        self.statements.append((" ".join(sql.split()), params))


# =====================================================================
# 2, 14. SCHEMA FACT
# =====================================================================

class ResidualSchemaFactTests(unittest.TestCase):
    """The real CHECK is a charset, not an actor allowlist."""

    def events_table(self):
        text = migration_text()
        match = re.search(r"CREATE TABLE metered_reconciliation_events"
                          r"\s*\((.*?)\n\);", text, re.DOTALL)
        self.assertIsNotNone(match, "events table not declared")
        return match.group(1)

    def test_actor_is_text_not_null(self):
        body = self.events_table()
        self.assertRegex(body, r"actor TEXT NOT NULL")

    def test_actor_check_is_a_generic_charset_not_an_allowlist(self):
        body = self.events_table()
        check = re.search(r"CHECK \(actor ~ '([^']+)'\)", body)
        self.assertIsNotNone(check, "actor CHECK missing")
        self.assertEqual(r"^[A-Za-z0-9_.:-]{1,80}$", check.group(1))
        # The schema must NOT encode the production actor names.
        for literal in ("controller", "accounting-timer", "operator"):
            self.assertNotIn(
                literal, check.group(1),
                "schema CHECK must stay generic; actor authenticity is "
                "enforced in code, not here")

    def test_schema_charset_accepts_generic_values_the_code_rejects(self):
        """Deliberate evidence that schema validation != actor authenticity."""
        charset = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
        for value in ("operator", "service", "root", "anything"):
            self.assertTrue(charset.match(value), value)
        from devai import reconciliation as rec
        # and the production code rejects what the schema permits
        cur = RecordingCursor()
        for value in ("service", "root"):
            with self.assertRaises(ReconciliationError):
                rec._event(cur, "c", "opened", value)

    def test_events_table_is_append_only_structurally(self):
        """STRUCTURAL ONLY: no PostgreSQL here, so no live-enforcement claim."""
        text = migration_text()
        self.assertIn("reject_metered_audit_mutation", text)
        self.assertRegex(
            text,
            r"CREATE TRIGGER metered_audit_append_only BEFORE UPDATE OR DELETE"
            r"\s*ON metered_reconciliation_events")
        self.assertIn("METERED_AUDIT_APPEND_ONLY", text)

    def test_no_production_code_mutates_events(self):
        src = normalised()
        self.assertNotIn("UPDATE metered_reconciliation_events", src)
        self.assertNotIn("DELETE FROM metered_reconciliation_events", src)


# =====================================================================
# 3, 4, 5, 8, 9. PRODUCTION WRITER INVENTORY
# =====================================================================

class ResidualProductionWriterTests(unittest.TestCase):
    """Exactly three production _event sites, with known actor sources."""

    def event_sites(self):
        """(enclosing function, actor expression) for every _event CALL.

        Scope is top-level function bodies only, so the recursive call to
        _event from inside _event itself is not misattributed to the
        definition site.
        """
        tree = ast.parse(normalised())
        sites = []
        for node in tree.body:
            if not isinstance(node, ast.FunctionDef):
                continue
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name) \
                        and sub.func.id == "_event":
                    if len(sub.args) > 3:
                        actor = ast.unparse(sub.args[3])
                    else:
                        kw = next((k for k in sub.keywords
                                   if k.arg == "actor"), None)
                        actor = ast.unparse(kw.value) if kw else "?"
                    sites.append((node.name, actor))
        return sites

    def test_exactly_three_production_event_sites(self):
        self.assertEqual(3, len(self.event_sites()))

    def test_controller_actor_paths(self):
        """_open persists 'controller'; defer_missing_usage routes there."""
        self.assertIn(("_open", "'controller'"), self.event_sites())
        self.assertIn("_open(cur, attempt, tenant_id=owner_tenant)",
                      function_body("sweep"))
        self.assertIn("return _open(cur, attempt_id, result_success="
                      "result_success, tenant_id=tenant_id)",
                      function_body("defer_missing_usage"))
        self.assertIn("_event(cur, identifier, 'opened', 'controller')",
                      function_body("_open"))

    def test_sweep_actor_is_the_accounting_timer_literal(self):
        self.assertIn(("sweep", "'accounting-timer'"), self.event_sites())
        sweep = function_body("sweep")
        self.assertIn("_resolve(cur, tenant, identifier, "
                      "actor='accounting-timer', unrecoverable=True)", sweep)
        # and it is never derived from any input
        for derived in ("actor=data[", "actor=actor", "actor=os.environ",
                        "actor=json"):
            self.assertNotIn(derived, sweep)

    def test_resolve_event_forwards_the_actor_parameter(self):
        self.assertIn(("_resolve", "actor"), self.event_sites())
        # _resolve must not consult actor for anything but the event write
        body = function_body("_resolve")
        actor_lines = [ln for ln in body.splitlines() if "actor" in ln]
        self.assertEqual(2, len(actor_lines),
                         f"actor must appear only in the signature and the "
                         f"event call: {actor_lines}")
        self.assertTrue(actor_lines[0].lstrip().startswith("def _resolve("),
                        actor_lines)
        self.assertIn("*, actor,", actor_lines[0])
        self.assertTrue(actor_lines[1].lstrip().startswith("_event("),
                        actor_lines)

    def test_bare_operator_is_absent_from_production_call_sites(self):
        """Section 8 tripwire: production only, tests are excluded."""
        for fn, actor in self.event_sites():
            self.assertNotEqual("'operator'", actor,
                                f"{fn}() persists bare operator")
        # no production caller passes a bare 'operator' literal either
        tree = ast.parse(normalised())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = getattr(node.func, "id", None) or \
                    getattr(node.func, "attr", None)
                if name in ("resolve_case", "_resolve", "defer_missing_usage"):
                    for arg in list(node.args) + [k.value for k in node.keywords]:
                        self.assertNotEqual(
                            "'operator'", ast.unparse(arg),
                            f"{name} called with bare operator")

    def test_bare_operator_survives_only_in_tests_negative_control(self):
        """Section 9: prove the tripwire is not a naive repo-wide grep."""
        found = 0
        tests_dir = os.path.join(ROOT, "tests")
        for name in sorted(os.listdir(tests_dir)):
            if not name.endswith(".py"):
                continue
            with open(os.path.join(tests_dir, name),
                      encoding="utf-8") as handle:
                if re.search(r"actor\s*=\s*['\"]operator['\"]",
                             handle.read()):
                    found += 1
        self.assertGreater(found, 0,
                           "negative control empty: bare operator no longer "
                           "appears in tests, so the tripwire proves nothing")
        # and the production tripwire still passes despite those fixtures
        for fn, actor in self.event_sites():
            self.assertNotEqual("'operator'", actor)


# =====================================================================
# 6, 7, 10, 11. CLI ACTOR
# =====================================================================

class ResidualCliActorTests(unittest.TestCase):
    def test_cli_actor_is_prefix_plus_64_lowercase_hex(self):
        actor = EXPECTED_CLI_ACTOR
        self.assertTrue(actor.startswith("operator:"), actor)
        digest = actor.split(":", 1)[1]
        self.assertEqual(64, len(digest))
        self.assertRegex(digest, r"^[a-f0-9]{64}$")

    def test_cli_derivation_shape_is_pinned(self):
        """Derived from os.getuid(), not hard-coded to one host."""
        block = cli_block()
        self.assertIn("'operator:'", block)
        self.assertIn("hashlib.sha256", block)
        self.assertIn("os.getuid()", block)
        self.assertIn("uid:", block)
        self.assertNotIn("os.environ", block)

    def test_cli_actor_is_not_in_the_stdin_allowlist(self):
        allowed = stdin_allowlist()
        self.assertNotIn("actor", allowed)
        self.assertEqual({"tenant_id", "case_id", "usage", "statement_cost",
                          "evidence_sha256", "unrecoverable"}, allowed)

    def test_cli_passes_the_derived_actor_not_a_literal(self):
        block = cli_block()
        self.assertIn("actor=actor", block)
        self.assertNotIn("actor='operator'", block)

    def test_no_cli_argument_or_env_selects_actor(self):
        block = cli_block()
        for selector in ("add_argument('--actor", "add_argument(\"--actor",
                         "environ.get('ACTOR", 'environ["ACTOR'):
            self.assertNotIn(selector, block)

    def test_documentation_does_not_claim_authenticity(self):
        """Section 11: attribution metadata, not authentication."""
        text = open(os.path.join(ROOT, PRODUCTION_REL),
                    encoding="utf-8").read().lower()
        for overclaim in ("non-repudiation", "nonrepudiation",
                          "proves identity", "identity proof",
                          "actor authorizes", "actor is authorization"):
            self.assertNotIn(overclaim, text)


# =====================================================================
# 10. EVENT FORMAT VALIDATION (against the real production function)
# =====================================================================

class ResidualEventValidationTests(unittest.TestCase):
    def event(self, actor):
        cur = RecordingCursor()
        reconciliation._event(cur, "case-id", "opened", actor)
        return cur.statements

    def test_production_actor_forms_are_accepted(self):
        for actor in ("controller", "accounting-timer", "provider-import",
                      EXPECTED_CLI_ACTOR):
            statements = self.event(actor)
            self.assertEqual(1, len(statements), actor)
            self.assertIn("metered_reconciliation_events", statements[0][0])

    def test_bare_operator_is_still_format_valid(self):
        """It is rejected only by reachability discipline, not by format."""
        self.assertEqual(1, len(self.event("operator")))

    def test_malformed_actors_are_rejected_by_the_real_validator(self):
        cases = {
            "empty": "",
            "too long": "o" * 81,
            "whitespace": "operator one",
            "slash": "operator/root",
            "newline": "operator\nroot",
            "outside contract": "operator$",
            "short hash": "operator:" + "a" * 63,
            "uppercase hash": "operator:" + "A" * 64,
            "non hex hash": "operator:" + "z" * 64,
            "unknown literal": "root",
        }
        for label, actor in cases.items():
            with self.assertRaises(ReconciliationError, msg=label):
                self.event(actor)

    def test_invalid_evidence_is_also_rejected(self):
        cur = RecordingCursor()
        with self.assertRaises(ReconciliationError):
            reconciliation._event(cur, "c", "usage", "controller",
                                   evidence="not-a-digest")


# =====================================================================
# 12, 13. AUTHORIZATION SEPARATION
# =====================================================================

class ResidualAuthoritySeparationTests(unittest.TestCase):
    def sql_statements(self):
        """Only constants that ARE SQL, i.e. whose text starts with a verb.

        approval.py's module docstring discusses the actor-kind check and
        contains the word "SQL", so a naive 'contains a verb' scan treats
        prose as an executable statement. Requiring the stripped text to
        BEGIN with a statement verb is the discriminator.
        """
        for root in ("controller/devai",):
            for name in sorted(os.listdir(os.path.join(ROOT, root))):
                if not name.endswith(".py"):
                    continue
                tree = ast.parse(open(os.path.join(ROOT, root, name),
                                      encoding="utf-8").read())
                for node in ast.walk(tree):
                    if not (isinstance(node, ast.Constant)
                            and isinstance(node.value, str)):
                        continue
                    flat = " ".join(node.value.split())
                    if re.match(r"^(SELECT|UPDATE|INSERT|DELETE)\b", flat,
                                re.I):
                        yield name, flat

    def test_actor_never_appears_in_a_sql_predicate(self):
        for name, sql in self.sql_statements():
            self.assertNotRegex(
                sql, r"\bWHERE\b[^;]*\bactor\b",
                f"{name}: actor must never be an authorization predicate")
            self.assertNotRegex(
                sql, r"\bAND\b\s*actor\s*[=<]", f"{name}: actor in a predicate")

    def test_actor_is_not_a_column_anywhere_except_the_event_insert(self):
        offenders = [(name, sql) for name, sql in self.sql_statements()
                     if re.search(r"\bactor\b", sql)]
        for name, sql in offenders:
            self.assertIn("metered_reconciliation_events", sql, name)
            self.assertTrue(sql.upper().startswith("INSERT"), name)
        self.assertTrue(offenders,
                        "expected the event INSERT as the only actor column")
        self.assertEqual(1, len(offenders), offenders)

    def test_actor_absent_from_resolution_and_pricing_decisions(self):
        body = function_body("_resolve")
        # actor appears only in the signature and the event forwarding call
        actor_lines = [ln for ln in body.splitlines() if "actor" in ln]
        self.assertEqual(2, len(actor_lines), actor_lines)
        self.assertTrue(actor_lines[1].lstrip().startswith("_event("),
                        actor_lines)

    def test_resolve_case_still_exposes_actor_for_trusted_callers(self):
        """Section 13: parameter preserved, not redesigned."""
        import inspect
        signature = inspect.signature(reconciliation.resolve_case)
        self.assertIn("actor", signature.parameters)
        self.assertIs(signature.parameters["actor"].default,
                      inspect.Parameter.empty,
                      "actor must remain required, not defaulted")
        # keyword-only, so it cannot be bound positionally by mistake
        self.assertIs(signature.parameters["actor"].kind,
                      inspect.Parameter.KEYWORD_ONLY)

    def test_actor_is_not_part_of_idempotency(self):
        """Already-resolved returns False by status, not by actor."""
        body = function_body("_resolve")
        self.assertIn("if status == 'resolved' and (not late):", body)
        self.assertIn("return False", body)


# =====================================================================
# 15. PRINCIPAL CONCEPT SEPARATION
# =====================================================================

class ResidualPrincipalSeparationTests(unittest.TestCase):
    def test_principal_actor_kind_is_a_distinct_concept(self):
        self.assertEqual("operator", principal.OPERATOR_ACTOR)
        self.assertEqual("service", principal.SERVICE_ACTOR)
        # it is a TenantPrincipal actor_kind, and identity rides on subject
        built = principal.make_tenant_principal(
            tenant_id="11111111-1111-4111-8111-111111111111",
            subject="ops@example", actor_kind=principal.OPERATOR_ACTOR)
        self.assertEqual("ops@example", built.subject)
        self.assertEqual(principal.OPERATOR_ACTOR, built.actor_kind)

    def test_principal_actor_does_not_write_reconciliation_events(self):
        src = normalised(PRINCIPAL_REL)
        self.assertNotIn("metered_reconciliation_events", src)
        self.assertNotIn("_event", src)

    def test_events_actor_is_not_a_tenantprincipal_actor_kind(self):
        """The two concepts must never be conflated in the event path."""
        body = function_body("_event")
        self.assertNotIn("actor_kind", body)
        self.assertNotIn("TenantPrincipal", body)


# =====================================================================
# 16, 17. SYNTHETIC LOAD-BEARING CONTROLS
# =====================================================================

def actor_invariants(src):
    """Violated invariant names for a (possibly mutated) production source."""
    bad = []
    tree = ast.parse(src)
    cli = ""
    for node in tree.body:
        if isinstance(node, ast.If) and "__name__" in ast.unparse(node.test):
            cli = ast.unparse(node)
    functions = {n.name: ast.unparse(n) for n in tree.body
                 if isinstance(n, ast.FunctionDef)}

    # A: CLI actor must be the derived hashed form
    flat_cli = cli.replace(" ", "")
    if "'operator:'" not in flat_cli or "hashlib.sha256" not in flat_cli \
            or "os.getuid()" not in flat_cli:
        bad.append("cli_actor_is_derived_operator_hash")
    if "actor='operator'" in flat_cli:
        bad.append("cli_actor_is_derived_operator_hash")

    # C: stdin allowlist must not gain actor
    allowed = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "allowed"
                for t in node.targets):
            try:
                allowed = set(ast.literal_eval(node.value))
            except Exception:
                allowed = None
    if allowed is None or "actor" in allowed:
        bad.append("stdin_allowlist_excludes_actor")

    # B: sweep actor must be the accounting-timer literal
    sweep = functions.get("sweep", "")
    if "actor='accounting-timer'" not in sweep.replace(" ", ""):
        bad.append("sweep_actor_is_accounting_timer")
    if "actor=data[" in sweep or "actor=actor" in sweep:
        bad.append("sweep_actor_is_accounting_timer")

    # D: no bare operator in any production event call
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == "_event" and len(node.args) > 3:
            if ast.unparse(node.args[3]) == "'operator'":
                bad.append("no_bare_operator_in_production")

    # E: _event must keep a restrictive allowlist
    event = functions.get("_event", "")
    if "fullmatch" not in event:
        bad.append("event_actor_format_validated")
    elif "operator:[a-f0-9]{64}" not in event:
        bad.append("event_actor_format_validated")

    # F: actor must never enter a SQL predicate
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and re.search(r"\b(SELECT|UPDATE|INSERT|DELETE)\b",
                              node.value, re.I):
            if re.search(r"\bWHERE\b[^;]*\bactor\b", node.value, re.I):
                bad.append("actor_not_in_sql_predicate")
    return sorted(set(bad))


# (id, description, old, new, invariant)
SYNTHETIC_MUTATIONS = (
    ("RA-S01", "CLI emits bare operator",
     "actor = 'operator:' + hashlib.sha256(('uid:' + str(os.getuid()))"
     ".encode()).hexdigest()",
     "actor = 'operator'",
     "cli_actor_is_derived_operator_hash"),
    ("RA-S02", "sweep actor becomes caller input",
     "_resolve(cur, tenant, identifier, actor='accounting-timer', "
     "unrecoverable=True)",
     "_resolve(cur, tenant, identifier, actor=data['actor'], "
     "unrecoverable=True)",
     "sweep_actor_is_accounting_timer"),
    ("RA-S03", "stdin allowlist gains actor",
     "'evidence_sha256', 'unrecoverable'}",
     "'evidence_sha256', 'unrecoverable', 'actor'}",
     "stdin_allowlist_excludes_actor"),
    ("RA-S04", "production writer gains bare operator",
     "_event(cur, identifier, 'review_required', 'accounting-timer')",
     "_event(cur, identifier, 'review_required', 'operator')",
     "no_bare_operator_in_production"),
    ("RA-S05", "_event actor validation removed",
     "if not re.fullmatch('(?:controller|accounting-timer|operator|"
     "provider-import|operator:[a-f0-9]{64})', actor) or (evidence is not "
     "None and (not re.fullmatch('[a-f0-9]{64}', evidence))):",
     "if False:",
     "event_actor_format_validated"),
    ("RA-S06", "actor becomes an authorization predicate",
     "cur.execute('SELECT id,attempt_id,status,resolution,resolved_at\\n"
     "            FROM metered_reconciliations WHERE tenant_id=%s AND id=%s', "
     "(tenant_id, case_id))",
     "cur.execute('SELECT id,attempt_id,status,resolution,resolved_at\\n"
     "            FROM metered_reconciliations WHERE tenant_id=%s AND id=%s "
     "AND actor=%s', (tenant_id, case_id, actor))",
     "actor_not_in_sql_predicate"),
)


class ResidualSyntheticControlTests(unittest.TestCase):
    """Sections 16-17: prove the detectors actually fire."""

    def test_baseline_is_clean(self):
        self.assertEqual([], actor_invariants(normalised()))

    def test_every_target_isolated(self):
        base = normalised()
        for mid, desc, old, new, inv in SYNTHETIC_MUTATIONS:
            self.assertEqual(1, base.count(old), f"{mid}: target not unique")

    def results(self):
        base = normalised()
        rows = []
        for mid, desc, old, new, inv in SYNTHETIC_MUTATIONS:
            mutated = base.replace(old, new, 1)
            self.assertNotEqual(base, mutated, f"{mid}: no-op mutation")
            try:
                violated = actor_invariants(mutated)
            except SyntaxError as exc:
                rows.append((mid, desc, inv, "HARNESS_ERROR", [str(exc)]))
                continue
            status = ("ASSERTION_CAUGHT" if inv in violated
                      else "WRONG_INVARIANT" if violated else "SURVIVED")
            rows.append((mid, desc, inv, status, violated))
        return rows

    def test_all_synthetic_controls_are_caught_by_their_intended_invariant(self):
        rows = self.results()
        report = "\n".join(
            f"  {m} {s:<16} intended={i} got={v}" for m, _, i, s, v in rows)
        print("\n=== RESIDUAL-A SYNTHETIC CONTROLS ===")
        print(report)
        bad = [r for r in rows if r[3] != "ASSERTION_CAUGHT"]
        self.assertEqual([], bad, report)

    def test_repository_production_file_is_never_modified(self):
        path = os.path.join(ROOT, PRODUCTION_REL)
        with open(path, encoding="utf-8") as handle:
            before = handle.read()
        for mutant in SYNTHETIC_MUTATIONS:
            base = normalised()
            base.replace(mutant[2], mutant[3], 1)
        with open(path, encoding="utf-8") as handle:
            self.assertEqual(before, handle.read())


if __name__ == "__main__":
    unittest.main()