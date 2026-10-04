"""F10: dormant contract sentinel for execution_attempts.request_id.

This is an ACTIVATION TRIPWIRE, not a security assertion.

F10 reconfirmation established that execution_attempts.request_id is a dead
column: no production statement writes it, reads it, filters on it, joins on
it, or authorizes with it, and no test exercises it. UNIQUE(request_id)
therefore constrains a permanently-NULL column, which means it protects
nothing reachable today.

What is pinned here is the CURRENT DORMANT CONTRACT, so that activating the
column cannot happen silently:

  1. request_id remains nullable TEXT
  2. UNIQUE(request_id) remains GLOBAL, not tenant-local
  3. production does not populate it
  4. production does not read, filter, join or correlate by it
  5. request_id is NOT provider_request_id, and never will be conflated
  6. request_id carries no authority, retry or reconciliation role

If any future production change begins to use request_id, these tests FAIL
by design. That is the intent: a future phase must then decide what
request_id means, who supplies it, whether it is global or tenant-local,
whether it is security-sensitive, whether it needs normalization, and
whether UNIQUE(request_id) is still the correct constraint. The sentinel
never auto-adapts.

This file asserts nothing about the live protection provided by
UNIQUE(request_id), because there is none to assert.
"""
import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIGRATIONS = os.path.join(ROOT, "migrations")
PRODUCTION_ROOTS = ("controller/devai", "worker_agent")

# Exact-identifier match. A word boundary cannot fall between the '_' of
# "provider_" and the 'r' of "request_id", because '_' is itself a word
# character, so provider_request_id is NOT a hit. IGNORECASE is required:
# SQL identifiers are case-insensitive when unquoted, and a tripwire that a
# future author defeats by writing REQUEST_ID would not be a tripwire.
REQUEST_ID = re.compile(r"\brequest_id\b", re.IGNORECASE)
PROVIDER_REQUEST_ID = re.compile(r"\bprovider_request_id\b", re.IGNORECASE)


# =====================================================================
# SOURCE EXTRACTION
# =====================================================================

def production_sql(root_filter=None):
    """(module, function, lineno, sql) for every SQL literal in production.

    Only controller/devai and worker_agent are read, so schema text in
    migrations and assertions in tests can never be mistaken for production
    behaviour.
    """
    rows = []
    roots = PRODUCTION_ROOTS if root_filter is None else (root_filter,)
    for root in roots:
        base = os.path.join(ROOT, root)
        for name in sorted(os.listdir(base)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(base, name)
            tree = ast.parse(open(path, encoding="utf-8").read())
            owners = [(n.lineno, n.end_lineno, n.name)
                      for n in ast.walk(tree)
                      if isinstance(n, ast.FunctionDef)]
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant)
                        and isinstance(node.value, str)):
                    continue
                sql = re.sub(r"\s+", " ", node.value)
                if not re.search(r"\b(INSERT|UPDATE|SELECT|DELETE)\b", sql,
                                 re.IGNORECASE):
                    continue
                fn = next((n for lo, hi, n in owners
                           if lo <= node.lineno <= hi), "<module>")
                rows.append((f"{root}/{name}", fn, node.lineno, sql))
    return rows


def request_id_hits(rows=None):
    """Every production SQL statement that mentions exact request_id."""
    rows = production_sql() if rows is None else rows
    return [(module, function, lineno)
            for module, function, lineno, sql in rows
            if REQUEST_ID.search(sql)]


def provider_request_id_hits(rows=None):
    rows = production_sql() if rows is None else rows
    return [(module, function, lineno)
            for module, function, lineno, sql in rows
            if PROVIDER_REQUEST_ID.search(sql)]


TENANT_LOCAL_UNIQUE = re.compile(
    r"UNIQUE\s*\(\s*(?:tenant_id\s*,\s*request_id"
    r"|request_id\s*,\s*tenant_id)\s*\)", re.IGNORECASE)
GLOBAL_UNIQUE = re.compile(r"UNIQUE\s*\(\s*request_id\s*\)", re.IGNORECASE)


def schema_violations(text):
    """Reasons this schema text departs from the frozen F10 decision.

    Applied to the real migrations AND to synthetic schema strings, so one
    detector proves both the current state and the tripwire controls.
    """
    bad = []
    if not GLOBAL_UNIQUE.search(text):
        bad.append("global UNIQUE(request_id) absent")
    if TENANT_LOCAL_UNIQUE.search(text):
        bad.append("tenant-local request_id uniqueness present")
    if re.search(r"\brequest_id TEXT NOT NULL\b", text, re.IGNORECASE):
        bad.append("request_id is NOT NULL")
    if not re.search(r"\brequest_id TEXT\b", text, re.IGNORECASE):
        bad.append("request_id TEXT declaration absent")
    return bad


def schema_text():
    parts = []
    for name in sorted(os.listdir(MIGRATIONS)):
        if name.endswith(".sql"):
            raw = open(os.path.join(MIGRATIONS, name),
                       encoding="utf-8").read()
            parts.append(f"-- {name}\n{raw}")
    return re.sub(r"[ \t]+", " ", "\n".join(parts))


def column_list(sql):
    m = re.search(r"INSERT INTO execution_attempts\s*\((.*?)\)\s*(SELECT|VALUES)",
                  sql, re.IGNORECASE | re.DOTALL)
    return [c.strip() for c in m.group(1).split(",")] if m else []


def set_clause(sql):
    m = re.search(r"UPDATE execution_attempts\s+SET(.*?)"
                  r"(?:\bWHERE\b|\bRETURNING\b|\bORDER\b|\bLIMIT\b|$)",
                  sql, re.IGNORECASE | re.DOTALL)
    return m.group(1) if m else ""


# =====================================================================
# 1-3, 16. SCHEMA CONTRACT
# =====================================================================

class F10SchemaContractTests(unittest.TestCase):
    """The frozen schema decision, and that no migration moved it."""

    def test_request_id_is_text_and_nullable(self):
        text = schema_text()
        self.assertRegex(text, r"\brequest_id TEXT\b")
        self.assertNotRegex(text, r"\brequest_id TEXT NOT NULL\b")

    def test_uniqueness_is_global_not_tenant_local(self):
        text = schema_text()
        self.assertRegex(text, r"UNIQUE\s*\(\s*request_id\s*\)")
        for tenant_local in (
                r"UNIQUE\s*\(\s*tenant_id\s*,\s*request_id\s*\)",
                r"UNIQUE\s*\(\s*request_id\s*,\s*tenant_id\s*\)"):
            self.assertNotRegex(
                text, tenant_local,
                "tenant-local request_id uniqueness is a redesign and requires "
                "an explicit architecture decision, not a silent migration")

    def test_execution_attempts_has_no_tenant_id_column(self):
        # Ownership is derived through tasks -> jobs -> jobs.tenant_id.
        # F10 must not introduce a redundant, drift-prone second source.
        m = re.search(r"CREATE TABLE (?:IF NOT EXISTS )?execution_attempts"
                      r"\s*\((.*?)\n\);", schema_text(), re.DOTALL)
        self.assertIsNotNone(m)
        columns = m.group(1)
        self.assertNotIn("tenant_id", columns)
        self.assertIn("job_id UUID NOT NULL REFERENCES jobs(id)", columns)
        self.assertIn("task_id UUID NOT NULL REFERENCES tasks(id)", columns)

    def test_no_migration_altered_the_request_id_contract(self):
        text = schema_text()
        for forbidden, why in (
                (r"DROP COLUMN[^;]*\brequest_id\b", "column dropped"),
                (r"ALTER TABLE[^;]*\bDROP CONSTRAINT[^;]*request_id",
                 "uniqueness dropped"),
                (r"RENAME[^;]*\brequest_id\b", "column renamed"),
                (r"ALTER TABLE[^;]*\brequest_id\b[^;]*TYPE",
                 "column type changed"),
                (r"ALTER COLUMN\s+\brequest_id\b[^;]*SET NOT NULL",
                 "nullability tightened")):
            self.assertNotRegex(text, forbidden, f"request_id {why}")

    def test_attempt_identity_is_task_and_attempt_number(self):
        self.assertRegex(schema_text(),
                         r"UNIQUE\s*\(\s*task_id\s*,\s*attempt_number\s*\)")


# =====================================================================
# 4, 7, 8, 9. PRODUCTION DORMANCY
# =====================================================================

class F10ProductionDormancyTests(unittest.TestCase):
    """Production must not activate request_id, silently or otherwise."""

    def test_no_production_sql_mentions_request_id(self):
        hits = request_id_hits()
        self.assertEqual(
            [], [(m, fn, ln) for m, fn, ln in hits],
            "production activated execution_attempts.request_id; a deliberate "
            "design and security review is now required before this can pass")

    def test_insert_inventory_is_complete_and_never_names_request_id(self):
        inserts = [(m, fn, ln, column_list(sql))
                   for m, fn, ln, sql in production_sql()
                   if re.search(r"INSERT INTO execution_attempts",
                                sql, re.IGNORECASE)]
        self.assertEqual(3, len(inserts),
                         "execution_attempts INSERT inventory changed; "
                         "reconfirm before trusting this sentinel")
        for module, fn, ln, columns in inserts:
            self.assertNotIn("request_id", columns, f"{module}::{fn} L{ln}")
            self.assertFalse(
                [c for c in columns if c.lower().endswith("request_id")
                 and c.lower() != "request_id"],
                f"{module}::{fn} L{ln} names a request-id-like column; "
                "confirm it is not request_id")

    def test_update_inventory_never_assigns_request_id(self):
        updates = [(m, fn, ln, set_clause(sql))
                   for m, fn, ln, sql in production_sql()
                   if re.search(r"UPDATE execution_attempts\b", sql,
                                re.IGNORECASE)]
        self.assertTrue(updates, "no production UPDATE on execution_attempts")
        for module, fn, ln, sets in updates:
            self.assertIsNone(
                re.search(r"(?:^|,)\s*request_id\s*=(?!=)", sets,
                          re.IGNORECASE),
                f"{module}::{fn} L{ln} assigns request_id")

    def test_provider_request_id_assignments_remain_allowed(self):
        """The live column may keep moving; only request_id is pinned."""
        assigns = [(m, fn, ln)
                   for m, fn, ln, sets in
                   ((m, fn, ln, set_clause(sql)) for m, fn, ln, sql
                    in production_sql()
                    if re.search(r"UPDATE execution_attempts\b", sql,
                                 re.IGNORECASE))
                   if re.search(r"(?:^|,)\s*provider_request_id\s*=(?!=)",
                                sets, re.IGNORECASE)]
        self.assertTrue(assigns,
                        "expected the established provider_request_id "
                        "assignment to still exist")

    def test_request_id_is_never_used_as_a_null_identity_test(self):
        for module, fn, ln, sql in production_sql():
            self.assertNotRegex(
                sql, r"request_id\s+IS\s+NOT\s+NULL", f"{module}::{fn} L{ln}")
            self.assertNotRegex(
                sql, r"request_id\s*=\s*None", f"{module}::{fn} L{ln}")
            self.assertNotRegex(
                sql, r"COALESCE\s*\(\s*[^)]*request_id", f"{module}::{fn} L{ln}")

    def test_reconciliation_does_not_correlate_by_request_id(self):
        path = os.path.join(ROOT, "controller/devai/reconciliation.py")
        text = open(path, encoding="utf-8").read()
        self.assertIsNone(REQUEST_ID.search(text))
        self.assertIn("attempt_id", text)

    def test_no_production_retry_or_idempotency_use(self):
        for module, fn, ln, sql in production_sql():
            self.assertIsNone(
                REQUEST_ID.search(sql),
                f"{module}::{fn} L{ln} uses request_id in retry/idempotency SQL")


# =====================================================================
# 5, 6, 12, 13. IDENTIFIER DISAMBIGUATION
# =====================================================================

class F10IdentifierDisambiguationTests(unittest.TestCase):
    """request_id and provider_request_id are different identifiers."""

    def test_provider_request_id_really_exists_in_production(self):
        hits = provider_request_id_hits()
        self.assertTrue(
            hits,
            "negative control is empty: no provider_request_id occurrence was "
            "found, so this suite cannot prove its matcher discriminates")
        self.assertTrue(any("worker_dispatch" in m for m, _, _ in hits),
                        "expected a live-code provider_request_id occurrence")

    def test_provider_request_id_occurrences_are_not_request_id(self):
        overlap = [(m, fn, ln) for m, fn, ln, sql in production_sql()
                   if PROVIDER_REQUEST_ID.search(sql)
                   and REQUEST_ID.search(sql)]
        self.assertEqual(
            [], overlap,
            "a statement naming both identifiers needs manual review: the "
            "sentinel cannot separate them by token alone")

    def test_matcher_rejects_the_conflation_on_known_strings(self):
        for text in ("provider_request_id", "sub.provider_request_id",
                     "provider_request_id=%s", "PROVIDER_REQUEST_ID",
                     "request_identifier", "my_request_id"):
            self.assertIsNone(REQUEST_ID.search(text), text)
        for text in ("request_id", "d.request_id", '"request_id"',
                     "SET request_id =%s", "REQUEST_ID",
                     "t.request_id IS NULL"):
            self.assertIsNotNone(REQUEST_ID.search(text), text)

    def test_naive_substring_matcher_would_have_been_wrong(self):
        """The false-positive class this suite exists to prevent."""
        naive = re.compile(r"request_id", re.IGNORECASE)
        self.assertTrue(naive.search("provider_request_id"))
        self.assertIsNone(REQUEST_ID.search("provider_request_id"))

    def test_request_id_carries_no_authority_role(self):
        # No production statement may join, filter or authorize on it; with
        # zero occurrences overall this is implied, and asserted explicitly
        # so the intent is recorded rather than inferred.
        self.assertEqual([], request_id_hits())


# =====================================================================
# 17, 18. ACTIVATION TRIPWIRE (synthetic, load-bearing)
# =====================================================================

def synthetic_rows(sql):
    """Wrap a synthetic SQL string as a production-shaped row.

    Synthetic only. No repository file is read or modified; the point is to
    prove the detector reacts, not to change behaviour.
    """
    return [("<synthetic>", "<synthetic>", 0, sql)]


class F10ActivationTripwireTests(unittest.TestCase):
    """Controls proving the dormancy detector actually fires."""

    def assert_detected(self, sql, label):
        hits = request_id_hits(synthetic_rows(sql))
        self.assertTrue(hits, f"{label} was NOT detected -- sentinel is weak")

    def assert_not_detected(self, sql, label):
        hits = request_id_hits(synthetic_rows(sql))
        self.assertFalse(hits, f"{label} was wrongly detected as request_id")

    # ---- A: INSERT column activation ----
    def test_control_a_insert_adding_request_id_is_detected(self):
        self.assert_detected(
            "INSERT INTO execution_attempts (id, job_id, task_id, "
            "attempt_number, route_key, provider, gateway_model, status, "
            "request_id) SELECT %s, j.id, t.id, %s, %s, %s, %s, 'running', %s",
            "insert activation")

    def test_control_a_insert_with_provider_request_id_is_not_detected(self):
        self.assert_not_detected(
            "INSERT INTO execution_attempts (id, job_id, task_id, "
            "attempt_number, route_key, provider, gateway_model, status, "
            "provider_request_id) SELECT %s, j.id, t.id, %s, %s, %s, %s, "
            "'running', %s",
            "provider_request_id insert")

    # ---- B: UPDATE activation ----
    def test_control_b_update_setting_request_id_is_detected(self):
        self.assert_detected(
            "UPDATE execution_attempts SET status=%s, request_id=%s "
            "WHERE id=%s AND job_id=%s", "update activation")

    def test_control_b_update_setting_provider_request_id_is_not_detected(self):
        self.assert_not_detected(
            "UPDATE execution_attempts SET status=%s, provider_request_id=%s "
            "WHERE id=%s AND job_id=%s", "provider_request_id update")

    # ---- C: lookup activation ----
    def test_control_c_select_filtering_by_request_id_is_detected(self):
        self.assert_detected(
            "SELECT id FROM execution_attempts WHERE request_id = %s",
            "lookup activation")

    def test_control_c_join_on_request_id_is_detected(self):
        self.assert_detected(
            "SELECT a.id FROM execution_attempts a JOIN jobs j "
            "ON j.id = a.job_id WHERE a.request_id = %s",
            "join activation")

    def test_control_c_on_conflict_and_returning_are_detected(self):
        self.assert_detected(
            "INSERT INTO execution_attempts (id, job_id, request_id) "
            "VALUES (%s,%s,%s) ON CONFLICT (request_id) DO NOTHING "
            "RETURNING id", "on-conflict activation")
        self.assert_detected(
            "UPDATE execution_attempts SET status='succeeded' "
            "WHERE id=%s RETURNING request_id", "returning activation")
        self.assert_detected(
            "DELETE FROM execution_attempts WHERE request_id = %s",
            "delete activation")

    # ---- D: schema redesign detection ----
    def test_control_d_tenant_local_unique_is_detected(self):
        synthetic = ("CREATE TABLE execution_attempts ("
                     "id UUID PRIMARY KEY, request_id TEXT, "
                     "tenant_id UUID NOT NULL, "
                     "UNIQUE (tenant_id, request_id))")
        bad = schema_violations(synthetic)
        self.assertIn("tenant-local request_id uniqueness present", bad,
                      "control D must detect the tenant-local redesign")
        self.assertIn("global UNIQUE(request_id) absent", bad)

    def test_control_d_uniqueness_removal_is_detected(self):
        dropped = ("CREATE TABLE execution_attempts ("
                   "id UUID PRIMARY KEY, request_id TEXT)")
        self.assertIn("global UNIQUE(request_id) absent",
                      schema_violations(dropped))

    def test_control_d_not_null_tightening_is_detected(self):
        tightened = ("CREATE TABLE execution_attempts ("
                     "id UUID PRIMARY KEY, request_id TEXT NOT NULL, "
                     "UNIQUE (request_id))")
        self.assertIn("request_id is NOT NULL",
                      schema_violations(tightened))

    def test_control_d_current_schema_satisfies_the_same_detector(self):
        self.assertEqual([], schema_violations(schema_text()),
                         "current migrations must satisfy the same detector "
                         "the synthetic controls exercise")

    # ---- E: negative control on the real corpus ----
    def test_control_e_real_provider_request_id_sites_are_not_flagged(self):
        hits = provider_request_id_hits()
        self.assertTrue(hits, "negative control corpus is empty")
        for module, fn, ln, sql in production_sql():
            if PROVIDER_REQUEST_ID.search(sql):
                self.assertNotIn(
                    (module, fn, ln),
                    [(m, f, l) for m, f, l in request_id_hits()],
                    f"{module}::{fn} L{ln} is provider_request_id only")

    def test_current_corpus_is_clean_so_the_controls_mean_something(self):
        self.assertEqual([], request_id_hits())
        self.assertTrue(provider_request_id_hits())


if __name__ == "__main__":
    unittest.main()
