"""jobs.tenant_id immutability sentinel.

Re-audit trigger, not a security control: it fails loudly if any repository
change introduces a data write to the jobs tenant column outside the single
historically approved one-time backfill (migrations/007_tenants.sql).

Scope decisions (documented so reviewers can judge them):

- DATA WRITES are in scope: ``UPDATE jobs ... SET ... tenant_id = ...`` and
  the equivalent ``INSERT ... ON CONFLICT ... DO UPDATE SET tenant_id = ...``
  upsert arm. Both reassign the tenant of an existing job row.
- Row CREATION is out of scope: ``INSERT INTO jobs (..., tenant_id, ...)``
  sets the initial tenant (e.g. ledger.create_job) and does not mutate an
  existing row.
- DDL is out of scope: ``ALTER TABLE`` / ``CREATE INDEX`` / constraints
  never reassign row data and are covered by migration review instead. (This
  is why migrations/008_explicit_tenant_isolation.sql, which only drops a
  column default, is not flagged.)
- Only migrations/007_tenants.sql is allowlisted, by exact relative path.
  No future file may be added here: a hit in any other file fails the test.
  This file itself (tests/test_tenancy_invariants.py) is excluded from the
  repository scan because it necessarily embeds positive-control SQL
  literals; that exclusion is part of the detector, not a writer whitelist.

Robustness: detection works on a string-aware code view (comments removed
and string bodies masked without shifting newlines), so multiline statements
are handled and commented-out or string-embedded text never matches. Python
sources are scanned via ``ast`` string constants: ``#`` comments never reach
the AST (ignored inherently and safely), and docstrings are skipped because
documentation may legitimately discuss the forbidden statement shape. SQL
sources use an explicit string-aware lexer below.
"""

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_WRITER = Path("migrations/007_tenants.sql")
SELF = Path("tests/test_tenancy_invariants.py")

_UPDATE_TARGET_RE = re.compile(
    r"\s*UPDATE\s+(?:ONLY\s+)?"
    r"(?P<target>(?:\"[^\"]+\"|[A-Za-z_][\w$]*)"
    r"(?:\s*\.\s*(?:\"[^\"]+\"|[A-Za-z_][\w$]*))?)",
    re.IGNORECASE | re.DOTALL,
)
_SET_RE = re.compile(r"\bSET\b", re.IGNORECASE)
_CLAUSE_END_RE = re.compile(r"\bWHERE\b|\bRETURNING\b", re.IGNORECASE)
_TENANT_ASSIGN_RE = re.compile(r'\btenant_id\b"?\s*=', re.IGNORECASE)
_INSERT_JOBS_RE = re.compile(
    r"\s*INSERT\s+INTO\s+(?:\"[^\"]+\"|[A-Za-z_][\w$]*)"
    r"(?:\s*\.\s*(?:\"[^\"]+\"|[A-Za-z_][\w$]*))?",
    re.IGNORECASE | re.DOTALL,
)
_UPSERT_SET_RE = re.compile(
    r"\bON\s+CONFLICT\b[\s\S]*?\bDO\s+UPDATE\b\s+SET\b", re.IGNORECASE
)
_DOLLAR_TAG_RE = re.compile(r"\$[A-Za-z_][\w$]*\$|\$\$")


def _normalize_table(ref: str) -> str:
    return ref.split(".")[-1].strip().strip('"').lower()


def _code_view(text: str) -> str:
    """Return text with comments blanked and string bodies masked.

    Newlines are preserved so reported line numbers match the original.
    Double-quoted identifiers are kept verbatim (needed for target parsing).
    """
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        two = text[i : i + 2]
        if ch == "-" and two == "--":
            j = text.find("\n", i)
            if j == -1:
                out.append(" " * (n - i))
                i = n
            else:
                out.append(" " * (j - i))
                i = j
        elif ch == "/" and two == "/*":
            j = text.find("*/", i + 2)
            j = n - 1 if j == -1 else j + 1
            for k in range(i, j + 1):
                out.append("\n" if text[k] == "\n" else " ")
            i = j + 1
        elif ch == "'":
            out.append(ch)
            i += 1
            while i < n:
                if text[i] == "'" and text[i : i + 2] == "''":
                    out.append("''")
                    i += 2
                elif text[i] == "'":
                    out.append("'")
                    i += 1
                    break
                else:
                    out.append("\n" if text[i] == "\n" else " ")
                    i += 1
        elif ch == '"':
            out.append(ch)
            i += 1
            while i < n:
                if text[i] == '"' and text[i : i + 2] == '""':
                    out.append('""')
                    i += 2
                elif text[i] == '"':
                    out.append('"')
                    i += 1
                    break
                else:
                    out.append(text[i])
                    i += 1
        elif ch == "$":
            tag = _DOLLAR_TAG_RE.match(text, i)
            if tag is None:
                out.append(ch)
                i += 1
            else:
                tag_text = tag.group(0)
                close = text.find(tag_text, tag.end())
                close = n if close == -1 else close
                out.append(tag_text)
                for k in range(tag.end(), close):
                    out.append("\n" if text[k] == "\n" else " ")
                if close < n:
                    out.append(tag_text)
                    i = close + len(tag_text)
                else:
                    i = n
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def find_tenant_id_writes(sql_text: str) -> list[tuple[int, str]]:
    """Find data writes to the jobs tenant column in SQL text.

    Returns (1-based line number, snippet) hits. Multiline statements are
    handled because matching runs per top-level statement on the code view.
    """
    view = _code_view(sql_text)
    hits: list[tuple[int, str]] = []
    offset = 0
    for raw in view.split(";"):
        statement, base = raw, offset
        offset += len(raw) + 1
        if not statement.strip():
            continue
        line = view.count("\n", 0, base) + 1
        snippet = " ".join(statement.split())[:160]
        target = _UPDATE_TARGET_RE.match(statement)
        if target is not None and _normalize_table(target.group("target")) == "jobs":
            set_match = _SET_RE.search(statement, target.end())
            if set_match is not None:
                end = _CLAUSE_END_RE.search(statement, set_match.end())
                region = statement[
                    set_match.end() : end.start() if end else len(statement)
                ]
                if _TENANT_ASSIGN_RE.search(region):
                    hits.append((line, snippet))
            continue
        if _INSERT_JOBS_RE.match(statement) and _normalize_table(
            _INSERT_JOBS_RE.match(statement).group(0).split()[-1]
        ) == "jobs":
            upsert = _UPSERT_SET_RE.search(statement)
            if upsert is not None and _TENANT_ASSIGN_RE.search(
                statement[upsert.end() :]
            ):
                hits.append((line, snippet))
    return hits


def _python_sql_strings(path: Path) -> list[tuple[int, str]]:
    """Executable string literals of a Python file, with line numbers.

    Docstrings are skipped (documentation may describe the forbidden shape);
    ``#`` comments never appear in the AST at all.
    """
    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            first = node.body[0] if node.body else None
            if (
                isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)
            ):
                docstrings.add(id(first.value))
    found = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
            and "jobs" in node.value
            and "tenant_id" in node.value
        ):
            found.append((node.lineno, node.value))
    return found


def scan_repository(root: Path = ROOT) -> list[str]:
    """Scan *.sql / *.py sources; return human-readable violation locations."""
    violations: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in (".git", "__pycache__", ".venv") for part in path.parts):
            continue
        rel = path.relative_to(root)
        if rel == SELF:
            continue
        if path.suffix == ".sql":
            text = path.read_text(encoding="utf-8-sig")
            for line, snippet in find_tenant_id_writes(text):
                if rel != ALLOWED_WRITER:
                    violations.append(f"{rel}:{line}: {snippet}")
        elif path.suffix == ".py":
            for lineno, sql in _python_sql_strings(path):
                if find_tenant_id_writes(sql):
                    snippet = " ".join(sql.split())[:160]
                    violations.append(f"{rel}:{lineno}: {snippet}")
    return violations


POSITIVE_SAMPLES = [
    "UPDATE jobs SET tenant_id = '00000000-0000-4000-8000-000000000001' "
    "WHERE id = '11111111-0000-4000-8000-000000000001'",
    "UPDATE\n    jobs\nSET\n    tenant_id = %s\nWHERE id = %s",
    'UPDATE "jobs" SET "tenant_id" = %s WHERE id = %s',
    "UPDATE public.jobs SET tenant_id = %s WHERE id = %s",
    "UPDATE jobs AS j SET j.tenant_id = %s WHERE j.id = %s",
    "update JOBS set TENANT_ID = %s where id = %s",
    "INSERT INTO jobs (id, tenant_id, objective, status) VALUES (%s, %s, %s, %s) "
    "ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id",
    "UPDATE jobs SET tenant_id = %s -- reassign tenant\nWHERE id = %s",
    "UPDATE jobs /* reassign */ SET tenant_id = %s WHERE id = %s",
]

NEGATIVE_SAMPLES = [
    "INSERT INTO jobs (id, tenant_id, objective, status) "
    "VALUES (%s, %s, %s, %s)",
    "SELECT id, tenant_id FROM jobs WHERE tenant_id = %s",
    "UPDATE tasks SET tenant_id = %s WHERE id = %s",
    "UPDATE jobs SET status = 'completed', updated_at = now() WHERE id = %s",
    "-- UPDATE jobs SET tenant_id = %s",
    "/* UPDATE jobs SET tenant_id = %s WHERE id = %s */",
    "INSERT INTO audit_log (note) VALUES ('UPDATE jobs SET tenant_id = 1')",
    "UPDATE tasks SET approved_at = now(), approved_by = %s, status = 'pending', "
    "updated_at = now() WHERE id = %s AND requires_approval = TRUE "
    "AND status = 'waiting_approval' AND approved_at IS NULL AND EXISTS "
    "(SELECT 1 FROM jobs WHERE jobs.id = tasks.job_id AND jobs.tenant_id = %s)",
    "ALTER TABLE jobs ALTER COLUMN tenant_id DROP DEFAULT",
    "CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON jobs(tenant_id)",
]


class TenantImmutabilitySentinelTests(unittest.TestCase):
    def test_detector_positive_controls(self):
        for sql in POSITIVE_SAMPLES:
            with self.subTest(sql=sql[:60]):
                self.assertTrue(
                    find_tenant_id_writes(sql),
                    f"detector missed a jobs.tenant_id write: {sql[:80]}",
                )

    def test_detector_negative_controls(self):
        for sql in NEGATIVE_SAMPLES:
            with self.subTest(sql=sql[:60]):
                self.assertEqual(
                    find_tenant_id_writes(sql),
                    [],
                    f"detector false-positive: {sql[:80]}",
                )

    def test_historical_backfill_is_detected(self):
        text = (ROOT / ALLOWED_WRITER).read_text(encoding="utf-8-sig")
        self.assertTrue(
            find_tenant_id_writes(text),
            "detector must see the historical 007 backfill write",
        )

    def test_no_unapproved_jobs_tenant_id_writes(self):
        violations = scan_repository()
        self.assertEqual(
            violations,
            [],
            "jobs.tenant_id write outside migrations/007_tenants.sql "
            f"(re-audit required): {violations}",
        )


if __name__ == "__main__":
    unittest.main()
