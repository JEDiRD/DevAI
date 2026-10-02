"""jobs.tenant_id immutability + semantics sentinel.

Re-audit trigger, not a security control. It fails loudly if any repository
change reassigns the jobs tenant column, or alters jobs.tenant_id semantics,
outside a pinned set of historical statements.

Detection is token/structure based rather than line-regex based, because the
previous regex implementation was defeated by ordinary SQL shapes. A real
lexer (``_tokenize``) strips comments and string bodies, tracks parenthesis
depth, and understands PostgreSQL dollar quoting, so every UPDATE keyword in
executable position is located and its SET clause parsed structurally:

- CTE aware: ``WITH ... UPDATE jobs SET tenant_id = ...`` is found;
- tuple aware: ``SET (tenant_id, status) = (...)`` is found;
- depth aware: a ``WHERE`` inside a sub-select does not terminate the SET
  clause early, and a bare fragment with no terminator still parses;
- alias/qualified aware: ``UPDATE public.jobs AS j SET j.tenant_id`` works;
- upsert aware: ``ON CONFLICT ... DO UPDATE SET tenant_id`` is found,
  including the tuple form;
- dollar-quote aware: ``DO $$ ... $$`` and function bodies are lexed as
  code, so an UPDATE hidden inside one cannot hide.

Python sources are scanned through their AST so that ``#`` comments can never
match and docstrings (which may legitimately *discuss* the forbidden shape)
are skipped. Concatenation, f-strings, ``%``-formatting and ``.format()`` are
reconstructed, and simple module/function constant assignments are
inlined, so assembling SQL at runtime does not evade the scan.

Scope decisions:

- DATA WRITES in scope: any UPDATE/upsert reassigning jobs.tenant_id.
- Row CREATION is out of scope: ``INSERT INTO jobs (..., tenant_id, ...)``
  sets the initial tenant (e.g. ledger.create_job) and creates a row rather
  than moving an existing one.
- DDL is a re-audit tripwire (see B2 below): ``ALTER TABLE jobs`` mentioning
  tenant_id is flagged, because the safety argument depends on
  jobs.tenant_id immutability and semantics. ``CREATE INDEX`` alone is not
  flagged.

Historical exceptions are pinned by exact canonical statement text (a
token-level normalisation: upper-cased, whitespace-collapsed, string
literals masked). Whole files are never allowlisted, so appending a second
unauthorized mutation to migration 007 fails the sentinel.

This file (tests/test_tenancy_invariants.py) is excluded from the repository
scan because it necessarily embeds positive-control SQL. That exclusion is
part of the detector, not a writer whitelist.
"""

import ast
import bisect
import re
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SELF = Path("tests/test_tenancy_invariants.py")

# --- Pinned historical exceptions -----------------------------------------
# Canonical statement text. Never a line number: an appended second mutation
# in migration 007 canonicalises differently and therefore fails.
APPROVED_WRITES = frozenset(
    {
        "UPDATE JOBS SET TENANT_ID = ? WHERE TENANT_ID IS NULL",
    }
)
APPROVED_DDL = frozenset(
    {
        # migration 007: introduce the column and its historical guarantees.
        "ALTER TABLE JOBS ADD COLUMN IF NOT EXISTS TENANT_ID UUID",
        "ALTER TABLE JOBS ALTER COLUMN TENANT_ID SET NOT NULL",
        "ALTER TABLE JOBS ALTER COLUMN TENANT_ID SET DEFAULT ?",
        # migration 008: remove the bootstrap default (tightens isolation).
        "ALTER TABLE JOBS ALTER COLUMN TENANT_ID DROP DEFAULT",
    }
)

WRITE = "write"
DDL = "ddl"

_SQL_TOKEN_RE = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<line_comment>--[^\n]*)
    | (?P<block_comment>/\*.*?(?:\*/|$))
    | (?P<dollar>\$[A-Za-z_][\w$]*\$|\$\$)
    | (?P<string>'(?:''|[^'])*')
    | (?P<quoted>"(?:[^"]|"")*")
    | (?P<number>\d+(?:\.\d+)?)
    | (?P<placeholder>%\(\w+\)s|%s)
    | (?P<name>[A-Za-z_-￿][\w$]*)
    | (?P<punct>:=|\|\||::|<>|!=|<=|>=|\(|\)|,|;|\.|\*|@|=|>|<|\+|-|/|\||&)
    """,
    re.VERBOSE | re.DOTALL,
)

_KEYWORDS_BEFORE_SET = frozenset({"ONLY"})
_SET_TERMINATORS = frozenset({"WHERE", "RETURNING", "FROM"})


@dataclass(frozen=True)
class Finding:
    line: int
    kind: str
    statement: str
    approved: bool


@dataclass(frozen=True)
class _Tok:
    kind: str
    text: str
    line: int
    depth: int
    body: int | None = None


def _line_index(text):
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


def _tokenize(text):
    """Lex SQL into code tokens, tracking paren depth and dollar-quoted code."""
    starts = _line_index(text)
    toks: list[_Tok] = []
    depth = 0
    dollar_stack: list[tuple[str, int]] = []
    body_seq = 0
    i, n = 0, len(text)
    while i < n:
        m = _SQL_TOKEN_RE.match(text, i)
        if m is None:
            i += 1
            continue
        kind = m.lastgroup
        value = m.group()
        line = bisect.bisect_right(starts, m.start())
        if kind == "dollar":
            if dollar_stack and dollar_stack[-1][0] == value:
                dollar_stack.pop()
            elif not dollar_stack:
                dollar_stack.append((value, body_seq))
                body_seq += 1
            i = m.end()
            continue
        if kind in ("ws", "line_comment", "block_comment"):
            i = m.end()
            continue
        body = dollar_stack[-1][1] if dollar_stack else None
        if kind == "string" and body is not None:
            # quoted text inside a dollar block: data, not code
            i = m.end()
            continue
        if kind == "punct":
            if value == "(":
                toks.append(_Tok("punct", value, line, depth, body))
                depth += 1
                i = m.end()
                continue
            if value == ")":
                depth = max(0, depth - 1)
                toks.append(_Tok("punct", value, line, depth, body))
                i = m.end()
                continue
        toks.append(_Tok(kind, value, line, depth, body))
        i = m.end()
    return toks


def _canon_token(tok: _Tok) -> str:
    if tok.kind == "name":
        return tok.text.upper()
    if tok.kind == "string":
        return "?"
    if tok.kind == "quoted":
        return tok.text.replace('""', '"').upper()
    return tok.text


def canonical(toks) -> str:
    return " ".join(_canon_token(t) for t in toks)


def _is_name(tok: _Tok, word: str) -> bool:
    return tok.kind == "name" and tok.text.upper() == word


def _identifier_name(tok: _Tok) -> str:
    if tok.kind == "name":
        return tok.text.lower()
    if tok.kind == "quoted":
        return tok.text.replace('""', '"').strip('"').lower()
    return ""


def _qualified_name(toks, i):
    """Read a possibly schema-qualified, possibly quoted identifier at i."""
    parts = []
    while i < len(toks):
        tok = toks[i]
        if tok.kind in ("name", "quoted"):
            parts.append(_identifier_name(tok))
            i += 1
        else:
            break
        if i < len(toks) and toks[i].kind == "punct" and toks[i].text == ".":
            i += 1
            continue
        break
    return ".".join(parts), i


def _split_statements(toks):
    statements = []
    current = []
    for tok in toks:
        if tok.kind == "punct" and tok.text == ";":
            if current:
                statements.append(current)
            current = []
        else:
            current.append(tok)
    if current:
        statements.append(current)
    return statements


def _scan_set_clause(toks, start):
    """Return True if the SET clause starting at `start` assigns tenant_id.

    Structural: collects the assignment list at the SET's paren depth, so a
    WHERE/RETURNING/FROM nested inside a sub-select cannot end it early, and
    both ``col = ...`` and ``(a, b) = (...)`` forms are recognised.
    """
    set_depth = toks[start].depth
    i = start + 1
    depth = set_depth
    n = len(toks)
    tuple_candidate: list[_Tok] = []
    while i < n:
        tok = toks[i]
        if tok.kind == "punct" and tok.text == "(":
            depth += 1
            tuple_candidate.append(tok)
            i += 1
            continue
        if tok.kind == "punct" and tok.text == ")":
            depth -= 1
            i += 1
            if depth == set_depth and i < n and toks[i].kind == "punct" and toks[i].text == "=":
                # tuple assignment: (a, b) = (...)
                if any(
                    t.kind in ("name", "quoted")
                    and _identifier_name(t).split(".")[-1] == "tenant_id"
                    for t in tuple_candidate
                ):
                    return True
                tuple_candidate = []
                i += 1
                continue
            if depth < set_depth:
                break
            continue
        if depth != set_depth:
            if tok.kind in ("name", "quoted"):
                tuple_candidate.append(tok)
            i += 1
            continue
        if tok.kind == "name" and tok.text.upper() in _SET_TERMINATORS:
            break
        if tok.kind in ("name", "quoted"):
            if _identifier_name(tok).split(".")[-1] == "tenant_id":
                nxt = toks[i + 1] if i + 1 < n else None
                if (
                    nxt is not None
                    and nxt.kind == "punct"
                    and nxt.text == "="
                ):
                    return True
        i += 1
    return False


def _update_writes_jobs_tenant(toks):
    """True if this statement performs an UPDATE/upsert of jobs.tenant_id."""
    n = len(toks)
    for i, tok in enumerate(toks):
        if not _is_name(tok, "UPDATE"):
            continue
        j = i + 1
        while j < n and _is_name(toks[j], "ONLY"):
            j += 1
        target, after = _qualified_name(toks, j)
        if target.split(".")[-1] != "jobs":
            continue
        # locate the SET clause of this UPDATE
        k = after
        while k < n:
            if _is_name(toks[k], "SET"):
                if _scan_set_clause(toks, k):
                    return True
                break
            if _is_name(toks[k], "WHERE") or _is_name(toks[k], "RETURNING"):
                break
            k += 1
    # upsert reassignment: INSERT INTO jobs ... ON CONFLICT ... DO UPDATE SET
    for i, tok in enumerate(toks):
        if not _is_name(tok, "INSERT"):
            continue
        into = i + 1
        if into >= n or not _is_name(toks[into], "INTO"):
            continue
        if _qualified_name(toks, into + 1)[0].split(".")[-1] != "jobs":
            continue
        k = into + 2
        while k < n:
            if _is_name(toks[k], "ON") and _is_name(toks[k + 1] if k + 1 < n else tok, "CONFLICT"):
                j = k
                while j < n:
                    if (
                        _is_name(toks[j], "DO")
                        and _is_name(toks[j + 1] if j + 1 < n else tok, "UPDATE")
                    ):
                        m = j + 2
                        while m < n:
                            if _is_name(toks[m], "SET"):
                                if _scan_set_clause(toks, m):
                                    return True
                                break
                            m += 1
                        break
                    j += 1
                break
            k += 1
    return False


def _ddl_alters_jobs_tenant(toks):
    """True if this statement is ALTER TABLE jobs ... touching tenant semantics.

    Covers direct tenant_id references (ALTER COLUMN / DROP / RENAME / TYPE
    USING / DEFAULT) and tenant constraint changes, which never spell the
    column name but still change what tenant_id guarantees.
    """
    if not toks or not _is_name(toks[0], "ALTER"):
        return False
    i = 1
    if i < len(toks) and _is_name(toks[i], "TABLE"):
        i += 1
    else:
        return False
    while i < len(toks):
        if _is_name(toks[i], "IF"):
            i += 2  # IF EXISTS / IF NOT EXISTS
        elif _is_name(toks[i], "ONLY"):
            i += 1  # ALTER TABLE ONLY <table>
        else:
            break
    target, after = _qualified_name(toks, i)
    if target.split(".")[-1] != "jobs":
        return False
    rest = toks[after:]
    names = [t for t in rest if t.kind in ("name", "quoted")]
    segments = [_identifier_name(t).split(".")[-1] for t in names]
    if any(seg == "tenant_id" for seg in segments):
        return True
    # constraint-level changes to tenant isolation, e.g. DROP CONSTRAINT
    # jobs_tenant_fk, which never mention the column name directly.
    mentions_constraint = any(
        _is_name(t, "CONSTRAINT") for t in rest
    )
    if mentions_constraint and any("tenant" in seg for seg in segments):
        return True
    return False


def _dollar_bodies_are_code(stmt) -> bool:
    """True when this statement's dollar-quoted bodies are executable code.

    ``DO $$...$$``, ``CREATE FUNCTION ... $$...$$`` and ``EXECUTE $...$``
    bodies run; a dollar-quoted value in a plain VALUES list is data.
    """
    names = [t.text.upper() for t in stmt if t.kind == "name" and t.body is None]
    if not names:
        return False
    if names[0] == "DO":
        return True
    if "EXECUTE" in names:
        return True
    if names[0] == "CREATE":
        return any(
            w in names[:5] for w in ("FUNCTION", "PROCEDURE", "TRIGGER")
        )
    return False


def scan_sql(text):
    """Yield Findings for one SQL source text."""
    findings = []
    for stmt in _split_statements(_tokenize(text)):
        if not stmt:
            continue
        if _dollar_bodies_are_code(stmt):
            allowed = {t.body for t in stmt if t.body is not None}
        else:
            allowed = set()
        code = [t for t in stmt if t.body is None or t.body in allowed]
        if not code:
            continue
        canon = canonical(stmt)
        if not canon:
            continue
        line = stmt[0].line
        if _update_writes_jobs_tenant(code):
            findings.append(
                Finding(line, WRITE, canon[:200], canon in APPROVED_WRITES)
            )
        elif _ddl_alters_jobs_tenant(code):
            findings.append(
                Finding(line, DDL, canon[:200], canon in APPROVED_DDL)
            )
    return findings


# --- Python source extraction ---------------------------------------------


def _const_str_map(tree):
    """Map simple NAME = 'literal' assignments for later inlining."""
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            value = node.value
            if isinstance(target, ast.Name) and isinstance(value, ast.Constant):
                if isinstance(value.value, str):
                    out[target.id] = value.value
    return out


def _docstring_nodes(tree):
    out = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(
                body[0].value, ast.Constant
            ):
                if isinstance(body[0].value.value, str):
                    out.add(id(body[0].value))
    return out


def _reconstruct(node, consts, docs):
    """Best-effort reconstruction of executable SQL text from a Python node.

    Handles constants, f-strings, concatenation, %-format and .format().
    Returns a list of (lineno, text) candidates; multiple candidates are
    returned so that partial concatenation still yields usable fragments.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        if id(node) in docs:
            return []
        return [(node.lineno, node.value)]
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                sub = _reconstruct(value.value, consts, docs)
                parts.append(sub[0][1] if sub else "\x00")
            else:
                parts.append("\x00")
        return [(node.lineno, "".join(parts))]
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _reconstruct(node.left, consts, docs)
        right = _reconstruct(node.right, consts, docs)
        combined = []
        if left and right:
            joined = left[0][1] + (" %s" if isinstance(node.op, ast.Mod) else "") + right[0][1]
            combined.append((node.lineno, joined))
        return left + right + combined
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        base = _reconstruct(node.func.value, consts, docs)
        if base:
            return [(node.lineno, base[0][1])]
    if isinstance(node, ast.Name):
        if node.id in consts:
            return [(node.lineno, consts[node.id])]
    return []


def scan_python(text):
    tree = ast.parse(text)
    consts = _const_str_map(tree)
    docs = _docstring_nodes(tree)
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.BinOp) or isinstance(node, ast.Call) or isinstance(
            node, ast.JoinedStr
        ) or (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            if isinstance(node, ast.Constant) and id(node) in docs:
                continue
            for lineno, snippet in _reconstruct(node, consts, docs):
                for hit in scan_sql(snippet):
                    findings.append(Finding(lineno, hit.kind, hit.statement, hit.approved))
    return _dedupe(findings)


def _dedupe(findings):
    seen = set()
    out = []
    for f in findings:
        key = (f.line, f.kind, f.statement)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# --- repository scan -------------------------------------------------------


def scan_repository(root=ROOT, extra=None):
    """Scan *.sql / *.py sources. Returns list of violation strings.

    `extra` maps a repo-relative path to source text, letting tests feed a
    hypothetical future file through the identical detector.
    """
    violations = []
    entries = {}
    for path in sorted(Path(root).rglob("*")):
        if not path.is_file():
            continue
        if any(part in (".git", "__pycache__", ".venv") for part in path.parts):
            continue
        rel = path.relative_to(root)
        if rel == SELF:
            continue
        if path.suffix in (".sql", ".py"):
            entries[rel.as_posix()] = path.read_text(encoding="utf-8-sig")
    if extra:
        entries.update(extra)
    for rel, text in entries.items():
        hits = scan_sql(text) if rel.endswith(".sql") else scan_python(text)
        for f in hits:
            if not f.approved:
                kind = "tenant_id write" if f.kind == WRITE else "tenant_id DDL"
                violations.append(f"{rel}:{f.line}: [{kind}] {f.statement}")
    return violations


# --- controls --------------------------------------------------------------

# Positive: every escape form reproduced during independent review, plus
# historical backfill shapes. A regression to the previous regex-based
# detector fails here.
POSITIVE_SQL = [
    # basic + alias/qualified/quoted/case variants
    "UPDATE jobs SET tenant_id = %s WHERE id = %s",
    "UPDATE\n    jobs\nSET\n    tenant_id = %s\nWHERE id = %s",
    'UPDATE "jobs" SET "tenant_id" = %s WHERE id = %s',
    "UPDATE public.jobs SET tenant_id = %s WHERE id = %s",
    "UPDATE jobs AS j SET j.tenant_id = %s WHERE j.id = %s",
    "update JOBS set TENANT_ID = %s where id = %s",
    # CTE update
    "WITH moved AS (SELECT id FROM jobs) UPDATE jobs SET tenant_id = %s "
    "WHERE id IN (SELECT id FROM moved)",
    "WITH a AS (SELECT 1) UPDATE jobs j SET j.tenant_id = %s WHERE true",
    # tuple assignment
    "UPDATE jobs SET (tenant_id, status) = (%s, %s) WHERE id = %s",
    "UPDATE jobs SET (status, tenant_id) = (%s, %s) WHERE id = %s",
    # region-early-termination trap: WHERE nested inside a sub-select
    "UPDATE jobs SET tenant_id = %s WHERE id IN (SELECT id FROM tasks "
    "WHERE status = 'pending')",
    "UPDATE jobs SET tenant_id = (SELECT tenant_id FROM tenants WHERE false) "
    "WHERE id = %s",
    # UPDATE ... FROM
    "UPDATE jobs SET tenant_id = t.tenant_id FROM tenants t WHERE t.id = %s",
    # upsert reassignment (single + tuple)
    "INSERT INTO jobs (id, tenant_id, objective, status) VALUES (%s,%s,%s,%s) "
    "ON CONFLICT (id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id",
    "INSERT INTO jobs (id, tenant_id) VALUES (%s,%s) ON CONFLICT (id) "
    "DO UPDATE SET (tenant_id, status) = (EXCLUDED.tenant_id, EXCLUDED.status)",
    # dollar-quoted executable body
    "DO $$ BEGIN UPDATE jobs SET tenant_id = %s WHERE id = %s; END $$;",
    "CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN "
    "UPDATE jobs SET tenant_id = NEW.tenant_id; RETURN NEW; END $$ "
    "LANGUAGE plpgsql",
    # comment noise around a real write
    "UPDATE jobs SET tenant_id = %s -- reassign\nWHERE id = %s",
    "UPDATE jobs /* reassign */ SET tenant_id = %s WHERE id = %s",
    # historical backfill (approved) + a second unauthorized append
    "UPDATE jobs SET tenant_id = '00000000-0000-4000-8000-000000000001' "
    "WHERE tenant_id IS NULL",
]

POSITIVE_PYTHON = [
    # uppercase Python SQL literal
    'sql = "UPDATE JOBS SET TENANT_ID = %s WHERE id = %s"',
    # concatenation
    'sql = "UPDATE jobs SET tenant_id = " + placeholder',
    'sql = "UPDATE jobs " + "SET tenant_id = %s"',
    # f-string
    'sql = f"UPDATE jobs SET tenant_id = {tid} WHERE id = {jid}"',
    # .format()
    'sql = "UPDATE jobs SET tenant_id = %s WHERE id = %s".format(tid, jid)',
    # CTE via concatenation
    'sql = "WITH x AS (SELECT 1) " + "UPDATE jobs SET tenant_id = %s"',
    # constant table name inlined into an f-string
    'TABLE = "jobs"\nsql = f"UPDATE {TABLE} SET tenant_id = %s WHERE id = %s"',
]

# Negative: legitimate statements and decoys that must not fire.
NEGATIVE_SQL = [
    # row creation with an initial tenant
    "INSERT INTO jobs (id, tenant_id, objective, status) VALUES (%s,%s,%s,%s)",
    # read paths
    "SELECT id, tenant_id FROM jobs WHERE tenant_id = %s",
    "UPDATE tasks SET tenant_id = %s WHERE id = %s",
    # approval update touches tasks, scoping via EXISTS over jobs
    "UPDATE tasks SET approved_at = now(), approved_by = %s, status = 'pending', "
    "updated_at = now() WHERE id = %s AND requires_approval = TRUE "
    "AND status = 'waiting_approval' AND approved_at IS NULL AND EXISTS "
    "(SELECT 1 FROM jobs WHERE jobs.id = tasks.job_id AND jobs.tenant_id = %s)",
    # no tenant column touched
    "UPDATE jobs SET status = 'completed', updated_at = now() WHERE id = %s",
    # DDL not involving tenant_id
    "CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON jobs(tenant_id)",
    "ALTER TABLE jobs ADD COLUMN extra_note TEXT",
    "ALTER TABLE tasks ALTER COLUMN status SET DEFAULT 'pending'",
    # comment / string decoys
    "-- UPDATE jobs SET tenant_id = %s",
    "/* UPDATE jobs SET tenant_id = %s WHERE id = %s */",
    "INSERT INTO audit_log (note) VALUES ('UPDATE jobs SET tenant_id = 1')",
    "INSERT INTO audit_log (note) VALUES ($tag$ UPDATE jobs SET tenant_id = 1 $tag$)",
]

NEGATIVE_PYTHON = [
    "# UPDATE jobs SET tenant_id = %s",
    'sql = "UPDATE jobs SET status = %s WHERE id = %s"',
    'def f():\n    """Docstring discussing UPDATE jobs SET tenant_id = %s."""\n    return 1',
]


# Positive: DDL re-audit tripwire (B2). These are not data mutations, but the
# safety argument depends on jobs.tenant_id immutability and semantics.
POSITIVE_DDL = [
    "ALTER TABLE jobs ALTER COLUMN tenant_id DROP NOT NULL",
    "ALTER TABLE jobs DROP COLUMN tenant_id",
    "ALTER TABLE jobs RENAME COLUMN tenant_id TO owner_id",
    "ALTER TABLE jobs ALTER COLUMN tenant_id TYPE text USING tenant_id::text",
    "ALTER TABLE jobs ALTER COLUMN tenant_id "
    "SET DEFAULT '00000000-0000-4000-8000-000000000001'",
    "ALTER TABLE IF EXISTS jobs ALTER COLUMN tenant_id SET NOT NULL",
    "ALTER TABLE ONLY jobs ADD COLUMN tenant_id TEXT",
    "ALTER TABLE jobs DROP CONSTRAINT jobs_tenant_fk",
    'ALTER TABLE "jobs" ALTER COLUMN "tenant_id" DROP NOT NULL',
]


class TenantImmutabilitySentinelTests(unittest.TestCase):
    def test_positive_ddl_controls(self):
        for sql in POSITIVE_DDL:
            with self.subTest(sql=sql[:50]):
                hits = scan_sql(sql)
                self.assertTrue(
                    [f for f in hits if f.kind == DDL],
                    f"DDL tripwire missed: {sql[:80]}",
                )

    def test_negative_ddl_controls(self):
        for sql in (
            "CREATE INDEX IF NOT EXISTS idx_jobs_tenant ON jobs(tenant_id)",
            "ALTER TABLE jobs ADD COLUMN extra_note TEXT",
            "ALTER TABLE jobs RENAME COLUMN objective TO goal",
            "ALTER TABLE tasks ALTER COLUMN tenant_note SET DEFAULT 'x'",
            "ALTER TABLE worker_nodes ADD CONSTRAINT node_tenant_fk "
            "FOREIGN KEY (tenant_id) REFERENCES tenants(id)",
        ):
            with self.subTest(sql=sql[:50]):
                self.assertEqual(
                    scan_sql(sql), [], f"DDL false positive: {sql[:80]}"
                )
    def test_positive_sql_controls(self):
        for sql in POSITIVE_SQL:
            with self.subTest(sql=sql[:50]):
                self.assertTrue(
                    [f for f in scan_sql(sql) if f.kind == WRITE],
                    f"missed jobs.tenant_id write: {sql[:80]}",
                )

    def test_positive_python_controls(self):
        for src in POSITIVE_PYTHON:
            with self.subTest(src=src[:50]):
                self.assertTrue(
                    scan_python(src),
                    f"missed assembled jobs.tenant_id write: {src[:80]}",
                )

    def test_negative_sql_controls(self):
        for sql in NEGATIVE_SQL:
            with self.subTest(sql=sql[:50]):
                self.assertEqual(
                    scan_sql(sql), [], f"false positive: {sql[:80]}"
                )

    def test_negative_python_controls(self):
        for src in NEGATIVE_PYTHON:
            with self.subTest(src=src[:50]):
                self.assertEqual(
                    scan_python(src), [], f"false positive: {src[:80]}"
                )

    def test_historical_backfill_is_approved_not_flagged(self):
        hits = scan_sql(
            "UPDATE jobs SET tenant_id = '00000000-0000-4000-8000-000000000001' "
            "WHERE tenant_id IS NULL"
        )
        self.assertEqual(len(hits), 1)
        self.assertTrue(hits[0].approved)

    def test_extra_write_appended_to_migration_007_is_caught(self):
        """B1: the 007 exception is pinned to one statement, not the file."""
        original = (ROOT / "migrations" / "007_tenants.sql").read_text(
            encoding="utf-8-sig"
        )
        tampered = (
            original
            + "\nUPDATE jobs\nSET tenant_id = '00000000-0000-4000-8000-000000000002'\n"
            "WHERE id = '11111111-0000-4000-8000-000000000001';\n"
        )
        baseline = scan_repository(
            extra={"migrations/007_tenants.sql": original}
        )
        self.assertEqual(baseline, [], "clean 007 must produce no violations")
        after = scan_repository(extra={"migrations/007_tenants.sql": tampered})
        self.assertTrue(after, "appended 007 write must be caught")
        self.assertTrue(
            any("007_tenants.sql" in v for v in after), after
        )

    def test_repository_clean(self):
        self.assertEqual(scan_repository(), [])


if __name__ == "__main__":
    unittest.main()