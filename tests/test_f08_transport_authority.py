"""F08: live Worker transport authority.

Phase 2 policy, as authorized:

  P1  One live credential per Worker. issue_worker_token is provisioning
      only and refuses while a live credential exists. Replacement is
      rotate_worker_token. No intentional overlap window.
  P2  Plaintext HTTP inside a validated loopback/Tailscale boundary is an
      explicitly accepted Phase 2 risk. No TLS is introduced here, and no
      production file on the Worker side is modified.
  P3  X-Worker-Id is a mandatory consistency assertion. The bearer token
      remains the primary identity authority; the header is never promoted
      to identity.

Production changes are confined to controller/devai/worker_identity.py and
controller/devai/worker_api.py. worker_agent/client.py is FROZEN: the
endpoint, proxy and redirect policy it already implements is pinned here as
structural and behavioural evidence rather than rewritten.

Harness discipline. Every invariant below is evaluated against CODE ONLY,
with comments and docstrings stripped. An earlier draft of this file matched
its own explanatory prose -- the guard's docstring contains the phrase "no
LOCK TABLE", which made a "no global lock" check fail on the very text that
documented the guarantee. Text presence is not authority, in either
direction: prose must neither satisfy an invariant nor break one.
"""
import ast
import hashlib
import json
import os
import re
import threading
import unittest
import urllib.request as request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import HTTPException

from devai import worker_api, worker_identity
from worker_agent.client import (
    ProtocolError,
    WorkerApiClient,
    _NoRedirect,
    validate_private_base_url,
)

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    "worker_identity.py": ROOT / "controller" / "devai" / "worker_identity.py",
    "worker_api.py": ROOT / "controller" / "devai" / "worker_api.py",
    "client.py": ROOT / "worker_agent" / "client.py",
    "credential_store.py": ROOT / "worker_agent" / "credential_store.py",
}
ORIGIN = "http://100.91.132.78:8765"


def sources():
    return {name: path.read_text(encoding="utf-8") for name, path in FILES.items()}


def code_only(src):
    """Source with comments and docstrings removed.

    Invariants are evaluated against this, never against raw text, so that
    documentation can neither satisfy nor violate a structural guarantee.
    Note that ast.unparse re-flows the source, so invariant targets must be
    written in unparse's normalised form.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                             ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    and isinstance(node.body[0].value.value, str)):
                node.body.pop(0)
    return ast.unparse(tree)


def function_source(src, name, cls=None):
    """Exact source text of a function (optionally a method)."""
    tree = ast.parse(src)
    lines = src.splitlines()
    pool = []
    if cls:
        for node in tree.body:
            if isinstance(node, ast.ClassDef) and node.name == cls:
                pool = list(node.body)
    else:
        pool = list(tree.body)
    for node in pool:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return "\n".join(lines[node.lineno - 1:node.end_lineno])
    raise AssertionError(f"function {cls + '.' if cls else ''}{name} not found")


def code_of_function(src, name, cls=None):
    """CODE-ONLY source of one function, for invariant evaluation."""
    full = code_only(src)
    return function_source(full, name, cls)


def sql_of(fn_src):
    """SQL literals passed to cur.execute(...) inside a function.

    Extracted through the AST rather than by matching quote characters: an
    earlier draft read triple-quoted blocks, which silently returned nothing
    once ast.unparse re-rendered them as single-quoted escapes, and an empty
    SQL string makes every SQL invariant vacuously fail.
    """
    found = []
    for node in ast.walk(ast.parse(fn_src)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name not in ("execute", "executemany"):
            continue
        if node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, str):
            found.append(node.args[0].value)
    return found


def has_condition(sql, *fragments):
    """True when every fragment appears, ignoring table qualifiers/case."""
    flat = re.sub(r"\bt\.", "", sql.upper())
    flat = re.sub(r"\bn\.", "", flat)
    flat = re.sub(r"\s+", " ", flat)
    for frag in fragments:
        f = re.sub(r"\s+", " ", re.sub(r"\bt\.", "", frag.upper()))
        if f not in flat:
            return False
    return True


# =====================================================================
# INVARIANTS
# =====================================================================

def check_invariants(src):
    """Sorted names of violated invariants; empty means all hold."""
    bad = []
    wi, wa = code_only(src["worker_identity.py"]), code_only(src["worker_api.py"])
    cl = code_only(src["client.py"])
    cs = code_only(src["credential_store.py"])

    def fn(s, name, cls=None):
        try:
            return function_source(s, name, cls)
        except AssertionError:
            return ""

    issue = fn(wi, "issue_worker_token")
    rotate = fn(wi, "rotate_worker_token")
    guard = fn(wi, "_require_no_live_token")
    require_worker = fn(wi, "_require_worker")
    authn = fn(wi, "authenticate_worker_token")
    insert = fn(wi, "_insert_token")

    # ---- P1: one live credential per worker ----
    call = "_require_no_live_token(cur, tenant_id, worker_node_id)"
    if call not in issue:
        bad.append("issue_calls_live_guard")
    if issue and call in issue:
        if issue.index("_require_no_live_token") > issue.index("_insert_token"):
            bad.append("issue_guard_precedes_insert")
        if issue.index("_require_worker") > issue.index("_require_no_live_token"):
            bad.append("issue_locks_worker_before_live_check")
    if issue and "UPDATE worker_tokens" in issue:
        bad.append("issue_silently_revokes")

    guard_sql = " ".join(sql_of(guard))
    if not has_condition(guard_sql, "revoked_at IS NULL"):
        bad.append("guard_predicate_requires_unrevoked")
    if not has_condition(guard_sql, "expires_at IS NULL", "OR",
                         "expires_at > now()"):
        bad.append("guard_predicate_requires_unexpired")
    if "FOR UPDATE" not in guard_sql.upper():
        bad.append("guard_pins_matched_rows")
    # The conflict must be raised only when a live row was actually found.
    # Checking merely that the exception name appears is too weak: inverting
    # the condition to `is None` would still contain it, and would block
    # provisioning entirely while permitting an overlap.
    if not re.search(r"if cur\.fetchone\(\) is not None:\s*\n\s*raise "
                     r"WorkerTokenConflictError", guard):
        bad.append("guard_raises_stable_conflict")
    # The live predicate must be the SAME predicate authentication applies.
    if not has_condition(authn, "revoked_at IS NULL"):
        bad.append("live_predicate_missing_from_authentication")
    if not has_condition(authn, "expires_at IS NULL", "OR",
                         "expires_at > now()"):
        bad.append("live_predicate_diverges_from_authentication")

    # Serialization is the per-worker row lock, never a global mechanism.
    if not re.search(r"FOR UPDATE OF n", require_worker, re.I):
        bad.append("worker_row_lock_missing")
    if re.search(r"pg_advisory|LOCK TABLE|pg_try_advisory", wi, re.I):
        bad.append("global_lock_introduced")

    # ---- rotation stays the separate replacement path ----
    if "revoked_at = now()" not in " ".join(sql_of(rotate)):
        bad.append("rotate_does_not_revoke")
    if "rowcount != 1" not in rotate:
        bad.append("rotate_requires_exactly_one_live_row")
    if "WorkerTokenNotFound" not in rotate:
        bad.append("rotate_fails_closed_when_nothing_to_rotate")
    if "_require_no_live_token" in rotate:
        bad.append("rotate_wrongly_blocked_by_issue_guard")
    if "_insert_token" not in rotate:
        bad.append("rotate_does_not_issue_replacement")

    # ---- P3: mandatory header, token stays the authority ----
    rw = fn(wa, "require_worker")
    if "if x_worker_id is None:" not in rw:
        bad.append("header_absence_not_refused")
    if not re.search(r"x_worker_id != principal\.worker_node_id", rw):
        bad.append("header_mismatch_not_refused")
    if "principal = authenticate_worker_token(token)" not in rw:
        bad.append("principal_not_derived_from_token")
    if "WorkerPrincipal(" in rw:
        bad.append("identity_constructed_in_request_path")
    if "x_worker_id is not None" in rw:
        bad.append("header_still_optional")

    if "if x_worker_id is None:" in rw:
        tail = rw.split("if x_worker_id is None:", 1)[1]
        segment = tail.split("def ", 1)[0]
        if "status_code=401" not in segment.replace(" ", ""):
            bad.append("header_absence_not_401")
        if "Invalid Worker credential" not in segment:
            bad.append("header_absence_not_uniform_detail")

    # ---- closed-schema authentication logging ----
    af = fn(wa, "auth_failure")
    if "worker_auth_failure" not in af:
        bad.append("auth_failure_kind_missing")
    if "'status': status" not in af and '"status": status' not in af:
        bad.append("auth_failure_status_not_closed_schema")
    for forbidden in ("authorization", "bearer", "token", "credential"):
        if forbidden in af.lower():
            bad.append("auth_failure_may_interpolate_credential")
    if re.search(r"HTTPException\([^)]*(authorization|token)", wa, re.I | re.S):
        bad.append("exception_detail_may_leak_credential")

    # ---- P2: frozen client transport policy ----
    init = fn(cl, "__init__", "WorkerApiClient")
    if "validate_private_base_url(base_url)" not in init:
        bad.append("endpoint_not_validated_at_construction")
    if len(re.findall(r"self\.base_url\s*=(?!=)", cl)) != 1:
        bad.append("endpoint_mutable_after_construction")
    if re.search(r"base_url\s*:\s*str\s*=\s*[\"']", cl):
        bad.append("endpoint_has_default_fallback")
    if re.search(r"[\"']https?://(127\.0\.0\.1|localhost)", cl):
        bad.append("endpoint_localhost_fallback_present")
    if "ProxyHandler({})" not in cl:
        bad.append("ambient_proxy_not_suppressed")
    if "_NoRedirect()" not in cl:
        bad.append("redirect_defence_absent")
    # unparse renders string literals single-quoted.
    if "'Authorization': 'Bearer ' + self._token" not in cl:
        bad.append("authorization_header_not_sent_from_client_credential")
    if "os.environ" in init or "os.environ" in fn(cl, "_post",
                                                 "WorkerApiClient"):
        bad.append("transport_reads_environment")

    # ---- credential store: embedded worker identity ----
    load = fn(cs, "load", "WindowsDpapiCredentialStore")
    if "payload.get('worker_id') != str(worker_id)" not in load:
        bad.append("dpapi_embedded_worker_id_not_checked")
    if "Credential belongs to another Worker" not in load:
        bad.append("dpapi_worker_mismatch_not_refused")

    return sorted(set(bad))


# =====================================================================
# STRUCTURAL CONTROLS (Section 28)
# =====================================================================

class F08StructuralTests(unittest.TestCase):
    def test_all_f08_invariants_hold(self):
        self.assertEqual([], check_invariants(sources()))

    def test_issue_is_provisioning_only(self):
        wi = code_only(sources()["worker_identity.py"])
        issue = function_source(wi, "issue_worker_token")
        self.assertIn("_require_no_live_token", issue)
        self.assertNotIn("UPDATE worker_tokens", issue,
                         "issue must never silently revoke a live credential")

    def test_rotate_is_the_separate_replacement_path(self):
        wi = code_only(sources()["worker_identity.py"])
        rotate = function_source(wi, "rotate_worker_token")
        self.assertIn("_insert_token", rotate)
        self.assertNotIn("_require_no_live_token", rotate)

    def test_conflict_error_is_distinct_from_provisioning_error(self):
        self.assertTrue(issubclass(worker_identity.WorkerTokenConflictError,
                                   RuntimeError))
        self.assertFalse(issubclass(
            worker_identity.WorkerTokenConflictError,
            worker_identity.WorkerTokenProvisioningError))
        self.assertFalse(issubclass(
            worker_identity.WorkerTokenProvisioningError,
            worker_identity.WorkerTokenConflictError))

    def test_live_predicate_is_exactly_the_authentication_predicate(self):
        wi = code_only(sources()["worker_identity.py"])
        guard = " ".join(sql_of(function_source(wi, "_require_no_live_token")))
        authn = " ".join(sql_of(function_source(wi, "authenticate_worker_token")))
        for condition in (("revoked_at IS NULL",),
                          ("expires_at IS NULL", "OR", "expires_at > now()")):
            self.assertTrue(has_condition(guard, *condition), condition)
            self.assertTrue(has_condition(authn, *condition), condition)

    def test_guard_uses_no_new_expiry_model(self):
        wi = code_only(sources()["worker_identity.py"])
        guard = " ".join(sql_of(function_source(wi, "_require_no_live_token")))
        # Only the two established expiry columns may appear.
        found = set(re.findall(r"[a-z_]*expires_at", guard.lower()))
        self.assertEqual(found, {"expires_at"})

    def test_serialization_uses_the_worker_row_lock(self):
        wi = code_only(sources()["worker_identity.py"])
        # The lock itself.
        self.assertIn("FOR UPDATE OF n",
                      function_source(wi, "_require_worker"))
        # Every mutation path must take that lock before it inserts or
        # revokes, otherwise the live-token check could be raced.
        for name in ("issue_worker_token", "rotate_worker_token"):
            body = function_source(wi, name)
            self.assertIn("_require_worker", body, name)
            self.assertLess(body.index("_require_worker"),
                            body.index("_insert_token"), name)
        issue = function_source(wi, "issue_worker_token")
        rotate = function_source(wi, "rotate_worker_token")
        self.assertLess(issue.index("_require_no_live_token"),
                        issue.index("_insert_token"))
        # Rotation must not inherit the provisioning-only refusal.
        self.assertNotIn("_require_no_live_token", rotate)

    def test_no_migration_required(self):
        tokens = None
        for path in sorted((ROOT / "migrations").glob("*.sql")):
            body = path.read_text(encoding="utf-8")
            if "CREATE TABLE worker_tokens" in body:
                tokens = body
        self.assertIsNotNone(tokens)
        for column in ("revoked_at", "expires_at", "worker_node_id",
                       "tenant_id", "id"):
            self.assertIn(column, tokens)

    def test_identity_authority_remains_the_token(self):
        wa = code_only(sources()["worker_api.py"])
        rw = function_source(wa, "require_worker")
        self.assertIn("principal = authenticate_worker_token(token)", rw)
        self.assertNotIn("WorkerPrincipal(", rw)
        # No route may take identity from a header or body field.
        for node in ast.walk(ast.parse(wa)):
            if isinstance(node, ast.FunctionDef) and node.name != "require_worker":
                args = [a.arg for a in node.args.args]
                if "principal" in args:
                    self.assertNotIn("x_worker_id", args, node.name)
                    self.assertNotIn("worker_id", args, node.name)

    def test_frozen_transport_files_still_pin_the_policy(self):
        cl = sources()["client.py"]
        self.assertIn("100.64.0.0/10", cl)
        self.assertIn("is_loopback", cl)
        self.assertIn("ProxyHandler({})", cl)
        self.assertIn("_NoRedirect()", cl)

    def test_live_reachability_unchanged(self):
        devai = ROOT / "controller" / "devai"

        def deps(path):
            tree = ast.parse(Path(path).read_text(encoding="utf-8"))
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

        seen, stack = set(), ["worker_api"]
        while stack:
            mod = stack.pop()
            if mod in seen:
                continue
            seen.add(mod)
            candidate = devai / f"{mod}.py"
            if candidate.exists():
                stack += [d for d in deps(candidate)
                          if (devai / f"{d}.py").exists()]
        self.assertEqual(sorted(seen),
                         ["db", "worker_api", "worker_dispatch",
                          "worker_identity", "worker_registry"])
        for dormant in ("runtime", "scheduler", "checkpoint", "executor"):
            self.assertNotIn(dormant, seen)


# =====================================================================
# AUTH CONTRACT (P3) -- Sections 20-23
# =====================================================================

class F08AuthContractTests(unittest.TestCase):
    def setUp(self):
        self.tenant = uuid4()
        self.worker_a = uuid4()
        self.worker_b = uuid4()
        self.token = "devai_wkr_" + "A" * 43

    def principal_for(self, worker):
        return worker_identity.WorkerPrincipal(self.tenant, worker, uuid4())

    def call(self, *, token=None, header="unset", principal=None,
             auth_raises=False):
        kwargs = {}
        if token is not None:
            kwargs["authorization"] = "Bearer " + token
        if header != "unset":
            kwargs["x_worker_id"] = header
        with patch.object(worker_api, "authenticate_worker_token") as auth:
            if auth_raises:
                auth.side_effect = worker_identity.WorkerAuthenticationError()
            else:
                auth.return_value = principal
            return worker_api.require_worker(**kwargs)

    def test_matching_header_authenticates_principal_from_token(self):
        p = self.principal_for(self.worker_a)
        result = self.call(token=self.token, header=self.worker_a, principal=p)
        self.assertIs(result, p)
        self.assertEqual(result.worker_node_id, self.worker_a)
        self.assertEqual(result.tenant_id, self.tenant)

    def test_missing_header_is_refused(self):
        with self.assertRaises(HTTPException) as err:
            self.call(token=self.token, header=None,
                      principal=self.principal_for(self.worker_a))
        self.assertEqual(err.exception.status_code, 401)
        self.assertEqual(err.exception.detail, "Invalid Worker credential")

    def test_omitted_header_argument_is_refused(self):
        with self.assertRaises(HTTPException) as err:
            self.call(token=self.token,
                      principal=self.principal_for(self.worker_a))
        self.assertEqual(err.exception.status_code, 401)

    def test_token_a_with_header_b_is_refused(self):
        with self.assertRaises(HTTPException) as err:
            self.call(token=self.token, header=self.worker_b,
                      principal=self.principal_for(self.worker_a))
        self.assertEqual(err.exception.status_code, 403)
        self.assertEqual(err.exception.detail, "Worker identity mismatch")

    def test_header_never_becomes_the_identity(self):
        p = self.principal_for(self.worker_a)
        with patch.object(worker_api, "authenticate_worker_token") as auth:
            auth.return_value = p
            with self.assertRaises(HTTPException):
                worker_api.require_worker(authorization="Bearer " + self.token,
                                          x_worker_id=self.worker_b)
            self.assertEqual(auth.call_args.args[0], self.token)
        self.assertNotEqual(p.worker_node_id, self.worker_b)

    def test_bad_token_with_matching_header_is_refused(self):
        with self.assertRaises(HTTPException) as err:
            self.call(token="devai_wkr_bogus", header=uuid4(),
                      auth_raises=True)
        self.assertEqual(err.exception.status_code, 401)

    def test_header_does_not_rescue_failed_authentication(self):
        with patch.object(worker_api, "authenticate_worker_token") as auth:
            auth.side_effect = worker_identity.WorkerAuthenticationError()
            with self.assertRaises(HTTPException) as err:
                worker_api.require_worker(
                    authorization="Bearer devai_wkr_" + "Z" * 43,
                    x_worker_id=self.worker_a)
        self.assertEqual(err.exception.status_code, 401)

    def test_missing_authorization_refused_before_header(self):
        with self.assertRaises(HTTPException) as err:
            worker_api.require_worker(authorization=None,
                                      x_worker_id=self.worker_a)
        self.assertEqual(err.exception.status_code, 401)

    def test_absent_header_indistinguishable_from_bad_credential(self):
        with self.assertRaises(HTTPException) as absent:
            self.call(token=self.token, header=None,
                      principal=self.principal_for(self.worker_a))
        with self.assertRaises(HTTPException) as bad:
            self.call(token=self.token, header=self.worker_a,
                      auth_raises=True)
        self.assertEqual(absent.exception.status_code, bad.exception.status_code)
        self.assertEqual(absent.exception.detail, bad.exception.detail)
        self.assertEqual(absent.exception.headers, bad.exception.headers)

    def test_malformed_authorization_scheme_refused(self):
        for value in ("", "Basic abc", "bearer", "Bearer", "Bearer "):
            with self.assertRaises(HTTPException) as err:
                worker_api.require_worker(authorization=value,
                                          x_worker_id=self.worker_a)
            self.assertEqual(err.exception.status_code, 401, value)


# =====================================================================
# SECRET REDACTION (Sections 10, 24)
# =====================================================================

class F08SecretLoggingTests(unittest.TestCase):
    SENTINEL = "SENTINEL_F08_" + "K" * 20

    def log_for(self, *, authenticate, **kwargs):
        with patch.object(worker_api, "authenticate_worker_token") as auth:
            if isinstance(authenticate, Exception):
                auth.side_effect = authenticate
            else:
                auth.return_value = authenticate
            with self.assertLogs("devai.security",
                                 level="WARNING") as captured:
                with self.assertRaises(HTTPException):
                    worker_api.require_worker(**kwargs)
        return "\n".join(captured.output)

    def test_sentinel_absent_for_bad_token(self):
        log = self.log_for(
            authenticate=worker_identity.WorkerAuthenticationError(),
            authorization="Bearer devai_wkr_" + self.SENTINEL,
            x_worker_id=uuid4())
        self.assertNotIn(self.SENTINEL, log)
        self.assertNotIn("devai_wkr_", log)
        self.assertIn("worker_auth_failure", log)

    def test_sentinel_absent_for_missing_worker_header(self):
        worker = uuid4()
        log = self.log_for(
            authenticate=worker_identity.WorkerPrincipal(uuid4(), worker,
                                                         uuid4()),
            authorization="Bearer devai_wkr_" + self.SENTINEL,
            x_worker_id=None)
        self.assertNotIn(self.SENTINEL, log)
        self.assertIn("worker_auth_failure", log)

    def test_sentinel_absent_for_worker_header_mismatch(self):
        worker = uuid4()
        log = self.log_for(
            authenticate=worker_identity.WorkerPrincipal(uuid4(), worker,
                                                         uuid4()),
            authorization="Bearer devai_wkr_" + self.SENTINEL,
            x_worker_id=uuid4())
        self.assertNotIn(self.SENTINEL, log)
        self.assertIn("worker_auth_failure", log)

    def test_issued_token_is_not_in_repr(self):
        self.assertIn("token: str = field(repr=False)",
                      sources()["worker_identity.py"])
        self.assertNotIn("devai_wkr_", repr(
            worker_identity.IssuedWorkerToken(uuid4(), uuid4(), uuid4(),
                                              "devai_wkr_secretvalue")))

    def test_client_never_logs_or_prints(self):
        cl = code_only(sources()["client.py"])
        self.assertNotIn("print(", cl)
        for pattern in ("logging", "log.", "traceback"):
            self.assertNotIn(pattern, cl)


# =====================================================================
# ENDPOINT / TRANSPORT POLICY (Sections 11, 12, 13, 25, 26)
# =====================================================================

class FakeIncoming:
    def __init__(self, status, payload=b""):
        self.status = status
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, limit=-1):
        return self.payload


class FakeOpener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, outgoing, timeout=None):
        self.requests.append(outgoing)
        return self.responses.pop(0)


def dispatch_payload(**over):
    data = {
        "id": str(uuid4()), "route_key": "k", "gateway_model": "m",
        "prompt": "p", "claim_version": 1,
        "lease_expires_at": (datetime.now(timezone.utc)
                             + timedelta(seconds=30)).isoformat(),
        "connection_id": str(uuid4()), "adapter_key": "synthetic_test",
        "execution_timeout_seconds": 30, "spec_version": 1,
        "adapter_version": "1.0",
        "deadline_at": (datetime.now(timezone.utc)
                        + timedelta(seconds=30)).isoformat(),
        "idempotency_key": str(uuid4()),
        "server_time": datetime.now(timezone.utc).isoformat(),
    }
    data.update(over)
    return json.dumps(data).encode()


def client_with(responses, origin=ORIGIN):
    opener = FakeOpener(responses)
    return WorkerApiClient(origin, uuid4(), "devai_wkr_" + "T" * 43,
                           opener=opener), opener


class F08EndpointPolicyTests(unittest.TestCase):
    def test_accepted_origins_are_numeric_loopback_or_tailscale(self):
        for good in ("http://100.91.132.78:8765", "http://127.0.0.1:8765",
                     "http://[::1]:8765", "https://100.64.1.2:8765"):
            self.assertEqual(validate_private_base_url(good), good.rstrip("/"))

    def test_rejected_origins(self):
        for bad, why in (
            ("http://example.com:8765", "DNS name"),
            ("https://controller.example:8765", "DNS name"),
            ("http://8.8.8.8:8765", "public address"),
            ("http://10.0.0.5:8765", "private but not tailnet"),
            ("http://192.168.1.10:8765", "LAN"),
            ("http://user:pw@100.91.132.78:8765", "userinfo"),
            ("http://100.91.132.78:8765/admin", "path"),
            ("http://100.91.132.78:8765/?x=1", "query"),
            ("http://100.91.132.78:8765/#f", "fragment"),
            ("ftp://100.91.132.78:8765", "scheme"),
            ("", "empty"),
        ):
            with self.assertRaises(ValueError, msg=f"{bad} ({why})"):
                validate_private_base_url(bad)

    def test_client_endpoint_comes_from_constructor_context(self):
        client = WorkerApiClient(ORIGIN, uuid4(), "devai_wkr_" + "T" * 43)
        self.assertEqual(client.base_url, ORIGIN)

    def test_dispatch_response_cannot_move_the_endpoint(self):
        spoofed = dispatch_payload(api_base_url="http://8.8.8.8:8765",
                                   base_url="http://8.8.8.8:8765",
                                   endpoint="http://8.8.8.8:8765")
        client, opener = client_with([FakeIncoming(200, spoofed),
                                      FakeIncoming(200, dispatch_payload())])
        # An unexpected field is refused outright: the payload cannot even
        # introduce an endpoint claim.
        with self.assertRaises(ProtocolError):
            client.claim()
        self.assertEqual(client.base_url, ORIGIN)
        claimed = client.claim()
        self.assertIsNotNone(claimed)
        self.assertEqual(client.base_url, ORIGIN)
        for outgoing in opener.requests:
            self.assertEqual(urlsplit(outgoing.full_url).netloc,
                             urlsplit(ORIGIN).netloc)

    def test_repeated_claims_never_repoint_the_endpoint(self):
        client, opener = client_with([FakeIncoming(200, dispatch_payload())
                                      for _ in range(3)])
        for _ in range(3):
            client.claim()
        self.assertEqual(client.base_url, ORIGIN)
        self.assertEqual({urlsplit(r.full_url).netloc for r in opener.requests},
                         {urlsplit(ORIGIN).netloc})

    def test_agent_config_is_the_endpoint_source(self):
        from worker_agent.agent import AgentConfig
        cfg = AgentConfig(worker_id=uuid4(), api_base_url=ORIGIN,
                          credential_path=Path("x"))
        client, _ = client_with([])
        self.assertEqual(WorkerApiClient(cfg.api_base_url, cfg.worker_id,
                                         "devai_wkr_" + "T" * 43).base_url,
                         cfg.api_base_url)
        self.assertEqual(client.base_url, ORIGIN)

    def test_config_loader_takes_endpoint_only_from_the_config_file(self):
        from worker_agent.agent import AgentConfig
        import inspect as _inspect
        loader = _inspect.getsource(AgentConfig.load)
        self.assertIn('data["api_base_url"]', loader)
        self.assertNotIn("environ", loader)
        self.assertNotIn("getenv", loader)

    def test_no_endpoint_fallback_when_configuration_is_invalid(self):
        for bad in ("", "not-a-url", "http://example.com", "http://8.8.8.8"):
            with self.assertRaises(ValueError, msg=bad):
                WorkerApiClient(bad, uuid4(), "devai_wkr_" + "T" * 43)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(
            _NoRedirect().redirect_request(None, None, 302, "Found", {},
                                           "http://8.8.8.8/"))

    def test_ambient_proxy_environment_is_not_adopted(self):
        # Control first: the DEFAULT opener does adopt environment proxies,
        # so the assertion below is not vacuous.
        environ = {"http_proxy": "http://8.8.8.8:3128",
                   "HTTP_PROXY": "http://8.8.8.8:3128",
                   "ALL_PROXY": "socks5://8.8.8.8:1080"}
        with patch.dict(os.environ, environ, clear=False):
            default = request.build_opener(request.HTTPRedirectHandler())
            guarded = WorkerApiClient(ORIGIN, uuid4(),
                                      "devai_wkr_" + "T" * 43)._opener
        default_proxies = [h.proxies for h in default.handlers
                           if type(h).__name__ == "ProxyHandler"]
        self.assertTrue(default_proxies and default_proxies[0],
                        "control: default opener must adopt env proxies")
        # Passing ProxyHandler({}) removes the handler outright, so there is
        # no code path through which an environment proxy can be used.
        self.assertFalse([h for h in guarded.handlers
                          if type(h).__name__ == "ProxyHandler"])

    def test_no_redirect_handler_in_the_real_opener(self):
        opener = WorkerApiClient(ORIGIN, uuid4(),
                                 "devai_wkr_" + "T" * 43)._opener
        self.assertIn("_NoRedirect", {type(h).__name__
                                      for h in opener.handlers})

    def test_bearer_only_ever_sent_to_the_configured_origin(self):
        client, opener = client_with([FakeIncoming(204)])
        client.heartbeat("windows", "x64")
        outgoing = opener.requests[0]
        self.assertEqual(outgoing.get_header("Authorization"),
                         "Bearer devai_wkr_" + "T" * 43)
        self.assertEqual(urlsplit(outgoing.full_url).netloc,
                         urlsplit(ORIGIN).netloc)

    def test_credential_is_not_payload_derived(self):
        cl = sources()["client.py"]
        refresh = function_source(cl, "replace_token", "WorkerApiClient")
        self.assertEqual([ln.strip() for ln in refresh.splitlines()
                          if ln.strip() and not ln.strip().startswith("def")],
                         ["self._token = token"])
        self.assertEqual(len(re.findall(r"self\._token\s*=(?!=)", cl)), 2)

    def test_transport_reads_no_environment_variable(self):
        cl = code_only(sources()["client.py"])
        for name in ("environ", "getenv"):
            self.assertNotIn(name, cl)


# =====================================================================
# DATABASE (Sections 15-19)
# =====================================================================

def db_available():
    return bool(os.environ.get("DEVAI_TEST_DATABASE_URL"))


@unittest.skipUnless(db_available(),
                     "set DEVAI_TEST_DATABASE_URL to run F08 database tests")
class F08DatabaseTests(unittest.TestCase):
    """P1 against a real engine. Nothing here is faked."""

    def setUp(self):
        import psycopg
        self.psycopg = psycopg
        self.url = os.environ["DEVAI_TEST_DATABASE_URL"]
        self.tenant = uuid4()
        self.worker = uuid4()
        self.admin = psycopg.connect(self.url)
        self.addCleanup(self._cleanup)
        with self.admin.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants(id,slug,name) VALUES (%s,%s,'f08')",
                (self.tenant, str(self.tenant)))
            cur.execute(
                "INSERT INTO worker_nodes(id,tenant_id,name,status) "
                "VALUES (%s,%s,'f08','online')", (self.worker, self.tenant))

    def _cleanup(self):
        try:
            with self.admin.cursor() as cur:
                cur.execute("DELETE FROM worker_tokens WHERE tenant_id=%s",
                            (self.tenant,))
                cur.execute("DELETE FROM worker_nodes WHERE tenant_id=%s",
                            (self.tenant,))
                cur.execute("DELETE FROM tenants WHERE id=%s", (self.tenant,))
            self.admin.commit()
        except Exception:
            pass
        self.admin.close()

    def share(self):
        outer = self

        class Shared:
            def __enter__(self):
                return outer.admin

            def __exit__(self, *_):
                return False

        return patch.object(worker_identity, "connect", return_value=Shared())

    def real_connect(self):
        psycopg = self.psycopg
        url = self.url

        def factory():
            return psycopg.connect(url)
        return factory

    def live_count(self, cur, worker=None):
        cur.execute(
            "SELECT count(*) FROM worker_tokens WHERE tenant_id=%s "
            "AND worker_node_id=%s AND revoked_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > now())",
            (self.tenant, worker or self.worker))
        return cur.fetchone()[0]

    # ---- Section 15 ----
    def test_initial_issue_succeeds_with_one_live_credential(self):
        with self.share():
            issued = worker_identity.issue_worker_token(self.tenant,
                                                         self.worker)
        self.assertTrue(issued.token.startswith("devai_wkr_"))
        with self.admin.cursor() as cur:
            self.assertEqual(self.live_count(cur), 1)
            cur.execute("SELECT tenant_id, worker_node_id, token_hash "
                        "FROM worker_tokens WHERE id=%s", (issued.id,))
            row = cur.fetchone()
        self.assertEqual(row[0], self.tenant)
        self.assertEqual(row[1], self.worker)
        self.assertEqual(bytes(row[2]),
                         hashlib.sha256(issued.token.encode()).digest())

    # ---- Section 16 ----
    def test_second_issue_rejected_and_state_unchanged(self):
        with self.share():
            first = worker_identity.issue_worker_token(self.tenant,
                                                        self.worker)
            with self.assertRaises(worker_identity.WorkerTokenConflictError):
                worker_identity.issue_worker_token(self.tenant, self.worker)
            with self.admin.cursor() as cur:
                self.assertEqual(self.live_count(cur), 1)
                cur.execute("SELECT count(*) FROM worker_tokens "
                            "WHERE tenant_id=%s AND worker_node_id=%s",
                            (self.tenant, self.worker))
                self.assertEqual(cur.fetchone()[0], 1)
                cur.execute("SELECT id FROM worker_tokens "
                            "WHERE revoked_at IS NULL")
                self.assertEqual(cur.fetchone()[0], first.id)

    def test_expired_credential_does_not_block_issue(self):
        # LIVE follows the authentication predicate: an expired credential is
        # not live, so provisioning may proceed. This is the boundary that
        # keeps P1 from becoming an availability trap.
        with self.share():
            first = worker_identity.issue_worker_token(self.tenant,
                                                        self.worker)
            with self.admin.cursor() as cur:
                cur.execute("UPDATE worker_tokens SET expires_at = "
                            "now() - interval '1 second' WHERE id=%s",
                            (first.id,))
                self.assertEqual(self.live_count(cur), 0)
            second = worker_identity.issue_worker_token(self.tenant,
                                                        self.worker)
        self.assertNotEqual(first.token, second.token)

    # ---- Section 19 ----
    def test_rotation_remains_the_replacement_path(self):
        with self.share():
            old = worker_identity.issue_worker_token(self.tenant, self.worker)
            new = worker_identity.rotate_worker_token(self.tenant,
                                                       self.worker, old.id)
        self.assertNotEqual(old.token, new.token)
        with patch.object(worker_identity, "connect", self.real_connect()):
            with self.assertRaises(worker_identity.WorkerAuthenticationError):
                worker_identity.authenticate_worker_token(old.token)
            principal = worker_identity.authenticate_worker_token(new.token)
            self.assertEqual(principal.worker_node_id, self.worker)
            self.assertEqual(principal.tenant_id, self.tenant)
            with self.admin.cursor() as cur:
                self.assertEqual(self.live_count(cur), 1)

    # ---- Section 17 ----
    def test_concurrent_issue_same_worker_yields_one_credential(self):
        self.admin.commit()
        barrier = threading.Barrier(2)
        outcomes, lock = [], threading.Lock()

        def attempt(_):
            barrier.wait(timeout=15)
            try:
                with patch.object(worker_identity, "connect",
                                  self.real_connect()):
                    issued = worker_identity.issue_worker_token(
                        self.tenant, self.worker)
                verdict = "issued"
            except worker_identity.WorkerTokenConflictError:
                verdict = "conflict"
            except Exception as exc:
                verdict = "error:" + type(exc).__name__
            with lock:
                outcomes.append(verdict)

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(attempt, range(2)))

        self.assertEqual(sorted(outcomes), ["conflict", "issued"], outcomes)
        with self.psycopg.connect(self.url) as conn, conn.cursor() as cur:
            self.assertEqual(self.live_count(cur), 1)
            cur.execute("SELECT count(*) FROM worker_tokens "
                        "WHERE tenant_id=%s AND worker_node_id=%s",
                        (self.tenant, self.worker))
            self.assertEqual(cur.fetchone()[0], 1)

    # ---- Section 18 ----
    def test_concurrent_issue_distinct_workers_both_succeed(self):
        other = uuid4()
        with self.admin.cursor() as cur:
            cur.execute(
                "INSERT INTO worker_nodes(id,tenant_id,name,status) "
                "VALUES (%s,%s,'f08-b','online')", (other, self.tenant))
        self.admin.commit()
        barrier = threading.Barrier(2)
        results, lock = {}, threading.Lock()

        def attempt(worker):
            barrier.wait(timeout=15)
            try:
                with patch.object(worker_identity, "connect",
                                  self.real_connect()):
                    issued = worker_identity.issue_worker_token(
                        self.tenant, worker)
                value = issued.id
            except Exception as exc:
                value = "error:" + type(exc).__name__
            with lock:
                results[str(worker)] = value

        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(attempt, (self.worker, other)))

        # Proof is resulting database state, never wall-clock latency.
        self.assertEqual(len(results), 2, results)
        for key, value in results.items():
            self.assertNotIsInstance(value, str, (key, results))
        with self.psycopg.connect(self.url) as conn, conn.cursor() as cur:
            for worker in (self.worker, other):
                self.assertEqual(self.live_count(cur, worker), 1, worker)


# =====================================================================
# MUTATION MATRIX (Sections 29, 30)
# =====================================================================

# Frozen before execution. Each entry names the exact target text (which must
# occur exactly once in the CODE-ONLY form, proving isolation), the
# replacement, and the exact invariant whose violation rejects the mutant.
MUTATION_MATRIX = (
    ("F08M01", "worker_identity.py",
     "_require_worker(cur, tenant_id, worker_node_id)\n"
     "            _require_no_live_token(cur, tenant_id, worker_node_id)",
     "_require_worker(cur, tenant_id, worker_node_id)",
     "issue_calls_live_guard"),
    ("F08M02", "worker_identity.py",
     "AND revoked_at IS NULL\\n"
     "          AND (expires_at IS NULL OR expires_at > now())",
     "AND (expires_at IS NULL OR expires_at > now())",
     "guard_predicate_requires_unrevoked"),
    ("F08M03", "worker_identity.py",
     "AND revoked_at IS NULL\\n"
     "          AND (expires_at IS NULL OR expires_at > now())",
     "AND revoked_at IS NULL",
     "guard_predicate_requires_unexpired"),
    ("F08M04", "worker_identity.py",
     "AND (expires_at IS NULL OR expires_at > now())\\n        FOR UPDATE",
     "AND (expires_at IS NULL OR expires_at > now())",
     "guard_pins_matched_rows"),
    ("F08M05", "worker_identity.py",
     "FOR UPDATE OF n",
     "",
     "worker_row_lock_missing"),
    ("F08M06", "worker_identity.py",
     "_require_no_live_token(cur, tenant_id, worker_node_id)\n"
     "            issued = _insert_token(cur, tenant_id, worker_node_id, "
     "expires_at)",
     "cur.execute('UPDATE worker_tokens SET revoked_at = now() WHERE "
     "tenant_id=%s AND worker_node_id=%s AND revoked_at IS NULL', "
     "(tenant_id, worker_node_id))\n"
     "            issued = _insert_token(cur, tenant_id, worker_node_id, "
     "expires_at)",
     "issue_silently_revokes"),
    ("F08M07", "worker_identity.py",
     "if cur.fetchone() is not None:\n"
     "        raise WorkerTokenConflictError",
     "if cur.fetchone() is None:\n"
     "        raise WorkerTokenConflictError",
     "guard_raises_stable_conflict"),
    ("F08M08", "worker_identity.py",
     "AND revoked_at IS NULL\\n"
     "          AND (expires_at IS NULL OR expires_at > now())",
     "AND tenant_id = %s AND worker_node_id = %s",
     "guard_predicate_requires_unrevoked"),
    ("F08M09", "worker_identity.py",
     "_require_no_live_token(cur, tenant_id, worker_node_id)\n"
     "            issued = _insert_token(cur, tenant_id, worker_node_id, "
     "expires_at)",
     "issued = _insert_token(cur, tenant_id, worker_node_id, expires_at)",
     "issue_calls_live_guard"),
    ("F08M10", "worker_api.py",
     "if x_worker_id is None:",
     "if False:",
     "header_absence_not_refused"),
    ("F08M11", "worker_api.py",
     "if x_worker_id != principal.worker_node_id:",
     "if False:",
     "header_mismatch_not_refused"),
    ("F08M12", "worker_api.py",
     "principal = authenticate_worker_token(token)",
     "principal = WorkerPrincipal(x_worker_id, x_worker_id, token)",
     "principal_not_derived_from_token"),
    ("F08M13", "worker_api.py",
     "except WorkerAuthenticationError:\n        auth_failure(401)",
     "except WorkerAuthenticationError:\n"
     "        if x_worker_id is not None:\n"
     "            return WorkerPrincipal(x_worker_id, x_worker_id, token)\n"
     "        auth_failure(401)",
     "identity_constructed_in_request_path"),
    ("F08M14", "worker_api.py",
     "auth_failure(401)\n"
     "        raise HTTPException(status_code=401, "
     "detail='Invalid Worker credential', "
     "headers={'WWW-Authenticate': 'Bearer'})\n"
     "    if x_worker_id != principal.worker_node_id:",
     "auth_failure(401)\n"
     "        raise HTTPException(status_code=401, "
     "detail='Worker identity mismatch', "
     "headers={'WWW-Authenticate': 'Bearer'})\n"
     "    if x_worker_id != principal.worker_node_id:",
     "header_absence_not_uniform_detail"),
    ("F08M15", "client.py",
     "self.base_url = validate_private_base_url(base_url)",
     "self.base_url = base_url",
     "endpoint_not_validated_at_construction"),
    ("F08M16", "client.py",
     "self.base_url = validate_private_base_url(base_url)",
     "self.base_url = base_url if base_url else "
     "'http://127.0.0.1:8765'",
     "endpoint_localhost_fallback_present"),
    ("F08M17", "client.py",
     "request.ProxyHandler({}), _NoRedirect()",
     "request.ProxyHandler(), _NoRedirect()",
     "ambient_proxy_not_suppressed"),
    ("F08M18", "client.py",
     "request.ProxyHandler({}), _NoRedirect()",
     "request.ProxyHandler({})",
     "redirect_defence_absent"),
    ("F08M19", "client.py",
     "'Authorization': 'Bearer ' + self._token, ",
     "",
     "authorization_header_not_sent_from_client_credential"),
    ("F08M20", "credential_store.py",
     "if payload.get('worker_id') != str(worker_id):",
     "if False:",
     "dpapi_embedded_worker_id_not_checked"),
    ("F08M21", "worker_api.py",
     "'status': status",
     "'status': status, 'token': status",
     "auth_failure_may_interpolate_credential"),
)


class F08MutationMatrixTests(unittest.TestCase):
    def test_inventory_is_frozen_and_unique(self):
        ids = [m[0] for m in MUTATION_MATRIX]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids[0], "F08M01")
        self.assertEqual(ids[-1], "F08M21")

    def test_every_mutant_target_present_exactly_once(self):
        base = {k: code_only(v) for k, v in sources().items()}
        for mid, rel, old, new, invariant in MUTATION_MATRIX:
            self.assertEqual(
                base[rel].count(old), 1,
                f"{mid}: target occurs {base[rel].count(old)} times in {rel}; "
                "a non-unique target cannot prove isolation")

    def test_every_mutant_is_rejected_by_its_invariant(self):
        # Mutate the CODE-ONLY form so targets are written in one canonical
        # shape; check_invariants is idempotent over that form.
        base = {k: code_only(v) for k, v in sources().items()}
        self.assertEqual([], check_invariants(sources()),
                         "baseline must satisfy every invariant")
        problems = []
        for mid, rel, old, new, invariant in MUTATION_MATRIX:
            mutated = dict(base)
            mutated[rel] = mutated[rel].replace(old, new, 1)
            if mutated[rel] == base[rel]:
                problems.append((mid, "HARNESS_ERROR:no-op"))
                continue
            violated = check_invariants(mutated)
            if invariant in violated:
                continue
            problems.append((mid, "WRONG_INVARIANT:" + ",".join(violated)
                             if violated else "SURVIVED"))
        self.assertEqual([], problems)


if __name__ == "__main__":
    unittest.main()
