"""RH-B STEP 5F-H: shared, deterministic release-artifact primitives.

Trust model (three nested layers, never collapsed):

  LAYER A  outer release artifact   -- trusted externally supplied SHA256 of
                                        the .tar bytes. That is ARTIFACT_INTEGRITY
                                        relative to the trusted channel. It is NOT
                                        publisher authentication: no signing key
                                        exists in RH-B. Publisher identity/signing
                                        is a separate future capability.
  LAYER B  release.json              -- authenticated BY layer A. Binds source
                                        commit/tree, manifest.json, the installer
                                        script, runtime identity and the
                                        dependency locks.
  LAYER C  package payload           -- manifest.json binds per-file sha256+size
                                        and the recomputed V2 aggregate.

Determinism rules enforced here:
  * SOURCE_DATE_EPOCH is the exact Git commit timestamp, never wall clock.
  * Canonical JSON: UTF-8, no BOM, LF, sorted keys, compact separators,
    trailing LF.
  * Nothing may depend on username, HOME, USERPROFILE, LOCALAPPDATA, CWD or
    hostname.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

RELEASE_FORMAT = "DEVAIRELEASE"
RELEASE_SCHEMA_VERSION = 1
RELEASE_NAME = "release.json"
ARTIFACT_FORMAT = "tar"
PLATFORM = "windows-x64"

HEX64 = re.compile(r"^[0-9a-f]{64}$")
GIT_OID = re.compile(r"^[0-9a-f]{40}$")

# Members that must never appear in a release artifact. Name-based, structural.
FORBIDDEN_BASENAMES = frozenset({
    "worker.dpapi", "service.json", ".gitignore", ".gitattributes",
    ".coverage", "coverage.xml",
})
FORBIDDEN_SUBSTRINGS = (
    "personal_denial_fixture", "personal-denial.fixture",
    "service-access-denial.fixture", "__pycache__", ".pytest_cache", ".pyc",
    ".git/", "/.git", ".venv", "venv/", "site-packages",
)
ALLOWED_TOP_LEVEL = ("release.json", "package", "lock", "requirements.in")

# Target configuration keys that must never appear in an immutable artifact.
TARGET_STATE_KEYS = frozenset({
    "worker_id", "api_base_url", "personal_denial_fixture", "credential_path",
    "token", "service_sid", "volume_guid",
})

# Content needles that would leak builder-machine identity into release metadata.
# Applied to release.json and lock inputs only: the package payload legitimately
# contains *references* to $env:USERPROFILE and "AppData" as policy code, so a
# blanket content scan over payload would be a false positive generator.
IDENTITY_LEAK_NEEDLES = (
    b"C:\\Users\\", b"/home/", b"/root/", b"AppData",
    b"USERPROFILE", b"LOCALAPPDATA", b"\\Users\\",
)


# Immutable package members that MUST be present. Without this, a packaging
# bug that drops an entire subtree can produce a self-consistent artifact that
# still verifies -- exactly the failure mode where two implementations agree on
# a wrong answer.
REQUIRED_PACKAGE_MEMBERS = (
    "install-worker.ps1",
    "install-support.ps1",
    "manifest.json",
    "control/worker_agent/__init__.py",
    "control/worker_agent/__main__.py",
    "control/worker_agent/windows_service.py",
    "control/worker_agent/provision.py",
)


# Runtime install-payload completeness. A package that carries ANY runtime
# payload member must carry ALL of them: the proven failure was a dropped
# sandbox-runtime alongside a present host-runtime, whose manifest stayed
# self-consistent, verified clean, then died at install with PathNotFound.
# (A wholly runtime-less package is still rejected at install time by the
# installer payload preflight; the fast runtime-less build mode used by
# tests stays usable.) Keep aligned with Get-RequiredInstallPayloadMembers
# and the builder sandbox contract.
RUNTIME_PAYLOAD_MEMBERS = (
    "host-runtime/python.exe",
    "sandbox-runtime/python.exe",
    "sandbox-runtime/synthetic_process.py",
)


def assert_runtime_payload_complete(present,
                                    code: str = "INCOMPLETE_RUNTIME_PAYLOAD",
                                    *, allow_absent: bool = False):
    """Completeness of the runtime install payload.

    Strict by default: every listed member must be present. A manifest that
    accurately describes a runtime-less or runtime-partial payload is
    self-consistent yet uninstallable (observed: dropped sandbox-runtime
    verified clean, then failed install with PathNotFound), so production
    release verification must refuse it -- and does, because the release
    verifier never passes allow_absent.

    allow_absent=True is ONLY for the build staging self-check, which must
    stay usable in the deliberate runtime-less fast-build test mode (the
    pinned 11 MB runtime archive is a CI/production input, not a unit-test
    input). A build that was GIVEN a runtime but dropped part of it still
    fails: callers pass allow_absent only when no runtime was requested.
    """
    have = set(present)
    if allow_absent and not any(member in have
                                for member in RUNTIME_PAYLOAD_MEMBERS):
        return
    for member in RUNTIME_PAYLOAD_MEMBERS:
        if member not in have:
            raise ReleaseError("%s:%s" % (code, member))


def assert_required_package_members(present, code: str = "REQUIRED_PACKAGE_MEMBER_MISSING"):
    have = set(present)
    for member in REQUIRED_PACKAGE_MEMBERS:
        if member not in have:
            raise ReleaseError("%s:%s" % (code, member))


class ReleaseError(RuntimeError):
    """Fail-closed release/verification error.

    Carries only a control code and a member/field name. Never a secret, never
    a supplied value, never a resolved environment path.
    """


def canonical_json_bytes(document) -> bytes:
    """UTF-8, no BOM, LF, sorted keys, compact separators, trailing LF."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True)
    return (text + "\n").encode("utf-8")


def pretty_json_bytes(document) -> bytes:
    """Human-reviewable deterministic JSON (sorted keys, indent 2, trailing LF)."""
    text = json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True)
    return (text + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_hex64(value, code: str) -> str:
    if not isinstance(value, str) or not HEX64.match(value):
        raise ReleaseError(code)
    return value


def require_git_oid(value, code: str) -> str:
    if not isinstance(value, str) or not GIT_OID.match(value):
        raise ReleaseError(code)
    return value


# --------------------------------------------------------------------- git ---
def git(repo: Path, *args: str) -> str:
    """Run git and return stripped stdout. Never raises on content, only on exit."""
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, check=False)
    if result.returncode != 0:
        raise ReleaseError("GIT_COMMAND_FAILED:%s" % args[0])
    return result.stdout.decode("utf-8").strip()


def resolve_commit(repo: Path, revision: str = "HEAD") -> str:
    return git(repo, "rev-parse", "--verify", "%s^{commit}" % revision)


def commit_tree(repo: Path, commit: str) -> str:
    return git(repo, "rev-parse", "--verify", "%s^{tree}" % commit)


def commit_timestamp(repo: Path, commit: str) -> int:
    """Canonical release timestamp: the exact Git commit time, never wall clock."""
    raw = git(repo, "show", "-s", "--format=%ct", commit)
    try:
        value = int(raw)
    except ValueError:
        raise ReleaseError("SOURCE_DATE_EPOCH_UNAVAILABLE")
    if value <= 0:
        raise ReleaseError("SOURCE_DATE_EPOCH_INVALID")
    return value


def tree_of(repo: Path, commit: str, path: str) -> str:
    return git(repo, "rev-parse", "--verify", "%s:%s" % (commit, path))


def blob(repo: Path, commit: str, path: str) -> bytes:
    """Read a COMMITTED blob. Build inputs never come from the worktree."""
    result = subprocess.run(
        ["git", "-C", str(repo), "show", "%s:%s" % (commit, path)],
        capture_output=True, check=False)
    if result.returncode != 0:
        raise ReleaseError("SOURCE_BLOB_MISSING:%s" % path)
    return result.stdout


def blob_exists(repo: Path, commit: str, path: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", "%s:%s" % (commit, path)],
        capture_output=True, check=False)
    return result.returncode == 0


def worktree_is_clean(repo: Path) -> bool:
    return git(repo, "status", "--porcelain") == ""


# ------------------------------------------------------------------ sidecar ---
def sidecar_bytes(digest: str, filename: str) -> bytes:
    """<lowercase sha256><2 spaces><filename> LF. One deterministic format."""
    require_hex64(digest, "SIDECAR_DIGEST_MALFORMED")
    if filename != Path(filename).name or not filename or filename.strip() != filename:
        raise ReleaseError("SIDECAR_FILENAME_INVALID")
    return ("%s  %s\n" % (digest, filename)).encode("utf-8")


def parse_sidecar(data: bytes, artifact_name: str):
    """Fail closed on any deviation from the one canonical sidecar format."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ReleaseError("SIDECAR_NOT_UTF8")
    if text.endswith("\r\n"):
        raise ReleaseError("SIDECAR_NOT_LF")
    if not text.endswith("\n"):
        raise ReleaseError("SIDECAR_MISSING_TRAILING_LF")
    body = text[:-1]
    if "\n" in body:
        raise ReleaseError("SIDECAR_MULTIPLE_LINES")
    if "  " not in body:
        raise ReleaseError("SIDECAR_SEPARATOR_INVALID")
    digest, _, filename = body.partition("  ")
    if not HEX64.match(digest):
        raise ReleaseError("SIDECAR_DIGEST_MALFORMED")
    if filename != artifact_name:
        raise ReleaseError("SIDECAR_FILENAME_MISMATCH")
    return digest


# --------------------------------------------------------- path/member rules ---
def check_member_name(name: str) -> str:
    """Normalise and validate a tar member path. Fail closed, no ambiguity."""
    if not name or name != name.strip():
        raise ReleaseError("MEMBER_NAME_MALFORMED")
    if "\\" in name:
        raise ReleaseError("MEMBER_BACKSLASH_AMBIGUOUS:%s" % name)
    if name.startswith("/"):
        raise ReleaseError("MEMBER_ABSOLUTE_PATH:%s" % name)
    if re.match(r"^[A-Za-z]:", name):
        raise ReleaseError("MEMBER_DRIVE_QUALIFIED:%s" % name)
    if name.startswith("./") or name.startswith("../"):
        raise ReleaseError("MEMBER_RELATIVE_PREFIX:%s" % name)
    segments = name.split("/")
    if any(segment in ("", ".", "..") for segment in segments):
        raise ReleaseError("MEMBER_TRAVERSAL:%s" % name)
    lowered = name.lower()
    for bad in FORBIDDEN_SUBSTRINGS:
        if bad in lowered:
            raise ReleaseError("MEMBER_FORBIDDEN:%s" % name)
    if segments[-1] in FORBIDDEN_BASENAMES:
        raise ReleaseError("MEMBER_FORBIDDEN:%s" % name)
    return name


def is_target_state_member(name: str) -> bool:
    base = name.rsplit("/", 1)[-1]
    return base in ("worker.dpapi", "service.json") or "personal-denial.fixture" in name


def scan_identity_leak(data: bytes, member: str):
    for needle in IDENTITY_LEAK_NEEDLES:
        if needle in data:
            raise ReleaseError("IDENTITY_LEAK_IN_RELEASE:%s" % member)


def assert_no_target_state_keys(document, code: str) -> None:
    """Structural: no concrete target value may appear in an immutable document."""
    if not isinstance(document, dict):
        raise ReleaseError(code)
    for key in document:
        if key in TARGET_STATE_KEYS:
            raise ReleaseError("TARGET_STATE_KEY_IN_RELEASE:%s" % key)


def find_identity_leak(data: bytes):
    for needle in IDENTITY_LEAK_NEEDLES:
        if needle in data:
            return needle.decode("ascii", "replace")
    return None