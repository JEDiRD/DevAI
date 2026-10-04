"""Build the immutable Windows service package.

PURE BUILD STEP. This tool produces only immutable release identity. It has no
knowledge of any target machine, operator, or credential.

What this tool must never do (each is enforced below, not merely intended):

  * Never read a worker token, a DPAPI store, or any credential material.
  * Never emit `worker.dpapi` into the package.
  * Never discover, create, or record a personal profile directory.
  * Never embed an absolute builder path, username, or home directory.
  * Never let host Python (sys.base_prefix / sys.executable) determine
    package identity. The runtime comes only from the verified runtime lock.
  * Never silently skip a missing runtime component.

Given identical git source, dependency locks, pinned runtime, SOURCE_DATE_EPOCH
and tool version, the output bytes are identical regardless of current
username, USERPROFILE, LOCALAPPDATA, working directory or build machine.

Target-side concerns are the installer's responsibility:

  * personal-profile denial fixture creation (target-local absolute path)
  * credential provisioning into the target's DPAPI store
  * service.json generation

Legacy build-time options `--existing-config` and `--reuse-personal-fixture`
are retained as argument NAMES only, so an old invocation fails closed with a
migration message instead of being silently ignored or honoured. Their values
are never read, logged or embedded.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNTIME_LOCK = REPO_ROOT / "deploy" / "windows" / "runtime-lock.json"
MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = "DEVAI_PACKAGE_MANIFEST"
MANIFEST_SCHEMA_VERSION = 1
MANIFEST_FORMAT_V2 = "MANIFEST_FORMAT_V2"
LEGACY_MIGRATION = (
    "build-package.py no longer accepts target-specific configuration or "
    "personal fixtures. Supply these during installation/provisioning "
    "(-ReusePersonalFixture on install-worker.ps1), not at build time."
)

# Immutable payload sources. Only first-party, deterministic content.
PAYLOAD = (
    ("control/worker_agent", "worker_agent"),
    ("install-worker.ps1", "deploy/windows/install-worker.ps1"),
    ("install-support.ps1", "deploy/windows/install-support.ps1"),
)
RUNTIME_DIRS = ("host-runtime", "sandbox-runtime")
RUNTIME_CORE = ("python.exe", "python313.dll", "python3.dll",
                "vcruntime140.dll", "vcruntime140_1.dll")


class BuildError(RuntimeError):
    """Fail-closed error. Never carries a supplied option value."""


def _reject_legacy(options):
    """Legacy build inputs must fail closed, never be ignored or honoured."""
    for name, value in options:
        if value is None:
            continue
        # Deliberately do not include the value, the referenced path, or any
        # part of it in the message or in any emitted artifact.
        raise BuildError(LEGACY_MIGRATION + " (rejected option: %s)" % name)


def load_runtime_lock(path=RUNTIME_LOCK):
    lock = json.loads(Path(path).read_text(encoding="utf-8"))
    for field in ("python_version", "source_url", "source_sha256",
                  "source_size_bytes", "runtime_artifact_type", "architecture"):
        if field not in lock:
            raise BuildError("RUNTIME_LOCK_INCOMPLETE:%s" % field)
    return lock


def verify_runtime_artifact(artifact, lock):
    """Verify SHA256 and size of the runtime archive. Fail closed.

    `artifact` is a caller-supplied path to the already-downloaded canonical
    artifact. This function never downloads anything and never trusts a host
    interpreter as a substitute.
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        raise BuildError("RUNTIME_ARTIFACT_MISSING")
    size = artifact.stat().st_size
    if size != int(lock["source_size_bytes"]):
        raise BuildError("RUNTIME_ARTIFACT_SIZE_MISMATCH")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != lock["source_sha256"]:
        raise BuildError("RUNTIME_ARTIFACT_SHA256_MISMATCH")
    return digest


def _iter_payload_files(root):
    """Deterministic, sorted enumeration of tracked payload files.

    Sorting is by UTF-8 path bytes, never by filesystem iteration order.
    __pycache__ and VCS metadata are excluded.
    """
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in ("__pycache__", ".git"))
        for name in sorted(filenames):
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            found.append((rel, full))
    found.sort(key=lambda item: item[0].encode("utf-8"))
    return found


def write_package_files(destination, runtime_artifact=None):
    """Materialise immutable payload. Raises on any missing component."""
    destination.mkdir(parents=True, exist_ok=True)

    for out_rel, src_rel in PAYLOAD:
        src = REPO_ROOT / src_rel
        if not src.exists():
            raise BuildError("PAYLOAD_MISSING:%s" % src_rel)
        out = destination / out_rel
        out.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            for rel, full in _iter_payload_files(src):
                target = out / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(full.read_bytes())
        else:
            out.write_bytes(src.read_bytes())

    if runtime_artifact is not None:
        _install_runtime(destination, runtime_artifact)


def _install_runtime(destination, runtime_artifact):
    """Extract the verified embeddable runtime. Fail closed on gaps."""
    with zipfile.ZipFile(artifact := Path(runtime_artifact)) as archive:
        names = sorted(archive.namelist(), key=lambda n: n.encode("utf-8"))
        runtime = destination / RUNTIME_DIRS[0]
        runtime.mkdir(parents=True, exist_ok=True)
        for name in names:
            if name.endswith("/"):
                continue
            target = runtime / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(name))

    # Every expected core component must exist; absence is a hard failure
    # rather than a silent skip.
    for name in RUNTIME_CORE:
        if not (destination / RUNTIME_DIRS[0] / name).is_file():
            raise BuildError("RUNTIME_COMPONENT_MISSING:%s" % name)
    del artifact


def serialize_manifest_v2(entries):
    """Canonical MANIFEST_FORMAT_V2 identity serialization.

    This is an AGGREGATION ALGORITHM, not the package contract storage format.
    `manifest.json` on disk is structured JSON (see build_manifest_document);
    this function is the deterministic byte serialization whose SHA256 is the
    identity aggregate. Keeping the two separate means a consumer never has
    to parse a mislabeled line-oriented file.

    V2 canonical form: UTF-8, no BOM, LF separators, trailing LF, first line
    exactly "# MANIFEST_FORMAT_V2", then UTF-8 byte-sorted identity lines of
    "<sha256><2 spaces><decimal size><2 spaces><relative path>".
    """
    ordered = sorted(entries, key=lambda item: item[0].encode("utf-8"))
    lines = ["# " + MANIFEST_FORMAT_V2]
    for rel, data in ordered:
        lines.append("%s  %d  %s" % (hashlib.sha256(data).hexdigest(),
                                      len(data), rel))
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_manifest_document(destination, entries=None, runtime=None,
                            locks=None, release=None):
    """Build the structured JSON immutable release contract.

    This IS the package contract and MUST parse as JSON. It carries immutable
    identity and declarative policy requirements only. It never carries
    concrete target configuration (worker_id, api_base_url, fixture path) or
    secret state (worker.dpapi, tokens): those belong to service.json and the
    target credential store respectively.
    """
    destination = Path(destination) if destination is not None else None
    if entries is None:
        entries = []
        for rel, full in _iter_payload_files(destination):
            if rel == MANIFEST_NAME:
                continue
            entries.append((rel, full.read_bytes()))

    # Secret and target-state material is refused on every path, whether the
    # entries were discovered on disk or supplied directly. Failing closed
    # here means a forbidden file can never be manifested, let alone shipped.
    for rel, _data in entries:
        if rel == MANIFEST_NAME:
            continue
        if _is_forbidden(rel):
            raise BuildError("FORBIDDEN_PAYLOAD:%s" % rel)

    # Duplicate logical paths are refused: a later duplicate must never be
    # able to shadow an earlier verified entry.
    seen = set()
    for rel, _ in entries:
        if rel in seen:
            raise BuildError("DUPLICATE_MANIFEST_ENTRY:%s" % rel)
        seen.add(rel)

    entries.sort(key=lambda item: item[0].encode("utf-8"))
    v2_bytes = serialize_manifest_v2(entries)

    document = {
        "manifest_format": MANIFEST_FORMAT,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "files": [
            {"path": rel,
             "sha256": hashlib.sha256(data).hexdigest(),
             "size": len(data)}
            for rel, data in entries
        ],
        "policy_requirements": sorted(POLICY_REQUIREMENTS),
        "identity": {
            "format": MANIFEST_FORMAT_V2,
            "aggregate_sha256": hashlib.sha256(v2_bytes).hexdigest(),
        },
    }
    if runtime is not None:
        document["runtime"] = runtime
    if locks is not None:
        document["dependency_locks"] = locks
    if release is not None:
        document["release"] = release

    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    return text.encode("utf-8")


# Declarative capability requirements only. No concrete target values.
POLICY_REQUIREMENTS = (
    "requires_worker_identity",
    "requires_api_base_url",
    "requires_worker_credential",
    "requires_personal_profile_denial_fixture",
)


FORBIDDEN_BASENAMES = ("worker.dpapi",)
FORBIDDEN_SUBSTRINGS = ("personal_denial_fixture", "personal-denial.fixture",
                        "service.json")


def _is_forbidden(rel):
    name = rel.rsplit("/", 1)[-1]
    if name in FORBIDDEN_BASENAMES:
        return True
    return any(s in rel for s in FORBIDDEN_SUBSTRINGS)


def manifest_v1_bytes(entries):
    """Historical MANIFEST_FORMAT_V1: CRLF, trailing CRLF, no header.

    Retained so historical Stage-B aggregates remain verifiable. Never used to
    author new release manifests.
    """
    ordered = sorted(entries, key=lambda item: item[0].encode("utf-8"))
    lines = ["%s  %d  %s" % (hashlib.sha256(d).hexdigest(), len(d), r)
             for r, d in ordered]
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def parse_manifest(data):
    """Parse the structured JSON package contract.

    Returns the document plus [(path, sha256, size)] in canonical order.
    Historical V1 line-oriented text is parsed only by parse_manifest_v1, for
    verifying frozen Phase-2 aggregates -- never as a package contract.
    """
    if data[:3] == b"\xef\xbb\xbf":
        raise BuildError("MANIFEST_HAS_BOM")
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BuildError("MANIFEST_NOT_VALID_JSON") from exc
    if not isinstance(document, dict):
        raise BuildError("MANIFEST_NOT_AN_OBJECT")
    if document.get("manifest_format") != MANIFEST_FORMAT:
        raise BuildError("UNSUPPORTED_MANIFEST_FORMAT")
    version = document.get("manifest_schema_version")
    if version != MANIFEST_SCHEMA_VERSION:
        raise BuildError("UNSUPPORTED_MANIFEST_SCHEMA_VERSION")
    files = document.get("files")
    if not isinstance(files, list) or not files:
        raise BuildError("MANIFEST_FILES_MISSING")

    entries = []
    seen = set()
    for item in files:
        if not isinstance(item, dict):
            raise BuildError("MANIFEST_ENTRY_NOT_AN_OBJECT")
        for field in ("path", "sha256", "size"):
            if field not in item:
                raise BuildError("MANIFEST_ENTRY_FIELD_MISSING:%s" % field)
        path = item["path"]
        if not isinstance(path, str) or not path:
            raise BuildError("MANIFEST_ENTRY_PATH_INVALID")
        # A relative POSIX path only: no rooted, no traversal, no backslash,
        # no drive letter, no empty segment.
        if (path.startswith("/") or "\\" in path or ":" in path
                or any(seg in ("", ".", "..")
                       for seg in path.split("/"))):
            raise BuildError("UNSAFE_MANIFEST_PATH:%s" % path)
        # Case-insensitive filesystems make these two distinct spellings a
        # single logical file, so a second spelling would bypass validation.
        folded = path.casefold()
        if folded in seen:
            raise BuildError("MANIFEST_PATH_COLLISION:%s" % path)
        seen.add(folded)
        if not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise BuildError("MANIFEST_SHA256_MALFORMED")
        if not isinstance(item["size"], int) or item["size"] < 0:
            raise BuildError("MANIFEST_SIZE_MALFORMED")
        entries.append((path, item["sha256"], item["size"]))

    entries.sort(key=lambda e: e[0].encode("utf-8"))
    return document, entries


def parse_manifest_v1(data):
    """Parse frozen historical MANIFEST_FORMAT_V1 identity text.

    CRLF, no header, `<sha256>  <size>  <path>` lines. Used only to verify the
    historical Phase-2 aggregates; never used as a package contract.
    """
    text = data.decode("utf-8")
    if text.startswith("#"):
        raise BuildError("V1_MUST_HAVE_NO_HEADER")
    body = text.split("\r\n")[:-1]
    entries = []
    for line in body:
        if not line.strip():
            continue
        parts = line.split("  ", 2)
        if len(parts) != 3:
            raise BuildError("MANIFEST_LINE_MALFORMED")
        entries.append((parts[2], parts[0], int(parts[1])))
    return entries


def verify_manifest(destination, manifest_bytes):
    """Fail closed on modified file, wrong size, or unmanifested payload.

    The manifest is validated before any of its file entries are trusted.
    """
    destination = Path(destination)
    document, entries = parse_manifest(manifest_bytes)
    listed = set()
    for rel, digest, size in entries:
        listed.add(rel)
        target = destination / rel
        if not target.is_file():
            raise BuildError("MANIFEST_FILE_MISSING:%s" % rel)
        data = target.read_bytes()
        if len(data) != size:
            raise BuildError("MANIFEST_SIZE_MISMATCH:%s" % rel)
        if hashlib.sha256(data).hexdigest() != digest:
            raise BuildError("MANIFEST_HASH_MISMATCH:%s" % rel)
    for rel, _full in _iter_payload_files(destination):
        if rel == MANIFEST_NAME:
            continue
        if rel not in listed:
            raise BuildError("UNMANIFESTED_PAYLOAD:%s" % rel)
    return document["manifest_format"]


def verify_identity_aggregate(destination, manifest_bytes):
    """Independently recompute the V2 aggregate and compare to the document.

    The stored aggregate is never trusted because it exists; it is recomputed
    from the verified payload bytes.
    """
    document, entries = parse_manifest(manifest_bytes)
    payload = []
    for rel, _digest, _size in entries:
        payload.append((rel, (Path(destination) / rel).read_bytes()))
    recomputed = hashlib.sha256(serialize_manifest_v2(payload)).hexdigest()
    if recomputed != document["identity"]["aggregate_sha256"]:
        raise BuildError("IDENTITY_AGGREGATE_MISMATCH")
    return recomputed


def scan_for_absolute_paths(data):
    """Refuse builder-machine identity leaking into immutable bytes."""
    needles = [b"C:\\Users\\", b"/home/", b"/root/", b"AppData",
               b"USERPROFILE", b"LOCALAPPDATA", b"\\Users\\"]
    for needle in needles:
        if needle in data:
            return needle.decode("ascii", "replace")
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Build the immutable Windows service package.")
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--runtime-artifact", type=Path, default=None,
                        help="already-downloaded canonical runtime archive")
    parser.add_argument("--existing-config", default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument("--reuse-personal-fixture", default=None,
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    # Legacy build inputs fail closed BEFORE anything is created, read or
    # logged. The supplied value is never touched.
    _reject_legacy((("--existing-config", args.existing_config),
                    ("--reuse-personal-fixture",
                     args.reuse_personal_fixture)))

    lock = load_runtime_lock()
    if args.runtime_artifact is not None:
        verify_runtime_artifact(args.runtime_artifact, lock)

    destination = args.destination
    if destination.exists():
        raise BuildError("PACKAGE_DESTINATION_EXISTS")

    try:
        write_package_files(destination, args.runtime_artifact)
        manifest = build_manifest_document(
            destination, runtime={
                "python_version": lock["python_version"],
                "source_url": lock["source_url"],
                "source_sha256": lock["source_sha256"],
                "artifact_type": lock["runtime_artifact_type"],
            })
        leak = scan_for_absolute_paths(manifest)
        if leak:
            raise BuildError("BUILDER_PATH_LEAK:%s" % leak)
        (destination / MANIFEST_NAME).write_bytes(manifest)
        verify_manifest(destination, manifest)
        aggregate = verify_identity_aggregate(destination, manifest)
    except Exception:
        # Never leave a partially built artifact that could be mistaken for
        # a complete package.
        if destination.exists():
            for child in sorted(destination.rglob("*"), reverse=True):
                child.unlink() if child.is_file() else child.rmdir()
            destination.rmdir()
        raise

    print(json.dumps({
        "package_ready": True,
        "manifest_format": MANIFEST_FORMAT,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "identity_format": MANIFEST_FORMAT_V2,
        "identity_aggregate_sha256": aggregate,
        "python_version": lock["python_version"],
        "runtime_sha256": lock["source_sha256"],
        "contains_credentials": False,
        "contains_target_paths": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())