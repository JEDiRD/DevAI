#!/usr/bin/env python3
"""RH-B STEP 5F-H: fail-closed release artifact verifier.

    verify-release.py ARTIFACT --expected-sha256 <hash>
    verify-release.py ARTIFACT --sha256-file ARTIFACT.sha256

If both anchors are supplied they MUST agree; disagreement fails closed rather
than silently preferring one. No network access is used or required.

Verification order (nothing is reported PASS until every layer succeeds):

  LAYER A  1-3   sidecar/expected hash parsed -> raw bytes hashed -> compared
  LAYER A  4-6   tar members inspected WITHOUT unsafe extraction; member types
                 and paths validated; release structure normalised and validated
  LAYER B  7-9   release.json read, schema validated, source identity validated
  LAYER B  10-13 manifest.json / installer / runtime / dependency-lock identity
  LAYER C  14-16 authoritative 5A manifest verification, V2 recomputation,
                 unexpected-member rejection
          17    secret and target-state exclusion
          18    PASS

TRUST MODEL: an externally supplied SHA256 authenticates bytes RELATIVE TO A
TRUSTED CHANNEL. It is not publisher authentication; no signing key exists in
RH-B. Publisher identity/signing is a separate future capability.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tarfile
import tempfile
from pathlib import Path

# Verification must be side-effect free, exactly like the build. The sibling
# `release_lib` import and the importlib load of deploy/windows/build-package.py
# would otherwise write __pycache__/*.pyc into the source checkout, making a
# read-only verification look like it mutated the tree.
sys.dont_write_bytecode = True

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_lib import (  # noqa: E402
    ALLOWED_TOP_LEVEL, ARTIFACT_FORMAT, RELEASE_FORMAT, RELEASE_NAME,
    RELEASE_SCHEMA_VERSION, ReleaseError, assert_no_target_state_keys, assert_required_package_members,
    assert_runtime_mirror_complete, assert_runtime_payload_complete,
    check_member_name, commit_timestamp, commit_tree, find_identity_leak,
    parse_sidecar, require_git_oid, require_hex64, sha256_bytes, tree_of,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER_PATH = REPO_ROOT / "deploy" / "windows" / "build-package.py"
RUNTIME_LOCK_PATH = "deploy/windows/runtime-lock.json"
LOCK_METADATA_PATH = "lock/metadata.json"

# Sections whose presence/identity is mandatory. An unknown NEW top-level
# section is tolerated but never allowed to redefine these.
REQUIRED_SECTIONS = ("release_format", "release_schema_version", "source",
                     "package", "runtime", "dependencies", "protected_trees",
                     "migrations", "artifact")
# Documented optional namespaces reserved for later steps. They carry identity
# only; they never change existing semantics.
OPTIONAL_SECTIONS = ("sbom", "signature", "provenance")


def load_builder():
    spec = importlib.util.spec_from_file_location("devai_build_package", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------- LAYER A: the bytes ---
def resolve_expected_hash(artifact: Path, expected: str | None,
                          sidecar_path: Path | None) -> str:
    """Exactly one trusted-anchor form, or two that must agree."""
    from release_lib import HEX64
    values = []
    if expected is not None:
        if not HEX64.match(expected):
            raise ReleaseError("EXPECTED_SHA256_MALFORMED")
        values.append(expected)
    if sidecar_path is not None:
        if not sidecar_path.is_file():
            raise ReleaseError("SIDECAR_MISSING")
        values.append(parse_sidecar(sidecar_path.read_bytes(), artifact.name))
    if not values:
        raise ReleaseError("NO_TRUSTED_ANCHOR_SUPPLIED")
    if len(set(values)) != 1:
        raise ReleaseError("TRUSTED_ANCHOR_DISAGREEMENT")
    return values[0]


def verify_outer_hash(artifact: Path, expected: str) -> None:
    if not artifact.is_file():
        raise ReleaseError("ARTIFACT_MISSING")
    with artifact.open("rb") as handle:
        actual = sha256_bytes(handle.read())
    if actual != expected:
        raise ReleaseError("ARTIFACT_SHA256_MISMATCH")


# ------------------------------------------ LAYER A: safe tar inspection ---
def read_members(artifact: Path):
    """Inspect members WITHOUT extracting. Only regular files are accepted.

    Symlinks, hardlinks, devices, FIFOs and sockets are refused outright, so no
    later stage can be tricked by a link or a special file.
    """
    members = {}
    with tarfile.open(artifact, mode="r:") as archive:
        for info in archive.getmembers():
            if info.issym() or info.islnk():
                raise ReleaseError("TAR_LINK_MEMBER:%s" % info.name)
            if info.ischr() or info.isblk() or info.isfifo() or info.isdev():
                raise ReleaseError("TAR_SPECIAL_MEMBER:%s" % info.name)
            if not info.isfile():
                raise ReleaseError("TAR_NON_REGULAR_MEMBER:%s" % info.name)
            name = check_member_name(info.name)
            if name in members:
                raise ReleaseError("TAR_DUPLICATE_MEMBER:%s" % name)
            folded = name.lower()
            for existing in members:
                if existing.lower() == folded and existing != name:
                    raise ReleaseError("TAR_CASE_COLLISION:%s" % name)
            handle = archive.extractfile(info)
            if handle is None:
                raise ReleaseError("TAR_MEMBER_UNREADABLE:%s" % name)
            members[name] = handle.read()
    return members


def check_structure(members):
    """Validate the normalised release layout. No member may escape the root."""
    for name in members:
        top = name.split("/", 1)[0]
        if top not in ALLOWED_TOP_LEVEL:
            raise ReleaseError("UNEXPECTED_TOP_LEVEL_MEMBER:%s" % name)
    if RELEASE_NAME not in members:
        raise ReleaseError("RELEASE_JSON_MISSING")
    if "package/manifest.json" not in members:
        raise ReleaseError("PACKAGE_MANIFEST_MISSING")
    for required in ("requirements.in", "lock/metadata.json"):
        if required not in members:
            raise ReleaseError("RELEASE_INPUT_MISSING:%s" % required)
    if not any(n.startswith("package/") and n.endswith("install-worker.ps1")
               for n in members):
        raise ReleaseError("INSTALLER_MEMBER_MISSING")


def check_metadata(artifact: Path, epoch: int | None) -> None:
    """Tar metadata must be normalised, so byte-for-byte builds are possible."""
    with tarfile.open(artifact, mode="r:") as archive:
        for info in archive.getmembers():
            if info.uid != 0 or info.gid != 0:
                raise ReleaseError("TAR_OWNER_NOT_NORMALISED:%s" % info.name)
            if info.uname or info.gname:
                raise ReleaseError("TAR_NAME_NOT_NORMALISED:%s" % info.name)
            if epoch is not None and info.mtime != epoch:
                raise ReleaseError("TAR_MTIME_NOT_SOURCE_DATE_EPOCH:%s" % info.name)
            if info.isdir() and info.mode != 0o755:
                raise ReleaseError("TAR_DIRECTORY_MODE:%s" % info.name)
            if info.isfile() and info.mode != 0o644:
                raise ReleaseError("TAR_FILE_MODE:%s" % info.name)


# ------------------------------------------------- LAYER B: release.json ---
def load_release_json(data: bytes) -> dict:
    if data[:3] == b"\xef\xbb\xbf":
        raise ReleaseError("RELEASE_JSON_HAS_BOM")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ReleaseError("RELEASE_JSON_NOT_UTF8")
    if "\r" in text:
        raise ReleaseError("RELEASE_JSON_NOT_LF")
    if not text.endswith("\n"):
        raise ReleaseError("RELEASE_JSON_MISSING_TRAILING_LF")
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        raise ReleaseError("RELEASE_JSON_NOT_VALID_JSON")
    if not isinstance(document, dict):
        raise ReleaseError("RELEASE_JSON_NOT_OBJECT")
    return document


def validate_schema(document: dict) -> None:
    if document.get("release_format") != RELEASE_FORMAT:
        raise ReleaseError("UNSUPPORTED_RELEASE_FORMAT")
    if document.get("release_schema_version") != RELEASE_SCHEMA_VERSION:
        raise ReleaseError("UNSUPPORTED_RELEASE_SCHEMA_VERSION")
    for section in REQUIRED_SECTIONS:
        if section not in document:
            raise ReleaseError("RELEASE_SECTION_MISSING:%s" % section)
    for key in document:
        if key not in REQUIRED_SECTIONS and key not in OPTIONAL_SECTIONS:
            raise ReleaseError("UNKNOWN_RELEASE_SECTION:%s" % key)
    for section in ("source", "package", "runtime", "dependencies",
                    "protected_trees", "migrations", "artifact"):
        if not isinstance(document[section], dict):
            raise ReleaseError("RELEASE_SECTION_NOT_OBJECT:%s" % section)

    source = document["source"]
    require_git_oid(source.get("commit"), "SOURCE_COMMIT_MALFORMED")
    require_git_oid(source.get("tree"), "SOURCE_TREE_MALFORMED")
    epoch = source.get("source_date_epoch")
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch <= 0:
        raise ReleaseError("SOURCE_DATE_EPOCH_INVALID")

    package = document["package"]
    require_hex64(package.get("manifest_sha256"), "MANIFEST_SHA256_MALFORMED")
    require_hex64(package.get("manifest_v2_aggregate"), "V2_AGGREGATE_MALFORMED")
    require_hex64(package.get("installer_sha256"), "INSTALLER_SHA256_MALFORMED")

    runtime = document["runtime"]
    require_hex64(runtime.get("runtime_sha256"), "RUNTIME_SHA256_MALFORMED")
    if not isinstance(runtime.get("runtime_size"), int) or runtime["runtime_size"] <= 0:
        raise ReleaseError("RUNTIME_SIZE_INVALID")
    if not isinstance(runtime.get("python_version"), str) or not runtime["python_version"]:
        raise ReleaseError("RUNTIME_VERSION_INVALID")
    if not isinstance(runtime.get("runtime_url"), str) or not runtime["runtime_url"].startswith("https://"):
        raise ReleaseError("RUNTIME_URL_INVALID")

    dependencies = document["dependencies"]
    for key in ("requirements_in_sha256", "linux_lock_sha256", "windows_lock_sha256"):
        require_hex64(dependencies.get(key), "DEPENDENCY_SHA256_MALFORMED:%s" % key)

    for key, value in document["protected_trees"].items():
        require_git_oid(value, "PROTECTED_TREE_MALFORMED:%s" % key)
    if set(document["protected_trees"]) != {"controller", "worker_agent", "migrations"}:
        raise ReleaseError("PROTECTED_TREE_SET_MISMATCH")

    migrations = document["migrations"]
    if not isinstance(migrations.get("count"), int) or migrations["count"] < 0:
        raise ReleaseError("MIGRATION_COUNT_INVALID")
    if migrations.get("migration_016_present") is not False:
        raise ReleaseError("MIGRATION_016_PRESENT")

    artifact = document["artifact"]
    if artifact.get("format") != ARTIFACT_FORMAT:
        raise ReleaseError("UNSUPPORTED_ARTIFACT_FORMAT")
    if artifact.get("tar_compression") != "none":
        raise ReleaseError("ARTIFACT_COMPRESSION_NOT_DETERMINISTIC")
    for key in ("tar_uid", "tar_gid", "tar_mtime_source", "tar_member_order"):
        if key not in artifact:
            raise ReleaseError("ARTIFACT_FIELD_MISSING:%s" % key)
    # The self-reference paradox is forbidden by construction. This is a
    # KEY-name check at any depth, not a substring scan: a descriptive field
    # that merely mentions where the digest lives must not trip it.
    forbidden_hash_keys = ("artifact_sha256", "outer_sha256", "tar_sha256",
                           "self_sha256", "release_tar_sha256")
    stack = [document]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if key in forbidden_hash_keys:
                    raise ReleaseError("RELEASE_JSON_CONTAINS_OUTER_HASH")
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)


def verify_source_identity(document: dict, repo: Path | None,
                           expect_commit: str | None) -> None:
    source = document["source"]
    if expect_commit is not None and source["commit"] != expect_commit:
        raise ReleaseError("SOURCE_COMMIT_MISMATCH")
    if repo is None:
        return
    commit = source["commit"]
    if commit_tree(repo, commit) != source["tree"]:
        raise ReleaseError("SOURCE_TREE_MISMATCH")
    if commit_timestamp(repo, commit) != source["source_date_epoch"]:
        raise ReleaseError("SOURCE_DATE_EPOCH_MISMATCH")
    expected_trees = {"controller": "controller/devai",
                      "worker_agent": "worker_agent",
                      "migrations": "migrations"}
    for key, path in expected_trees.items():
        if tree_of(repo, commit, path) != document["protected_trees"][key]:
            raise ReleaseError("PROTECTED_TREE_MISMATCH:%s" % key)
    if _migration_count(repo, commit) != document["migrations"]["count"]:
        raise ReleaseError("MIGRATION_COUNT_MISMATCH")


def _migration_count(repo: Path, commit: str) -> int:
    import subprocess
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", commit, "migrations"],
        capture_output=True, check=False)
    names = [n.strip() for n in result.stdout.decode("utf-8").splitlines() if n.strip()]
    if any("016" in n for n in names):
        raise ReleaseError("MIGRATION_016_PRESENT")
    return len(names)


def verify_committed_inputs(document: dict, members: dict, repo: Path | None) -> None:
    """release.json must agree with the committed inputs it claims."""
    dependencies = document["dependencies"]
    if sha256_bytes(members["requirements.in"]) != dependencies["requirements_in_sha256"]:
        raise ReleaseError("REQUIREMENTS_IN_SHA256_MISMATCH")
    for name, key in (("lock/linux-cp313.txt", "linux_lock_sha256"),
                      ("lock/windows-cp313.txt", "windows_lock_sha256")):
        if name in members:
            if sha256_bytes(members[name]) != dependencies[key]:
                raise ReleaseError("DEPENDENCY_LOCK_MISMATCH:%s" % name)
    if repo is None:
        return
    commit = document["source"]["commit"]
    lock_metadata = json.loads(members["lock/metadata.json"].decode("utf-8"))
    if lock_metadata["windows"]["lock_sha256"] != dependencies["windows_lock_sha256"]:
        raise ReleaseError("WINDOWS_LOCK_IDENTITY_MISMATCH")
    if lock_metadata["linux"]["lock_sha256"] != dependencies["linux_lock_sha256"]:
        raise ReleaseError("LINUX_LOCK_IDENTITY_MISMATCH")
    runtime_lock = json.loads(
        (repo / RUNTIME_LOCK_PATH).read_text(encoding="utf-8"))
    if runtime_lock["source_sha256"] != document["runtime"]["runtime_sha256"]:
        raise ReleaseError("RUNTIME_SHA256_MISMATCH")
    if runtime_lock["python_version"] != document["runtime"]["python_version"]:
        raise ReleaseError("RUNTIME_VERSION_MISMATCH")
    if int(runtime_lock["source_size_bytes"]) != document["runtime"]["runtime_size"]:
        raise ReleaseError("RUNTIME_SIZE_MISMATCH")
    from release_lib import blob as git_blob
    if sha256_bytes(git_blob(repo, commit, "requirements.in")) != dependencies["requirements_in_sha256"]:
        raise ReleaseError("REQUIREMENTS_IN_COMMIT_MISMATCH")


# ------------------------------------------- LAYER C: package verification ---
def verify_package(document: dict, members: dict) -> str:
    manifest_bytes = members["package/manifest.json"]
    if sha256_bytes(manifest_bytes) != document["package"]["manifest_sha256"]:
        raise ReleaseError("MANIFEST_SHA256_MISMATCH")

    builder = load_builder()
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    assert_no_target_state_keys(manifest, "MANIFEST_NOT_OBJECT")

    installer = next(n for n in members if n == "package/install-worker.ps1")
    if sha256_bytes(members[installer]) != document["package"]["installer_sha256"]:
        raise ReleaseError("INSTALLER_SHA256_MISMATCH")

    package_members = {n[len("package/"):]: v for n, v in members.items()
                       if n.startswith("package/")}
    if "install-worker.ps1" not in package_members:
        raise ReleaseError("INSTALLER_NOT_IN_PACKAGE")
    # An incomplete package must NEVER verify, even when internally consistent.
    # A packaging bug that silently drops a committed subtree would otherwise
    # produce a self-consistent artifact that still passes every digest check.
    assert_required_package_members(package_members)
    # Runtime install payload must be complete when present at all: a dropped
    # sandbox-runtime beside a present host-runtime verified clean and then
    # failed install with PathNotFound.
    assert_runtime_payload_complete(package_members)
    # And the sandbox runtime must mirror the host runtime byte for byte: a
    # partial sandbox (proven: lone python.exe dies with STATUS_DLL_NOT_FOUND)
    # cannot execute the payload, even with the anchor files present.
    assert_runtime_mirror_complete(package_members)

    # Materialise ONLY already-validated regular files into a scratch directory
    # so the single authoritative 5A verifier can run. No archive extraction of
    # unvalidated content ever happens: names and types were checked first.
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        for relative, data in package_members.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        builder.verify_manifest(root, manifest_bytes)
        aggregate = builder.verify_identity_aggregate(root, manifest_bytes)

    if aggregate != document["package"]["manifest_v2_aggregate"]:
        raise ReleaseError("V2_AGGREGATE_MISMATCH")
    return aggregate


def check_exclusions(members: dict) -> None:
    """Secret / target-state exclusion, structurally where possible."""
    from release_lib import is_target_state_member
    for name in members:
        if is_target_state_member(name):
            raise ReleaseError("TARGET_STATE_MEMBER:%s" % name)
    for name in ("release.json", "requirements.in", "lock/metadata.json"):
        if name in members and find_identity_leak(members[name]) is not None:
            raise ReleaseError("IDENTITY_LEAK_IN_RELEASE:%s" % name)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed RH-B release verifier")
    parser.add_argument("artifact")
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--sha256-file", default=None)
    parser.add_argument("--repo", default=None,
                        help="Git repo to cross-check source identity against")
    parser.add_argument("--expect-commit", default=None)
    args = parser.parse_args(argv)

    artifact = Path(args.artifact)
    repo = Path(args.repo).resolve() if args.repo else None
    sidecar_path = Path(args.sha256_file) if args.sha256_file else None

    try:
        expected = resolve_expected_hash(artifact, args.expected_sha256, sidecar_path)
        verify_outer_hash(artifact, expected)

        members = read_members(artifact)
        check_structure(members)

        document = load_release_json(members[RELEASE_NAME])
        validate_schema(document)
        check_metadata(artifact, document["source"]["source_date_epoch"])

        verify_source_identity(document, repo, args.expect_commit)
        verify_committed_inputs(document, members, repo)
        aggregate = verify_package(document, members)
        check_exclusions(members)
    except ReleaseError as error:
        sys.stderr.write("RELEASE_VERIFICATION_FAILED:%s\n" % error)
        return 1

    sys.stdout.write("RELEASE_VERIFIED\n")
    sys.stdout.write("  artifact_sha256      : %s\n" % expected)
    sys.stdout.write("  source_commit        : %s\n" % document["source"]["commit"])
    sys.stdout.write("  source_tree          : %s\n" % document["source"]["tree"])
    sys.stdout.write("  source_date_epoch    : %d\n" % document["source"]["source_date_epoch"])
    sys.stdout.write("  manifest_sha256      : %s\n" % document["package"]["manifest_sha256"])
    sys.stdout.write("  manifest_v2_aggregate: %s\n" % aggregate)
    sys.stdout.write("  trust_model          : trusted-external-sha256 (no publisher signing)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())