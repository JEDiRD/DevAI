#!/usr/bin/env python3
"""RH-B STEP 5F-H: deterministic release artifact builder.

Produces, from a committed source state only:

    devai-<commit>-windows-x64.tar
    devai-<commit>-windows-x64.tar.sha256      (external sidecar)

The outer artifact SHA256 is deliberately NOT written inside release.json:
that would be a recursive self-reference. It lives in the sidecar, which is
external to the tar. This is ARTIFACT_INTEGRITY relative to a trusted channel,
not publisher authentication. No signing key exists in RH-B.

Determinism: SOURCE_DATE_EPOCH is the exact Git commit timestamp. All tar
members get uid=0, gid=0, uname="", gname="", mtime=SOURCE_DATE_EPOCH, mode
0755 for directories and 0644 for regular files. Nothing is derived from
umask, wall clock, username, HOME, USERPROFILE, LOCALAPPDATA, CWD or hostname.
"""
from __future__ import annotations

import argparse
import importlib.util
import io
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_lib import (  # noqa: E402
    PLATFORM, RELEASE_FORMAT, RELEASE_SCHEMA_VERSION, RELEASE_NAME,
    ReleaseError, assert_required_package_members, blob, check_member_name,
    commit_timestamp, commit_tree, find_identity_leak, pretty_json_bytes,
    require_hex64, resolve_commit, sha256_bytes, sidecar_bytes,
    tree_of, worktree_is_clean,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER_PATH = REPO_ROOT / "deploy" / "windows" / "build-package.py"
RUNTIME_LOCK_PATH = "deploy/windows/runtime-lock.json"
LOCK_METADATA_PATH = "lock/metadata.json"


def load_builder():
    """Reuse the STEP 5A authoritative package builder/verifier.

    There is exactly ONE Python implementation of the manifest contract. This
    tool does not grow a second, weaker copy of it.
    """
    spec = importlib.util.spec_from_file_location("devai_build_package", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage_payload(builder, repo: Path, commit: str, staging: Path,
                  runtime_artifact: Path | None) -> None:
    """Materialise immutable payload strictly from COMMITTED git blobs."""
    staging.mkdir(parents=True, exist_ok=True)
    for out_rel, src_rel in builder.PAYLOAD:
        if not _tree_has(repo, commit, src_rel):
            raise ReleaseError("PAYLOAD_MISSING:%s" % src_rel)
        if _is_tree(repo, commit, src_rel):
            for rel in _tree_files(repo, commit, src_rel):
                data = blob(repo, commit, "%s/%s" % (src_rel, rel))
                target = staging / out_rel / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        else:
            target = staging / out_rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob(repo, commit, src_rel))

    if runtime_artifact is not None:
        lock = load_runtime_lock(repo, commit)
        builder.verify_runtime_artifact(runtime_artifact, lock)
        builder._install_runtime(staging, runtime_artifact)


def _tree_has(repo: Path, commit: str, path: str) -> bool:
    from release_lib import blob_exists
    return blob_exists(repo, commit, path)


def _object_kind(repo: Path, commit: str, path: str) -> str:
    import subprocess
    result = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-t", "%s:%s" % (commit, path)],
        capture_output=True, check=False)
    if result.returncode != 0:
        return "missing"
    return result.stdout.decode("utf-8").strip()


def _is_tree(repo: Path, commit: str, path: str) -> bool:
    return _object_kind(repo, commit, path) == "tree"


def _tree_files(repo: Path, commit: str, path: str):
    """Enumerate files of a committed subtree.

    `git ls-tree <commit>:<path>` already yields paths RELATIVE to <path>, so no
    prefix filtering is applied here. An earlier revision filtered on a
    "<path>/" prefix that never appears, which silently produced an EMPTY file
    list and shipped a package with no worker code at all.
    """
    import subprocess
    result = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only",
         "%s:%s" % (commit, path)],
        capture_output=True, check=False)
    if result.returncode != 0:
        raise ReleaseError("PAYLOAD_TREE_UNREADABLE:%s" % path)
    names = [line.strip() for line in
             result.stdout.decode("utf-8").splitlines() if line.strip()]
    if not names:
        raise ReleaseError("PAYLOAD_TREE_EMPTY:%s" % path)
    return sorted(names, key=lambda n: n.encode("utf-8"))


def load_runtime_lock(repo: Path, commit: str):
    import json
    return json.loads(blob(repo, commit, RUNTIME_LOCK_PATH).decode("utf-8"))


def build_release_document(*, commit: str, tree: str, epoch: int,
                           manifest_bytes: bytes, manifest: dict,
                           runtime_lock: dict, lock_metadata: dict,
                           requirements_sha: str,
                           platform: str = PLATFORM) -> dict:
    """Structured, machine-readable release identity.

    Unknown extra keys are permitted only as a documented optional namespace
    (sbom / signature / provenance). A new top-level section must not silently
    change existing semantics.
    """
    document = {
        "release_format": RELEASE_FORMAT,
        "release_schema_version": RELEASE_SCHEMA_VERSION,
        "source": {
            "commit": commit,
            "tree": tree,
            "source_date_epoch": epoch,
        },
        "package": {
            "manifest_sha256": sha256_bytes(manifest_bytes),
            "manifest_v2_aggregate": manifest["identity"]["aggregate_sha256"],
            "installer_sha256": _manifest_digest(manifest, "install-worker.ps1"),
        },
        "runtime": {
            "python_version": runtime_lock["python_version"],
            "runtime_url": runtime_lock["source_url"],
            "runtime_size": int(runtime_lock["source_size_bytes"]),
            "runtime_sha256": require_hex64(runtime_lock["source_sha256"],
                                            "RUNTIME_SHA256_MALFORMED"),
        },
        "dependencies": {
            "requirements_in_sha256": requirements_sha,
            "linux_lock_sha256": require_hex64(
                lock_metadata["linux"]["lock_sha256"], "LINUX_LOCK_SHA256_MALFORMED"),
            "windows_lock_sha256": require_hex64(
                lock_metadata["windows"]["lock_sha256"], "WINDOWS_LOCK_SHA256_MALFORMED"),
        },
        "protected_trees": {
            "controller": _tree(repo=None, commit=commit, path="controller/devai"),
            "worker_agent": _tree(repo=None, commit=commit, path="worker_agent"),
            "migrations": _tree(repo=None, commit=commit, path="migrations"),
        },
        "migrations": {
            "count": _migration_count(),
            "migration_016_present": False,
        },
        "artifact": {
            "format": "tar",
            "platform": platform,
            "tar_member_order": "utf8-byte-ascending",
            "tar_uid": 0,
            "tar_gid": 0,
            "tar_uname": "",
            "tar_gname": "",
            "tar_mtime_source": "git-commit-timestamp",
            "tar_modes": {"directory": "0755", "file": "0644"},
            "tar_compression": "none",
            "sidecar_format": "<sha256><2 spaces><filename> LF",
            "outer_artifact_sha256_location": "external sidecar (never inside release.json)",
        },
    }
    return document


def _tree(*, repo, commit: str, path: str) -> str:
    return tree_of(REPO_ROOT, commit, path)


def _migration_count() -> int:
    import subprocess
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-r", "--name-only", "HEAD", "migrations"],
        capture_output=True, check=False)
    names = [n.strip() for n in result.stdout.decode("utf-8").splitlines() if n.strip()]
    if any("016" in n for n in names):
        raise ReleaseError("MIGRATION_016_PRESENT")
    return len(names)


def _manifest_digest(manifest: dict, relative: str) -> str:
    for entry in manifest["files"]:
        if entry["path"] == relative:
            return require_hex64(entry["sha256"], "INSTALLER_SHA256_MALFORMED")
    raise ReleaseError("INSTALLER_NOT_MANIFESTED")


def build_tar(members, epoch: int) -> bytes:
    """Deterministic UNCOMPRESSED tar.

    Members are emitted in UTF-8 byte order. Metadata is fully normalised:
    uid/gid 0, empty uname/gname, mtime = SOURCE_DATE_EPOCH, 0755 directories,
    0644 regular files. No PAX/nondeterministic metadata is produced because
    GNU_FORMAT is used explicitly.
    """
    buffer = io.BytesIO()
    # GNU_FORMAT is required for deterministic long-path handling without
    # emitting PAX extended headers.
    with tarfile.open(fileobj=buffer, mode="w",
                      format=tarfile.GNU_FORMAT) as archive:
        for name, data in sorted(members, key=lambda item: item[0].encode("utf-8")):
            check_member_name(name)
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic RH-B release build")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--commit", default="HEAD")
    parser.add_argument("--runtime-artifact", default=None,
                        help="Verified python-3.13.16-embed-amd64.zip")
    parser.add_argument("--allow-dirty-worktree", action="store_true",
                        help="Tooling self-test only. Never use for release evidence.")
    args = parser.parse_args(argv)

    try:
        commit = resolve_commit(REPO_ROOT, args.commit)
        if not args.allow_dirty_worktree and not worktree_is_clean(REPO_ROOT):
            raise ReleaseError("WORKTREE_NOT_CLEAN")

        builder = load_builder()
        epoch = commit_timestamp(REPO_ROOT, commit)
        runtime_artifact = Path(args.runtime_artifact) if args.runtime_artifact else None
        if runtime_artifact is not None and not runtime_artifact.is_file():
            raise ReleaseError("RUNTIME_ARTIFACT_MISSING")

        with tempfile.TemporaryDirectory() as scratch:
            staging = Path(scratch) / "package"
            stage_payload(builder, REPO_ROOT, commit, staging, runtime_artifact)

            runtime_lock = load_runtime_lock(REPO_ROOT, commit)
            import json
            lock_metadata = json.loads(
                blob(REPO_ROOT, commit, LOCK_METADATA_PATH).decode("utf-8"))
            manifest_bytes = builder.build_manifest_document(
                staging,
                runtime={"python_version": runtime_lock["python_version"],
                         "source_sha256": runtime_lock["source_sha256"]},
                locks={"windows": {"sha256": lock_metadata["windows"]["lock_sha256"],
                                   "package_count":
                                       lock_metadata["windows"]["resolved_package_count"]},
                       "linux": {"sha256": lock_metadata["linux"]["lock_sha256"],
                                 "package_count":
                                     lock_metadata["linux"]["resolved_package_count"]}},
            )
            manifest_path = staging / builder.MANIFEST_NAME
            manifest_path.write_bytes(manifest_bytes)

            # Self-check with the AUTHORITATIVE 5A verifier before packaging.
            # Fail closed if an entire committed subtree failed to stage.
            assert_required_package_members(
                [rel for rel, _full in builder._iter_payload_files(staging)] +
                [builder.MANIFEST_NAME])
            builder.verify_manifest(staging, manifest_bytes)
            builder.verify_identity_aggregate(staging, manifest_bytes)
            manifest = json.loads(manifest_bytes.decode("utf-8"))

            requirements_sha = sha256_bytes(blob(REPO_ROOT, commit, "requirements.in"))
            document = build_release_document(
                commit=commit,
                tree=commit_tree(REPO_ROOT, commit),
                epoch=epoch,
                manifest_bytes=manifest_bytes,
                manifest=manifest,
                runtime_lock=runtime_lock,
                lock_metadata=lock_metadata,
                requirements_sha=requirements_sha,
            )
            release_bytes = pretty_json_bytes(document)
            leak = find_identity_leak(release_bytes)
            if leak is not None:
                raise ReleaseError("IDENTITY_LEAK_IN_RELEASE_JSON")

            members = [(RELEASE_NAME, release_bytes),
                       ("requirements.in", blob(REPO_ROOT, commit, "requirements.in")),
                       ("lock/metadata.json",
                        blob(REPO_ROOT, commit, LOCK_METADATA_PATH)),
                       ("lock/%s-cp313.txt" % PLATFORM.split("-")[0],
                        blob(REPO_ROOT, commit, "lock/%s-cp313.txt" % PLATFORM.split("-")[0]))]
            for relative, full in builder._iter_payload_files(staging):
                members.append(("package/" + relative, full.read_bytes()))

            artifact = build_tar(members, epoch)
    except ReleaseError as error:
        sys.stderr.write("BUILD_FAILED:%s\n" % error)
        return 1

    filename = "devai-%s-%s.tar" % (commit, PLATFORM)
    digest = sha256_bytes(artifact)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    (output / filename).write_bytes(artifact)
    (output / (filename + ".sha256")).write_bytes(sidecar_bytes(digest, filename))
    sys.stdout.write("%s  %s\n" % (digest, filename))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())