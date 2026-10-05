"""RH-B STEP 5F-H: deterministic release artifact + fail-closed verifier.

Tests build a REAL artifact, then mutate it and require the verifier to fail
closed with a specific control code. Assertions are structural (parsed JSON,
parsed tar members, recomputed digests), never prose substrings of source.

NOTE ON TRUST: an externally supplied SHA256 authenticates bytes relative to a
trusted channel. It is NOT publisher authentication; no signing key exists in
RH-B. These tests must never be read as proving publisher identity.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
BUILD = TOOLS / "build-release.py"
VERIFY = TOOLS / "verify-release.py"

# This module imports release_lib from the release tooling path, so it must
# disable bytecode BEFORE that import. tools/build-release.py and
# tools/verify-release.py set the same guard for their own imports; without it
# here, running the suite wrote tools/__pycache__/release_lib.cpython-*.pyc
# into the source checkout, which the source-pollution gate correctly rejects.
sys.dont_write_bytecode = True

sys.path.insert(0, str(TOOLS))
import release_lib as rl  # noqa: E402

ARTIFACT_MEMBERS_CACHE: dict[str, bytes] = {}
_BUILD_DIR: Path | None = None
_ARTIFACT: Path | None = None
_SIDECAR: Path | None = None
_DIGEST = ""


def setUpModule():
    global _BUILD_DIR, _ARTIFACT, _SIDECAR, _DIGEST
    _BUILD_DIR = Path(tempfile.mkdtemp(prefix="rhb-release-"))
    result = subprocess.run(
        [sys.executable, str(BUILD), "--output-dir", str(_BUILD_DIR),
         "--allow-dirty-worktree"],
        capture_output=True, text=True, cwd=str(REPO), timeout=600)
    if result.returncode != 0:
        raise AssertionError("BUILD_FAILED:%s" % result.stderr)
    _DIGEST = result.stdout.split()[0]
    tarballs = list(_BUILD_DIR.glob("*.tar"))
    assert len(tarballs) == 1, tarballs
    _ARTIFACT = tarballs[0]
    _SIDECAR = _ARTIFACT.with_suffix(_ARTIFACT.suffix + ".sha256")


def tearDownModule():
    if _BUILD_DIR is not None:
        shutil.rmtree(_BUILD_DIR, ignore_errors=True)


# ------------------------------------------------------------------ helpers ---
def read_members(path: Path) -> dict[str, bytes]:
    out = {}
    with tarfile.open(path, "r:") as archive:
        for info in archive.getmembers():
            handle = archive.extractfile(info)
            out[info.name] = handle.read() if handle else b""
    return out


def member_metadata(path: Path) -> list[tuple]:
    rows = []
    with tarfile.open(path, "r:") as archive:
        for info in archive.getmembers():
            rows.append((info.name, info.uid, info.gid, info.uname, info.gname,
                         info.mtime, oct(info.mode), info.type))
    return rows


def write_tar(path: Path, members, epoch: int, *, specials=()) -> None:
    """Rewrite a tar from (name, bytes) pairs plus optional special entries."""
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        for name, data in sorted(members, key=lambda i: i[0].encode("utf-8")):
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for maker in specials:
            info, payload = maker()
            archive.addfile(info, io.BytesIO(payload) if payload else None)


def verify(artifact: Path, *, expected=None, sidecar=None, repo=None,
           commit=None):
    argv = [sys.executable, str(VERIFY), str(artifact)]
    if expected:
        argv += ["--expected-sha256", expected]
    if sidecar:
        argv += ["--sha256-file", str(sidecar)]
    if repo:
        argv += ["--repo", str(repo)]
    if commit:
        argv += ["--expect-commit", commit]
    return subprocess.run(argv, capture_output=True, text=True,
                          cwd=str(REPO), timeout=600)


def expect_failure(case: unittest.TestCase, artifact: Path, code: str,
                   *, expected=None, repo=None):
    """The verifier must fail closed AND name the expected control code."""
    digest = expected or hashlib.sha256(artifact.read_bytes()).hexdigest()
    result = verify(artifact, expected=digest, repo=repo)
    combined = result.stdout + result.stderr
    case.assertNotEqual(0, result.returncode,
                        "verifier ACCEPTED a mutated artifact")
    case.assertNotIn("RELEASE_VERIFIED", combined)
    case.assertIn(code, combined)
    return combined


def mutate_release_json(work: Path, mutate) -> dict:
    """Rebuild the artifact with a mutated release.json. Returns old document."""
    members = read_members(_ARTIFACT)
    old = json.loads(members["release.json"].decode("utf-8"))
    # Mutate IN PLACE. A mutator implemented as dict.update() returns None, so
    # the return value must never be treated as the document.
    document = json.loads(json.dumps(old))
    mutate(document)
    members["release.json"] = json.dumps(
        document, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    epoch = old["source"]["source_date_epoch"]
    out = work / "mutated.tar"
    write_tar(out, list(members.items()), epoch)
    return old


def mutate_member_bytes(work: Path, name: str, transform) -> Path:
    members = read_members(_ARTIFACT)
    members[name] = transform(members[name])
    epoch = json.loads(members["release.json"].decode("utf-8"))[
        "source"]["source_date_epoch"]
    out = work / "mutated.tar"
    write_tar(out, list(members.items()), epoch)
    return out


# ============================================================ determinism ====
class DeterminismTests(unittest.TestCase):
    """Section 18: validates the deterministic ALGORITHM (not STEP 6 evidence)."""

    def test_two_builds_are_byte_identical(self):
        second = Path(tempfile.mkdtemp(prefix="rhb-release2-"))
        try:
            result = subprocess.run(
                [sys.executable, str(BUILD), "--output-dir", str(second),
                 "--allow-dirty-worktree"],
                capture_output=True, text=True, cwd=str(REPO), timeout=600)
            self.assertEqual(0, result.returncode, result.stderr)
            other = list(second.glob("*.tar"))[0]
            self.assertEqual(_ARTIFACT.read_bytes(), other.read_bytes())
            self.assertEqual(_SIDECAR.read_bytes(), other.with_suffix(
                other.suffix + ".sha256").read_bytes())
        finally:
            shutil.rmtree(second, ignore_errors=True)

    def test_release_json_bytes_identical(self):
        a = read_members(_ARTIFACT)["release.json"]
        b = read_members(_ARTIFACT)["release.json"]
        self.assertEqual(a, b)
        self.assertTrue(a.endswith(b"\n"))
        self.assertFalse(a.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", a)
        # sorted keys, deterministic re-serialisation
        document = json.loads(a.decode("utf-8"))
        self.assertEqual(rl.pretty_json_bytes(document), a)

    def test_member_order_is_utf8_byte_ascending(self):
        names = [name for name, _ in read_members(_ARTIFACT).items()]
        ordered = sorted(names, key=lambda n: n.encode("utf-8"))
        with tarfile.open(_ARTIFACT, "r:") as archive:
            emitted = [i.name for i in archive.getmembers()]
        self.assertEqual(ordered, emitted)

    def test_tar_metadata_is_normalised(self):
        for name, uid, gid, uname, gname, mtime, mode, kind in member_metadata(_ARTIFACT):
            with self.subTest(member=name):
                self.assertEqual(0, uid)
                self.assertEqual(0, gid)
                self.assertEqual("", uname)
                self.assertEqual("", gname)
                self.assertEqual("0o644", mode)
                self.assertEqual(tarfile.REGTYPE, kind)
        epoch = json.loads(read_members(_ARTIFACT)["release.json"].decode())[
            "source"]["source_date_epoch"]
        for row in member_metadata(_ARTIFACT):
            self.assertEqual(epoch, row[5])

    def test_source_date_epoch_is_git_commit_timestamp(self):
        document = json.loads(read_members(_ARTIFACT)["release.json"].decode())
        epoch = document["source"]["source_date_epoch"]
        out = subprocess.run(["git", "-C", str(REPO), "show", "-s",
                              "--format=%ct", document["source"]["commit"]],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(int(out.stdout.strip()), epoch)

    def test_sidecar_is_canonical_and_deterministic(self):
        raw = _SIDECAR.read_bytes()
        self.assertEqual(b"\r" not in raw, True)
        self.assertTrue(raw.endswith(b"\n"))
        digest, sep, name = raw.decode("utf-8")[:-1].partition("  ")
        self.assertEqual("  ", sep)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(_ARTIFACT.name, name)
        self.assertEqual(raw, rl.sidecar_bytes(digest, name))

    def test_uncompressed_tar(self):
        with open(_ARTIFACT, "rb") as handle:
            handle.seek(257)
            magic = handle.read(5)
        # ustar (GNU/USTAR) not gzip (1f 8b) and not a zip local header (PK).
        self.assertEqual(b"ustar", magic)


# ========================================================== happy path ========
class VerifyHappyPathTests(unittest.TestCase):
    def test_sidecar_anchor_verifies(self):
        result = verify(_ARTIFACT, sidecar=_SIDECAR)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("RELEASE_VERIFIED", result.stdout)

    def test_expected_hash_anchor_verifies(self):
        result = verify(_ARTIFACT, expected=_DIGEST)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_agreeing_anchors_verify(self):
        result = verify(_ARTIFACT, expected=_DIGEST, sidecar=_SIDECAR)
        self.assertEqual(0, result.returncode, result.stderr)

    def test_repo_cross_check_verifies(self):
        result = verify(_ARTIFACT, sidecar=_SIDECAR, repo=REPO,
                        commit=json.loads(
                            read_members(_ARTIFACT)["release.json"].decode()
                        )["source"]["commit"])
        self.assertEqual(0, result.returncode, result.stderr)

    def test_no_anchor_supplied_fails_closed(self):
        result = verify(_ARTIFACT)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("NO_TRUSTED_ANCHOR_SUPPLIED", result.stdout + result.stderr)


# ======================================================= mutation: LAYER A ===
class OuterArtifactMutationTests(unittest.TestCase):
    """Section 17A."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-mutA-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_wrong_expected_artifact_hash(self):
        expect_failure(self, _ARTIFACT, "ARTIFACT_SHA256_MISMATCH",
                       expected="0" * 64)

    def test_malformed_sidecar_missing_trailing_lf(self):
        side = self.work / "bad.sha256"
        side.write_bytes(b"%s  %s" % (b"a" * 64, _ARTIFACT.name.encode()))
        result = verify(_ARTIFACT, sidecar=side)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SIDECAR_MISSING_TRAILING_LF", result.stdout + result.stderr)

    def test_malformed_sidecar_bad_digest(self):
        side = self.work / "bad.sha256"
        side.write_bytes(b"NOTAHASH  %s\n" % _ARTIFACT.name.encode())
        result = verify(_ARTIFACT, sidecar=side)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SIDECAR_DIGEST_MALFORMED", result.stdout + result.stderr)

    def test_sidecar_filename_mismatch(self):
        side = self.work / "bad.sha256"
        side.write_bytes(b"%s  other-name.tar\n" % (_DIGEST.encode(),))
        result = verify(_ARTIFACT, sidecar=side)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SIDECAR_FILENAME_MISMATCH", result.stdout + result.stderr)

    def test_sidecar_hash_disagreement_fails_closed(self):
        side = self.work / "disagree.sha256"
        side.write_bytes(b"%s  %s\n" % (b"b" * 64, _ARTIFACT.name.encode()))
        result = verify(_ARTIFACT, expected=_DIGEST, sidecar=side)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("TRUSTED_ANCHOR_DISAGREEMENT", result.stdout + result.stderr)
        # It must NOT silently prefer one anchor.
        self.assertNotIn("RELEASE_VERIFIED", result.stdout)

    def test_sidecar_crlf_rejected(self):
        side = self.work / "crlf.sha256"
        side.write_bytes(b"%s  %s\r\n" % (_DIGEST.encode(), _ARTIFACT.name.encode()))
        result = verify(_ARTIFACT, sidecar=side)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SIDECAR_NOT_LF", result.stdout + result.stderr)

    def test_missing_artifact(self):
        result = verify(self.work / "nope.tar", expected=_DIGEST)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("ARTIFACT_MISSING", result.stdout + result.stderr)


# ======================================================= mutation: LAYER A tar ==
class TarMutationTests(unittest.TestCase):
    """Section 17B."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-mutB-"))
        self.members = read_members(_ARTIFACT)
        self.epoch = json.loads(
            self.members["release.json"].decode())["source"]["source_date_epoch"]

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _with_special(self, maker):
        out = self.work / "special.tar"
        write_tar(out, list(self.members.items()), self.epoch, specials=[maker])
        return out

    def _with_member(self, name, data):
        members = dict(self.members)
        members[name] = data
        out = self.work / "extra.tar"
        write_tar(out, list(members.items()), self.epoch)
        return out

    def test_absolute_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("/etc/evil.txt")
            info.size = 0
            info.mtime = self.epoch
            return info, b""
        expect_failure(self, self._with_special(maker), "MEMBER_ABSOLUTE_PATH")

    def test_traversal_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("../escape.txt")
            info.size = 0
            info.mtime = self.epoch
            return info, b""
        expect_failure(self, self._with_special(maker), "MEMBER_RELATIVE_PREFIX")

    def test_symlink_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("package/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            info.mtime = self.epoch
            return info, None
        expect_failure(self, self._with_special(maker), "TAR_LINK_MEMBER")

    def test_hardlink_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("package/hard")
            info.type = tarfile.LNKTYPE
            info.linkname = "package/install-worker.ps1"
            info.mtime = self.epoch
            return info, None
        expect_failure(self, self._with_special(maker), "TAR_LINK_MEMBER")

    def test_fifo_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("package/pipe")
            info.type = tarfile.FIFOTYPE
            info.mtime = self.epoch
            return info, None
        expect_failure(self, self._with_special(maker), "TAR_SPECIAL_MEMBER")

    def test_device_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("package/dev")
            info.type = tarfile.CHRTYPE
            info.mtime = self.epoch
            return info, None
        expect_failure(self, self._with_special(maker), "TAR_SPECIAL_MEMBER")

    def test_drive_qualified_member_rejected(self):
        def maker():
            info = tarfile.TarInfo("C:/evil.txt")
            info.size = 0
            info.mtime = self.epoch
            return info, b""
        expect_failure(self, self._with_special(maker), "MEMBER_DRIVE_QUALIFIED")

    def test_backslash_ambiguity_rejected(self):
        expect_failure(self, self._with_member("package\\evil.txt", b"x"),
                       "MEMBER_BACKSLASH_AMBIGUOUS")

    def test_unexpected_top_level_member_rejected(self):
        expect_failure(self, self._with_member("secrets.txt", b"x"),
                       "UNEXPECTED_TOP_LEVEL_MEMBER")

    def test_vcs_metadata_rejected(self):
        expect_failure(self, self._with_member("package/.git/config", b"x"),
                       "MEMBER_FORBIDDEN")

    def test_pycache_rejected(self):
        expect_failure(
            self, self._with_member("package/control/__pycache__/x.pyc", b"x"),
            "MEMBER_FORBIDDEN")

    def test_duplicate_member_rejected(self):
        out = self.work / "dup.tar"
        items = list(self.members.items())
        items.append(("release.json", b"{}"))
        write_tar(out, items, self.epoch)
        # write_tar sorts, so duplicates land adjacent; tarfile keeps both.
        expect_failure(self, out, "TAR_DUPLICATE_MEMBER")

    def test_case_collision_rejected(self):
        expect_failure(self, self._with_member("package/INSTALL-WORKER.PS1", b"x"),
                       "TAR_CASE_COLLISION")

    def test_missing_release_json_rejected(self):
        members = {k: v for k, v in self.members.items() if k != "release.json"}
        out = self.work / "norelease.tar"
        write_tar(out, list(members.items()), self.epoch)
        expect_failure(self, out, "RELEASE_JSON_MISSING")

    def test_missing_package_manifest_rejected(self):
        members = {k: v for k, v in self.members.items()
                   if k != "package/manifest.json"}
        out = self.work / "nopkg.tar"
        write_tar(out, list(members.items()), self.epoch)
        expect_failure(self, out, "PACKAGE_MANIFEST_MISSING")

    def test_nondeterministic_mtime_rejected(self):
        out = self.work / "mtime.tar"
        write_tar(out, list(self.members.items()), self.epoch + 1)
        expect_failure(self, out, "TAR_MTIME_NOT_SOURCE_DATE_EPOCH")

    def test_non_normalised_owner_rejected(self):
        out = self.work / "owner.tar"
        with tarfile.open(out, "w", format=tarfile.GNU_FORMAT) as archive:
            for name, data in sorted(self.members.items(),
                                     key=lambda i: i[0].encode("utf-8")):
                info = tarfile.TarInfo(name)
                info.mtime = self.epoch
                info.uid, info.gid = 1000, 1000
                info.uname = info.gname = ""
                info.mode = 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        expect_failure(self, out, "TAR_OWNER_NOT_NORMALISED")


# ================================================ mutation: LAYER B release.json ==
class ReleaseJsonMutationTests(unittest.TestCase):
    """Section 17C."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-mutC-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def _mutate(self, fn):
        out = self.work / "rj.tar"
        mutate_release_json(self.work, fn)
        written = self.work / "mutated.tar"
        written.replace(out)
        return out

    def test_malformed_json(self):
        members = read_members(_ARTIFACT)
        members["release.json"] = b"{not json\n"
        out = self.work / "bad.tar"
        write_tar(out, list(members.items()), json.loads(
            read_members(_ARTIFACT)["release.json"].decode())[
                "source"]["source_date_epoch"])
        expect_failure(self, out, "RELEASE_JSON_NOT_VALID_JSON")

    def test_bom_rejected(self):
        members = read_members(_ARTIFACT)
        members["release.json"] = b"\xef\xbb\xbf" + members["release.json"]
        out = self.work / "bom.tar"
        epoch = json.loads(read_members(_ARTIFACT)["release.json"].decode())[
            "source"]["source_date_epoch"]
        write_tar(out, list(members.items()), epoch)
        expect_failure(self, out, "RELEASE_JSON_HAS_BOM")

    def test_unsupported_release_format(self):
        out = self._mutate(lambda d: d.update(release_format="SOMETHING_ELSE"))
        expect_failure(self, out, "UNSUPPORTED_RELEASE_FORMAT")

    def test_unsupported_schema_version(self):
        out = self._mutate(lambda d: d.update(release_schema_version=99))
        expect_failure(self, out, "UNSUPPORTED_RELEASE_SCHEMA_VERSION")

    def test_missing_required_section(self):
        out = self._mutate(lambda d: d.pop("runtime"))
        expect_failure(self, out, "RELEASE_SECTION_MISSING")

    def test_unknown_section_rejected(self):
        out = self._mutate(lambda d: d.update(mystery_section={"a": 1}))
        expect_failure(self, out, "UNKNOWN_RELEASE_SECTION")

    def test_outer_hash_self_reference_rejected(self):
        out = self._mutate(lambda d: d["artifact"].update(artifact_sha256="a" * 64))
        expect_failure(self, out, "RELEASE_JSON_CONTAINS_OUTER_HASH")

    def test_target_state_key_rejected(self):
        out = self._mutate(lambda d: d.update(worker_id="11111111-1111-4111-8111-111111111111"))
        expect_failure(self, out, "UNKNOWN_RELEASE_SECTION")

    def test_malformed_commit(self):
        out = self._mutate(lambda d: d["source"].update(commit="XYZ"))
        expect_failure(self, out, "SOURCE_COMMIT_MALFORMED")

    def test_malformed_manifest_hash(self):
        out = self._mutate(lambda d: d["package"].update(manifest_sha256="short"))
        expect_failure(self, out, "MANIFEST_SHA256_MALFORMED")

    def test_source_tree_changed(self):
        out = self._mutate(lambda d: d["source"].update(tree="0" * 40))
        expect_failure(self, out, "SOURCE_TREE_MISMATCH", repo=REPO)

    def test_source_date_epoch_changed_inconsistently(self):
        out = self._mutate(lambda d: d["source"].update(source_date_epoch=1))
        # metadata check fires first (mtime no longer matches the declared epoch)
        expect_failure(self, out, "TAR_MTIME_NOT_SOURCE_DATE_EPOCH", repo=REPO)

    def test_runtime_sha_changed(self):
        out = self._mutate(lambda d: d["runtime"].update(runtime_sha256="b" * 64))
        expect_failure(self, out, "RUNTIME_SHA256_MISMATCH", repo=REPO)

    def test_runtime_version_changed(self):
        out = self._mutate(lambda d: d["runtime"].update(python_version="3.12.0"))
        expect_failure(self, out, "RUNTIME_VERSION_MISMATCH", repo=REPO)

    def test_runtime_size_changed(self):
        out = self._mutate(lambda d: d["runtime"].update(runtime_size=1))
        expect_failure(self, out, "RUNTIME_SIZE_MISMATCH", repo=REPO)

    def test_windows_lock_sha_changed(self):
        # The embedded lock BYTES are cross-checked against the claimed digest
        # before release.json is compared to lock/metadata.json, so the stricter
        # and earlier gate fires. The point of the test is that the artifact
        # does not verify; it is not that one specific message wins.
        out = self._mutate(lambda d: d["dependencies"].update(windows_lock_sha256="c" * 64))
        expect_failure(self, out, "DEPENDENCY_LOCK_MISMATCH:lock/windows-cp313.txt", repo=REPO)

    def test_linux_lock_sha_changed(self):
        out = self._mutate(lambda d: d["dependencies"].update(linux_lock_sha256="d" * 64))
        expect_failure(self, out, "LINUX_LOCK_IDENTITY_MISMATCH", repo=REPO)

    def test_requirements_sha_changed(self):
        out = self._mutate(lambda d: d["dependencies"].update(requirements_in_sha256="e" * 64))
        expect_failure(self, out, "REQUIREMENTS_IN_SHA256_MISMATCH", repo=REPO)

    def test_protected_tree_identity_changed(self):
        out = self._mutate(lambda d: d["protected_trees"].update(controller="0" * 40))
        expect_failure(self, out, "PROTECTED_TREE_MISMATCH:controller", repo=REPO)

    def test_migration_016_flag_rejected(self):
        out = self._mutate(lambda d: d["migrations"].update(migration_016_present=True))
        expect_failure(self, out, "MIGRATION_016_PRESENT")

    def test_migration_count_changed(self):
        out = self._mutate(lambda d: d["migrations"].update(count=99))
        expect_failure(self, out, "MIGRATION_COUNT_MISMATCH", repo=REPO)

    def test_compressed_artifact_claim_rejected(self):
        out = self._mutate(lambda d: d["artifact"].update(tar_compression="gzip"))
        expect_failure(self, out, "ARTIFACT_COMPRESSION_NOT_DETERMINISTIC")

    def test_manifest_sha_changed(self):
        out = self._mutate(lambda d: d["package"].update(manifest_sha256="f" * 64))
        expect_failure(self, out, "MANIFEST_SHA256_MISMATCH")

    def test_installer_sha_changed(self):
        out = self._mutate(lambda d: d["package"].update(installer_sha256="1" * 64))
        expect_failure(self, out, "INSTALLER_SHA256_MISMATCH")

    def test_v2_aggregate_changed(self):
        out = self._mutate(lambda d: d["package"].update(manifest_v2_aggregate="2" * 64))
        expect_failure(self, out, "V2_AGGREGATE_MISMATCH")

    def test_expect_commit_mismatch(self):
        result = verify(_ARTIFACT, sidecar=_SIDECAR, repo=REPO, commit="0" * 40)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("SOURCE_COMMIT_MISMATCH", result.stdout + result.stderr)


# ==================================================== mutation: LAYER C package ==
class PackageMutationTests(unittest.TestCase):
    """Section 17D."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-mutD-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_payload_byte_modified_equal_size(self):
        target = "package/control/worker_agent/windows_service.py"
        original = read_members(_ARTIFACT)[target]

        def flip(data):
            # Same length: only the digest changes, so this cannot pass as a size check.
            return bytes([data[0] ^ 0x01]) + data[1:]

        out = mutate_member_bytes(self.work, target, flip)
        expect_failure(self, out, "MANIFEST_HASH_MISMATCH:control/worker_agent/windows_service.py")

    def test_payload_size_changed(self):
        target = "package/control/worker_agent/windows_service.py"
        out = mutate_member_bytes(self.work, target, lambda d: d + b"\n")
        expect_failure(self, out, "MANIFEST_SIZE_MISMATCH")

    def test_unmanifested_immutable_payload(self):
        out = mutate_member_bytes(self.work, "package/extra.txt",
                                  lambda d: d) if False else None
        members = read_members(_ARTIFACT)
        members["package/extra.txt"] = b"unexpected"
        epoch = json.loads(members["release.json"].decode())[
            "source"]["source_date_epoch"]
        path = self.work / "extra.tar"
        write_tar(path, list(members.items()), epoch)
        expect_failure(self, path, "UNMANIFESTED_PAYLOAD:extra.txt")

    def test_manifest_modified(self):
        def bump(data):
            document = json.loads(data.decode("utf-8"))
            document["policy_requirements"] = sorted(
                document["policy_requirements"]) + ["requires_extra_thing"]
            return json.dumps(document, sort_keys=True, indent=2).encode() + b"\n"

        out = mutate_member_bytes(self.work, "package/manifest.json", bump)
        expect_failure(self, out, "MANIFEST_SHA256_MISMATCH")

    def test_v2_aggregate_mismatch(self):
        """Rewrite the manifest so the STORED aggregate no longer matches payload."""
        def rewrite(data):
            document = json.loads(data.decode("utf-8"))
            document["identity"]["aggregate_sha256"] = "3" * 64
            return json.dumps(document, sort_keys=True, indent=2).encode() + b"\n"

        members = read_members(_ARTIFACT)
        # Keep release.json consistent so the manifest-hash gate is NOT what fires.
        manifest = json.loads(members["package/manifest.json"].decode("utf-8"))
        members["package/manifest.json"] = rewrite(members["package/manifest.json"])
        document = json.loads(members["release.json"].decode("utf-8"))
        document["package"]["manifest_sha256"] = hashlib.sha256(
            members["package/manifest.json"]).hexdigest()
        members["release.json"] = json.dumps(
            document, sort_keys=True, indent=2).encode() + b"\n"
        path = self.work / "v2.tar"
        write_tar(path, list(members.items()), document["source"]["source_date_epoch"])
        expect_failure(self, path, "IDENTITY_AGGREGATE_MISMATCH")

    def test_worker_dpapi_injected(self):
        members = read_members(_ARTIFACT)
        members["package/worker.dpapi"] = b"\x00" * 32
        epoch = json.loads(members["release.json"].decode())["source"]["source_date_epoch"]
        path = self.work / "dpapi.tar"
        write_tar(path, list(members.items()), epoch)
        combined = expect_failure(self, path, "MEMBER_FORBIDDEN:package/worker.dpapi")

    def test_service_json_injected(self):
        members = read_members(_ARTIFACT)
        members["package/service.json"] = b"{}"
        epoch = json.loads(members["release.json"].decode())["source"]["source_date_epoch"]
        path = self.work / "svc.tar"
        write_tar(path, list(members.items()), epoch)
        expect_failure(self, path, "MEMBER_FORBIDDEN:package/service.json")

    def test_target_fixture_path_injected(self):
        members = read_members(_ARTIFACT)
        members["package/personal-denial.fixture"] = b"x"
        epoch = json.loads(members["release.json"].decode())["source"]["source_date_epoch"]
        path = self.work / "fix.tar"
        write_tar(path, list(members.items()), epoch)
        expect_failure(self, path, "MEMBER_FORBIDDEN")

    def test_missing_installer_member_rejected(self):
        members = {k: v for k, v in read_members(_ARTIFACT).items()
                   if k != "package/install-worker.ps1"}
        epoch = json.loads(members["release.json"].decode())["source"]["source_date_epoch"]
        path = self.work / "noinst.tar"
        write_tar(path, list(members.items()), epoch)
        expect_failure(self, path, "INSTALLER_MEMBER_MISSING")


# ============================================ exclusion / trust-model gates ====
class ExclusionAndTrustModelTests(unittest.TestCase):
    """Sections 17 (secret/target-state) and 4/21 (terminology discipline)."""

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-mutE-"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_identity_leak_in_release_json_rejected(self):
        members = read_members(_ARTIFACT)
        document = json.loads(members["release.json"].decode())
        document["source"]["note"] = "C:\\Users\\builder\\leak"
        members["release.json"] = json.dumps(
            document, sort_keys=True, indent=2).encode() + b"\n"
        path = self.work / "leak.tar"
        write_tar(path, list(members.items()), document["source"]["source_date_epoch"])
        expect_failure(self, path, "IDENTITY_LEAK_IN_RELEASE")

    def test_artifact_contains_no_target_state(self):
        for name in read_members(_ARTIFACT):
            self.assertNotIn("worker.dpapi", name)
            self.assertNotIn("service.json", name)
            self.assertNotIn("personal-denial.fixture", name)

    def test_manifest_has_no_target_state_keys(self):
        manifest = json.loads(read_members(_ARTIFACT)["package/manifest.json"].decode())
        for key in manifest:
            self.assertNotIn(key, rl.TARGET_STATE_KEYS)

    def test_release_json_does_not_contain_outer_hash(self):
        document = json.loads(read_members(_ARTIFACT)["release.json"].decode())

        def walk(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotIn(key, ("artifact_sha256", "outer_sha256",
                                           "tar_sha256", "self_sha256"))
                    walk(value)
            elif isinstance(node, list):
                for item in node:
                    walk(item)

        walk(document)
        # The digest is reachable only via the external sidecar.
        self.assertEqual(_DIGEST, _SIDECAR.read_bytes().decode().split("  ")[0])

    def test_no_signing_key_in_repository_release_tooling(self):
        for name in ("build-release.py", "verify-release.py", "release_lib.py"):
            source = (TOOLS / name).read_text(encoding="utf-8")
            for banned in ("gpg", "minisign", "sigstore", "BEGIN PRIVATE KEY",
                           "cosign", "sign("):
                self.assertNotIn(banned, source.lower(),
                                 f"{name} must not introduce signing")


class CanonicalSerialisationTests(unittest.TestCase):
    """Section 7: release.json serialisation is deterministic and machine-readable."""

    def test_canonical_json_bytes(self):
        payload = rl.canonical_json_bytes({"b": 1, "a": [1, 2]})
        self.assertEqual(b'{"a":[1,2],"b":1}\n', payload)
        self.assertFalse(payload.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"\r", payload)

    def test_pretty_json_bytes_sorted_and_lf(self):
        payload = rl.pretty_json_bytes({"z": 1, "a": 2})
        self.assertEqual(b'{\n  "a": 2,\n  "z": 1\n}\n', payload)

    def test_member_name_policy(self):
        rl.check_member_name("package/install-worker.ps1")
        for bad, code in (
            ("/abs", "MEMBER_ABSOLUTE_PATH"),
            ("../up", "MEMBER_RELATIVE_PREFIX"),
            ("a/../b", "MEMBER_TRAVERSAL"),
            ("C:/x", "MEMBER_DRIVE_QUALIFIED"),
            ("a\\b", "MEMBER_BACKSLASH_AMBIGUOUS"),
            ("a//b", "MEMBER_TRAVERSAL"),
            ("package/mod.pyc", "MEMBER_FORBIDDEN"),
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(rl.ReleaseError) as ctx:
                    rl.check_member_name(bad)
                self.assertIn(code, str(ctx.exception))

    def test_sidecar_parser_rejects_deviations(self):
        good = b"%s  a.tar\n" % (b"a" * 64)
        self.assertEqual("a" * 64, rl.parse_sidecar(good, "a.tar"))
        for bad in (b"", b"a" * 64 + b"  a.tar",
                    b"A" * 64 + b"  a.tar\n",
                    b"a" * 64 + b" a.tar\n",
                    b"a" * 64 + b"  b.tar\n",
                    b"a" * 64 + b"  a.tar\r\n",
                    b"a" * 64 + b"  a.tar\nb" * 1):
            with self.subTest(bad=bad):
                with self.assertRaises(rl.ReleaseError):
                    rl.parse_sidecar(bad, "a.tar")


class IncompletePackageRegressionTests(unittest.TestCase):
    """Regression guard for a real defect found while building this tooling.

    A staging bug once dropped the ENTIRE committed worker_agent subtree. The
    resulting artifact was still internally consistent: every digest matched,
    the V2 aggregate matched, and BOTH the builder's self-check and the verifier
    reported success. The package simply contained no worker code.

    These tests exist so that "self-consistent but incomplete" can never verify
    again.
    """

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="rhb-incomplete-"))
        self.members = read_members(_ARTIFACT)
        self.epoch = json.loads(
            self.members["release.json"].decode())["source"]["source_date_epoch"]

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_real_artifact_carries_the_whole_worker_subtree(self):
        present = read_members(_ARTIFACT)
        agent = sorted(n for n in present
                       if n.startswith("package/control/worker_agent/"))
        # Compare against the committed source count, not a magic number.
        out = subprocess.run(
            ["git", "-C", str(REPO), "ls-tree", "-r", "--name-only",
             "HEAD", "worker_agent"], capture_output=True, text=True, timeout=120)
        committed = [n for n in out.stdout.split() if n.strip()]
        self.assertEqual(len(committed), len(agent),
                         "packaged worker module count differs from committed tree")

    def test_required_members_are_enforced(self):
        for member in rl.REQUIRED_PACKAGE_MEMBERS:
            self.assertIn("package/" + member, self.members)

    def test_dropping_the_whole_worker_subtree_is_rejected(self):
        members = {k: v for k, v in self.members.items()
                   if not k.startswith("package/control/worker_agent/")}
        path = self.work / "noagent.tar"
        write_tar(path, list(members.items()), self.epoch)
        combined = expect_failure(self, path,
                                  "REQUIRED_PACKAGE_MEMBER_MISSING")
        self.assertNotIn("RELEASE_VERIFIED", combined)

    def test_dropping_a_single_worker_module_is_rejected(self):
        members = {k: v for k, v in self.members.items()
                   if k != "package/control/worker_agent/windows_service.py"}
        path = self.work / "nosvc.tar"
        write_tar(path, list(members.items()), self.epoch)
        expect_failure(self, path, "REQUIRED_PACKAGE_MEMBER_MISSING")


if __name__ == "__main__":
    unittest.main()