"""RH-B STEP 6: the canonical release build must not pollute the source tree.

STEP 6 found that a normal, production-path release build left bytecode caches
inside the source checkout:

  tools/__pycache__/release_lib.cpython-313.pyc
  deploy/windows/__pycache__/build-package.cpython-313.pyc

Both are written by local imports inside tools/build-release.py, not by the
artifact. `.gitignore` hides them from `git status`, which is exactly why a
git-status-only cleanliness gate is insufficient.

The fix is `sys.dont_write_bytecode = True` set before any local import. These
tests assert the observable property -- a filesystem scan, not a git check --
so the defect cannot return behind a gitignore rule.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TOOLS = REPO / "tools"
BUILD = TOOLS / "build-release.py"
VERIFY = TOOLS / "verify-release.py"

# Names that indicate build products, not source.
POLLUTION_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache"}
POLLUTION_SUFFIXES = {".pyc", ".pyo"}
POLLUTION_FILES = {".coverage", "coverage.xml"}


def scan_pollution(root: Path) -> list[str]:
    """Filesystem scan for build products. Deliberately ignores .gitignore."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        for name in dirnames:
            if name in POLLUTION_DIRS:
                found.append(str(Path(dirpath, name).relative_to(root)))
        for name in filenames:
            path = Path(dirpath, name)
            if path.suffix in POLLUTION_SUFFIXES or name in POLLUTION_FILES:
                found.append(str(path.relative_to(root)))
    return sorted(found)


# Synthetic runtime payload completing an offline-built test artifact.
# Same fixture discipline as test_release_artifact: the offline build carries
# no pinned runtime, while production verification strictly requires a
# complete one. Fixed labeled bytes; digests recomputed over actual bytes.
_SYNTHETIC_RUNTIME = (
    ("package/host-runtime/python.exe",
     b"RHB-TEST-FIXTURE-RUNTIME:host-python"),
    ("package/sandbox-runtime/python.exe",
     b"RHB-TEST-FIXTURE-RUNTIME:sandbox-python"),
    ("package/sandbox-runtime/synthetic_process.py",
     b"RHB-TEST-FIXTURE-RUNTIME:synthetic-payload"),
)


def _complete_test_artifact_runtime(path: Path) -> None:
    """Add synthetic runtime members; regenerate manifest/release/sidecar."""
    import io
    import json
    import tarfile
    sys.dont_write_bytecode = True
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "devai_package_builder_for_pollution_tests",
        REPO / "deploy" / "windows" / "build-package.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    members = {}
    with tarfile.open(path, "r:") as archive:
        for info in archive.getmembers():
            handle = archive.extractfile(info)
            members[info.name] = handle.read() if handle else b""
    for name, data in _SYNTHETIC_RUNTIME:
        members[name] = data
    entries = sorted(
        (name[len("package/"):], data)
        for name, data in members.items()
        if name.startswith("package/") and name != "package/manifest.json")
    manifest = json.loads(members["package/manifest.json"])
    manifest["files"] = [
        {"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
         "size": len(data)}
        for rel, data in entries]
    manifest["identity"]["aggregate_sha256"] = hashlib.sha256(
        builder.serialize_manifest_v2(entries)).hexdigest()
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True)
                      + "\n").encode("utf-8")
    members["package/manifest.json"] = manifest_bytes
    release = json.loads(members["release.json"])
    release["package"]["manifest_sha256"] = hashlib.sha256(
        manifest_bytes).hexdigest()
    release["package"]["manifest_v2_aggregate"] = manifest["identity"][
        "aggregate_sha256"]
    members["release.json"] = (json.dumps(release, indent=2, sort_keys=True)
                               + "\n").encode("utf-8")
    epoch = release["source"]["source_date_epoch"]
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as archive:
        for name, data in sorted(members.items(),
                                 key=lambda item: item[0].encode("utf-8")):
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mode = 0o644
            info.type = tarfile.REGTYPE
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))


class ToolingDisablesBytecodeTests(unittest.TestCase):
    """The narrow fix itself: bytecode writing is disabled before local imports."""

    def test_build_tool_disables_bytecode_before_local_import(self):
        source = BUILD.read_text(encoding="utf-8")
        self.assertIn("sys.dont_write_bytecode = True", source)
        # Anchor on the real import statement (newline + "from"), not on the
        # explanatory comment that quotes the same phrase.
        self.assertLess(source.index("sys.dont_write_bytecode = True"),
                        source.index("\nfrom release_lib import"))

    def test_verify_tool_disables_bytecode_before_local_import(self):
        source = VERIFY.read_text(encoding="utf-8")
        self.assertIn("sys.dont_write_bytecode = True", source)
        self.assertLess(source.index("sys.dont_write_bytecode = True"),
                        source.index("\nfrom release_lib import"))

    def test_release_lib_does_not_write_bytecode_on_import(self):
        """Importing the shared helper alone must be side-effect free.

        PYTHONDONTWRITEBYTECODE is set to "1", not to an empty string. An empty
        value is present but not truthy, so CPython still writes bytecode; that
        left tools/__pycache__/release_lib.cpython-*.pyc in the source checkout
        and made the source-pollution gate reject the tree it had just polluted.
        """
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, r'%s'); import release_lib; "
             "print('ok')" % TOOLS],
            capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertNotIn("__pycache__", "\n".join(
            str(p) for p in TOOLS.rglob("__pycache__")),
            "importing release_lib must not create bytecode in tools/")


class CanonicalBuildPollutionTests(unittest.TestCase):
    """Section 3: observable filesystem cleanliness around a real build."""

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="rhb-pollution-"))
        cls.clone = cls.work / "src"
        subprocess.run(["git", "clone", "--quiet", str(REPO), str(cls.clone)],
                       check=True, capture_output=True, timeout=600)
        head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                              capture_output=True, text=True, check=True)
        subprocess.run(["git", "-C", str(cls.clone), "checkout", "--quiet",
                        head.stdout.strip()], check=True, capture_output=True,
                       timeout=300)
        # Apply the working-tree tooling change under test.
        for name in ("build-release.py", "verify-release.py", "release_lib.py"):
            shutil.copy2(TOOLS / name, cls.clone / "tools" / name)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_no_pollution_before_build(self):
        self.assertEqual([], scan_pollution(self.clone))

    def test_canonical_build_leaves_no_pollution(self):
        out = self.work / "out"
        result = subprocess.run(
            [sys.executable, str(self.clone / "tools" / "build-release.py"),
             "--output-dir", str(out), "--allow-dirty-worktree"],
            capture_output=True, text=True, timeout=900, cwd=str(self.clone))
        self.assertEqual(0, result.returncode, result.stderr)
        after = scan_pollution(self.clone)
        self.assertEqual([], after,
                         "canonical build polluted the source tree: %s" % after)

    def test_canonical_verify_leaves_no_pollution(self):
        out = self.work / "out"
        tarballs = list(out.glob("*.tar"))
        self.assertTrue(tarballs, "build produced no artifact")
        tar = tarballs[0]
        # Complete the runtime payload synthetically: production verification
        # strictly requires a complete runtime, while the offline build
        # carries no pinned runtime (same fixture discipline as
        # test_release_artifact). Digests are recomputed over actual bytes.
        _complete_test_artifact_runtime(tar)
        digest = hashlib.sha256(tar.read_bytes()).hexdigest()
        before = scan_pollution(self.clone)
        self.assertEqual([], before)
        result = subprocess.run(
            [sys.executable, str(self.clone / "tools" / "verify-release.py"),
             str(tar), "--expected-sha256", digest],
            capture_output=True, text=True, timeout=600, cwd=str(self.clone))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual([], scan_pollution(self.clone),
                         "verification polluted the source tree")


if __name__ == "__main__":
    unittest.main()