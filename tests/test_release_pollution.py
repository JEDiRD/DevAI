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
        """Importing the shared helper alone must be side-effect free."""
        result = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.path.insert(0, r'%s'); import release_lib; "
             "print('ok')" % TOOLS],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": ""})
        self.assertEqual(0, result.returncode, result.stderr)


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