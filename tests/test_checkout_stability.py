"""RH-B STEP 6 regression: checkout-stable release-input identity.

STEP 6 exists to produce canonical native x64 reproducibility evidence, and it
immediately found a real defect: the repository had no `.gitattributes`, so a
GitHub windows-* runner (core.autocrlf=true) rewrote LF -> CRLF on checkout.
The identical commit therefore produced DIFFERENT SHA256 identities for the
recorded release inputs on Windows versus Linux, and the release-input identity
gate failed closed.

These tests pin the fix. They are cheap, offline, and must never be removed: a
regression here silently reintroduces platform-dependent release identity.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LOCK_METADATA = REPO / "lock" / "metadata.json"

# The release inputs whose SHA256 identities are recorded and enforced.
RELEASE_INPUTS = (
    "requirements.in",
    "lock/linux-cp313.txt",
    "lock/windows-cp313.txt",
)


def blob_bytes(path: str) -> bytes:
    """Read the COMMITTED blob, never the worktree copy."""
    result = subprocess.run(["git", "-C", str(REPO), "cat-file", "blob",
                             "HEAD:%s" % path],
                            capture_output=True, check=True)
    return result.stdout


class CheckoutStabilityTests(unittest.TestCase):
    def test_gitattributes_exists_and_pins_lf(self):
        attributes = REPO / ".gitattributes"
        self.assertTrue(attributes.is_file(),
                        "missing .gitattributes: release-input identity would "
                        "become platform dependent again")
        text = attributes.read_text(encoding="utf-8")
        self.assertIn("eol=lf", text)
        self.assertIn("text=auto", text)

    def test_release_input_blobs_are_lf_only(self):
        """The committed bytes themselves must already be LF-only."""
        for name in RELEASE_INPUTS:
            with self.subTest(path=name):
                data = blob_bytes(name)
                self.assertNotIn(b"\r\n", data,
                                 "%s blob contains CRLF; its SHA256 would change "
                                 "under a normalizing checkout" % name)
                self.assertNotIn(b"\r", data)

    def test_release_input_blobs_match_recorded_identities(self):
        """Blob identity must equal what lock/metadata.json records."""
        metadata = json.loads(LOCK_METADATA.read_text(encoding="utf-8"))
        expected = {
            "requirements.in": metadata["requirements_sha256"],
            "lock/linux-cp313.txt": metadata["linux"]["lock_sha256"],
            "lock/windows-cp313.txt": metadata["windows"]["lock_sha256"],
        }
        for name in RELEASE_INPUTS:
            with self.subTest(path=name):
                actual = hashlib.sha256(blob_bytes(name)).hexdigest()
                self.assertEqual(expected[name], actual)

    def test_worktree_copy_matches_blob(self):
        """With .gitattributes in force the worktree must equal the blob."""
        for name in RELEASE_INPUTS:
            with self.subTest(path=name):
                self.assertEqual(blob_bytes(name), (REPO / name).read_bytes())

    def test_crlf_conversion_would_change_identity(self):
        """Demonstrate the defect the fix prevents.

        If a CRLF checkout produced the recorded identity, this test would be
        vacuous. It asserts the recorded values are the LF forms and that the
        CRLF forms differ.
        """
        metadata = json.loads(LOCK_METADATA.read_text(encoding="utf-8"))
        pairs = (
            ("requirements.in", metadata["requirements_sha256"]),
            ("lock/linux-cp313.txt", metadata["linux"]["lock_sha256"]),
            ("lock/windows-cp313.txt", metadata["windows"]["lock_sha256"]),
        )
        for name, recorded in pairs:
            with self.subTest(path=name):
                lf = blob_bytes(name)
                crlf = lf.replace(b"\n", b"\r\n")
                self.assertEqual(recorded, hashlib.sha256(lf).hexdigest())
                self.assertNotEqual(recorded, hashlib.sha256(crlf).hexdigest())

    def test_runtime_lock_is_checkout_stable(self):
        data = blob_bytes("deploy/windows/runtime-lock.json")
        self.assertNotIn(b"\r\n", data)
        self.assertEqual(data, (REPO / "deploy" / "windows"
                                / "runtime-lock.json").read_bytes())

    def test_cross_platform_tooling_sources_are_lf_only(self):
        """Files whose recorded identity or tooling role must be byte-stable."""
        for name in ("deploy/windows/build-package.py",
                     "tools/build-release.py",
                     "tools/verify-release.py",
                     "tools/release_lib.py"):
            with self.subTest(path=name):
                self.assertNotIn(b"\r\n", blob_bytes(name))

    def test_release_builder_is_blob_based_not_worktree_based(self):
        """Payload EOL style cannot make the artifact host-dependent.

        The PowerShell payload scripts are Windows-native and their blobs may
        carry CRLF. That is harmless ONLY because the release builder reads
        every payload byte from the committed blob, never from the worktree.
        This test pins that property so it cannot silently regress into
        worktree reads, which WOULD make the artifact depend on the builder's
        platform and autocrlf setting.
        """
        source = (REPO / "tools" / "build-release.py").read_text(encoding="utf-8")
        self.assertIn("blob(REPO_ROOT, commit", source)
        # No payload member may be sourced from a live filesystem path.
        for forbidden in ("REPO_ROOT / src_rel", "src.read_bytes()"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        # The verifier likewise must not depend on the worktree.
        verifier = (REPO / "tools" / "verify-release.py").read_text(encoding="utf-8")
        self.assertNotIn("REPO_ROOT / src_rel", verifier)


if __name__ == "__main__":
    unittest.main()