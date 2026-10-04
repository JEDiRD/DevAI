"""RH-B STEP 5I-K: static documentation and security-posture checks.

These are deliberately SEMANTIC checks, not brittle prose-position assertions.
They verify that the operational documentation does not recommend an unsafe
action, and that the release documentation actually records the real identities
and the honest gate states.

A documentation bug is a security bug here: an operator who follows a wrong
procedure can leak a token or bypass a gate. These tests are the guard.
"""
from __future__ import annotations

import json
import re
import subprocess
import tarfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"
WORKER_DOC = DOCS / "NETWORK_WORKER.md"
RELEASE_DOC = DOCS / "RELEASE_PROCESS.md"
TOOLS = REPO / "tools"

CANONICAL_PYTHON = "3.13.16"
PIP_TOOLS = "7.6.1"
REQUIREMENTS_SHA = "275bdf2469a4d401813ec8a90fe63494ca5324ef6a6466c5904184cbdf6166ad"
LINUX_LOCK_SHA = "05c9744beb969acc37b4a89eb61cb4d618291d53ae975ddab5503765c94c9560"
WINDOWS_LOCK_SHA = "a2647d678c0029d8ce0e5ce696ab342327cc929fb3e96988bb1665d7e771d125"
RUNTIME_URL = "python-3.13.16-embed-amd64.zip"
RUNTIME_SHA = "97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297"
RUNTIME_SIZE = "11439094"


def doc_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def flat(text: str) -> str:
    """Collapse line wrapping.

    Prose is hard-wrapped, so a phrase can straddle a newline. Searching raw
    text for multi-word phrases produces false negatives that look like a
    missing requirement. Assertions therefore run against flattened text.
    """
    return re.sub(r"\s+", " ", text)


NEGATION_MARKERS = (
    "not ", "never", "no ", "cannot", "must not", "do not", "don't",
    "forbidden", "prohibited", "instead of",
)


class NetworkWorkerDocTests(unittest.TestCase):
    """Section 2: the six required operational sections exist."""

    def setUp(self):
        self.text = doc_text(WORKER_DOC)
        self.flat = flat(self.text)
        self.lower = self.text.lower()

    def test_all_six_operational_sections_present(self):
        for heading in ("Initial Provisioning", "Credential Rotation",
                        "Worker Replacement", "Worker Identity Lifecycle",
                        "Token / Credential Lifecycle", "Failure and Recovery"):
            with self.subTest(section=heading):
                self.assertIn(heading, self.text)

    def test_provisioning_sequence_is_documented_in_order(self):
        """The documented order must match the implemented order."""
        required = ["verify outer release artifact", "supply workerid",
                    "supply apibaseurl", "personal denial fixture",
                    "generate service.json", "provision token through stdin",
                    "register service", "start service"]
        positions = []
        for step in required:
            index = self.lower.find(step)
            self.assertNotEqual(-1, index, f"missing provisioning step: {step}")
            positions.append(index)
        self.assertEqual(sorted(positions), positions,
                         "provisioning steps are documented out of order")

    def test_secret_and_non_secret_are_distinguished(self):
        self.assertIn("Non-secret", self.text)
        self.assertIn("Secret", self.text)

    def test_token_must_never_be_placed_in_unsafe_locations(self):
        """The doc must forbid every unsafe token location, not merely omit them."""
        forbidden_phrases = [
            "on a command line", "in an environment variable",
            "in `service.json`", "in a script",
        ]
        for phrase in forbidden_phrases:
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.lower)

    def test_rotation_semantics_documented(self):
        for statement in ("Normal reinstall (same release)",
                          "Upgrade to a new release",
                          "Rollback to a previous release"):
            self.assertIn(statement, self.text)
        self.assertIn("Rotation is explicit", self.text)
        self.assertIn("Failed rotation preserves the last valid credential",
                      self.text)

    def test_credential_validation_limitation_stated_honestly(self):
        """The doc must admit presence/path/ACL only, with no semantic claim."""
        self.assertIn("Stated validation limitation", self.text)
        self.assertIn("does **not** decrypt", self.text)
        for item in ("**presence**", "**path**", "**ACL**"):
            self.assertIn(item, self.text)

    def test_code_reinstall_distinguished_from_worker_replacement(self):
        self.assertIn("Code reinstall (same identity)", self.text)
        self.assertIn("Worker replacement (new identity)", self.text)
        self.assertIn("never generates a new `WorkerId` automatically", self.text)

    def test_identity_lifecycle_rules_documented(self):
        for statement in ("Generated or assigned outside the immutable package",
                          "Stable** across normal reinstall",
                          "WORKER_ID_CONFLICT",
                          "API_BASE_URL_CONFLICT",
                          "no precedence rule",
                          "does not own identity"):
            with self.subTest(statement=statement):
                self.assertIn(statement, self.text)

    def test_api_base_url_policy_is_described_accurately(self):
        """The real policy is loopback/CGNAT over http AND https."""
        self.assertIn("NOT \"HTTPS only\"", self.text)
        self.assertIn("100.64.0.0/10", self.text)
        self.assertIn("loopback", self.lower)
        self.assertIn("literal IP address", self.text)
        self.assertIn("RFC1918", self.text)
        # It must not be simplified into the false claim.
        self.assertNotIn("HTTPS only", self.text.replace('NOT "HTTPS only"', ""))

    def test_token_lifecycle_documents_dpapi_binding(self):
        self.assertIn("not portable", self.lower)
        self.assertIn("Target-local", self.text)
        self.assertIn("secret-free", self.text)
        self.assertIn("redirected stdin", self.text)

    def test_failure_table_covers_required_conditions(self):
        for code in ("ARTIFACT_SHA256_MISMATCH", "PACKAGE_MANIFEST_CHANGED",
                     "PACKAGE_INSTALLER_CHANGED", "RUNTIME_SHA256_MISMATCH",
                     "DEPENDENCY_LOCK_MISMATCH", "INVALID_WORKER_ID",
                     "INVALID_API_BASE_URL", "WORKER_ID_CONFLICT",
                     "CREDENTIAL_PROVISIONING_FAILED"):
            with self.subTest(code=code):
                self.assertIn(code, self.text)

    def test_no_bypass_instructions(self):
        lower = self.lower
        for banned in ("temporarily disable validation",
                       "disable validation",
                       "skip validation",
                       "bypass the acl",
                       "remove the reparse check",
                       "edit manifest.json to"):
            with self.subTest(banned=banned):
                self.assertNotIn(banned, lower)

    def test_personal_fixture_documented_as_runtime_witness(self):
        self.assertIn("service_personal_profile_denied", self.text)
        self.assertIn("INSTALLER_ACL_POLICY_GATE", self.text)
        self.assertIn("RUNTIME_SERVICE_PERSONAL_PROFILE_DENIAL_GATE", self.text)
        self.assertIn("BLOCKED_PENDING_ELEVATED_EXECUTION", self.text)
        # Exactly three ACEs and no service SID must be stated.
        self.assertIn("S-1-5-18", self.text)
        self.assertIn("S-1-5-32-544", self.text)
        self.assertIn("No** service-SID ACE", self.text)
        # Mocks must not be offered as equivalent evidence.
        self.assertIn("must not be simulated with mocks", self.text)


class ReleaseProcessDocTests(unittest.TestCase):
    """Sections 10, 11, 12, 15, 16, 19, 21."""

    def setUp(self):
        self.text = doc_text(RELEASE_DOC)
        self.flat = flat(self.text)
        self.lower = self.text.lower()

    def test_required_sections_present(self):
        for heading in ("Release prerequisites", "Canonical environment",
                        "Source eligibility", "Dependency locks",
                        "Runtime pin", "Build procedure",
                        "Release artifact layout", "Verification procedure",
                        "Trust model", "Rollback material",
                        "Rollback procedure", "Migration policy",
                        "SBOM procedure", "Signing status", "Retention",
                        "Post-deploy verification",
                        "Known external gates"):
            with self.subTest(section=heading):
                self.assertIn(heading, self.text)

    def test_canonical_environment_exact(self):
        self.assertIn(CANONICAL_PYTHON, self.text)
        self.assertIn(PIP_TOOLS, self.text)
        self.assertIn(REQUIREMENTS_SHA, self.text)
        self.assertIn(LINUX_LOCK_SHA, self.text)
        self.assertIn(WINDOWS_LOCK_SHA, self.text)
        self.assertIn(RUNTIME_URL, self.text)
        self.assertIn(RUNTIME_SHA, self.text)
        self.assertIn(RUNTIME_SIZE, self.text)

    def test_python_3_13_0_is_not_described_as_canonical(self):
        self.assertIn("Python 3.13.0 is NOT canonical", self.text)

    def test_hashed_lock_install_documented(self):
        self.assertIn("--require-hashes", self.text)
        self.assertIn("lock/windows-cp313.txt", self.text)
        self.assertIn("lock/linux-cp313.txt", self.text)
        self.assertIn("source intent", self.lower)
        self.assertIn("installation authority", self.lower)

    def test_ranged_requirements_fallback_forbidden(self):
        self.assertIn("may fall back to ranged requirements", self.lower)
        self.assertIn("Never install from `requirements.in` directly", self.text)

    def test_build_and_verify_tooling_documented(self):
        self.assertIn("tools/build-release.py", self.text)
        self.assertIn("tools/verify-release.py", self.text)
        self.assertIn("--repo", self.text)
        self.assertIn("--expect-commit", self.text)

    def test_source_date_epoch_from_commit_documented(self):
        self.assertIn("git show -s --format=%ct", self.text)
        self.assertIn("never** wall-clock time", self.text)

    def test_outer_hash_lives_outside_release_json(self):
        self.assertIn("does **not** contain the outer artifact SHA256", self.text)
        self.assertIn("external sidecar", self.lower)

    def test_launcher_two_anchors_documented(self):
        self.assertIn("-ExpectedManifestSHA256", self.text)
        self.assertIn("-ExpectedInstallerSHA256", self.text)

    def test_internal_consistency_is_not_authenticity(self):
        self.assertIn("Internal consistency is not authenticity", self.text)

    def test_trust_model_terminology_and_status(self):
        self.assertIn("artifact integrity", self.lower)
        self.assertIn("trusted external hash anchor", self.lower)
        self.assertIn("NOT IMPLEMENTED", self.text)
        self.assertIn("does not by itself establish publisher identity", self.text)
        self.assertIn("untrusted channel", self.lower)

    def test_signing_status_is_not_implemented(self):
        self.assertIn("PUBLISHER_SIGNATURE: NOT_IMPLEMENTED", self.text)

    def test_sbom_procedure_is_defined_but_generator_unpinned(self):
        self.assertIn("CycloneDX", self.text)
        self.assertIn("SBOM_GENERATOR_PIN", self.text)
        self.assertIn("PENDING_STEP_6_OR_RELEASE_PROCESS_VALIDATION", self.text)
        # Must not tell operators to use an unpinned tool.
        self.assertIn('**Do not** run "the latest CycloneDX tool"', self.flat)
        self.assertIn("latest cyclonedx tool", self.flat.lower())
        # Scope must exclude database rows.
        self.assertIn("Database tables, schemas and rows are **not**", self.text)
        # Optional field omitted, never reserved with a fake value.
        self.assertIn("omitted entirely", self.text)

    def test_rollback_material_complete_and_secret_free(self):
        for item in ("outer release artifact", "artifact SHA256 sidecar",
                     "`release.json`", "`manifest.json`",
                     "platform lock file", "runtime identity",
                     "source commit + tree identity"):
            with self.subTest(item=item):
                self.assertIn(item, self.text)
        for secret in ("`worker.dpapi`", "plaintext token",
                       "personal-denial fixture"):
            with self.subTest(secret=secret):
                self.assertIn(secret, self.text)
        self.assertIn("Never retain inside release archives", self.text)

    def test_rollback_procedure_is_artifact_coherent(self):
        for step in ("verify its trusted external hash",
                     "check migration compatibility",
                     "preserve target identity",
                     "preserve target credential"):
            with self.subTest(step=step):
                self.assertIn(step, self.text)
        self.assertIn("coherent unit", self.text)
        self.assertIn("Never assemble a rollback package ad", self.text)

    def test_migration_downgrade_policy_fails_closed(self):
        self.assertIn("no silent database migration downgrade", self.lower)
        self.assertIn("STOP", self.text)
        self.assertIn("001–015", self.text)
        self.assertIn("016 is absent", self.text)
        self.assertIn("must not be created", self.text)

    def test_retention_requires_current_and_previous(self):
        self.assertIn("CURRENT", self.text)
        self.assertIn("PREVIOUS KNOWN-GOOD", self.text)

    def test_post_deploy_verification_covers_required_checks(self):
        for item in ("deployed release identity", "V2 aggregate recomputed",
                     "runtime identity", "dependency identity",
                     "credential state present", "service healthy",
                     "worker registration", "controller/worker communication"):
            with self.subTest(item=item):
                self.assertIn(item, self.text)

    def test_elevated_gates_reported_pending_not_pass(self):
        self.assertIn("BLOCKED_PENDING_ELEVATED_EXECUTION", self.text)
        self.assertIn("must be reported as pending, never as PASS", self.text)
        self.assertIn("WINDOWS_NATIVE_VOLUME_GATE", self.text)
        self.assertIn("RUNTIME_SERVICE_PERSONAL_PROFILE_DENIAL_GATE", self.text)

    def test_cwd_requirement_documented(self):
        """Section 23: F11 CWD debt closed by documentation."""
        self.assertIn("Run all release commands from the repository root", self.text)
        self.assertIn("current working directory", self.flat)


class UnsafeRecommendationTests(unittest.TestCase):
    """Section 24: docs must not recommend an unsafe action anywhere."""

    UNSAFE = (
        "--token",
        "-Token $",
        "DEVAI_WORKER_TOKEN",
        "token=plaintext",
        "copy worker.dpapi into the release",
        "add worker.dpapi to the release",
        "disable the reparse",
        "skip the reparse",
        "disable the acl",
        "weaken the acl",
        "edit manifest.json to",
        "modify manifest.json to match",
        "pip install -r requirements.in",
        "install from requirements.in",
    )

    def test_no_unsafe_recommendations_in_any_doc(self):
        """A banned phrase is only an offence when it is RECOMMENDED.

        Prohibitions ("Do not weaken the ACL") legitimately contain the very
        phrase they forbid, so a naive substring scan reports them as
        violations. Each hit is therefore checked against negation markers on
        the same line.
        """
        offenders = []
        for path in sorted(DOCS.glob("*.md")):
            for number, line in enumerate(doc_text(path).splitlines(), 1):
                lowered = line.lower()
                for needle in self.UNSAFE:
                    if needle.lower() not in lowered:
                        continue
                    if any(marker in lowered for marker in NEGATION_MARKERS):
                        continue
                    offenders.append(f"{path.name}:{number}: {needle}")
        self.assertEqual([], offenders,
                         "documentation recommends an unsafe action: "
                         + "; ".join(offenders))

    def test_prohibitions_are_actually_present(self):
        """Guard the scanner itself: the docs must forbid the unsafe actions."""
        worker = flat(doc_text(WORKER_DOC)).lower()
        for prohibition in ("do not weaken the acl",
                            "never place the token",
                            "must not be simulated with mocks",
                            "do not bypass a security check"):
            with self.subTest(prohibition=prohibition):
                self.assertIn(prohibition, worker)

    def test_worker_doc_does_not_show_token_in_argv_or_env(self):
        text = doc_text(WORKER_DOC)
        # A code fence must never contain a token assignment to argv or env.
        for bad in ("$env:DEVAI", "-WorkerToken", "--worker-token",
                    "-Token '", "echo $token"):
            self.assertNotIn(bad, text)

    def test_release_doc_has_no_secret_in_examples(self):
        text = doc_text(RELEASE_DOC)
        for bad in ("-WorkerToken", "--token", "worker.dpapi --store"):
            self.assertNotIn(bad, text)


class ReleaseJsonHygieneTests(unittest.TestCase):
    """Section 1: optional capability fields are omitted, never faked."""

    def test_optional_fields_absent_from_release_json_schema(self):
        source = (TOOLS / "build-release.py").read_text(encoding="utf-8")
        for field in ("sbom", "signature", "provenance"):
            with self.subTest(field=field):
                self.assertNotIn('"%s":' % field, source)
                self.assertNotIn("'%s':" % field, source)

    def test_no_placeholder_null_or_empty_objects_emitted(self):
        for tool in ("build-release.py", "verify-release.py", "release_lib.py"):
            source = (TOOLS / tool).read_text(encoding="utf-8")
            for banned in ('"sbom": None', "'sbom': None",
                           '"signature": None', "'signature': None",
                           '"provenance": None', "'provenance': None"):
                with self.subTest(tool=tool, banned=banned):
                    self.assertNotIn(banned, source)

    def test_optional_sections_are_name_only_reservations(self):
        """The verifier tolerates these names but requires no value."""
        source = (TOOLS / "verify-release.py").read_text(encoding="utf-8")
        self.assertIn("OPTIONAL_SECTIONS", source)
        self.assertIn("sbom", source)
        self.assertIn("signature", source)
        self.assertIn("provenance", source)

    def test_emitted_release_json_has_no_optional_sections(self):
        """End-to-end: a real build emits only required sections."""
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                ["python", str(TOOLS / "build-release.py"),
                 "--output-dir", tmp, "--allow-dirty-worktree"],
                capture_output=True, text=True, cwd=str(REPO), timeout=600)
            self.assertEqual(0, result.returncode, result.stderr)
            tarball = next(Path(tmp).glob("*.tar"))
            with tarfile.open(tarball) as archive:
                document = json.loads(
                    archive.extractfile("release.json").read().decode("utf-8"))
        for field in ("sbom", "signature", "provenance"):
            self.assertNotIn(field, document)
        for value in document.values():
            self.assertIsNotNone(value)
            self.assertNotEqual({}, value)


class BomScanTests(unittest.TestCase):
    """Section 22: F10 BOM hygiene."""

    TEXT_SUFFIXES = {".md", ".py", ".ps1", ".json", ".txt"}

    def test_no_utf8_bom_in_tracked_text_files(self):
        offenders = []
        for path in REPO.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.suffix.lower() not in self.TEXT_SUFFIXES:
                continue
            data = path.read_bytes()
            if data[:3] == b"\xef\xbb\xbf":
                offenders.append(str(path.relative_to(REPO)))
        self.assertEqual([], offenders, "UTF-8 BOM present: " + ", ".join(offenders))

    def test_protected_trees_were_not_touched_for_eol(self):
        """Trailing-EOL debt inside protected trees is documented, not 'fixed'."""
        for tree, expected in (("controller/devai", "ddc349d72ca32ec55e41357db6f231dcd178004b"),
                               ("worker_agent", "2d688436cf088b0a52698f1a46e475639243c230"),
                               ("migrations", "76ba0edfcfc65a5de0527881d6b56f755b8d653e")):
            with self.subTest(tree=tree):
                out = subprocess.run(["git", "-C", str(REPO), "rev-parse",
                                      "HEAD:%s" % tree],
                                     capture_output=True, text=True, timeout=120)
                self.assertEqual(expected, out.stdout.strip())
        status = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain",
                                 "--", "controller/devai", "worker_agent", "migrations"],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual("", status.stdout.strip())


if __name__ == "__main__":
    unittest.main()