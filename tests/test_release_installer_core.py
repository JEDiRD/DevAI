"""RH-B 5A-2A: installer core + manifest trust-chain migration.

These tests drive the REAL PowerShell helper and installer code, not a
reimplementation. Each negative case must fail closed with its specific
control code.

Trust model under test:
  * The launcher holds the EXTERNAL trust anchor (caller-supplied digest).
  * install-worker.ps1 verifies internal consistency from verified bytes.
  * Internal consistency is NOT release authenticity, and is never called so.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy" / "windows"
SUPPORT = DEPLOY / "install-support.ps1"
INSTALLER = DEPLOY / "install-worker.ps1"
LAUNCHER = DEPLOY / "launch-worker-install.ps1"

ENABLED = os.name == "nt" and bool(
    os.environ.get("SystemRoot"))


def ps(script, *args):
    """Run a PowerShell snippet and return (exit_code, stdout, stderr)."""
    tmp = Path(tempfile.mkdtemp())
    try:
        path = tmp / "probe.ps1"
        path.write_text(script, encoding="utf-8")
        env = {**os.environ,
               "PSModulePath": str(Path(os.environ["SystemRoot"]) / "System32"
                                   / "WindowsPowerShell" / "v1.0" / "Modules")}
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(path), *args],
            capture_output=True, text=True, timeout=120, env=env)
        return result.returncode, result.stdout, result.stderr
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def make_package(root: Path, *, extra_files=(), runtime=False):
    """Build a minimal but structurally valid release package.

    manifest.json is OUTSIDE files[] (it cannot hash itself); every other
    immutable member is inside.
    """
    (root / "control" / "worker_agent").mkdir(parents=True, exist_ok=True)
    (root / "control" / "worker_agent" / "windows_service.py").write_bytes(b"# svc\n")
    (root / "control" / "worker_agent" / "provision.py").write_bytes(b"# prov\n")
    shutil.copy2(INSTALLER, root / "install-worker.ps1")
    shutil.copy2(SUPPORT, root / "install-support.ps1")
    if runtime:
        rt = root / "host-runtime"
        rt.mkdir(parents=True, exist_ok=True)
        (rt / "python.exe").write_bytes(b"MZfake")
    for name, body in extra_files:
        (root / name).write_bytes(body)

    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel == "manifest.json":
            continue
        data = path.read_bytes()
        files.append({"path": rel, "sha256": hashlib.sha256(data).hexdigest(),
                      "size": len(data)})
    files.sort(key=lambda f: f["path"].encode("utf-8"))
    doc = {
        "manifest_format": "DEVAI_PACKAGE_MANIFEST",
        "manifest_schema_version": 1,
        "files": files,
        "policy_requirements": [
            "requires_api_base_url", "requires_personal_profile_denial_fixture",
            "requires_worker_credential", "requires_worker_identity"],
        "identity": {"format": "MANIFEST_FORMAT_V2", "aggregate_sha256": "0" * 64},
        "runtime": {"python_version": "3.13.16", "source_sha256": "1" * 64},
    }
    (root / "manifest.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
    return doc


# The V2 aggregate must be recomputed the same way on both sides, so the test
# seeds a correct value using the canonical algorithm.
def seed_aggregate(root: Path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "rb", REPO / "deploy" / "windows" / "build-package.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    entries = [(f["path"], (root / f["path"]).read_bytes())
               for f in doc["files"]]
    aggregate = hashlib.sha256(mod.serialize_manifest_v2(entries)).hexdigest()
    doc["identity"]["aggregate_sha256"] = aggregate
    (root / "manifest.json").write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
    return aggregate


def try_validate(root: Path):
    """Run install-worker.ps1 -ValidateOnly; return the control code."""
    code, out, err = ps(
        "$ErrorActionPreference='Stop'\n"
        "& $args[0] -PackageRoot $args[1] -ValidateOnly\n",
        str(INSTALLER), str(root))
    if code == 0 and "DEVAI_PACKAGE_VALIDATED" in out:
        return "PASS"
    text = (out + err)
    for marker in ("UNSUPPORTED_LEGACY_PACKAGE_FORMAT", "MANIFEST_MISSING",
                   "MANIFEST_NOT_VALID_JSON", "MANIFEST_HAS_BOM",
                   "UNSUPPORTED_MANIFEST_FORMAT",
                   "UNSUPPORTED_MANIFEST_SCHEMA_VERSION",
                   "MANIFEST_FILES_MISSING", "UNSAFE_MANIFEST_PATH",
                   "MANIFEST_PATH_COLLISION", "MANIFEST_FILE_MISSING",
                   "MANIFEST_SIZE_MISMATCH", "MANIFEST_HASH_MISMATCH",
                   "MANIFEST_IDENTITY_AGGREGATE_MISMATCH",
                   "UNMANIFESTED_PACKAGE_FILE", "REQUIRED_MANIFEST_MEMBER_MISSING"):
        if marker in text:
            return marker
    return "UNEXPECTED:" + text.strip()[-200:]


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class TrustAnchorTests(unittest.TestCase):
    """Section 1: the EXTERNAL anchor must survive the migration."""

    def test_launcher_no_longer_references_package_json(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertNotIn("package.json", source)

    def test_launcher_anchors_manifest_json(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("manifest.json", source)
        self.assertIn("ExpectedManifestSHA256", source)
        self.assertIn("PACKAGE_MANIFEST_CHANGED", source)

    def test_launcher_missing_manifest_is_a_controlled_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            code, out, err = ps(
                "$ErrorActionPreference='Stop'\n"
                "& $args[0] -PackageRoot $args[1] -ExpectedManifestSHA256 ('a'*64) "
                "-ExpectedInstallerSHA256 ('a'*64) -ResultPath (Join-Path $args[1] 'r.json') -DiagnoseOnly\n",
                str(LAUNCHER), str(root))
            self.assertNotEqual(0, code)
            self.assertIn("UNSUPPORTED_LEGACY_PACKAGE_FORMAT", out + err)

    def test_launcher_rejects_manifest_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            code, out, err = ps(
                "$ErrorActionPreference='Stop'\n"
                "& $args[0] -PackageRoot $args[1] -ExpectedManifestSHA256 ('0'*64) "
                "-ExpectedInstallerSHA256 ('0'*64) -ResultPath (Join-Path $args[1] 'r.json') -DiagnoseOnly\n",
                str(LAUNCHER), str(root))
            self.assertNotEqual(0, code)
            self.assertIn("PACKAGE_MANIFEST_CHANGED", out + err)

    def test_launcher_accepts_correct_manifest_hash(self):
        """Correct external digest must get PAST the anchor to validation."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            seed_aggregate(root)
            digest = hashlib.sha256(
                (root / "manifest.json").read_bytes()).hexdigest()
            code, out, err = ps(
                "$ErrorActionPreference='Stop'\n"
                "& $args[0] -PackageRoot $args[1] -ExpectedManifestSHA256 $args[2] "
                "-ExpectedInstallerSHA256 ('0'*64) -ResultPath (Join-Path $args[1] 'r.json') -DiagnoseOnly\n",
                str(LAUNCHER), str(root), digest)
            # It must NOT fail with PACKAGE_MANIFEST_CHANGED.
            self.assertNotIn("PACKAGE_MANIFEST_CHANGED", out + err)

    def test_modified_payload_with_updated_aggregate_still_needs_anchor(self):
        """An attacker who rewrites the manifest cannot move the external anchor.

        Even with the internal aggregate recomputed to match, the caller-supplied
        digest no longer matches. This is the property that would be LOST if the
        anchor were replaced by self-consistency.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            seed_aggregate(root)
            original = hashlib.sha256(
                (root / "manifest.json").read_bytes()).hexdigest()
            # Attacker: modify a payload file and rebuild a consistent manifest.
            (root / "control" / "worker_agent" / "provision.py").write_bytes(b"# evil\n")
            seed_aggregate(root)
            code, out, err = ps(
                "$ErrorActionPreference='Stop'\n"
                "& $args[0] -PackageRoot $args[1] -ExpectedManifestSHA256 $args[2] "
                "-ExpectedInstallerSHA256 ('0'*64) -ResultPath (Join-Path $args[1] 'r.json') -DiagnoseOnly\n",
                str(LAUNCHER), str(root), original)
            self.assertNotEqual(0, code)
            self.assertIn("PACKAGE_MANIFEST_CHANGED", out + err)


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class BootstrapModelTests(unittest.TestCase):
    """Section 2: manifest.json is the ONLY unmanifested exemption."""

    def _pkg_with_evil(self, temp, name):
        """Add a file that is NOT in files[] - the actual bootstrap threat."""
        root = Path(temp)
        make_package(root)
        seed_aggregate(root)
        (root / name).write_bytes(b"{}" if name.endswith(".json") else b"x")
        return root

    def test_manifest_json_is_the_only_exemption(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            seed_aggregate(root)
            self.assertEqual("PASS", try_validate(root))

    def test_unexpected_txt_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg_with_evil(temp, "evil.txt")
            self.assertEqual("UNMANIFESTED_PACKAGE_FILE", try_validate(root))

    def test_unexpected_json_is_rejected(self):
        """No broad *.json exemption: an unmanifested evil.json must fail."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg_with_evil(temp, "evil.json")
            self.assertEqual("UNMANIFESTED_PACKAGE_FILE", try_validate(root))

    def test_unexpected_nested_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg_with_evil(temp, "evil.json")
            (root / "control" / "evil.json").write_bytes(b"{}")
            self.assertEqual("UNMANIFESTED_PACKAGE_FILE", try_validate(root))

    def test_unexpected_lock_like_json_is_rejected(self):
        """A plausible metadata name must not be exempted by name pattern."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg_with_evil(temp, "runtime-lock.json")
            self.assertEqual("UNMANIFESTED_PACKAGE_FILE", try_validate(root))


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class ManifestGateTests(unittest.TestCase):
    """Section 15: every manifest negative must fail closed."""

    def _pkg(self, temp, **kw):
        root = Path(temp)
        make_package(root, **kw)
        seed_aggregate(root)
        return root

    def test_valid_package_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual("PASS", try_validate(self._pkg(temp)))

    def test_missing_manifest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            (root / "manifest.json").unlink()
            self.assertEqual("MANIFEST_MISSING", try_validate(root))

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            (root / "manifest.json").write_text("{not json", encoding="utf-8")
            self.assertEqual("MANIFEST_NOT_VALID_JSON", try_validate(root))

    def test_bom(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            (root / "manifest.json").write_bytes(
                b"\xef\xbb\xbf" + (root / "manifest.json").read_bytes())
            self.assertEqual("MANIFEST_HAS_BOM", try_validate(root))

    def test_unsupported_format(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["manifest_format"] = "SOMETHING"
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("UNSUPPORTED_MANIFEST_FORMAT", try_validate(root))

    def test_unsupported_schema(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["manifest_schema_version"] = 99
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("UNSUPPORTED_MANIFEST_SCHEMA_VERSION",
                             try_validate(root))

    def test_traversal_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["files"][0]["path"] = "../escape"
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("UNSAFE_MANIFEST_PATH", try_validate(root))

    def test_absolute_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["files"][0]["path"] = "/etc/passwd"
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("UNSAFE_MANIFEST_PATH", try_validate(root))

    def test_case_collision(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            clone = dict(doc["files"][0])
            clone["path"] = clone["path"].upper()
            doc["files"].append(clone)
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("MANIFEST_PATH_COLLISION", try_validate(root))

    def test_missing_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            (root / "control" / "worker_agent" / "provision.py").unlink()
            self.assertEqual("MANIFEST_FILE_MISSING", try_validate(root))

    def test_modified_member(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            # Same LENGTH on purpose: only the hash differs, so this cannot
            # accidentally pass or fail as a size check.
            target = root / "control" / "worker_agent" / "provision.py"
            target.write_bytes(b"#" * len(target.read_bytes()))
            self.assertEqual("MANIFEST_HASH_MISMATCH", try_validate(root))

    def test_size_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["files"][0]["size"] += 1
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("MANIFEST_SIZE_MISMATCH", try_validate(root))

    def test_identity_aggregate_mismatch(self):
        """A self-consistent-looking manifest with a wrong aggregate fails."""
        with tempfile.TemporaryDirectory() as temp:
            root = self._pkg(temp)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            doc["identity"]["aggregate_sha256"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            self.assertEqual("MANIFEST_IDENTITY_AGGREGATE_MISMATCH",
                             try_validate(root))

    def test_required_member_absent(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "control" / "worker_agent").mkdir(parents=True)
            (root / "control" / "worker_agent" / "windows_service.py").write_bytes(b"x")
            shutil.copy2(SUPPORT, root / "install-support.ps1")
            shutil.copy2(INSTALLER, root / "install-worker.ps1")
            files = []
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.name != "manifest.json":
                    data = path.read_bytes()
                    files.append({"path": path.relative_to(root).as_posix(),
                                  "sha256": hashlib.sha256(data).hexdigest(),
                                  "size": len(data)})
            doc = {"manifest_format": "DEVAI_PACKAGE_MANIFEST",
                   "manifest_schema_version": 1, "files": files,
                   "policy_requirements": [],
                   "identity": {"format": "MANIFEST_FORMAT_V2",
                                "aggregate_sha256": "0" * 64},
                   "runtime": {"python_version": "3.13.16", "source_sha256": "1" * 64}}
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            # install-support.ps1 itself is missing from this package.
            (root / "install-support.ps1").unlink()
            self.assertEqual("MANIFEST_FILE_MISSING", try_validate(root))


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class LegacyFormatTests(unittest.TestCase):
    """Section 14: old artifacts fail clearly, no crash."""

    def test_package_json_only_artifact_fails_clearly(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(json.dumps(
                {"worker_id": "11111111-1111-4111-8111-111111111111",
                 "api_base_url": "https://127.0.0.1/", "files": {}}),
                encoding="utf-8")
            self.assertEqual("UNSUPPORTED_LEGACY_PACKAGE_FORMAT",
                             try_validate(root))

    def test_install_worker_has_no_package_json_dependency(self):
        """Only the controlled legacy DETECTION may reference package.json."""
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("$package.", source)
        self.assertNotIn("$package[", source)
        self.assertNotIn("package.files", source)
        self.assertIn("UNSUPPORTED_LEGACY_PACKAGE_FORMAT", source)

    def test_install_worker_does_not_ship_worker_dpapi(self):
        """worker.dpapi must be provisioned, never copied out of the release."""
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("Join-Path $PackageRoot 'worker.dpapi'", source)
        self.assertNotIn("Join-Path $PackageRoot \"worker.dpapi\"", source)

    def test_install_worker_provisions_credential_via_stdin_helper(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("Invoke-TargetCredentialProvisioning", source)
        self.assertIn("Read-Host", source)
        self.assertIn("ZeroFreeBSTR", source)
        # The secret must not reach argv, the environment, or a config file.
        self.assertNotIn("--token", source)
        self.assertNotIn("$env:DEVAI", source)

    def test_manifest_contains_no_credential_artifact(self):
        """The release contract must not describe or carry the DPAPI store."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            self.assertNotIn("worker.dpapi", json.dumps(doc))
            self.assertNotIn("worker.dpapi", json.dumps(
                [f["path"] for f in doc["files"]]))


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class TargetIdentityTests(unittest.TestCase):
    """Sections 6-7: identity resolution and the preserved URL policy."""

    def _resolve(self, cli_worker, cli_url, config_json):
        script = (
            "$ErrorActionPreference='Stop'\n"
            f". '{SUPPORT}'\n"
            "$cfg=$null\n"
            "if ($args[3]) { $cfg=$args[3] | ConvertFrom-Json }\n"
            "try {\n"
            "  $r=Resolve-TargetIdentity -CliWorkerId $args[0] -CliApiBaseUrl $args[1] -Config $cfg\n"
            "  Write-Output ('OK:'+$r.WorkerId)\n"
            "} catch { Write-Output ('THROW:'+$_.Exception.Message) }\n")
        _, out, _ = ps(script, cli_worker, cli_url, "", config_json or "")
        return out.strip().splitlines()[-1] if out.strip() else ""

    def test_fresh_install_requires_worker_id(self):
        self.assertIn("THROW:WORKER_ID_REQUIRED", self._resolve("", "", None))

    def test_fresh_install_requires_api_base_url(self):
        self.assertIn("THROW:API_BASE_URL_REQUIRED", self._resolve(
            "11111111-1111-4111-8111-111111111111", "", None))

    def test_invalid_worker_id_rejected(self):
        self.assertIn("THROW:INVALID_WORKER_ID", self._resolve(
            "not-a-uuid", "https://127.0.0.1/", None))

    def test_invalid_api_url_rejected(self):
        self.assertIn("THROW:INVALID_API_BASE_URL", self._resolve(
            "11111111-1111-4111-8111-111111111111", "https://8.8.8.8/", None))

    def test_existing_config_supplies_values(self):
        config = json.dumps({"worker_id": "11111111-1111-4111-8111-111111111111",
                             "api_base_url": "https://127.0.0.1/"})
        self.assertTrue(self._resolve("", "", config).startswith("OK:"))

    def test_worker_id_conflict_fails_closed(self):
        config = json.dumps({"worker_id": "11111111-1111-4111-8111-111111111111",
                             "api_base_url": "https://127.0.0.1/"})
        self.assertIn("THROW:WORKER_ID_CONFLICT", self._resolve(
            "22222222-2222-4222-8222-222222222222", "", config))

    def test_api_url_conflict_fails_closed(self):
        config = json.dumps({"worker_id": "11111111-1111-4111-8111-111111111111",
                             "api_base_url": "https://127.0.0.1/"})
        self.assertIn("THROW:API_BASE_URL_CONFLICT", self._resolve(
            "", "https://127.0.0.2/", config))

    def test_api_url_matrix_unchanged(self):
        """Section 3: the 18-case baseline must be byte-for-byte preserved."""
        expected = {
            "https://127.0.0.1/": True, "http://127.0.0.1/": True,
            "https://127.0.0.1:8443/": True, "https://100.64.0.1/": True,
            "https://100.127.255.1/": True, "https://100.128.0.1/": False,
            "https://[::1]/": True, "https://10.0.0.1/": False,
            "https://192.168.1.1/": False, "https://8.8.8.8/": False,
            "https://example.com/": False, "ftp://127.0.0.1/": False,
            "https://user:pw@127.0.0.1/": False,
            "https://127.0.0.1/path": False, "https://127.0.0.1/?q=1": False,
            "https://127.0.0.1/#f": False, "not a url": False, "/relative/": False,
        }
        cases = "".join(
            f"Write-Output ('{u}|' + (Test-TargetApiBaseUrl '{u}'))\n"
            for u in expected)
        _, out, _ = ps(f"$ErrorActionPreference='Stop'\n. '{SUPPORT}'\n{cases}")
        got = {}
        for line in out.splitlines():
            if "|" in line:
                url, _, value = line.rpartition("|")
                got[url] = value.strip().lower() == "true"
        self.assertEqual(expected, got)
        self.assertEqual(18, len(got))


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class BootstrapAndDomainSeparationTests(unittest.TestCase):
    """Trust domains must stay separate."""

    def test_immutable_helper_does_not_read_service_json(self):
        source = SUPPORT.read_text(encoding="utf-8")
        manifest_section = source.split("--- A. IMMUTABLE RELEASE")[1] \
                                  .split("--- B. TARGET STATE")[0]
        self.assertNotIn("service.json", manifest_section)

    def test_target_helper_does_not_authenticate_payload(self):
        source = SUPPORT.read_text(encoding="utf-8")
        target_section = source.split("--- B. TARGET STATE")[1]
        self.assertNotIn("Get-FileHash", target_section)

    def test_manifest_declares_policy_not_concrete_target_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_package(root)
            doc = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            for banned in ("worker_id", "api_base_url",
                           "personal_denial_fixture", "credential_path"):
                self.assertNotIn(banned, doc)
            self.assertIn("requires_worker_identity", doc["policy_requirements"])


if __name__ == "__main__":
    unittest.main()