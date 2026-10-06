"""RH-B 5A-2B: consumer retirement, installer ACL policy, service ordering,
trust-anchor preservation and secret-containment gates.

The ACL test drives a REAL NTFS fixture through the production helper and
inspects the resulting descriptor structurally. It does not mock Get-Acl, and
it does not claim to prove the runtime denial property.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parent.parent
DEPLOY = REPO / "deploy" / "windows"
HARNESS = REPO / "tests" / "windows"
INSTALLER = DEPLOY / "install-worker.ps1"
SUPPORT = DEPLOY / "install-support.ps1"
LAUNCHER = DEPLOY / "launch-worker-install.ps1"

ENABLED = os.name == "nt" and bool(os.environ.get("SystemRoot"))


def run_ps1(script: Path, timeout=120):
    env = {**os.environ,
           "PSModulePath": str(Path(os.environ["SystemRoot"]) / "System32"
                               / "WindowsPowerShell" / "v1.0" / "Modules")}
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
         "Bypass", "-File", str(script)],
        capture_output=True, text=True, timeout=timeout, env=env)


# The five former package.json consumers, plus the installer and launcher.
MIGRATED = [
    "diagnose-worker-workspace-access.ps1",
    "repair-worker-workspace.ps1",
    "update-worker-access-diagnostic.ps1",
    "update-worker-capacity.ps1",
    "update-worker-startup-diagnostic.ps1",
]


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class PackageJsonRetirementTests(unittest.TestCase):
    """Section 11: no executable package.json consumer may survive."""

    def test_no_migrated_consumer_references_package_json(self):
        for name in MIGRATED:
            with self.subTest(script=name):
                source = (DEPLOY / name).read_text(encoding="utf-8")
                self.assertNotIn("package.json", source)
                self.assertNotIn("$package", source)

    def test_installer_and_launcher_have_no_package_json_dependency(self):
        for path in (INSTALLER, LAUNCHER):
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                self.assertNotIn("$package", source)
                self.assertNotIn("package.files", source)
        self.assertEqual(0, LAUNCHER.read_text(encoding="utf-8").count("package.json"))

    def test_legacy_reference_in_installer_is_detection_only(self):
        """The only package.json use left is controlled fail-closed DETECTION."""
        source = INSTALLER.read_text(encoding="utf-8")
        hits = [ln.strip() for ln in source.splitlines() if "package.json" in ln]
        self.assertTrue(hits)
        for line in hits:
            self.assertTrue(
                line.startswith("#") or "Test-Path" in line,
                f"non-detection package.json reference: {line}")
        self.assertIn("UNSUPPORTED_LEGACY_PACKAGE_FORMAT", source)

    def test_no_dual_shape_seam_in_helper_layer(self):
        """The temporary compatibility seam must not survive."""
        source = SUPPORT.read_text(encoding="utf-8")
        for banned in ("TEMPORARY", "isDictionary",
                       "PSObject.Properties[$prop.Name]"):
            self.assertNotIn(banned, source)
        # Exactly one release digest source, read from a validated manifest.
        self.assertIn("foreach ($key in $ReleaseManifest.Files.Keys)", source)

    def test_migrated_consumers_anchor_manifest_json(self):
        for name in MIGRATED:
            with self.subTest(script=name):
                source = (DEPLOY / name).read_text(encoding="utf-8")
                self.assertIn("manifest.json", source)
                self.assertIn("ExpectedManifestSHA256", source)
                self.assertIn("Read-ReleaseManifest", source)

    def test_legacy_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text("{}", encoding="utf-8")
            script = Path(temp) / "probe.ps1"
            script.write_text(
                "$ErrorActionPreference='Stop'\n"
                f"& '{INSTALLER}' -PackageRoot '{root}' -ValidateOnly\n",
                encoding="utf-8")
            result = run_ps1(script)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("UNSUPPORTED_LEGACY_PACKAGE_FORMAT",
                          result.stdout + result.stderr)


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class TrustAnchorPreservationTests(unittest.TestCase):
    """Section 1: both external anchors must still exist and stay independent."""

    def test_launcher_retains_both_external_anchors(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("ExpectedManifestSHA256", source)
        self.assertIn("ExpectedInstallerSHA256", source)
        self.assertIn("PACKAGE_MANIFEST_CHANGED", source)
        self.assertIn("PACKAGE_INSTALLER_CHANGED", source)

    def test_installer_anchor_is_a_separate_check_not_derived_from_manifest(self):
        """A valid payload manifest must NOT be able to authorise the script."""
        source = LAUNCHER.read_text(encoding="utf-8")
        installer_check = source[source.index("$installer="):source.index("$phase='package_validation'")]
        self.assertIn("Get-FileHash", installer_check)
        self.assertIn("$ExpectedInstallerSHA256", installer_check)
        self.assertNotIn("Get-ManifestFileDigest", installer_check)
        self.assertNotIn("$manifest.Files", installer_check)

    def test_installer_anchor_precedes_execution(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertLess(source.index("$ExpectedInstallerSHA256.ToLowerInvariant()"),
                        source.index("& $installer -PackageRoot $PackageRoot"))

    def test_launcher_forwards_target_inputs(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        for name in ("$WorkerId", "$ApiBaseUrl", "$ExistingConfig"):
            self.assertIn(name, source)
        self.assertEqual(2, source.count("-WorkerId $WorkerId -ApiBaseUrl $ApiBaseUrl"))


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class RealAclPolicyTests(unittest.TestCase):
    """Sections 5/6/8: real NTFS ACL coverage for the denial fixture."""

    def test_real_ntfs_fixture_acl_policy(self):
        result = run_ps1(HARNESS / "test_personal_fixture_acl.ps1", timeout=180)
        self.assertEqual(0, result.returncode, result.stderr)
        report = json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report["passed"])
        self.assertEqual("REAL_NTFS", report["acl_harness"])
        # The recovered historical model, asserted structurally.
        self.assertTrue(report["dacl_protected"])
        self.assertEqual(3, report["ace_count"])
        principal_set = set(report["principals"])
        self.assertEqual(3, len(principal_set))
        self.assertIn("S-1-5-18", principal_set)
        self.assertIn("S-1-5-32-544", principal_set)
        owner = principal_set - {"S-1-5-18", "S-1-5-32-544"}
        self.assertEqual(1, len(owner))
        self.assertRegex(owner.pop(), r"^S-1-5-21(-\d+)+$")
        self.assertFalse(report["service_sid_ace_present"])
        self.assertFalse(report["broad_principal_ace_present"])
        self.assertTrue(report["reparse_fixture_rejected"])
        self.assertTrue(report["reparse_parent_rejected"])
        self.assertTrue(report["forbidden_location_rejected"])
        # The runtime denial property is explicitly NOT claimed here.
        self.assertEqual("BLOCKED_PENDING_ELEVATED_EXECUTION",
                         report["runtime_denial_gate"])

    def test_service_sid_ace_would_be_rejected(self):
        """The validator must refuse a fixture that grants the worker identity."""
        with tempfile.TemporaryDirectory() as temp:
            probe = Path(temp) / "probe.ps1"
            probe.write_text(
                "$ErrorActionPreference='Stop'\n"
                f". '{SUPPORT}'\n"
                "$d=Join-Path $env:USERPROFILE 'rhb-svc-probe.fixture'\n"
                "[IO.File]::WriteAllText($d,'x')\n"
                "$sid='S-1-5-80-1-2-3-4-5'\n"
                "$acl=New-Object Security.AccessControl.FileSecurity\n"
                "$acl.SetAccessRuleProtection($true,$false)\n"
                "$me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n"
                "foreach($i in @('S-1-5-18','S-1-5-32-544',$sid))"
                "{$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("
                "[Security.Principal.SecurityIdentifier]::new($i),'FullControl','None','None','Allow')))}\n"
                "([IO.FileInfo]$d).SetAccessControl($acl)\n"
                # Owner is declared as the service SID so the expected 3-principal set MATCHES
                # and the dedicated service-read check is the one that must fire.
                "try{Assert-TargetPersonalDenialFixture -Fixture $d -OwnerSid $sid "
                "-ServiceSid $sid | Out-Null; Write-Output 'ACCEPTED'}\n"
                "catch{Write-Output ('REJECTED:'+$_.Exception.Message)}\n"
                "[IO.File]::Delete($d)\n", encoding="utf-8")
            result = run_ps1(probe)
            self.assertIn("REJECTED", result.stdout)
            self.assertNotIn("ACCEPTED", result.stdout)
            self.assertIn("PERSONAL_FIXTURE_SERVICE_READ_GRANTED", result.stdout)


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class ServiceStartOrderTests(unittest.TestCase):
    """Section 10: AST call-order, not source-line matching."""

    #: The resume/inspect branch returns early and legitimately starts services
    #: before the fresh-install fixture exists. Ordering is therefore asserted
    #: against the FRESH-INSTALL region only.
    FRESH_INSTALL_ANCHOR = "EXISTING_SERVICE_REQUIRES_REVIEWED_UPGRADE"

    def _offsets(self, names, min_offset=0):
        script = Path(tempfile.mkdtemp()) / "order.ps1"
        script.write_text(
            "$t=$null;$e=$null\n"
            f"$a=[Management.Automation.Language.Parser]::ParseFile('{INSTALLER}',[ref]$t,[ref]$e)\n"
            "$names=@(" + ",".join("'" + n + "'" for n in names) + ")\n"
            f"$min={int(min_offset)}\n"
            "$r=@{}\n"
            "foreach($c in $a.FindAll({param($n) $n -is "
            "[Management.Automation.Language.CommandAst]},$true)){\n"
            "  $n=$c.GetCommandName()\n"
            "  if($c.Extent.StartOffset -lt $min){continue}\n"
            "  if($names -contains $n -and -not $r.ContainsKey($n)){$r[$n]=$c.Extent.StartOffset}}\n"
            "$r | ConvertTo-Json -Compress\n", encoding="utf-8")
        result = run_ps1(script)
        return {k: int(v) for k, v in json.loads(result.stdout.strip()).items()}

    def test_immutable_gate_precedes_all_fresh_install_mutations(self):
        source = INSTALLER.read_text(encoding="utf-8")
        fresh = source.index(self.FRESH_INSTALL_ANCHOR)
        offsets = self._offsets(["New-TargetPersonalDenialFixture",
                                 "New-Service", "Start-Service"], fresh)
        gate = source.index("Assert-ManifestIdentityAggregate")
        for name, offset in offsets.items():
            self.assertLess(gate, fresh + offset,
                            f"{name} precedes the immutable gate")

    def test_required_start_order(self):
        required = [
            "Read-ReleaseManifest",
            "Assert-ManifestPayload",
            "Assert-ManifestIdentityAggregate",
            "New-TargetPersonalDenialFixture",
            "Invoke-TargetCredentialProvisioning",
            "New-Service",
            "Start-Service",
        ]
        source = INSTALLER.read_text(encoding="utf-8")
        fresh = source.index(self.FRESH_INSTALL_ANCHOR)
        immutable_order = ["Read-ReleaseManifest", "Assert-ManifestPayload",
                           "Assert-ManifestIdentityAggregate"]
        mutation_order = ["New-TargetPersonalDenialFixture",
                          "Invoke-TargetCredentialProvisioning",
                          "New-Service", "Start-Service"]
        immutable = self._offsets(immutable_order)
        mutation = self._offsets(mutation_order, fresh)
        for name in immutable_order + mutation_order:
            self.assertIn(name, list(immutable) + list(mutation),
                          f"stage not found: {name}")
        self.assertEqual(
            [immutable[n] for n in immutable_order],
            sorted(immutable[n] for n in immutable_order),
            f"immutable verification out of order: {immutable}")
        self.assertEqual(
            [mutation[n] for n in mutation_order],
            sorted(mutation[n] for n in mutation_order),
            f"target provisioning out of order: {mutation}")
        self.assertLess(max(immutable.values()),
                        min(fresh + mutation[n] for n in mutation_order),
                        "a target mutation precedes the immutable verification")

    def test_every_required_stage_is_present(self):
        for name in ("Read-ReleaseManifest", "Assert-ManifestPayload",
                     "Assert-ManifestIdentityAggregate",
                     "New-TargetPersonalDenialFixture",
                     "Invoke-TargetCredentialProvisioning",
                     "New-Service", "Start-Service"):
            with self.subTest(stage=name):
                self.assertIn(name, INSTALLER.read_text(encoding="utf-8"))

    def test_credential_check_precedes_service_start(self):
        source = INSTALLER.read_text(encoding="utf-8")
        fresh = source.index(self.FRESH_INSTALL_ANCHOR)
        self.assertLess(source.index("CREDENTIAL_PROVISIONING_FAILED", fresh),
                        source.index("Start-Service -Name DevAIWorker", fresh))
        # The resume path validates the credential ACL via Assert-PartialWorkerInstall.
        self.assertLess(source.index("Assert-PartialWorkerInstall $installRoot"),
                        source.index("Start-Service -Name DevAIWorker"))

    def test_no_mutation_before_immutable_verification(self):
        """The immutable gate must complete before any target mutation."""
        source = INSTALLER.read_text(encoding="utf-8")
        gate = source.index("Assert-ManifestIdentityAggregate")
        for mutation in ("New-Item -ItemType Directory", "Set-ManagedAcl ",
                         "New-TargetPersonalDenialFixture", "New-Service ",
                         "Start-Service "):
            self.assertLess(gate, source.index(mutation),
                            f"mutation {mutation!r} precedes the immutable gate")


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class SecretContainmentTests(unittest.TestCase):
    """Section 18: the token must not reach argv, env, config, or the artifact."""

    def test_token_never_reaches_argv_or_environment(self):
        source = SUPPORT.read_text(encoding="utf-8")
        body = source[source.index("function Invoke-TargetCredentialProvisioning"):]
        argv = re.search(r"\$psi\.Arguments\s*=\s*(.+)", body).group(1)
        self.assertNotIn("Token", argv)
        self.assertNotIn("--token", argv)
        self.assertNotIn("$env:", body.replace("$env:SystemRoot", ""))

    def test_token_is_delivered_only_over_redirected_stdin(self):
        source = SUPPORT.read_text(encoding="utf-8")
        body = source[source.index("function Invoke-TargetCredentialProvisioning"):]
        self.assertIn("RedirectStandardInput=$true", body)
        # The writer is taken into a local because Process.StandardInput is
        # read-only: assigning to the property throws PropertyAssignmentException
        # and killed every fresh install (RH-D). The local must write, flush
        # and close; the property itself must never be assigned.
        self.assertIn("$stdinWriter=$process.StandardInput", body)
        self.assertIn("$stdinWriter.Write($Token)", body)
        self.assertIn("$stdinWriter.Flush()", body)
        self.assertIn("$stdinWriter.Close()", body)
        self.assertNotIn("$process.StandardInput=", body)
        # The provision child resolves worker_agent through the one canonical
        # isolated-module helper (the embedded interpreter honors neither cwd
        # nor PYTHONPATH for -m resolution, proven on RH-D).
        self.assertIn("Get-IsolatedModuleArguments", body)
        self.assertIn("'worker_agent.provision'", body)
        self.assertNotIn("-m worker_agent", body)

    def test_bstr_is_freed(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("ZeroFreeBSTR", source)
        self.assertIn("finally", source)

    def test_service_json_schema_excludes_secrets(self):
        source = INSTALLER.read_text(encoding="utf-8")
        start = source.index("$config=@{")
        end = source.index("ConvertTo-Json", start)
        block = source[start:end]
        lowered = block.lower()
        for banned in ("token", "dpapi", "password", "secret"):
            self.assertNotIn(banned, lowered)

    def test_manifest_declares_policy_not_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sys_path = root / "control" / "worker_agent"
            sys_path.mkdir(parents=True)
            (sys_path / "windows_service.py").write_bytes(b"# svc\n")
            shutil.copy2(SUPPORT, root / "install-support.ps1")
            shutil.copy2(INSTALLER, root / "install-worker.ps1")
            entries = []
            for path in sorted(root.rglob("*")):
                if path.is_file() and path.name != "manifest.json":
                    data = path.read_bytes()
                    entries.append({"path": path.relative_to(root).as_posix(),
                                    "sha256": hashlib.sha256(data).hexdigest(),
                                    "size": len(data)})
            doc = {"manifest_format": "DEVAI_PACKAGE_MANIFEST",
                   "manifest_schema_version": 1, "files": entries,
                   "policy_requirements": ["requires_worker_credential"],
                   "identity": {"format": "MANIFEST_FORMAT_V2", "aggregate_sha256": "0" * 64},
                   "runtime": {"python_version": "3.13.16", "source_sha256": "1" * 64}}
            (root / "manifest.json").write_text(json.dumps(doc), encoding="utf-8")
            blob = json.dumps(doc)
            self.assertNotIn("worker.dpapi", blob)
            self.assertNotIn("token", blob)


@unittest.skipUnless(ENABLED, "Windows PowerShell required")
class ServiceCommandResolutionTests(unittest.TestCase):
    """The service BinaryPathName must resolve the package without cwd help.

    RH-D: `-m worker_agent.windows_service` could never import the package,
    because SCM starts the service with cwd=System32 and the pinned embedded
    interpreter honors neither cwd nor PYTHONPATH (python313._pth) nor site.
    Resolution must go through the one canonical helper shared with credential
    provisioning, with the isolation flags and argument tail untouched."""

    def test_service_command_does_not_depend_on_dash_m_resolution(self):
        source = SUPPORT.read_text(encoding="utf-8")
        body = source[source.index("function Get-WorkerServiceCommand"):]
        body = body[:body.index("\n}")]
        code = "\n".join(line for line in body.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertNotIn("-m worker_agent", code)
        self.assertIn("Get-IsolatedModuleArguments", code)
        self.assertIn(" -I -S -B ", code)

    def test_provisioning_and_service_share_one_canonical_invocation(self):
        source = SUPPORT.read_text(encoding="utf-8")
        # Exactly two consumers: provisioning and the service command. Any
        # third inline invocation shape would be drift.
        self.assertEqual(
            len(re.findall(r"Get-IsolatedModuleArguments\s+-ControlDir", source)), 2)
        for stale in ("-m worker_agent.provision", "-m worker_agent.windows_service"):
            self.assertNotIn(stale, source)
        helper = source[source.index("function Get-IsolatedModuleArguments"):]
        helper = helper[:helper.index("\n}")]
        code = "\n".join(line for line in helper.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertIn("sys.path.insert", code)
        self.assertIn("runpy.run_module", code)
        # Isolation flags stay with the caller, which owns them.
        self.assertNotIn("-I -S -B", code)

    def test_no_isolation_bypass_is_introduced(self):
        source = SUPPORT.read_text(encoding="utf-8")
        code = "\n".join(line for line in source.splitlines()
                         if not line.lstrip().startswith("#"))
        self.assertNotIn("PYTHONPATH", code)
        self.assertNotIn("import site", code)

    def test_resume_and_diagnostics_compare_the_generated_command(self):
        # The resume/partial-install comparison must derive from the same
        # helper, never from a hardcoded legacy command line.
        source = SUPPORT.read_text(encoding="utf-8")
        self.assertNotIn("-m worker_agent", source)
        body = source[source.index("function Assert-PartialWorkerInstall"):]
        self.assertIn("Get-WorkerServiceCommand", body)
        self.assertIn("$worker.PathName -cne $base", body)
        self.assertIn("$base+' --volume-host'", body)


class TrustDomainSeparationTests(unittest.TestCase):
    """Immutable release helpers must not touch target state, and vice versa."""

    @unittest.skipUnless(ENABLED, "Windows PowerShell required")
    def test_immutable_domain_never_reads_service_json(self):
        source = SUPPORT.read_text(encoding="utf-8")
        immutable = source.split("--- A. IMMUTABLE RELEASE")[1].split("--- B. TARGET STATE")[0]
        self.assertNotIn("service.json", immutable)
        self.assertNotIn("worker.dpapi", immutable)

    @unittest.skipUnless(ENABLED, "Windows PowerShell required")
    def test_target_domain_never_authenticates_payload(self):
        source = SUPPORT.read_text(encoding="utf-8")
        target = source.split("--- B. TARGET STATE")[1]
        self.assertNotIn("Get-FileHash", target)
        self.assertNotIn("manifest.json", target)


if __name__ == "__main__":
    unittest.main()