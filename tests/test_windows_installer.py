"""Exercise the real installer validator using Windows PowerShell 5.1."""
import json
import importlib.util
import os
import ctypes
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


def _is_elevated():
    """True only under a genuine elevated Windows token. Never faked."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def check_installer_canary(stdout):
    """Enforce the privilege-aware canary branch (RH-D hardening).

    The harness records its ACTUAL privilege via WindowsPrincipal semantics
    (CANARY:IS_ADMIN=) and the boundary it reached
    (CANARY:IDENTITY_GLUE_OK_NEXT=). Non-elevated MUST stop at
    ADMINISTRATOR_INSTALL_REQUIRED; elevated MUST stop at
    MUTATION_INTERCEPTED. Anything else — wrong branch, identity code, or
    missing markers — raises AssertionError with a distinct message, so the
    four bad states are distinguishable. Returns (is_admin, next_code).
    """
    m_admin=re.search(r'^CANARY:IS_ADMIN=(True|False)\s*$',stdout,re.M)
    if not m_admin:
        raise AssertionError('CANARY_MARKER_MISSING:IS_ADMIN')
    is_admin=(m_admin.group(1)=='True')
    m_next=re.search(r'^CANARY:IDENTITY_GLUE_OK_NEXT=(\S+)\s*$',stdout,re.M)
    if not m_next:
        raise AssertionError('CANARY_MARKER_MISSING:IDENTITY_GLUE_OK_NEXT')
    nxt=m_next.group(1)
    if re.match(r'^(EXISTING_CONFIG_|WORKER_ID_|API_BASE_URL_|INVALID_)',nxt):
        raise AssertionError('CANARY_IDENTITY_FAILURE:'+nxt)
    expected='MUTATION_INTERCEPTED' if is_admin else 'ADMINISTRATOR_INSTALL_REQUIRED'
    if nxt!=expected:
        raise AssertionError('CANARY_WRONG_BRANCH:is_admin=%r got=%s want=%s'
                             % (is_admin,nxt,expected))
    return is_admin,nxt


class CanaryParserTests(unittest.TestCase):
    """Deterministic coverage of BOTH canary branches at the parser layer.

    No elevation is faked: these are synthetic harness-output strings that
    prove the branch-selection logic requires the matching boundary. They
    are not native elevated runtime evidence.
    """
    def test_non_admin_requires_admin_boundary(self):
        self.assertEqual(check_installer_canary(
            'CANARY:IS_ADMIN=False\nCANARY:IDENTITY_GLUE_OK_NEXT=ADMINISTRATOR_INSTALL_REQUIRED\n'),
            (False,'ADMINISTRATOR_INSTALL_REQUIRED'))
    def test_admin_requires_interception_boundary(self):
        self.assertEqual(check_installer_canary(
            'CANARY:IS_ADMIN=True\nCANARY:IDENTITY_GLUE_OK_NEXT=MUTATION_INTERCEPTED\n'),
            (True,'MUTATION_INTERCEPTED'))
    def test_non_admin_with_interception_fails(self):
        with self.assertRaisesRegex(AssertionError,'CANARY_WRONG_BRANCH'):
            check_installer_canary(
                'CANARY:IS_ADMIN=False\nCANARY:IDENTITY_GLUE_OK_NEXT=MUTATION_INTERCEPTED\n')
    def test_admin_with_admin_boundary_fails(self):
        with self.assertRaisesRegex(AssertionError,'CANARY_WRONG_BRANCH'):
            check_installer_canary(
                'CANARY:IS_ADMIN=True\nCANARY:IDENTITY_GLUE_OK_NEXT=ADMINISTRATOR_INSTALL_REQUIRED\n')
    def test_identity_regression_fails(self):
        with self.assertRaisesRegex(AssertionError,'CANARY_IDENTITY_FAILURE'):
            check_installer_canary(
                'CANARY:IS_ADMIN=False\nCANARY:IDENTITY_GLUE_OK_NEXT=EXISTING_CONFIG_WORKER_ID_MISSING\n')
    def test_missing_markers_fail(self):
        with self.assertRaisesRegex(AssertionError,'CANARY_MARKER_MISSING'):
            check_installer_canary('INSTALLER_GLUE_CASES_PASSED\n')
        with self.assertRaisesRegex(AssertionError,'CANARY_MARKER_MISSING'):
            check_installer_canary('CANARY:IS_ADMIN=False\n')

@unittest.skipUnless(sys.platform=='win32','Windows PowerShell required')
class InstallerTests(unittest.TestCase):
    def test_installer_identity_glue_no_collision_and_real_resolution_path(self):
        """RH-D: install-worker.ps1 used $existingConfig as if it were distinct
        from the [string] $ExistingConfig parameter. PowerShell is
        case-insensitive, so fresh installs always failed closed with
        EXISTING_CONFIG_WORKER_ID_MISSING. The harness audits the whole
        deploy/windows surface by AST, exercises the real identity glue for
        CLI-only / config-only / matching / conflicting / missing inputs,
        proves the config object (not a String) reaches resolution, and
        records its actual privilege plus the boundary it reached; the
        parser requires the matching boundary for that privilege."""
        script=Path(__file__).parent/'windows'/'test_installer_identity_glue.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=180,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('VARIABLE_COLLISION_AUDIT_PASSED',result.stdout)
        self.assertIn('INSTALLER_GLUE_CASES_PASSED',result.stdout)
        # Privilege-aware canary: the harness reports its actual privilege and
        # the parser requires the matching boundary (never "either is fine").
        is_admin,nxt=check_installer_canary(result.stdout)
        self.assertIn('OUTPUT_CONTRACTS_PASSED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        self.assertEqual(report['collision_sites'],0)
        self.assertEqual(report.get('is_admin'),is_admin)
        canary=[c for c in report['glue_cases'] if c.startswith('CANARY:IDENTITY_GLUE_OK_NEXT=')]
        self.assertEqual(canary,['CANARY:IDENTITY_GLUE_OK_NEXT='+nxt])
        for marker in ('A:CLI_ONLY_PASS','B:CONFIG_ONLY_PASS','C:MATCHING_PASS',
                       'D:CONFLICT_FAILS_CLOSED','E:MISSING_FAILS_CLOSED'):
            self.assertIn(marker,report['glue_cases'])
        for marker in ('ManifestPayload:1xHashtable','ReadConfig:1xPSCustomObject',
                       'Fixture:1xString-fresh-and-existing'):
            self.assertIn(marker,report['output_contracts'])
        self.assertTrue(any(m.startswith('NegativeControl:leak-detected-count=') and not m.endswith('=1')
                            for m in report['output_contracts']))

    def test_installer_payload_preflight_rejects_incomplete_package(self):
        """RH-D: a dropped sandbox-runtime verified clean and died with
        PathNotFound at the copy loop. The installer preflights required
        payload dirs/members before identity, elevation and any mutation;
        a complete package proceeds past both validation and preflight."""
        script=Path(__file__).parent/'windows'/'test_installer_payload_preflight.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=180,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('INSTALLER_PREFLIGHT_CASES_PASSED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        for marker in ('POSITIVE:BEYOND_COPY_POINT',
                       'NEGATIVE_DIR:FAIL_CLOSED_PRE_MUTATION',
                       'NEGATIVE_MEMBER:FAIL_CLOSED_PRE_MUTATION',
                       'MANIFEST_GATE:INTACT'):
            self.assertIn(marker,report['cases'])

    def test_workspace_volume_provisioning_normalizes_fresh_roots(self):
        """RH-D: fresh NTFS workspace volumes came out owned by NETWORK
        SERVICE, which the installer assumed trusted instead of
        establishing. New-PrivateWorkspaceVolume now stamps the trusted
        owner explicitly (new volumes only) before policy verification.
        Non-elevated hosts get the standard blocked marker (exit 0, no
        verdict); elevated hosts run the full normalization, read-back,
        exact-policy, pre-existing-rejection and failure-atomicity proofs."""
        script=Path(__file__).parent/'windows'/'test_workspace_volume_provisioning.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=600,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        if not _is_elevated():
            self.assertIn('BLOCKED_PENDING_ELEVATED_EXECUTION',result.stdout)
            return
        self.assertIn('WORKSPACE_VOLUME_PROVISIONING_PASSED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        for marker in ('FRESH_ROOT:NORMALIZED_AND_READ_BACK',
                       'READBACK:UNBLOCKED',
                       'POLICY:EXACT_OWNER_GROUP_DACL_PROTECTION',
                       'PREEXISTING:REJECTED_NOT_SEIZED',
                       'FAILURE:ATOMIC_NO_SERVICE_NO_CREDENTIAL'):
            self.assertIn(marker,report['cases'])

    def test_credential_provisioning_stdin_writer_closed_no_property_assignment(self):
        """RH-D: the provisioner assigned $null to the read-only
        Process.StandardInput property, killing every fresh install after
        the token prompt. The fix writes/flushes/closes through a local
        writer reference. Proved here with a disposable token and a
        controlled fixture child (no DPAPI, no network, no secrets);
        plus the old shape failing with the reproduced ReadOnly error."""
        script=Path(__file__).parent/'windows'/'test_credential_provisioning.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=600,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('CREDENTIAL_PROVISIONING_CASES_PASSED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        for marker in ('SUCCESS:EXACT_STDIN_CLEAN_ARGV_CLEAN_ENV_REPEATABLE',
                       'FAILURE:PROPAGATED_NO_CREDENTIAL',
                       'NEGATIVE:OLD_SHAPE_REJECTED_WITH_READONLY',
                       'CLEANUP:INTACT_NO_PROPERTY_ASSIGNMENT',
                       'SECRECY:NO_TOKEN_IN_FILES_OR_OUTPUT'):
            self.assertIn(marker,report['cases'])

    def test_provision_child_resolves_package_from_control_dir(self):
        """RH-D mechanism proof: -m worker_agent.provision resolves only
        from a directory containing top-level worker_agent (an empty dir
        yields ModuleNotFoundError). The isolated embedded interpreter
        additionally ignores cwd and PYTHONPATH (python313._pth), which is
        why the product inserts the control dir into sys.path explicitly;
        this test pins the underlying resolution rule with the real module
        (--help needs only stdlib at import; no DPAPI, no network)."""
        repo = Path(__file__).resolve().parent.parent
        # Scrub PYTHONPATH: the child must resolve the package from its
        # working directory alone, exactly like the provision child.
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        ok = subprocess.run(
            [sys.executable, "-m", "worker_agent.provision", "--help"],
            capture_output=True, text=True, timeout=120, cwd=str(repo),
            env=env)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("usage", ok.stdout.lower())
        with tempfile.TemporaryDirectory() as temp:
            bad = subprocess.run(
                [sys.executable, "-m", "worker_agent.provision", "--help"],
                capture_output=True, text=True, timeout=120, cwd=temp,
                env=env)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("ModuleNotFoundError", bad.stderr)

    def test_service_command_resolves_package_outside_the_package_dir(self):
        """RH-D mechanism proof for the service entry point.

        SCM starts DevAIWorker with cwd=System32, and the pinned interpreter
        honors neither cwd nor PYTHONPATH, so the legacy
        `-m worker_agent.windows_service` shape could not import the package on
        any install. The harness runs the EXACT generated service command
        against a real interpreter and the real worker_agent package in the
        production control/ layout from System32, and pins the legacy shape as
        a negative control so the pass cannot come from the environment."""
        script=Path(__file__).parent/'windows'/'test_service_command_resolution.ps1'
        env={k: v for k, v in os.environ.items() if k != 'PYTHONPATH'}
        env['PSModulePath']=str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=1800,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('SERVICE_COMMAND_RESOLUTION_CASES_PASSED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        for marker in ('RESOLVES_FROM_SYSTEM32:EXACT_GENERATED_COMMAND',
                       'VOLUME_HELPER:FLAG_PRESERVED_AND_RESOLVES',
                       'NEGATIVE_CONTROL:LEGACY_DASH_M_REPRODUCES_MODULE_NOT_FOUND',
                       'NO_BYPASS:ISOLATION_FLAGS_AND_NO_ENV_DEPENDENCY'):
            self.assertIn(marker,report['cases'])

    def test_service_access_update_restores_both_files_and_manifest_on_integrity_failure(self):
        script=Path(__file__).parent/'windows'/'test_access_update_rollback.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('ACCESS_UPDATE_AND_ROLLBACK_PASSED',result.stdout)

    def test_workspace_access_diagnostic_distinguishes_reparse_entry_and_target_read_only(self):
        script=Path(__file__).parent/'windows'/'test_workspace_access_diagnostic.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('WORKSPACE_ACCESS_DIAGNOSTIC_PASSED',result.stdout)

    def test_capacity_update_preserves_root_acl_and_rejects_invalid_package_before_mutation(self):
        script=Path(__file__).parent/'windows'/'test_capacity_update.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('CAPACITY_UPDATE_BOUNDARY_PASSED',result.stdout)

    def test_workspace_volume_root_security_native_roundtrip_and_scoped_policy(self):
        script=Path(__file__).parent/'windows'/'test_workspace_security.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('WORKSPACE_ROOT_SECURITY_TEST_PASSED',result.stdout)

    def test_startup_update_validates_before_mutation_and_preserves_system_scope(self):
        script=Path(__file__).parent/'windows'/'test_startup_update.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('STARTUP_UPDATE_VALIDATION_BOUNDARY_PASSED',result.stdout)

    def test_service_diagnostic_redacts_logs_and_is_read_only(self):
        script=Path(__file__).parent/'windows'/'test_service_diagnostic.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('SAFE_SERVICE_DIAGNOSTIC_TEST_PASSED',result.stdout)

    def test_structured_service_creation_and_storage_resume_guards(self):
        script=Path(__file__).parent/'windows'/'test_install_support.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertTrue(report['passed'])
        self.assertTrue(report['service_quoting'])
        self.assertTrue(report['resume_no_format'])
        self.assertEqual(report['storage_rejection_cases'],8)

    def test_legacy_build_inputs_rejected_and_runtime_not_host_derived(self):
        """RH-B: legacy build inputs fail closed; runtime is hash-pinned.

        OLD_ASSERTION: with sys.version_info patched to (3,11), main() raised
        CPYTHON_313_RUNTIME_REQUIRED, the personal probe was not called, and
        --existing-config was accepted as a build input.

        NEW_ASSERTION: the builder accepts no target-specific input at all, and
        the shipped runtime is bound to a hash-pinned artifact rather than to
        whichever interpreter happens to run the build.

        WHY_NOT_WEAKER: the old gate asserted only the BUILDER'S OWN
        interpreter version. A self-check says nothing about which runtime is
        shipped, so it would still pass if the wrong runtime were packaged.
        Binding the artifact by SHA256 and proving host Python cannot influence
        identity covers the same property more strongly.
        """
        builder=Path(__file__).parent.parent/'deploy'/'windows'/'build-package.py'
        spec=importlib.util.spec_from_file_location('devai_package_builder_runtime',builder)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertFalse(hasattr(module,'prepare_personal_fixture'))
        with tempfile.TemporaryDirectory(prefix='devai-runtime-guard-') as temp:
            destination=Path(temp)/'package'
            for legacy in (['--existing-config','unused'],
                           ['--reuse-personal-fixture','unused']):
                with self.assertRaises(module.BuildError):
                    module.main(['--destination',str(destination)]+legacy)
            self.assertFalse(destination.exists())
        lock=module.load_runtime_lock()
        self.assertEqual('3.13.16',lock['python_version'])
        self.assertEqual('97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297',
                         lock['source_sha256'])

    def test_build_creates_no_personal_fixture_and_no_credential(self):
        """RH-B: the immutable package carries no fixture path or credential.

        OLD_ASSERTION: prepare_personal_fixture(owner) created a private,
        non-virtualized fixture with a locked-down ACL and supported reuse.

        NEW_ASSERTION: the immutable build contains no personal fixture, no
        fixture path and no credential material, and is buildable with no
        worker configuration present.

        WHY_NOT_WEAKER: the denial property itself is NOT removed.
        worker_agent/windows_service.py remains byte-identical and still
        enforces service_personal_profile_denied from target-side config; only
        the builder-MACHINE absolute path is removed from immutable identity.
        The fixture's ACL properties move to the target, where they belong,
        and must be re-asserted by the 5A-2 installer tests before any commit.
        """
        builder=Path(__file__).parent.parent/'deploy'/'windows'/'build-package.py'
        spec=importlib.util.spec_from_file_location('devai_package_builder_pf',builder)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertFalse(hasattr(module,'prepare_personal_fixture'))
        for forbidden in ('personal_denial_fixture','service.json','worker.dpapi'):
            self.assertTrue(module._is_forbidden(forbidden),forbidden)
        with tempfile.TemporaryDirectory(prefix='devai-clean-build-') as temp:
            dest=Path(temp)/'pkg'
            module.write_package_files(dest)
            data=module.build_manifest_document(dest)
            self.assertEqual('DEVAI_PACKAGE_MANIFEST',module.verify_manifest(dest,data))
            self.assertFalse((dest/'worker.dpapi').exists())
            document=json.loads(data.decode('utf-8'))
            self.assertEqual('DEVAI_PACKAGE_MANIFEST',document['manifest_format'])
            self.assertIn('requires_personal_profile_denial_fixture',
                          document['policy_requirements'])
            # Structural, not substring: the declarative REQUIREMENT legitimately
            # contains the word "personal"; a concrete fixture PATH must not exist.
            self.assertNotIn('personal_denial_fixture',document)
            self.assertNotIn('worker_id',document)
            self.assertNotIn('api_base_url',document)
            for entry in document['files']:
                self.assertNotIn('worker.dpapi',entry['path'].lower())
                self.assertNotIn('personal_denial_fixture',entry['path'])
                self.assertNotIn('personal-denial.fixture',entry['path'])
            self.assertNotIn('dpapi',[e['path'] for e in document['files']])

    def test_launcher_preserves_original_location_without_secret_text(self):
        script=Path(__file__).parent/'windows'/'test_install_launcher.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('LAUNCHER_DIAGNOSTICS_TEST_PASSED',result.stdout)

    def test_source_paths_and_read_only_package_boundary(self):
        script=Path(__file__).parent/'windows'/'test_installer.ps1'
        # The test runner may inherit a PowerShell 7 module path. Use the actual
        # Windows PowerShell 5.1 built-in modules, without ambient user modules.
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=30,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertTrue(report['passed'])
        self.assertTrue(report['source_tested'])
        self.assertTrue(report['mutation_interceptors'])
        self.assertEqual(report['path_cases'],10)
