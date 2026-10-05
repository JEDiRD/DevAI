"""Exercise the real installer validator using Windows PowerShell 5.1."""
import json
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

@unittest.skipUnless(sys.platform=='win32','Windows PowerShell required')
class InstallerTests(unittest.TestCase):
    def test_installer_identity_glue_no_collision_and_real_resolution_path(self):
        """RH-D: install-worker.ps1 used $existingConfig as if it were distinct
        from the [string] $ExistingConfig parameter. PowerShell is
        case-insensitive, so fresh installs always failed closed with
        EXISTING_CONFIG_WORKER_ID_MISSING. The harness audits the whole
        deploy/windows surface by AST, exercises the real identity glue for
        CLI-only / config-only / matching / conflicting / missing inputs,
        proves the config object (not a String) reaches resolution, and proves
        valid CLI-only input reaches ADMINISTRATOR_INSTALL_REQUIRED."""
        script=Path(__file__).parent/'windows'/'test_installer_identity_glue.ps1'
        env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
            '-File',str(script)],capture_output=True,text=True,timeout=180,env=env)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('VARIABLE_COLLISION_AUDIT_PASSED',result.stdout)
        self.assertIn('INSTALLER_GLUE_CASES_PASSED',result.stdout)
        self.assertIn('INSTALLER_GLUE_CANARY_PASSED:ADMINISTRATOR_INSTALL_REQUIRED',result.stdout)
        report=json.loads(result.stdout.strip().splitlines()[-1])
        self.assertTrue(report['passed'])
        self.assertEqual(report['collision_sites'],0)
        for marker in ('A:CLI_ONLY_PASS','B:CONFIG_ONLY_PASS','C:MATCHING_PASS',
                       'D:CONFLICT_FAILS_CLOSED','E:MISSING_FAILS_CLOSED'):
            self.assertIn(marker,report['glue_cases'])

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
