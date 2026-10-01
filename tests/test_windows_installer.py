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

    def test_unsupported_runtime_rejected_before_package_or_probe_creation(self):
        builder=Path(__file__).parent.parent/'deploy'/'windows'/'build-package.py'
        spec=importlib.util.spec_from_file_location('devai_package_builder_runtime',builder)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(prefix='devai-runtime-guard-') as temp:
            destination=Path(temp)/'package'
            with patch.object(sys,'version_info',(3,11)),patch.object(sys,'argv',[
                str(builder),'--destination',str(destination),'--existing-config','unused']),\
                patch.object(module,'prepare_personal_fixture') as probe:
                with self.assertRaisesRegex(RuntimeError,'CPYTHON_313_RUNTIME_REQUIRED'):
                    module.main()
                probe.assert_not_called()
            self.assertFalse(destination.exists())

    def test_personal_probe_is_private_and_outside_virtualized_appdata(self):
        builder=Path(__file__).parent.parent/'deploy'/'windows'/'build-package.py'
        spec=importlib.util.spec_from_file_location('devai_package_builder',builder)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        owner=re.search(r'S-1-5-\d+(?:-\d+)+',subprocess.check_output(
            ['whoami.exe','/user','/fo','csv','/nh'],text=True)).group()
        with tempfile.TemporaryDirectory(prefix='devai-profile-fixture-') as temp:
            profile=Path(temp)
            fixture=module.prepare_personal_fixture(owner,profile=profile)
            self.assertEqual(fixture,profile/'DevAIWorkerAccessProbe'/'service-access-denial.fixture')
            self.assertNotIn('AppData',fixture.relative_to(profile).parts)
            before=fixture.stat().st_mtime_ns
            self.assertEqual(module.prepare_personal_fixture(owner,reuse=True,profile=profile),fixture)
            self.assertEqual(fixture.stat().st_mtime_ns,before)
            with self.assertRaisesRegex(RuntimeError,'PERSONAL_TEST_FIXTURE_ALREADY_EXISTS'):
                module.prepare_personal_fixture(owner,profile=profile)
            # Read only ACL metadata, never credentials or exception text.
            env={**os.environ,'PSModulePath':str(Path(os.environ['SystemRoot'])/'System32'/'WindowsPowerShell'/'v1.0'/'Modules')}
            script="""param($Path,$Owner)
$ErrorActionPreference='Stop'
foreach($item in @($Path,(Split-Path -Parent $Path))) {
  $acl=Get-Acl -LiteralPath $item
  if (!$acl.AreAccessRulesProtected) { exit 10 }
  $sids=@($acl.Access | ForEach-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value})
  if ($sids.Count -ne 3) { exit 11 }
  foreach($sid in @('S-1-5-18','S-1-5-32-544',$Owner)) { if($sid -notin $sids) { exit 12 } }
}
Write-Output 'PRIVATE_PROFILE_PROBE_VERIFIED'
"""
            check=profile/'check-probe.ps1'
            check.write_text(script)
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-File',str(check),
                str(fixture),owner],capture_output=True,text=True,timeout=30,env=env)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('PRIVATE_PROFILE_PROBE_VERIFIED',result.stdout)

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
