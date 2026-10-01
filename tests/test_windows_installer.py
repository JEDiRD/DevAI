"""Exercise the real installer validator using Windows PowerShell 5.1."""
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

@unittest.skipUnless(sys.platform=='win32','Windows PowerShell required')
class InstallerTests(unittest.TestCase):
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
