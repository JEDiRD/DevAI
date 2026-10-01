import json
from pathlib import Path
import unittest
from unittest.mock import patch
from worker_agent.windows_service import safe_startup_failure, STARTUP_PHASES


class StartupDiagnosticTests(unittest.TestCase):
    def test_exception_text_paths_secrets_and_unknown_metadata_are_omitted(self):
        try:
            error=FileNotFoundError(2, 'token=DO_NOT_LOG_THIS_FIXTURE', 'DO_NOT_LOG_THIS_FIXTURE')
            error.winerror=3
            error.code='DO_NOT_LOG_THIS_FIXTURE'
            raise error
        except FileNotFoundError as failure:
            result=safe_startup_failure(failure,'personal_probe')
        self.assertEqual(result,{'phase':'personal_probe','error':'FileNotFoundError','frames':[], 'errno':2,'winerror':3})
        self.assertNotIn('DO_NOT_LOG_THIS_FIXTURE',json.dumps(result))

    def test_unknown_class_phase_and_non_numeric_error_cannot_be_emitted(self):
        class SecretClassDO_NOT_LOG_THIS_FIXTURE(Exception): pass
        error=SecretClassDO_NOT_LOG_THIS_FIXTURE('secret')
        error.errno=True
        error.winerror='secret'
        result=safe_startup_failure(error,'secret')
        self.assertEqual(result,{'phase':'unknown','error':'UNKNOWN_ERROR_CLASS','frames':[]})

    def test_trusted_source_location_is_retained_without_exception_message(self):
        from worker_agent.windows_service import verify_install
        with patch.dict('os.environ',{'ProgramFiles':'managed-code','ProgramData':'managed-state'}):
            try:
                verify_install(Path('unmanaged-config'),{})
            except RuntimeError as failure:
                result=safe_startup_failure(failure,'install_verification')
        self.assertEqual(result['phase'],'install_verification')
        self.assertEqual(result['frames'][0]['file'],'windows_service.py')
        self.assertGreater(result['frames'][0]['line'],0)
        self.assertNotIn('UNMANAGED_SERVICE_CONFIG',json.dumps(result))

    def test_missing_personal_fixture_still_fails_closed(self):
        # A missing file is not evidence of denied access. Keep FileNotFoundError
        # distinct from PermissionError in the deployed service startup gate.
        import ast
        path=Path(__file__).parent.parent/'worker_agent'/'windows_service.py'
        tree=ast.parse(path.read_text())
        probes=[node for node in ast.walk(tree) if isinstance(node,ast.Try) and
            any(isinstance(child,ast.Name) and child.id=='personal_fixture' for child in ast.walk(node))]
        probe=min(probes,key=lambda node:node.end_lineno-node.lineno)
        self.assertEqual([handler.type.id for handler in probe.handlers],['PermissionError'])
        self.assertIn('personal_probe',STARTUP_PHASES)
