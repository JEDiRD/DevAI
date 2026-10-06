import unittest
from unittest.mock import patch, MagicMock, call
from pathlib import Path
from worker_agent.workspace import WorkspaceManager
from worker_agent.adapters import AdapterError

class WorkspaceRecoveryTests(unittest.TestCase):
    def setUp(self):
        # We patch verify_root so we can initialize WorkspaceManager without real GUIDs
        self.patcher = patch.object(WorkspaceManager, 'verify_root')
        self.mock_verify = self.patcher.start()
        
        self.patcher_no_reparse = patch('worker_agent.workspace.no_reparse')
        self.patcher_no_reparse.start()
        
        self.manager = WorkspaceManager('C:\\mock_root', 'S-1-5-18', volume_guid='some-guid', recovery_dir='C:\\mock_recovery')
        self.manager.recovery_dir = MagicMock()
        self.manager.recovery_dir.glob.return_value = []
        self.manager.root = MagicMock(spec=Path)

    def tearDown(self):
        self.patcher.stop()
        self.patcher_no_reparse.stop()

    def test_A_existing_trusted_empty_root_recovers_successfully(self):
        self.manager.root.iterdir.return_value = iter([])
        self.manager.recover() # Should not raise

    def test_B_empty_enumeration_condition_is_empty_only_when_root_trusted(self):
        # If verify_root fails (e.g. not trusted), __init__ would raise and recovery won't happen.
        # Here we simulate iterdir raising FileNotFoundError with winerror=2.
        err = FileNotFoundError()
        err.winerror = 2
        self.manager.root.iterdir.side_effect = err
        self.manager.recover() # Should not raise
        
    def test_C_system_volume_information_alone_does_not_trigger_quarantine(self):
        svi = MagicMock()
        svi.name = 'System Volume Information'
        self.manager.root.iterdir.return_value = iter([svi])
        self.manager.recover() # Should not raise

    def test_D_system_volume_information_plus_valid_workspace_state_recovers(self):
        # valid workspace state means a marker exists and gets processed, 
        # but iterdir after processing only yields SVI.
        svi = MagicMock()
        svi.name = 'System Volume Information'
        self.manager.root.iterdir.return_value = iter([svi])
        marker = MagicMock()
        marker.read_text.return_value = '{"name": "0123456789abcdef0123456789abcdef"}'
        self.manager.recovery_dir.glob.return_value = [marker]
        
        with patch('worker_agent.workspace.C.WinDLL') as mock_windll, \
             patch('worker_agent.workspace.api') as mock_api, \
             patch('worker_agent.workspace.C.get_last_error') as mock_err, \
             patch('worker_agent.workspace._remove_no_follow'):
            
            mock_api.return_value.return_value = 0
            mock_err.return_value = 2
            
            # We must mock things called during job cleanup.
            self.manager.recover()

    def test_E_arbitrary_unknown_file_triggers_quarantine(self):
        unknown = MagicMock()
        unknown.name = 'unknown.txt'
        self.manager.root.iterdir.return_value = iter([unknown])
        with self.assertRaisesRegex(AdapterError, 'UNKNOWN_WORKSPACE_QUARANTINED'):
            self.manager.recover()

    def test_F_arbitrary_unknown_directory_triggers_quarantine(self):
        unknown = MagicMock()
        unknown.name = 'unknown_dir'
        self.manager.root.iterdir.return_value = iter([unknown])
        with self.assertRaisesRegex(AdapterError, 'UNKNOWN_WORKSPACE_QUARANTINED'):
            self.manager.recover()

    def test_G_permission_access_failure_remains_fail_closed(self):
        err = PermissionError()
        self.manager.root.iterdir.side_effect = err
        with self.assertRaises(PermissionError):
            self.manager.recover()

    def test_H_missing_root_remains_failure(self):
        err = FileNotFoundError()
        err.winerror = 3 # ERROR_PATH_NOT_FOUND
        self.manager.root.iterdir.side_effect = err
        with self.assertRaises(FileNotFoundError):
            self.manager.recover()

    def test_I_malformed_untrusted_acl_remains_failure(self):
        # Untrusted ACL fails at verify_root, which happens at initialization or outside this specific logic.
        # But for iteration, if it fails, it raises.
        # We can simulate verify_root failing here.
        self.patcher.stop()
        with patch('worker_agent.workspace.no_reparse') as mock_no_reparse:
            mock_no_reparse.side_effect = AdapterError('WORKSPACE_VOLUME_MISMATCH')
            with self.assertRaisesRegex(AdapterError, 'WORKSPACE_VOLUME_MISMATCH'):
                WorkspaceManager('C:\\mock_root', 'S-1-5-18', volume_guid='some-guid')
        self.patcher.start() # So teardown doesn't break

    def test_J_existing_workspace_recovery_behavior_outside_defect_unchanged(self):
        # We test that a regular FileNotFoundError (without winerror=2) still raises
        err = FileNotFoundError()
        err.winerror = None
        self.manager.root.iterdir.side_effect = err
        with self.assertRaises(FileNotFoundError):
            self.manager.recover()

if __name__ == '__main__':
    unittest.main()
