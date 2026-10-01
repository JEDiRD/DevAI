import base64
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from worker_agent.volume_host import attach_workspace_volume


class VolumeHostTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='devai-volume-host-test-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.volumes=self.root/'DevAIWorker'/'volumes'
        self.volumes.mkdir(parents=True)
        self.vhd=self.volumes/'workspace.vhdx'
        self.vhd.write_text('non-secret placeholder, never mounted')
        self.description=self.volumes/'attach.txt'
        self.description.write_text(f'select vdisk file="{self.vhd}"\nattach vdisk\nexit\n')
        self.env=patch.dict(os.environ,{'ProgramData':str(self.root),'SystemRoot':'C:\\Windows'})
        self.env.start();self.addCleanup(self.env.stop)
        self.config={'volume_guid':'pinned-test-guid','service_sid':'test-service-sid'}

    def test_fixed_image_mount_has_no_drive_letter_or_format_command(self):
        with patch('worker_agent.volume_host.subprocess.run',return_value=subprocess.CompletedProcess([],0)) as run,\
             patch('worker_agent.volume_host.WorkspaceManager') as manager:
            attach_workspace_volume(self.config)
        args=run.call_args.args[0]
        self.assertEqual(Path(args[0]),Path('C:\\Windows')/'System32'/'WindowsPowerShell'/'v1.0'/'powershell.exe')
        script=base64.b64decode(args[-1]).decode('utf-16-le')
        self.assertIn('Mount-DiskImage -ImagePath $path -NoDriveLetter',script)
        self.assertIn('$disk.IsBoot -or $disk.IsSystem',script)
        self.assertNotIn('diskpart',script.lower())
        for forbidden in ('format-volume','initialize-disk','new-partition','automount','worker_token'):
            self.assertNotIn(forbidden,script.lower())
        manager.assert_called_once_with(self.root/'DevAIWorker'/'workspace-volume','test-service-sid',volume_guid='pinned-test-guid')

    def test_altered_attach_description_rejected_before_mount(self):
        self.description.write_text('select disk 0\nformat\n')
        with patch('worker_agent.volume_host.subprocess.run') as run:
            with self.assertRaisesRegex(RuntimeError,'UNSAFE_VOLUME_ATTACH_CONFIG'):
                attach_workspace_volume(self.config)
            run.assert_not_called()

    def test_failed_storage_verification_does_not_start_workspace(self):
        with patch('worker_agent.volume_host.subprocess.run',return_value=subprocess.CompletedProcess([],12)),\
             patch('worker_agent.volume_host.WorkspaceManager') as manager:
            with self.assertRaisesRegex(RuntimeError,'WORKSPACE_VOLUME_ATTACH_FAILED'):
                attach_workspace_volume(self.config)
            manager.assert_not_called()
