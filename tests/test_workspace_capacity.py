import ctypes as C
from pathlib import Path
import unittest
from unittest.mock import patch
from worker_agent.adapters import AdapterError
from worker_agent.workspace import WorkspaceManager, WORKSPACE_BYTES


class WorkspaceCapacityTests(unittest.TestCase):
    guid='\\\\?\\Volume{25914664-0000-0000-0000-010000000000}\\'

    def run_query(self,size=WORKSPACE_BYTES,fail=False,mismatch=False):
        seen=[]
        def api(dll,name,*args):
            if name=='GetVolumeNameForVolumeMountPointW':
                def volume(path,buffer,length):
                    buffer.value='wrong-volume' if mismatch else self.guid
                    return True
                return volume
            self.assertEqual(name,'GetDiskFreeSpaceExW')
            def space(path,available,total,free):
                seen.append(path)
                if fail:return False
                C.cast(total,C.POINTER(C.c_uint64)).contents.value=size
                return True
            return space
        with patch('worker_agent.workspace.no_reparse'),patch('worker_agent.workspace.api',side_effect=api),\
            patch('worker_agent.workspace.C.WinDLL',create=True),\
            patch('worker_agent.windows_security.C.get_last_error',return_value=5,create=True):
            WorkspaceManager(Path('managed-mount'),'synthetic-sid',volume_guid=self.guid)
        return seen

    def test_capacity_query_uses_only_already_pinned_volume_root(self):
        self.assertEqual(self.run_query(),[self.guid])

    def test_capacity_limit_remains_fail_closed(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_QUOTA_TOO_LARGE'):
            self.run_query(size=WORKSPACE_BYTES+1)

    def test_access_denied_does_not_disable_hard_quota(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_CAPACITY_QUERY_FAILED'):
            self.run_query(fail=True)

    def test_wrong_volume_fails_before_capacity_query(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_VOLUME_MISMATCH'):
            self.run_query(mismatch=True)
