import ctypes as C
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch
from worker_agent.adapters import AdapterError
from worker_agent.workspace import WorkspaceManager, WORKSPACE_BYTES, directory_capacity, IO_STATUS_BLOCK, FILE_FS_SIZE_INFORMATION


class WorkspaceCapacityTests(unittest.TestCase):
    guid='\\\\?\\Volume{25914664-0000-0000-0000-010000000000}\\'

    def run_query(self,size=WORKSPACE_BYTES,fail=False,mismatch=False,open_fail=False,
                  handle_mismatch=False,invalid=False,truncated=False,io_failure=False):
        seen=[]
        def api(dll,name,*args):
            if name=='GetVolumeNameForVolumeMountPointW':
                def volume(path,buffer,length):
                    buffer.value='wrong-volume' if mismatch else self.guid
                    return True
                return volume
            if name=='CreateFileW':
                def opened(path,access,sharing,security,creation,flags,template):
                    seen.append('open')
                    self.assertEqual(access,1)
                    self.assertEqual(sharing,7)
                    self.assertIsNone(security)
                    self.assertEqual(creation,3)
                    self.assertEqual(flags,0x02000000)
                    return C.c_void_p(-1).value if open_fail else 42
                return opened
            if name=='GetFinalPathNameByHandleW':
                def final(handle,buffer,length,flags):
                    self.assertEqual(handle,42)
                    self.assertEqual(flags,1)
                    buffer.value='wrong-volume' if handle_mismatch else self.guid
                    return len(buffer.value)
                return final
            if name=='NtQueryVolumeInformationFile':
                def query(handle,status,info,length,kind):
                    seen.append('query')
                    self.assertEqual(handle,42)
                    self.assertEqual(kind,3)
                    self.assertEqual(length,24)
                    block=C.cast(status,C.POINTER(IO_STATUS_BLOCK)).contents
                    block.value.status=-1073741790 if io_failure else 0
                    block.information=0 if truncated else length
                    data=C.cast(info,C.POINTER(FILE_FS_SIZE_INFORMATION)).contents
                    data.total_units=size//512
                    data.available_units=0
                    data.sectors_per_unit=1
                    data.bytes_per_sector=0 if invalid else 512
                    return -1073741790 if fail else 0
                return query
            if name=='RtlNtStatusToDosError':return lambda status:5
            if name=='CloseHandle':
                def close(handle):
                    self.assertEqual(handle,42)
                    seen.append('close')
                    return True
                return close
            self.fail('UNEXPECTED_NATIVE_API')
        with patch('worker_agent.workspace.no_reparse'),patch('worker_agent.workspace.api',side_effect=api),\
            patch('worker_agent.workspace.C.WinDLL',create=True),\
            patch('worker_agent.windows_security.C.get_last_error',return_value=5,create=True):
            try: WorkspaceManager(Path('managed-mount'),'synthetic-sid',volume_guid=self.guid)
            finally:
                if 'open' in seen and not open_fail:self.assertEqual(seen[-1],'close')
        return seen

    def test_capacity_query_is_bound_to_noninheritable_directory_handle(self):
        self.assertEqual(self.run_query(),['open','query','close'])

    def test_capacity_limit_remains_fail_closed(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_QUOTA_TOO_LARGE'):
            self.run_query(size=WORKSPACE_BYTES+512)

    def test_access_denied_does_not_disable_hard_quota(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_CAPACITY_QUERY_FAILED') as caught:
            self.run_query(fail=True)
        self.assertEqual(caught.exception.winerror,5)

    def test_wrong_volume_fails_before_capacity_query(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_VOLUME_MISMATCH'):
            self.run_query(mismatch=True)

    def test_denied_directory_open_is_distinct_from_denied_size_query(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_DIRECTORY_OPEN_FAILED'):
            self.run_query(open_fail=True)

    def test_handle_target_mismatch_is_rejected_before_size_query(self):
        with self.assertRaisesRegex(AdapterError,'WORKSPACE_HANDLE_VOLUME_MISMATCH'):
            self.run_query(handle_mismatch=True)

    def test_malformed_truncated_and_unsuccessful_io_results_fail_closed(self):
        for kwargs,code in (({'invalid':True},'WORKSPACE_CAPACITY_INVALID'),
                ({'truncated':True},'WORKSPACE_CAPACITY_INVALID'),
                ({'io_failure':True},'WORKSPACE_CAPACITY_QUERY_FAILED')):
            with self.subTest(kwargs=kwargs),self.assertRaisesRegex(AdapterError,code):
                self.run_query(**kwargs)

    @unittest.skipUnless(sys.platform=='win32','Native Windows filesystem required')
    def test_real_directory_handle_query_without_disk_mutation_or_elevation(self):
        from ctypes import wintypes as W
        from worker_agent.windows_security import api,check
        root=Path(os.environ['SystemDrive']+'\\')
        buffer=C.create_unicode_buffer(1024)
        kernel=C.WinDLL('kernel32',use_last_error=True)
        check(api(kernel,'GetVolumeNameForVolumeMountPointW',W.BOOL,[W.LPCWSTR,W.LPWSTR,W.DWORD])(
            str(root),buffer,1024))
        size=directory_capacity(root,buffer.value)
        self.assertGreater(size,WORKSPACE_BYTES)
