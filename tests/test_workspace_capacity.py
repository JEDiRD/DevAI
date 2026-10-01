import ctypes as C
from pathlib import Path
import os
import sys
import unittest
from unittest.mock import patch
from worker_agent.adapters import AdapterError
from worker_agent.workspace import (WorkspaceManager, WORKSPACE_BYTES, directory_capacity,
    IO_STATUS_BLOCK, FILE_FS_SIZE_INFORMATION, effective_token_metadata,
    directory_open_metadata, workspace_access_metadata)


class WorkspaceCapacityTests(unittest.TestCase):
    guid='\\\\?\\Volume{25914664-0000-0000-0000-010000000000}\\'

    def test_access_metadata_rejects_unmanaged_root_before_native_operations(self):
        with patch.dict(os.environ,{'ProgramData':'managed-state'}),\
                patch('worker_agent.workspace.C.WinDLL',create=True) as dll:
            self.assertEqual(workspace_access_metadata(Path('Controller-cwd'),self.guid),{'status':'UNAVAILABLE'})
            self.assertEqual(workspace_access_metadata(Path('managed-state')/'DevAIWorker'/'workspace-volume','invalid'),{'status':'UNAVAILABLE'})
            dll.assert_not_called()

    def test_access_probe_opens_only_read_handles_and_closes_each_success(self):
        seen=[]
        def native(dll,name,*signature):
            if name=='CreateFileW':
                def opened(path,access,share,security,creation,flags,template):
                    self.assertEqual(path,'DO_NOT_REPORT_THIS_PATH')
                    self.assertIn(access,(1,0x80,0x20000));self.assertEqual(share,7)
                    self.assertIsNone(security);self.assertEqual(creation,3)
                    self.assertEqual(flags,0x02200000);self.assertIsNone(template)
                    seen.append(access)
                    return C.c_void_p(-1).value if access==1 else 42
                return opened
            if name=='CloseHandle':
                def close(handle):seen.append('close');self.assertEqual(handle,42);return True
                return close
            self.fail('UNEXPECTED_NATIVE_API')
        with patch('worker_agent.workspace.C.WinDLL',create=True),\
                patch('worker_agent.workspace.api',side_effect=native),\
                patch('worker_agent.workspace.C.get_last_error',return_value=5,create=True):
            result=directory_open_metadata((('mount_host_entry','DO_NOT_REPORT_THIS_PATH',True),))
        self.assertEqual(seen,[1,0x80,'close',0x20000,'close'])
        self.assertEqual(result[0],{'label':'mount_host_entry','access':'list','opened':False,'winerror':5})
        self.assertNotIn('DO_NOT_REPORT_THIS_PATH',str(result))

    def test_thread_token_denial_is_not_replaced_by_process_token(self):
        def native(dll,name,*signature):
            if name=='GetCurrentThread':return lambda:42
            if name=='OpenThreadToken':return lambda *args:False
            if name=='CloseHandle':return lambda *args:True
            self.fail('PRIMARY_TOKEN_USED_AFTER_THREAD_ACCESS_DENIAL')
        with patch('worker_agent.workspace.C.WinDLL',create=True),\
                patch('worker_agent.workspace.api',side_effect=native),\
                patch('worker_agent.workspace.C.get_last_error',return_value=5,create=True):
            self.assertEqual(effective_token_metadata(),{'status':'UNAVAILABLE','winerror':5})

    def test_service_metadata_pins_mount_before_token_and_open_probes(self):
        def run(mismatch,token_fail=False):
            def native(dll,name,*signature):
                self.assertEqual(name,'GetVolumeNameForVolumeMountPointW')
                def volume(path,buffer,length):buffer.value='wrong-volume' if mismatch else self.guid;return True
                return volume
            with patch.dict(os.environ,{'ProgramData':'managed-state'}),\
                    patch('worker_agent.workspace.no_reparse'),\
                    patch('worker_agent.workspace.C.WinDLL',create=True),\
                    patch('worker_agent.workspace.api',side_effect=native),\
                    patch('worker_agent.workspace.effective_token_metadata',return_value={'status':'AVAILABLE'}) as token,\
                    patch('worker_agent.workspace.directory_open_metadata',return_value=[]) as opens:
                if token_fail:token.side_effect=RuntimeError('DO_NOT_LOG_THIS_FIXTURE')
                result=workspace_access_metadata(Path('managed-state')/'DevAIWorker'/'workspace-volume',self.guid)
                if mismatch:
                    token.assert_not_called();opens.assert_not_called()
                    self.assertEqual(result,{'status':'UNAVAILABLE'})
                else:
                    self.assertEqual(result['context'],'VERIFIED_WORKER_STARTUP')
                    targets=opens.call_args.args[0]
                    self.assertEqual(len(targets),6)
                    self.assertEqual(targets[-1],('guid_root',self.guid,False))
                    if token_fail:
                        self.assertEqual(result['token'],{'status':'UNAVAILABLE'})
                        self.assertNotIn('DO_NOT_LOG_THIS_FIXTURE',str(result))
        run(False);run(True);run(False,True)

    @unittest.skipUnless(sys.platform=='win32','Native Windows token required')
    def test_real_effective_token_query_and_owned_directory_open_matrix(self):
        import tempfile
        token=effective_token_metadata()
        self.assertEqual(token['status'],'AVAILABLE')
        self.assertIn(token['source'],('thread','process'))
        self.assertIs(type(token['change_notify_enabled']),bool)
        self.assertGreaterEqual(token['restricted_sid_count'],0)
        with tempfile.TemporaryDirectory(prefix='devai-open-matrix-') as path:
            result=directory_open_metadata((('mount_target',path,False),
                                            ('mount_target_trailing',path+'\\',False)))
            self.assertEqual(len(result),6)
            self.assertTrue(all(row['opened'] and row['winerror']==0 for row in result))
            self.assertNotIn(path,str(result))

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
