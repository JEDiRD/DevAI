"""Worker-generated workspaces, pinned volume, no reparse traversal, explicit cleanup."""
import ctypes as C
from ctypes import wintypes as W
from pathlib import Path
import os
import json
import time
import stat
import threading
from uuid import uuid4

from .adapters import AdapterError
from .windows_security import AppContainerSid, api, check, no_reparse, set_directory_acl

WORKSPACE_BYTES = 128 * 1024 * 1024
MAX_FILES = 4096

ACCESS_LABELS = ('state_parent', 'state_root', 'mount_host_entry',
                 'mount_target', 'mount_target_trailing', 'guid_root')
ACCESS_KINDS = (('list', 1), ('attributes', 0x80), ('read_control', 0x20000))


def effective_token_metadata():
    """Query this thread's effective token, never enable/adjust any privilege.

    Return only numeric/boolean metadata, no SIDs, privilege lists or token bytes.
    If a thread token exists it takes precedence over the process primary token.
    """
    kernel = C.WinDLL('kernel32', use_last_error=True)
    security = C.WinDLL('advapi32', use_last_error=True)
    token = W.HANDLE()
    close = api(kernel, 'CloseHandle', W.BOOL, [W.HANDLE])
    thread = api(kernel, 'GetCurrentThread', W.HANDLE, [])()
    opened = api(security, 'OpenThreadToken', W.BOOL,
                 [W.HANDLE, W.DWORD, W.BOOL, C.POINTER(W.HANDLE)])
    source = 'thread'
    if not opened(thread, 8, True, C.byref(token)):
        # ERROR_NO_TOKEN is the ONLY reason to consult the primary token.
        if C.get_last_error() != 1008:
            return {'status': 'UNAVAILABLE', 'winerror': C.get_last_error()}
        process = api(kernel, 'GetCurrentProcess', W.HANDLE, [])()
        if not api(security, 'OpenProcessToken', W.BOOL,
                   [W.HANDLE, W.DWORD, C.POINTER(W.HANDLE)])(process, 8, C.byref(token)):
            return {'status': 'UNAVAILABLE', 'winerror': C.get_last_error()}
        source = 'process'
    try:
        getter = api(security, 'GetTokenInformation', W.BOOL,
                     [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.POINTER(W.DWORD)])

        def information(kind):
            needed = W.DWORD()
            # Bounded single query also handles classes returning BAD_LENGTH for
            # a zero-byte size probe. Respect the ACTUAL returned byte count.
            data = C.create_string_buffer(4 if kind in (20, 21, 29) else 65536)
            check(getter(token, kind, data, len(data), C.byref(needed)))
            if not 1 <= needed.value <= len(data):
                raise AdapterError('TOKEN_METADATA_UNAVAILABLE')
            return bytearray(data.raw[:needed.value])

        result = {'status': 'AVAILABLE', 'source': source}
        for field, kind in (('elevated', 20), ('has_restrictions', 21), ('appcontainer', 29)):
            data = information(kind)
            # TokenHasRestrictions returns BOOLEAN (one byte) on this Windows
            # runtime; other flag classes return DWORD. Never overread the buffer.
            value = (C.c_uint8 if kind == 21 and len(data) == 1 else C.c_uint32).from_buffer(data).value
            if value not in (0, 1): raise AdapterError('TOKEN_METADATA_UNAVAILABLE')
            result[field] = bool(value)
        restricted = C.c_uint32.from_buffer(information(11)).value
        if restricted > 128: raise AdapterError('TOKEN_METADATA_UNAVAILABLE')
        result['restricted_sid_count'] = restricted
        privileges = information(3)
        count = C.c_uint32.from_buffer(privileges).value
        if count > 128 or len(privileges) < 4 + 12 * count:
            raise AdapterError('TOKEN_METADATA_UNAVAILABLE')
        # LUID is two 32-bit fields. TOKEN_PRIVILEGES entries have a 12-byte stride.
        for label, name in (('change_notify', 'SeChangeNotifyPrivilege'),
                            ('backup', 'SeBackupPrivilege'), ('restore', 'SeRestorePrivilege')):
            luid = (C.c_uint32 * 2)()
            check(api(security, 'LookupPrivilegeValueW', W.BOOL,
                      [W.LPCWSTR, W.LPCWSTR, C.c_void_p])(None, name, luid))
            result[label + '_present'] = False
            result[label + '_enabled'] = False
            for index in range(count):
                entry = (C.c_uint32 * 3).from_buffer(privileges, 4 + index * 12)
                if entry[0] == luid[0] and entry[1] == luid[1]:
                    result[label + '_present'] = True
                    result[label + '_enabled'] = bool(entry[2] & 2)
        return result
    finally:
        close(token)


def directory_open_metadata(targets):
    """Bounded opens only; never enumerate/read contents or request write access."""
    kernel = C.WinDLL('kernel32', use_last_error=True)
    opened = api(kernel, 'CreateFileW', W.HANDLE,
                 [W.LPCWSTR, W.DWORD, W.DWORD, C.c_void_p, W.DWORD, W.DWORD, W.HANDLE])
    close = api(kernel, 'CloseHandle', W.BOOL, [W.HANDLE])
    results = []
    if len(targets) > len(ACCESS_LABELS): raise AdapterError('ACCESS_METADATA_UNAVAILABLE')
    for label, path, no_follow in targets:
        if label not in ACCESS_LABELS: raise AdapterError('ACCESS_METADATA_UNAVAILABLE')
        for kind, access in ACCESS_KINDS:
            handle = opened(str(path), access, 7, None, 3,
                            0x02000000 | (0x00200000 if no_follow else 0), None)
            ok = handle is not None and handle != C.c_void_p(-1).value
            error = 0 if ok else C.get_last_error()
            if ok: close(handle)
            results.append({'label': label, 'access': kind, 'opened': ok, 'winerror': error})
    return results


def workspace_access_metadata(root, expected_guid):
    """Called ONLY after verified Worker startup fails at workspace_open.

    This is diagnostics, never a fallback or an execution/authorization gate.
    Fixed managed paths, pinned mount, no arbitrary Controller path accepted.
    """
    import re
    root = Path(root)
    state = Path(os.environ['ProgramData']) / 'DevAIWorker'
    if root != state / 'workspace-volume' or not re.fullmatch(
            r'\\\\\?\\Volume\{[0-9a-fA-F-]{36}\}\\', expected_guid):
        return {'status': 'UNAVAILABLE'}
    no_reparse(root, allowed_mount=root)
    kernel = C.WinDLL('kernel32', use_last_error=True)
    guid = C.create_unicode_buffer(1024)
    check(api(kernel, 'GetVolumeNameForVolumeMountPointW', W.BOOL,
              [W.LPCWSTR, W.LPWSTR, W.DWORD])(str(root) + '\\', guid, 1024))
    if guid.value != expected_guid: return {'status': 'UNAVAILABLE'}
    try:
        token = effective_token_metadata()
    except Exception:
        # Token-query availability cannot hide the independent directory probes.
        # No exception text or token bytes are published on this path either.
        token = {'status': 'UNAVAILABLE'}
    return {'status': 'AVAILABLE', 'context': 'VERIFIED_WORKER_STARTUP',
            'token': token,
            'opens': directory_open_metadata((
                ('state_parent', state.parent, True), ('state_root', state, True),
                ('mount_host_entry', root, True), ('mount_target', root, False),
                ('mount_target_trailing', str(root) + '\\', False),
                ('guid_root', expected_guid, False)))}


class IO_STATUS_VALUE(C.Union):
    _fields_ = [('status', C.c_int32), ('pointer', C.c_void_p)]


class IO_STATUS_BLOCK(C.Structure):
    _fields_ = [('value', IO_STATUS_VALUE), ('information', C.c_size_t)]


class FILE_FS_SIZE_INFORMATION(C.Structure):
    _fields_ = [('total_units', C.c_int64), ('available_units', C.c_int64),
               ('sectors_per_unit', C.c_uint32), ('bytes_per_sector', C.c_uint32)]


def directory_capacity(root, expected_guid):
    """Query via a noninheritable directory handle, never a raw device handle.

    Requires FILE_LIST_DIRECTORY. Bind the opened root to the pinned GUID before
    querying size, and close the handle on every path. No elevation or fallback.
    """
    kernel = C.WinDLL('kernel32', use_last_error=True)
    opened = api(kernel, 'CreateFileW', W.HANDLE,
        [W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE])
    handle = opened(str(root).rstrip('\\/')+'\\',1,7,None,3,0x02000000,None)
    check(handle and handle != C.c_void_p(-1).value, 'WORKSPACE_DIRECTORY_OPEN_FAILED')
    try:
        final = C.create_unicode_buffer(1024)
        received = api(kernel,'GetFinalPathNameByHandleW',W.DWORD,
            [W.HANDLE,W.LPWSTR,W.DWORD,W.DWORD])(handle,final,1024,1)
        check(received and received < 1024, 'WORKSPACE_HANDLE_PATH_QUERY_FAILED')
        if final.value.rstrip('\\').casefold() != expected_guid.rstrip('\\').casefold():
            raise AdapterError('WORKSPACE_HANDLE_VOLUME_MISMATCH')
        status, size = IO_STATUS_BLOCK(), FILE_FS_SIZE_INFORMATION()
        native = C.WinDLL('ntdll',use_last_error=True)
        result = api(native,'NtQueryVolumeInformationFile',C.c_int32,
            [W.HANDLE,C.POINTER(IO_STATUS_BLOCK),C.c_void_p,C.c_uint32,C.c_int])(
                handle,C.byref(status),C.byref(size),C.sizeof(size),3)
        if result != 0 or status.value.status != 0:
            failure = AdapterError('WORKSPACE_CAPACITY_QUERY_FAILED')
            failure.winerror = int(api(native,'RtlNtStatusToDosError',C.c_uint32,[C.c_int32])(
                result if result != 0 else status.value.status))
            raise failure
        if status.information != C.sizeof(size) or size.total_units <= 0 or \
            size.available_units < 0 or size.available_units > size.total_units or \
            size.sectors_per_unit == 0 or size.bytes_per_sector == 0:
            raise AdapterError('WORKSPACE_CAPACITY_INVALID')
        return size.total_units * size.sectors_per_unit * size.bytes_per_sector
    finally:
        check(api(kernel,'CloseHandle',W.BOOL,[W.HANDLE])(handle),'WORKSPACE_DIRECTORY_CLOSE_FAILED')


class WorkspaceManager:
    def __init__(self, root, owner_sid, *, volume_guid=None, require_hard_quota=True, recovery_dir=None):
        self.root = Path(os.path.abspath(root))
        self.owner_sid = owner_sid
        self.volume_guid = volume_guid
        self.require_hard_quota = require_hard_quota
        self._slot = threading.BoundedSemaphore(1)
        self.recovery_dir = Path(recovery_dir) if recovery_dir else None
        self.verify_root()

    def recover(self):
        """SCM restart: open/kill/wait named jobs before removing private markers.

        The only inherited handles were pipes. A nonexistent named job has already
        released its final kernel reference; KILL_ON_JOB_CLOSE applies on crash.
        Unknown directories are quarantined by refusing execution, never followed.
        """
        if self.recovery_dir is None:
            return
        no_reparse(self.recovery_dir)
        k = C.WinDLL('kernel32', use_last_error=True)
        opened = api(k, 'OpenJobObjectW', W.HANDLE, [W.DWORD,W.BOOL,W.LPCWSTR])
        close = api(k, 'CloseHandle', W.BOOL,[W.HANDLE])
        for marker in self.recovery_dir.glob('workspace-*.json'):
            no_reparse(marker)
            data = json.loads(marker.read_text())
            name = data['name']
            if len(name)!=32 or any(c not in '0123456789abcdef' for c in name):
                raise AdapterError('UNSAFE_WORKSPACE_RECOVERY_MARKER')
            job_name = 'Local\\DevAIWorker.' + name
            job = opened(4|8,False,job_name)
            if job:
                from .windows_process import ACCOUNTING
                try:
                    check(api(k,'TerminateJobObject',W.BOOL,[W.HANDLE,W.UINT])(job,1),'PROCESS_TREE_TERMINATION_FAILED')
                    until = time.monotonic()+5
                    while True:
                        info = ACCOUNTING()
                        check(api(k,'QueryInformationJobObject',W.BOOL,[W.HANDLE,C.c_int,C.c_void_p,W.DWORD,C.c_void_p])(job,1,C.byref(info),C.sizeof(info),None),'JOB_QUERY_FAILED')
                        if not info.active: break
                        if time.monotonic()>=until: raise AdapterError('PROCESS_TREE_TERMINATION_UNCONFIRMED')
                        time.sleep(.02)
                finally:
                    close(job)
            elif C.get_last_error()!=2:
                raise AdapterError('JOB_RECOVERY_UNCONFIRMED')
            path = self.root/name
            if path.exists():
                no_reparse(path,allowed_mount=self.root if self.volume_guid else None)
                _remove_no_follow(path)
            result = api(C.WinDLL('userenv'),'DeleteAppContainerProfile',C.c_long,[W.LPCWSTR])('DevAI.'+name)
            if result not in (0, -2147024894, -2147023728):
                raise AdapterError('APPCONTAINER_PROFILE_CLEANUP_FAILED')
            marker.unlink()
        if any(self.root.iterdir()):
            raise AdapterError('UNKNOWN_WORKSPACE_QUARANTINED')

    def verify_root(self):
        if self.require_hard_quota and not self.volume_guid:
            raise AdapterError('HARD_WORKSPACE_QUOTA_REQUIRED')
        mount = self.root if self.volume_guid else None
        no_reparse(self.root, allowed_mount=mount)
        if self.volume_guid:
            k = C.WinDLL('kernel32', use_last_error=True)
            volume = C.create_unicode_buffer(1024)
            get = api(k, 'GetVolumeNameForVolumeMountPointW', W.BOOL, [W.LPCWSTR, W.LPWSTR, W.DWORD])
            check(get(str(self.root) + '\\', volume, 1024), 'WORKSPACE_VOLUME_NOT_MOUNTED')
            if volume.value != self.volume_guid:
                raise AdapterError('WORKSPACE_VOLUME_MISMATCH')
            total = directory_capacity(self.root,self.volume_guid)
            if total > WORKSPACE_BYTES:
                raise AdapterError('WORKSPACE_QUOTA_TOO_LARGE')

    def create(self):
        self.verify_root()
        if not self._slot.acquire(blocking=False):
            raise AdapterError('WORKSPACE_CONCURRENCY_LIMIT')
        path = self.root / uuid4().hex  # Never a Controller-provided cwd/name.
        sid = None
        try:
            path.mkdir()
            sid = AppContainerSid('DevAI.' + path.name)
            # The OS-created profile must not become an unbounded second workspace.
            set_directory_acl(sid.folder, self.owner_sid)
            sid.restrict_registry(self.owner_sid)
            set_directory_acl(path, self.owner_sid, sid.text, low=True,
                allowed_mount=self.root if self.volume_guid else None)
            if self.recovery_dir:
                marker = self.recovery_dir/('workspace-'+path.name+'.json')
                marker.write_text(json.dumps({'name':path.name}))
            return Workspace(self, path, sid)
        except Exception:
            if sid:
                sid.close()
            path.rmdir()
            self._slot.release()
            raise


class Workspace:
    def __init__(self, manager, path, sid):
        self.manager, self.path, self.sid = manager, path, sid
        self.closed = False
        self.termination_confirmed = False
        self.job_name = 'Local\\DevAIWorker.' + path.name

    def verify(self):
        self.manager.verify_root()
        no_reparse(self.path, allowed_mount=self.manager.root if self.manager.volume_guid else None)
        count, size = 0, 0
        for directory, folders, files in os.walk(self.path, followlinks=False):
            for name in (*folders, *files):
                entry = Path(directory) / name
                info = entry.lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                    raise AdapterError('REPARSE_POINT_REJECTED')
                count += 1
                size += info.st_size if stat.S_ISREG(info.st_mode) else 0
                if count > MAX_FILES or size > WORKSPACE_BYTES:
                    raise AdapterError('WORKSPACE_QUOTA_EXCEEDED')

    def close(self):
        if self.closed:
            return
        if not self.termination_confirmed:
            raise AdapterError('WORKSPACE_PROCESS_TERMINATION_REQUIRED')
        # Only after the Job Object is empty. Never follow even attacker-created links.
        self.manager.verify_root()
        no_reparse(self.path, allowed_mount=self.manager.root if self.manager.volume_guid else None)
        _remove_no_follow(self.path)
        self.sid.close()
        if self.manager.recovery_dir:
            (self.manager.recovery_dir/('workspace-'+self.path.name+'.json')).unlink(missing_ok=True)
        self.manager._slot.release()
        self.closed = True


def _remove_no_follow(directory):
    pending = [(directory, False)]
    while pending:
        directory, visited = pending.pop()
        if visited:
            os.rmdir(directory)
            continue
        pending.append((directory, True))
        children = []
        with os.scandir(directory) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                reparse = getattr(info, 'st_file_attributes', 0) & 0x400
                if entry.is_symlink() or reparse:
                    if stat.S_ISDIR(info.st_mode): os.rmdir(entry.path)
                    else: os.unlink(entry.path)
                elif stat.S_ISDIR(info.st_mode):
                    children.append((entry.path, False))
                else: os.unlink(entry.path)
        pending.extend(children)
