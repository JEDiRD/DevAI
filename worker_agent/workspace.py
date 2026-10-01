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
            available, total, free = C.c_uint64(), C.c_uint64(), C.c_uint64()
            disk = api(k, 'GetDiskFreeSpaceExW', W.BOOL, [W.LPCWSTR, C.POINTER(C.c_uint64), C.POINTER(C.c_uint64), C.POINTER(C.c_uint64)])
            # Query the already pinned target volume explicitly. A mounted
            # folder has a separate host-side security descriptor; do not use
            # that object to infer the target volume's capacity/access policy.
            check(disk(self.volume_guid, C.byref(available), C.byref(total), C.byref(free)),
                  'WORKSPACE_CAPACITY_QUERY_FAILED')
            if total.value > WORKSPACE_BYTES:
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
