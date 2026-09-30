"""No-network AppContainer + suspended assignment to a non-breakaway Job Object."""
import ctypes as C
from ctypes import wintypes as W
from dataclasses import dataclass
from pathlib import Path
import subprocess
import threading
import time

from .adapters import AdapterError, AdapterResult, LIMITS, bounded_redacted_stream
from .windows_security import api, check, no_reparse, windows_only


class STARTUPINFO(C.Structure):
    _fields_ = [('cb', W.DWORD), ('reserved', W.LPWSTR), ('desktop', W.LPWSTR),
        ('title', W.LPWSTR), ('x', W.DWORD), ('y', W.DWORD), ('width', W.DWORD),
        ('height', W.DWORD), ('xchars', W.DWORD), ('ychars', W.DWORD),
        ('fill', W.DWORD), ('flags', W.DWORD), ('show', W.WORD),
        ('reserved_count', W.WORD), ('reserved_bytes', C.c_void_p),
        ('stdin', W.HANDLE), ('stdout', W.HANDLE), ('stderr', W.HANDLE)]


class STARTUPINFOEX(C.Structure):
    _fields_ = [('startup', STARTUPINFO), ('attributes', C.c_void_p)]


class PROCESSINFO(C.Structure):
    _fields_ = [('process', W.HANDLE), ('thread', W.HANDLE), ('pid', W.DWORD), ('tid', W.DWORD)]


class SECURITYATTRIBUTES(C.Structure):
    _fields_ = [('length', W.DWORD), ('descriptor', C.c_void_p), ('inherit', W.BOOL)]


class SECURITYCAPABILITIES(C.Structure):
    _fields_ = [('sid', C.c_void_p), ('capabilities', C.c_void_p),
               ('count', W.DWORD), ('reserved', W.DWORD)]


class BASICLIMITS(C.Structure):
    _fields_ = [('process_time', C.c_int64), ('job_time', C.c_int64),
        ('flags', W.DWORD), ('minimum_working_set', C.c_size_t),
        ('maximum_working_set', C.c_size_t), ('active_processes', W.DWORD),
        ('affinity', C.c_size_t), ('priority', W.DWORD), ('scheduling', W.DWORD)]


class EXTENDEDLIMITS(C.Structure):
    _fields_ = [('basic', BASICLIMITS), ('io', C.c_uint64 * 6),
        ('process_memory', C.c_size_t), ('job_memory', C.c_size_t),
        ('peak_process_memory', C.c_size_t), ('peak_job_memory', C.c_size_t)]


class ACCOUNTING(C.Structure):
    _fields_ = [('times', C.c_int64 * 4), ('faults', W.DWORD),
        ('total', W.DWORD), ('active', W.DWORD), ('terminated', W.DWORD)]


class CPULIMITS(C.Structure):
    _fields_ = [('flags', W.DWORD), ('rate', W.DWORD)]


@dataclass(frozen=True)
class ProcessAllowlist:
    executable: Path
    payload: Path
    executable_sha256: str
    payload_sha256: str

    def verify(self, policy):
        import hashlib
        policy.validate()
        if policy.executable != self.executable or policy.arguments[:4] != ('-I', '-S', '-B', str(self.payload)):
            raise AdapterError('EXECUTABLE_NOT_ALLOWLISTED')
        if len(policy.arguments) != 4:
            raise AdapterError('ARGUMENTS_NOT_ALLOWLISTED')
        for path, digest in ((self.executable, self.executable_sha256), (self.payload, self.payload_sha256)):
            no_reparse(path)
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise AdapterError('ALLOWLIST_INTEGRITY_FAILED')


class WindowsProcessTreeLauncher:
    def __init__(self, allowlist):
        windows_only()
        self.allowlist = allowlist
        self.kernel = C.WinDLL('kernel32', use_last_error=True)
        self.close = api(self.kernel, 'CloseHandle', W.BOOL, [W.HANDLE])

    def launch(self, policy, *, stdin_payload, environment, shell=False, workspace=None):
        self.allowlist.verify(policy)
        if shell is not False or workspace is None or policy.working_directory != workspace.path:
            raise AdapterError('UNSAFE_LOCAL_PROCESS_POLICY')
        if len(stdin_payload) > LIMITS.max_prompt_bytes:
            raise AdapterError('PROMPT_LIMIT_EXCEEDED')
        allowed_env = {'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA'}
        if set(environment) - allowed_env or any(environment.get(key)!=str(workspace.path)
            for key in ('TEMP','TMP','USERPROFILE','LOCALAPPDATA','APPDATA')):
            raise AdapterError('UNSAFE_PROCESS_ENVIRONMENT')
        workspace.verify()
        k = self.kernel
        create_job = api(k, 'CreateJobObjectW', W.HANDLE, [C.c_void_p, W.LPCWSTR])
        job = create_job(None, workspace.job_name)
        check(job)
        if C.get_last_error()==183:
            self.close(job)
            raise AdapterError('JOB_NAME_COLLISION')
        process_info = PROCESSINFO()
        handles = []
        attributes = None
        try:
            setter = api(k, 'SetInformationJobObject', W.BOOL, [W.HANDLE, C.c_int, C.c_void_p, W.DWORD])
            limits = EXTENDEDLIMITS()
            limits.basic.flags = 0x2000 | 0x100 | 0x200 | 0x8 | 0x400
            limits.basic.active_processes = 8
            limits.process_memory = 128 * 1024 * 1024
            limits.job_memory = 256 * 1024 * 1024
            check(setter(job, 9, C.byref(limits), C.sizeof(limits)), 'JOB_RESOURCE_LIMIT_FAILED')
            cpu = CPULIMITS(1 | 4, 3000)
            check(setter(job, 15, C.byref(cpu), C.sizeof(cpu)), 'JOB_CPU_LIMIT_FAILED')
            pipe = api(k, 'CreatePipe', W.BOOL, [C.POINTER(W.HANDLE), C.POINTER(W.HANDLE), C.POINTER(SECURITYATTRIBUTES), W.DWORD])
            uninherit = api(k, 'SetHandleInformation', W.BOOL, [W.HANDLE, W.DWORD, W.DWORD])
            sa = SECURITYATTRIBUTES(C.sizeof(SECURITYATTRIBUTES), None, True)
            pairs = []
            for _ in range(3):
                read, write = W.HANDLE(), W.HANDLE()
                check(pipe(C.byref(read), C.byref(write), C.byref(sa), 0))
                pairs.append((read.value, write.value))
                handles.extend((read.value, write.value))
            stdin_read, stdin_write = pairs[0]
            stdout_read, stdout_write = pairs[1]
            stderr_read, stderr_write = pairs[2]
            for handle in (stdin_write, stdout_read, stderr_read):
                check(uninherit(handle, 1, 0))
            inherited = (W.HANDLE * 3)(stdin_read, stdout_write, stderr_write)
            initialize = api(k, 'InitializeProcThreadAttributeList', W.BOOL,
                [C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t)])
            size = C.c_size_t()
            initialize(None, 2, 0, C.byref(size))
            attributes = C.create_string_buffer(size.value)
            check(initialize(attributes, 2, 0, C.byref(size)))
            update = api(k, 'UpdateProcThreadAttribute', W.BOOL,
                [C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p])
            capabilities = SECURITYCAPABILITIES(workspace.sid.pointer, None, 0, 0)
            check(update(attributes, 0, 0x20009, C.byref(capabilities), C.sizeof(capabilities), None, None), 'APPCONTAINER_CREATION_FAILED')
            check(update(attributes, 0, 0x20002, inherited, C.sizeof(inherited), None, None))
            startup = STARTUPINFOEX()
            startup.startup.cb = C.sizeof(STARTUPINFOEX)
            startup.startup.flags = 0x100 | 0x1
            startup.startup.show = 0
            startup.startup.stdin, startup.startup.stdout, startup.startup.stderr = stdin_read, stdout_write, stderr_write
            startup.attributes = C.cast(attributes, C.c_void_p)
            # list2cmdline quotes LOCAL fixed arguments. Prompt is exclusively stdin.
            command = C.create_unicode_buffer(subprocess.list2cmdline([str(policy.executable), *policy.arguments]))
            env = C.create_unicode_buffer('\0'.join(f'{key}={value}' for key, value in sorted(environment.items())) + '\0\0')
            create = api(k, 'CreateProcessW', W.BOOL, [W.LPCWSTR, W.LPWSTR, C.c_void_p,
                C.c_void_p, W.BOOL, W.DWORD, C.c_void_p, W.LPCWSTR, C.POINTER(STARTUPINFOEX), C.POINTER(PROCESSINFO)])
            check(create(str(policy.executable), command, None, None, True,
                0x4 | 0x80000 | 0x400 | 0x08000000, env, str(workspace.path),
                C.byref(startup), C.byref(process_info)), 'ISOLATED_PROCESS_CREATION_FAILED')
            assign = api(k, 'AssignProcessToJobObject', W.BOOL, [W.HANDLE, W.HANDLE])
            check(assign(job, process_info.process), 'JOB_ASSIGNMENT_FAILED')
            resume = api(k, 'ResumeThread', W.DWORD, [W.HANDLE])
            check(resume(process_info.thread) != 0xFFFFFFFF, 'PROCESS_RESUME_FAILED')
            self.close(process_info.thread)
            process_info.thread = None
            for handle in (stdin_read, stdout_write, stderr_write):
                self.close(handle)
                handles.remove(handle)
            session = WindowsProcessTreeSession(self, job, process_info.process,
                process_info.pid, stdin_write, stdout_read, stderr_read, stdin_payload, workspace)
            handles.clear()
            job = None
            process_info.process = None
            return session
        finally:
            cleanup_unconfirmed = False
            if process_info.process:
                # Still suspended if containment failed: never resume outside the job.
                killed = api(k, 'TerminateProcess', W.BOOL, [W.HANDLE, W.UINT])(process_info.process, 1)
                waited = api(k, 'WaitForSingleObject', W.DWORD, [W.HANDLE, W.DWORD])(process_info.process, 5000)
                self.close(process_info.process)
                cleanup_unconfirmed = not killed or waited != 0
            if process_info.thread:
                self.close(process_info.thread)
            for handle in handles:
                self.close(handle)
            if attributes:
                api(k, 'DeleteProcThreadAttributeList', None, [C.c_void_p])(attributes)
            if job:
                self.close(job)
            if cleanup_unconfirmed:
                raise AdapterError('PROCESS_TREE_TERMINATION_UNCONFIRMED')


class WindowsProcessTreeSession:
    def __init__(self, launcher, job, process, pid, stdin, stdout, stderr, payload, workspace):
        self.launcher, self.job, self.process, self.pid = launcher, job, process, pid
        self.workspace = workspace
        self.stdout, self.stderr = bytearray(), bytearray()
        self.overflow = threading.Event()
        self._lock = threading.Lock()
        self._threads = []
        self.termination_confirmed = False
        for handle, buffer in ((stdout, self.stdout), (stderr, self.stderr)):
            thread = threading.Thread(target=self._read, args=(handle, buffer), daemon=True)
            self._threads.append(thread)
            thread.start()
        thread = threading.Thread(target=self._write, args=(stdin, payload), daemon=True)
        self._threads.append(thread)
        thread.start()

    def _read(self, handle, buffer):
        read = api(self.launcher.kernel, 'ReadFile', W.BOOL,
            [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
        try:
            block = C.create_string_buffer(4096)
            count = W.DWORD()
            while read(handle, block, 4096, C.byref(count), None) and count.value:
                with self._lock:
                    remaining = LIMITS.max_output_bytes - len(self.stdout) - len(self.stderr)
                    buffer.extend(block.raw[:min(count.value, max(0, remaining))])
                    if count.value > remaining:
                        self.overflow.set()
        finally:
            self.launcher.close(handle)

    def _write(self, handle, payload):
        write = api(self.launcher.kernel, 'WriteFile', W.BOOL,
            [W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p])
        try:
            offset, count = 0, W.DWORD()
            while offset < len(payload):
                block = payload[offset:offset + 4096]
                if not write(handle, block, len(block), C.byref(count), None) or not count.value:
                    break
                offset += count.value
        finally:
            self.launcher.close(handle)

    def active_processes(self):
        info = ACCOUNTING()
        query = api(self.launcher.kernel, 'QueryInformationJobObject', W.BOOL,
                    [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p])
        check(query(self.job, 1, C.byref(info), C.sizeof(info), None), 'JOB_QUERY_FAILED')
        return info.active

    def process_ids(self):
        class LIST(C.Structure):
            _fields_ = [('assigned', W.DWORD), ('count', W.DWORD), ('ids', C.c_size_t * 32)]
        info = LIST()
        query = api(self.launcher.kernel, 'QueryInformationJobObject', W.BOOL,
                    [W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p])
        check(query(self.job, 3, C.byref(info), C.sizeof(info), None), 'JOB_QUERY_FAILED')
        return list(info.ids[:info.count])

    def terminate_tree_and_wait(self):
        if self.termination_confirmed:
            return
        terminate = api(self.launcher.kernel, 'TerminateJobObject', W.BOOL, [W.HANDLE, W.UINT])
        check(terminate(self.job, 1), 'PROCESS_TREE_TERMINATION_FAILED')
        end = time.monotonic() + 5
        while self.active_processes():
            if time.monotonic() >= end:
                raise AdapterError('PROCESS_TREE_TERMINATION_UNCONFIRMED')
            time.sleep(.02)
        for thread in self._threads:
            thread.join(timeout=1)
        if any(thread.is_alive() for thread in self._threads):
            raise AdapterError('PROCESS_IO_TERMINATION_UNCONFIRMED')
        self.termination_confirmed = True
        self.launcher.close(self.process)
        self.process = None
        self.launcher.close(self.job)  # Non-inheritable final handle: kill-on-close too.
        self.job = None

    def bounded_result(self, context):
        wait = api(self.launcher.kernel, 'WaitForSingleObject', W.DWORD, [W.HANDLE, W.DWORD])
        exit_code = W.DWORD()
        get_exit = api(self.launcher.kernel, 'GetExitCodeProcess', W.BOOL, [W.HANDLE, C.POINTER(W.DWORD)])
        try:
            while True:
                status = wait(self.process, 20)
                if status == 0:
                    break
                if status != 0x102:
                    raise AdapterError('PROCESS_WAIT_FAILED')
                context.check()
                self.workspace.verify()
                if self.overflow.is_set():
                    raise AdapterError('OUTPUT_LIMIT_EXCEEDED')
            check(get_exit(self.process, C.byref(exit_code)))
            context.check()
            if exit_code.value:
                raise AdapterError('PROCESS_EXECUTION_FAILED')
        finally:
            self.terminate_tree_and_wait()  # Includes descendants after normal parent exit.
        if self.overflow.is_set():
            raise AdapterError('OUTPUT_LIMIT_EXCEEDED')
        return AdapterResult(bounded_redacted_stream(bytes(self.stdout)))
