"""Windows-only native security operations; never weaken a failed boundary."""
import ctypes as C
from ctypes import wintypes as W
import os
from pathlib import Path
import sys

from .adapters import AdapterError


def windows_only():
    if sys.platform != 'win32':
        raise AdapterError('WINDOWS_ISOLATION_REQUIRED')


def api(dll, name, result, arguments):
    function = getattr(dll, name)
    function.restype = result
    function.argtypes = arguments
    return function


def check(ok, code='WINDOWS_SECURITY_OPERATION_FAILED'):
    if not ok:
        error = AdapterError(code)
        error.winerror = C.get_last_error() if sys.platform == 'win32' else None
        raise error


def no_reparse(path, *, allowed_mount=None):
    """Check lexical ancestors before opening: resolving first would hide escapes."""
    path = Path(os.path.abspath(path))
    for entry in (*reversed(path.parents), path):
        if allowed_mount is not None and entry == allowed_mount:
            continue  # Caller has separately verified its pinned volume GUID.
        attributes = entry.lstat().st_file_attributes if sys.platform == 'win32' else 0
        if attributes & 0x400 or entry.is_symlink():
            raise AdapterError('REPARSE_POINT_REJECTED')
    return path


class AppContainerSid:
    def __init__(self, name):
        windows_only()
        self.pointer = C.c_void_p()
        userenv = C.WinDLL('userenv', use_last_error=True)
        advapi = C.WinDLL('advapi32', use_last_error=True)
        self._free = api(advapi, 'FreeSid', C.c_void_p, [C.c_void_p])
        self.name = name
        self._delete = api(userenv, 'DeleteAppContainerProfile', C.c_long, [W.LPCWSTR])
        create = api(userenv, 'CreateAppContainerProfile', C.c_long,
                     [W.LPCWSTR, W.LPCWSTR, W.LPCWSTR, C.c_void_p, W.DWORD, C.POINTER(C.c_void_p)])
        check(create(name, name, 'DevAI disposable execution isolation', None, 0,
                     C.byref(self.pointer)) == 0, 'APPCONTAINER_PROFILE_FAILED')
        text = W.LPWSTR()
        convert = api(advapi, 'ConvertSidToStringSidW', W.BOOL,
                      [C.c_void_p, C.POINTER(W.LPWSTR)])
        check(convert(self.pointer, C.byref(text)))
        self.text = text.value
        local_free = api(C.WinDLL('kernel32'), 'LocalFree', C.c_void_p, [C.c_void_p])
        local_free(C.cast(text, C.c_void_p))
        folder = W.LPWSTR()
        get_folder = api(userenv, 'GetAppContainerFolderPath', C.c_long,
                         [W.LPCWSTR, C.POINTER(W.LPWSTR)])
        check(get_folder(self.text, C.byref(folder)) == 0, 'APPCONTAINER_STORAGE_FAILED')
        self.folder = Path(folder.value)
        api(C.WinDLL('ole32'), 'CoTaskMemFree', None, [C.c_void_p])(C.cast(folder, C.c_void_p))

    def close(self):
        if self.pointer:
            check(self._delete(self.name) == 0, 'APPCONTAINER_PROFILE_CLEANUP_FAILED')
            self._free(self.pointer)
            self.pointer = C.c_void_p()

    def restrict_registry(self, owner_sid):
        import winreg
        advapi = C.WinDLL('advapi32', use_last_error=True)
        path = r'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage' + '\\' + self.text
        descriptor = C.c_void_p()
        convert = api(advapi,'ConvertStringSecurityDescriptorToSecurityDescriptorW',W.BOOL,
            [W.LPCWSTR,W.DWORD,C.POINTER(C.c_void_p),C.c_void_p])
        sddl=f'D:P(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;{owner_sid})(A;CI;KR;;;{self.text})'
        check(convert(sddl,1,C.byref(descriptor),None))
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER,path,0,winreg.KEY_ALL_ACCESS) as key:
                setter=api(advapi,'RegSetKeySecurity',W.LONG,[W.HKEY,W.DWORD,C.c_void_p])
                check(setter(int(key),4|0x80000000,descriptor)==0,'APPCONTAINER_REGISTRY_ISOLATION_FAILED')
        finally:
            api(C.WinDLL('kernel32'),'LocalFree',C.c_void_p,[C.c_void_p])(descriptor)


def set_directory_acl(path, owner_sid, app_sid=None, *, app_read_only=False, low=False, allowed_mount=None):
    """Protected allowlist DACL; low integrity only on the disposable workspace."""
    windows_only()
    no_reparse(path, allowed_mount=allowed_mount)
    advapi = C.WinDLL('advapi32', use_last_error=True)
    descriptor = C.c_void_p()
    convert = api(advapi, 'ConvertStringSecurityDescriptorToSecurityDescriptorW',
                  W.BOOL, [W.LPCWSTR, W.DWORD, C.POINTER(C.c_void_p), C.c_void_p])
    sddl = f'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner_sid})'
    if app_sid:
        rights = 'GRGX' if app_read_only else '0x1301bf'
        sddl += f'(A;OICI;{rights};;;{app_sid})'
    if low:
        sddl += 'S:(ML;OICI;NW;;;LW)'
    check(convert(sddl, 1, C.byref(descriptor), None))
    try:
        present, defaulted, acl = W.BOOL(), W.BOOL(), C.c_void_p()
        get_dacl = api(advapi, 'GetSecurityDescriptorDacl', W.BOOL,
                       [C.c_void_p, C.POINTER(W.BOOL), C.POINTER(C.c_void_p), C.POINTER(W.BOOL)])
        setter = api(advapi, 'SetNamedSecurityInfoW', W.DWORD,
                     [W.LPWSTR, W.DWORD, W.DWORD, C.c_void_p, C.c_void_p, C.c_void_p, C.c_void_p])
        check(get_dacl(descriptor, C.byref(present), C.byref(acl), C.byref(defaulted)))
        check(setter(str(path), 1, 4 | 0x80000000, None, None, acl, None) == 0)
        if low:
            get_sacl = api(advapi, 'GetSecurityDescriptorSacl', W.BOOL,
                           [C.c_void_p, C.POINTER(W.BOOL), C.POINTER(C.c_void_p), C.POINTER(W.BOOL)])
            check(get_sacl(descriptor, C.byref(present), C.byref(acl), C.byref(defaulted)))
            check(setter(str(path), 1, 0x10, None, None, None, acl) == 0)
    finally:
        api(C.WinDLL('kernel32'), 'LocalFree', C.c_void_p, [C.c_void_p])(descriptor)
