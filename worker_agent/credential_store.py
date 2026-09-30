"""Worker credential storage. Only the backend depends on Windows."""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
from typing import Protocol
from uuid import UUID, uuid4


class CredentialStore(Protocol):
    def load(self, worker_id: UUID) -> str: ...
    def save(self, worker_id: UUID, token: str) -> None: ...


def default_credential_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise RuntimeError("LOCALAPPDATA is unavailable")
    return Path(local_app_data) / "DevAI" / "worker-token.dpapi"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
    ]


def _dpapi(data: bytes, *, protect: bool, machine: bool = False) -> bytes:
    if sys.platform != "win32":
        raise OSError("Windows DPAPI is available only on Windows")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    function = (
        crypt32.CryptProtectData
        if protect else crypt32.CryptUnprotectData
    )
    function.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    function.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    input_buffer = ctypes.create_string_buffer(data)
    input_blob = _DataBlob(
        len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte))
    )
    output_blob = _DataBlob()
    if not function(
        ctypes.byref(input_blob),
        None,
        None,
        None,
        None,
        0x1 | (0x4 if machine and protect else 0),
        ctypes.byref(output_blob),
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(output_blob.pbData, ctypes.c_void_p))


class WindowsDpapiCredentialStore:
    def __init__(self, path: Path | None = None):
        if sys.platform != "win32":
            raise OSError("Windows credential store requires Windows")
        self.path = path or default_credential_path()

    def save(self, worker_id: UUID, token: str) -> None:
        if not token.startswith("devai_wkr_"):
            raise ValueError("Invalid Worker token format")
        payload = json.dumps({
            "worker_id": str(worker_id),
            "token": token,
        }).encode("utf-8")
        encrypted = _dpapi(payload, protect=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(
            self.path.name + "." + uuid4().hex + ".tmp"
        )
        try:
            temporary.write_bytes(encrypted)
            os.replace(temporary, self.path)
        finally:
            temporary.unlink(missing_ok=True)

    def load(self, worker_id: UUID) -> str:
        payload = json.loads(
            _dpapi(self.path.read_bytes(), protect=False).decode("utf-8")
        )
        if payload.get("worker_id") != str(worker_id):
            raise ValueError("Credential belongs to another Worker")
        token = payload.get("token")
        if not isinstance(token, str) or not token.startswith("devai_wkr_"):
            raise ValueError("Invalid stored Worker credential")
        return token
