"""Fixed Windows helper: native explicit distrust with exact-entry recovery."""

import base64
import ctypes
import json
import sys
from contextlib import contextmanager
from ctypes import wintypes as w

from .windows_native import CryptoAPI
from .windows_policy import (
    decode,
    encode,
    fingerprint,
    is_intermediate,
    unbase,
    validate_transition,
)

WRITE_STARTED = False


def current_sid():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = w.HANDLE
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)]
    advapi.GetTokenInformation.argtypes = [
        w.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        w.DWORD,
        ctypes.POINTER(w.DWORD),
    ]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    token = w.HANDLE()
    CryptoAPI.check(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)))
    try:
        size = w.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 0 < size.value < 65536:
            raise ValueError("Cannot identify Windows security principal")
        buffer = ctypes.create_string_buffer(size.value)
        CryptoAPI.check(advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)))
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        text = ctypes.c_wchar_p()
        CryptoAPI.check(advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)))
        try:
            return text.value
        finally:
            kernel.LocalFree(text)
    finally:
        kernel.CloseHandle(token)


@contextmanager
def operation_lock(location):
    scope = location if location == "LocalMachine" else location + ":" + current_sid()
    name = "Global\\emudhra-remover-" + fingerprint(scope.encode())
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateMutexW.argtypes, kernel.CreateMutexW.restype = (
        [ctypes.c_void_p, w.BOOL, w.LPCWSTR],
        w.HANDLE,
    )
    kernel.WaitForSingleObject.argtypes, kernel.WaitForSingleObject.restype = (
        [w.HANDLE, w.DWORD],
        w.DWORD,
    )
    kernel.ReleaseMutex.argtypes = [w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    mutex = CryptoAPI.check(kernel.CreateMutexW(None, False, name))
    acquired = False
    try:
        result = kernel.WaitForSingleObject(mutex, 0)
        if result not in (0, 0x80):  # acquired or abandoned by a crashed helper
            raise ValueError("Windows certificate operation busy or mutex unavailable")
        acquired = True
        yield
    finally:
        if acquired:
            kernel.ReleaseMutex(mutex)
        kernel.CloseHandle(mutex)


class StoreOperation:
    def __init__(self, api, source, denied):
        self.api, self.source, self.denied = api, source, denied

    def snapshot(self):
        snapshot = {
            "source": self.api.entries(self.source),
            "denied": self.api.entries(self.denied),
        }
        data = encode(snapshot)
        decode(data)
        return data

    def replace(self, request):
        global WRITE_STARTED
        desired_data = unbase(request["data"])
        desired = decode(desired_data)
        current_data = self.snapshot()
        current = decode(current_data)
        if "recovery_from" in request:
            original_data = unbase(request["recovery_from"])
            original = decode(original_data)
            if fingerprint(original_data) != request["expected_sha256"]:
                raise ValueError("Windows recovery snapshot hash mismatch")
            if not is_intermediate(current, original, desired):
                raise ValueError("Windows stores conflict with recovery snapshots")
        else:
            original = current
            if fingerprint(current_data) != request["expected_sha256"]:
                raise ValueError("Windows stores changed since planning")
        validate_transition(original, desired)
        for key, record in desired["denied"].items():
            self.api.validate_record(key, record)
        working = current
        added = desired["denied"].keys() - current["denied"].keys()
        removed = current["denied"].keys() - desired["denied"].keys()
        for key in sorted(added | removed):
            # A fresh native RESYNC precedes every mutation, including recovery.
            if self.snapshot() != encode(working):
                raise ValueError("Concurrent Windows certificate-store update detected")
            WRITE_STARTED = True
            if key in added:
                self.api.add(self.denied, key, desired["denied"][key])
                working["denied"][key] = desired["denied"][key]
            else:
                self.api.delete(self.denied, key, working["denied"][key])
                del working["denied"][key]
            if self.snapshot() != encode(working):
                raise ValueError("Windows post-write certificate/property verification failed")
        if self.snapshot() != desired_data:
            raise ValueError("Windows final verification failed")
        return {"sha256": fingerprint(desired_data)}


def perform(request):
    global WRITE_STARTED
    WRITE_STARTED = False
    path = request["path"].split("/")
    if (
        len(path) != 4
        or path[:2] != ["cert:", ""]
        or path[2] not in ("CurrentUser", "LocalMachine")
        or path[3] not in ("Root", "CA")
    ):
        raise ValueError("Windows path must be cert://CurrentUser|LocalMachine/Root|CA")
    if request["operation"] not in ("read", "replace"):
        raise ValueError("Unsupported Windows operation")
    location, name = path[2:]
    api = CryptoAPI()
    with (
        operation_lock(location),
        api.open(location, name) as source,
        api.open(
            location, "Disallowed", physical=True, writable=request["operation"] == "replace"
        ) as denied,
    ):
        operation = StoreOperation(api, source, denied)
        if request["operation"] == "read":
            data = operation.snapshot()
            return {"data": base64.b64encode(data).decode(), "sha256": fingerprint(data)}
        return operation.replace(request)


def main(request):
    try:
        print(json.dumps(perform(request)))
    except Exception as error:
        print(json.dumps({"error": str(error), "write_may_have_occurred": WRITE_STARTED}))
        sys.exit(1)
