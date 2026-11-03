"""Process-private registry redirection: never alter real Root/Disallowed stores."""

import base64
import ctypes
import json
import sys
import uuid
import winreg
from contextlib import ExitStack
from ctypes import wintypes as w


def delete_tree(parent, name):
    with winreg.OpenKey(parent, name, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        while True:
            try:
                child = winreg.EnumKey(key, 0)
            except OSError:
                break
            delete_tree(key, child)
    winreg.DeleteKey(parent, name)


def run():
    data = json.loads(sys.stdin.read())
    fixture_name = "Software\\EmudhraFixture-" + uuid.uuid4().hex
    original = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "", 0, winreg.KEY_READ | winreg.KEY_WRITE)
    fixture = winreg.CreateKey(original, fixture_name)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    advapi.RegOverridePredefKey.argtypes = [w.HKEY, w.HKEY]
    advapi.RegOverridePredefKey.restype = w.LONG
    redirected = False
    sentinel = None
    try:
        assert advapi.RegOverridePredefKey(winreg.HKEY_CURRENT_USER, int(fixture)) == 0
        redirected = True
        # Load CryptoAPI only after installing process-local redirection.
        from emudhra_remover.windows_native import CONTEXT, CryptoAPI

        api = CryptoAPI()
        with ExitStack() as stack:
            sentinel = "EmudhraFixture-" + uuid.uuid4().hex
            stack.enter_context(
                api.open("CurrentUser", sentinel, physical=True, writable=True, create=True)
            )
            # Refuse the probe unless native CryptoAPI demonstrably uses the fixture.
            try:
                with winreg.OpenKey(
                    fixture, "Software\\Microsoft\\SystemCertificates\\" + sentinel
                ):
                    pass
            except FileNotFoundError:
                print(
                    json.dumps(
                        {
                            "isolation_unavailable": (
                                "CryptoAPI bypassed HKCU redirection; "
                                "no Root/Disallowed write attempted"
                            )
                        }
                    )
                )
                return
            source = stack.enter_context(
                api.open(
                    "CurrentUser",
                    "EmudhraFixture-Source",
                    physical=True,
                    writable=True,
                    create=True,
                )
            )
            denied = stack.enter_context(
                api.open("CurrentUser", "Disallowed", physical=True, writable=True, create=True)
            )
            for cert in data["chain"][:2]:
                with api.certificate(base64.b64decode(cert)) as context:
                    key, record = api.record(context)
                api.add(source, key, record)
            with winreg.OpenKey(fixture, "Software\\Microsoft\\SystemCertificates\\Disallowed"):
                pass

            class ENGINE(ctypes.Structure):
                _fields_ = [
                    ("size", w.DWORD),
                    ("root", w.HANDLE),
                    ("trust", w.HANDLE),
                    ("other", w.HANDLE),
                    ("count", w.DWORD),
                    ("additional", ctypes.c_void_p),
                    ("flags", w.DWORD),
                    ("timeout", w.DWORD),
                    ("maximum", w.DWORD),
                    ("cycle", w.DWORD),
                    ("exclusive", w.HANDLE),
                    ("people", w.HANDLE),
                    ("exclusive_flags", w.DWORD),
                ]

            class USAGE(ctypes.Structure):
                _fields_ = [("type", w.DWORD), ("count", w.DWORD), ("oids", ctypes.c_void_p)]

            class PARAMETERS(ctypes.Structure):
                _fields_ = [
                    ("size", w.DWORD),
                    ("usage", USAGE),
                    ("issuance", USAGE),
                    ("timeout", w.DWORD),
                    ("fresh_check", w.BOOL),
                    ("fresh", w.DWORD),
                    ("cache_time", ctypes.c_void_p),
                    ("strong", ctypes.c_void_p),
                    ("strong_flags", w.DWORD),
                ]

            class CHAIN_HEAD(ctypes.Structure):
                _fields_ = [("size", w.DWORD), ("errors", w.DWORD), ("info", w.DWORD)]

            api.dll.CertCreateCertificateChainEngine.argtypes = [
                ctypes.POINTER(ENGINE),
                ctypes.POINTER(w.HANDLE),
            ]
            api.dll.CertCreateCertificateChainEngine.restype = w.BOOL
            api.dll.CertGetCertificateChain.argtypes = [
                w.HANDLE,
                CONTEXT,
                ctypes.c_void_p,
                w.HANDLE,
                ctypes.POINTER(PARAMETERS),
                w.DWORD,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            api.dll.CertGetCertificateChain.restype = w.BOOL
            api.dll.CertFreeCertificateChain.argtypes = [ctypes.c_void_p]
            api.dll.CertFreeCertificateChainEngine.argtypes = [w.HANDLE]

            def verify():
                config = ENGINE()
                config.size, config.exclusive, config.other, config.flags = (
                    ctypes.sizeof(config),
                    source,
                    source,
                    0x2004,
                )
                engine = w.HANDLE()
                api.check(
                    api.dll.CertCreateCertificateChainEngine(
                        ctypes.byref(config), ctypes.byref(engine)
                    )
                )
                try:
                    with api.certificate(base64.b64decode(data["chain"][2])) as leaf:
                        parameters = PARAMETERS()
                        parameters.size = ctypes.sizeof(parameters)
                        chain = ctypes.c_void_p()
                        api.check(
                            api.dll.CertGetCertificateChain(
                                engine,
                                leaf,
                                None,
                                source,
                                ctypes.byref(parameters),
                                0x2004,
                                None,
                                ctypes.byref(chain),
                            )
                        )
                        try:
                            return ctypes.cast(chain, ctypes.POINTER(CHAIN_HEAD)).contents.errors
                        finally:
                            api.dll.CertFreeCertificateChain(chain)
                finally:
                    api.dll.CertFreeCertificateChainEngine(engine)

            before = verify()
            with api.certificate(base64.b64decode(data["chain"][data["selected"]])) as context:
                key, record = api.record(context)
            api.add(denied, key, record)
            after = verify()
            api.delete(denied, key, record)
            restored = verify()
            print(json.dumps({"before": before, "after": after, "restored": restored}))
    finally:
        if redirected:
            assert advapi.RegOverridePredefKey(winreg.HKEY_CURRENT_USER, None) == 0
        if sentinel:
            try:
                delete_tree(original, "Software\\Microsoft\\SystemCertificates\\" + sentinel)
            except FileNotFoundError:
                pass
        fixture.Close()
        delete_tree(original, fixture_name)
        original.Close()


if __name__ == "__main__":
    run()
