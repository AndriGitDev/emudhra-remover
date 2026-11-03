"""SST interoperability in memory stores only; no registry store is opened."""

import ctypes
import sys
from contextlib import contextmanager
from ctypes import wintypes as w

import pytest
from test_cryptoapi import certificate

from emudhra_remover.adapters.sst import filter_sst, read_sst
from emudhra_remover.windows_native import CryptoAPI

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows CryptoAPI required")


class BLOB(ctypes.Structure):
    _fields_ = [("size", w.DWORD), ("data", ctypes.c_void_p)]


@contextmanager
def memory_store(api, data=None):
    buffer = ctypes.create_string_buffer(data) if data is not None else None
    blob = BLOB(len(data), ctypes.cast(buffer, ctypes.c_void_p)) if buffer is not None else None
    handle = api.check(
        api.dll.CertOpenStore(
            6 if data is not None else 2,
            0,
            None,
            0x200,
            ctypes.byref(blob) if blob is not None else None,
        )
    )
    try:
        yield handle
    finally:
        api.check(api.dll.CertCloseStore(handle, 0))


def save_memory(api, handle):
    function = api.dll.CertSaveStore
    function.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD, w.DWORD, ctypes.c_void_p, w.DWORD]
    function.restype = w.BOOL
    blob = BLOB()
    api.check(function(handle, 0, 1, 2, ctypes.byref(blob), 0))
    assert 20 <= blob.size <= 16 * 1024 * 1024
    buffer = ctypes.create_string_buffer(blob.size)
    blob.data = ctypes.cast(buffer, ctypes.c_void_p)
    api.check(function(handle, 0, 1, 2, ctypes.byref(blob), 0))
    return buffer.raw[: blob.size]


def native_records(api, handle):
    records, context = {}, None
    try:
        while True:
            context = api.dll.CertEnumCertificatesInStore(handle, context)
            if not context:
                break
            key, record = api.record(context)
            assert key not in records
            records[key] = record
    finally:
        if context:
            api.dll.CertFreeCertificateContext(context)
    return records


def set_property(api, context, identifier, value):
    function = api.dll.CertSetCertificateContextProperty
    function.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.c_void_p]
    function.restype = w.BOOL
    buffer = ctypes.create_string_buffer(value)
    blob = BLOB(len(value), ctypes.cast(buffer, ctypes.c_void_p))
    api.check(function(context, identifier, 0, ctypes.byref(blob)))


@pytest.mark.parametrize("metadata", [False, True, "combined-hash"])
def test_native_sst_export_filter_reopen_preserves_certificates_and_properties(metadata):
    api, expected, selected = CryptoAPI(), {}, None
    with memory_store(api) as source:
        for i in range(2):
            with api.certificate(certificate(f"SST fixture {i}")) as context:
                if metadata:
                    set_property(api, context, 11, f"Friendly ü {i}\0".encode("utf-16-le"))
                    set_property(api, context, 13, f"Description {i}\0".encode("utf-16-le"))
                if metadata == "combined-hash":
                    import hashlib

                    size = w.DWORD(52)
                    buffer = ctypes.create_string_buffer(52)
                    api.check(
                        api.dll.CertGetCertificateContextProperty(
                            context, 129, buffer, ctypes.byref(size)
                        )
                    )
                    der = ctypes.string_at(context.contents.encoded, context.contents.length)
                    assert size.value == 52
                    assert buffer.raw == hashlib.sha1(der).digest() + hashlib.sha256(der).digest()
                    set_property(api, context, 129, buffer.raw)
                key, record = api.record(context)
                expected[key] = record
                if i == 0:
                    selected = key
                api.check(api.dll.CertAddCertificateContextToStore(source, context, 1, None))
        original = save_memory(api, source)
        assert native_records(api, source) == expected
        matches, output, count = filter_sst(original, {"certificates": [{"sha256": selected}]})
        assert count == 2 and len(matches) == 1
        with memory_store(api, output) as reopened:
            assert native_records(api, reopened) == {
                k: v for k, v in expected.items() if k != selected
            }
            native_output = save_memory(api, reopened)
            assert len(read_sst(native_output)) == 1
        assert native_records(api, source) == expected
        assert filter_sst(original, {"certificates": []}) == ([], original, 2)


@pytest.mark.parametrize("identifier,value", [(19, b""), (104, bytes(8)), (9, b"0\0")])
def test_native_sst_policy_and_archive_exports_are_refused(identifier, value):
    api = CryptoAPI()
    with memory_store(api) as source:
        with api.certificate(certificate("SST restricted metadata")) as context:
            set_property(api, context, identifier, value)
            api.check(api.dll.CertAddCertificateContextToStore(source, context, 1, None))
        original = save_memory(api, source)
        with pytest.raises(ValueError, match="unsupported"):
            read_sst(original)
