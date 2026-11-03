"""Native CryptoAPI support; importable elsewhere, executable only on Windows.

Uses logical source stores read-only and the physical registry Disallowed store.
Tests substitute unique custom registry stores; they never write Root/Disallowed.
"""

import base64
import ctypes
import hashlib
from contextlib import contextmanager
from ctypes import wintypes as w

from .windows_serialized import canonical_element


class CERT_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("encoding", w.DWORD),
        ("encoded", ctypes.POINTER(ctypes.c_ubyte)),
        ("length", w.DWORD),
        ("info", ctypes.c_void_p),
        ("store", ctypes.c_void_p),
    ]


CONTEXT = ctypes.POINTER(CERT_CONTEXT)
NOT_FOUND = 0x80092004


class CryptoAPI:
    def __init__(self):
        self.dll = ctypes.WinDLL("crypt32", use_last_error=True)
        self.store_paths = {}
        specifications = {
            "CertOpenStore": (
                [ctypes.c_void_p, w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.c_void_p],
                ctypes.c_void_p,
            ),
            "CertCloseStore": ([ctypes.c_void_p, w.DWORD], w.BOOL),
            "CertEnumCertificatesInStore": ([ctypes.c_void_p, CONTEXT], CONTEXT),
            "CertGetCertificateContextProperty": (
                [CONTEXT, w.DWORD, ctypes.c_void_p, ctypes.POINTER(w.DWORD)],
                w.BOOL,
            ),
            "CertEnumCertificateContextProperties": ([CONTEXT, w.DWORD], w.DWORD),
            "CertSerializeCertificateStoreElement": (
                [CONTEXT, w.DWORD, ctypes.c_void_p, ctypes.POINTER(w.DWORD)],
                w.BOOL,
            ),
            "CertCreateCertificateContext": ([w.DWORD, ctypes.c_void_p, w.DWORD], CONTEXT),
            "CertFreeCertificateContext": ([CONTEXT], w.BOOL),
            "CertAddSerializedElementToStore": (
                [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    w.DWORD,
                    w.DWORD,
                    w.DWORD,
                    w.DWORD,
                    ctypes.POINTER(w.DWORD),
                    ctypes.POINTER(CONTEXT),
                ],
                w.BOOL,
            ),
            "CertAddCertificateContextToStore": (
                [ctypes.c_void_p, CONTEXT, w.DWORD, ctypes.POINTER(CONTEXT)],
                w.BOOL,
            ),
            "CertDeleteCertificateFromStore": ([CONTEXT], w.BOOL),
            "CertControlStore": ([ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.c_void_p], w.BOOL),
            "CertEnumCRLsInStore": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
            "CertFreeCRLContext": ([ctypes.c_void_p], w.BOOL),
            "CertEnumCTLsInStore": ([ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
            "CertFreeCTLContext": ([ctypes.c_void_p], w.BOOL),
        }
        for name, (arguments, result) in specifications.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def check(result):
        if not result:
            raise OSError(ctypes.get_last_error(), "Windows certificate operation failed")
        return result

    @contextmanager
    def open(self, location, name, *, writable=False, physical=False, create=False):
        if location not in ("CurrentUser", "LocalMachine"):
            raise ValueError("Unsupported Windows store location")
        # ENUM_ARCHIVED includes records normal enumeration would otherwise hide.
        flags = (0x10000 if location == "CurrentUser" else 0x20000) | 0x200
        if not create:
            flags |= 0x4000  # OPEN_EXISTING; audits never create stores
        if not writable:
            flags |= 0x8000  # READONLY
        store_name = ctypes.c_wchar_p(name)
        handle = self.check(
            self.dll.CertOpenStore(13 if physical else 10, 0, None, flags, store_name)
        )
        self.store_paths[handle] = (location, name)
        try:
            yield handle
        finally:
            self.store_paths.pop(handle, None)
            self.check(self.dll.CertCloseStore(handle, 0))

    def flush(self, handle):
        # Registry providers persist immediately but may defer the disk flush.
        import winreg

        location, name = self.store_paths[handle]
        hive = winreg.HKEY_CURRENT_USER if location == "CurrentUser" else winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, "Software\\Microsoft\\SystemCertificates\\" + name) as key:
            winreg.FlushKey(key)

    def serialize(self, context):
        # Registry insertion materializes this derived property. Include it in
        # in-memory previews too, so predictions equal persisted native records.
        sha_size = w.DWORD(20)
        sha_buffer = ctypes.create_string_buffer(20)
        self.check(
            self.dll.CertGetCertificateContextProperty(
                context, 3, sha_buffer, ctypes.byref(sha_size)
            )
        )
        der = ctypes.string_at(context.contents.encoded, context.contents.length)
        if sha_size.value != 20 or sha_buffer.raw != hashlib.sha1(der).digest():
            raise ValueError("Windows cached certificate identity does not match DER")
        size = w.DWORD()
        self.check(
            self.dll.CertSerializeCertificateStoreElement(context, 0, None, ctypes.byref(size))
        )
        if not 0 < size.value <= 16 * 1024 * 1024:
            raise ValueError("Oversized Windows certificate entry")
        buffer = ctypes.create_string_buffer(size.value)
        self.check(
            self.dll.CertSerializeCertificateStoreElement(context, 0, buffer, ctypes.byref(size))
        )
        return canonical_element(buffer.raw[: size.value])

    @contextmanager
    def certificate(self, der):
        context = self.check(self.dll.CertCreateCertificateContext(1, der, len(der)))
        try:
            yield context
        finally:
            self.dll.CertFreeCertificateContext(context)

    def record(self, context):
        property_id = 0
        seen = set()
        while True:
            property_id = self.dll.CertEnumCertificateContextProperties(context, property_id)
            if not property_id:
                break
            if property_id in seen or len(seen) > 256:
                raise ValueError("Invalid Windows certificate properties")
            seen.add(property_id)
        # Refuse private-key/provider handles and archived key material before transfer.
        if seen & {1, 2, 5, 6, 12, 65, 78, 79}:
            raise ValueError("Windows identity/private-key certificates are unsupported")
        if not 0 < context.contents.length <= 16 * 1024 * 1024:
            raise ValueError("Oversized Windows certificate")
        der = ctypes.string_at(context.contents.encoded, context.contents.length)
        serialized = self.serialize(context)
        with self.certificate(der) as plain:
            plain_bytes = self.serialize(plain)
        return hashlib.sha256(der).hexdigest(), {
            "der": base64.b64encode(der).decode(),
            "serialized": base64.b64encode(serialized).decode(),
            "plain": base64.b64encode(plain_bytes).decode(),
        }

    def entries(self, handle):
        self.check(self.dll.CertControlStore(handle, 0, 1, None))  # RESYNC
        for kind in ("CRL", "CTL"):
            context = getattr(self.dll, "CertEnum" + kind + "sInStore")(handle, None)
            if context:
                getattr(self.dll, "CertFree" + kind + "Context")(context)
                raise ValueError("Windows stores containing CRL/CTL records are unsupported")
            if (ctypes.get_last_error() & 0xFFFFFFFF) not in (NOT_FOUND, 18):
                raise OSError(ctypes.get_last_error(), "Cannot enumerate Windows store")
        entries, total, context = {}, 0, None
        try:
            while True:
                context = self.dll.CertEnumCertificatesInStore(handle, context)
                if not context:
                    if (ctypes.get_last_error() & 0xFFFFFFFF) not in (NOT_FOUND, 18):
                        raise OSError(
                            ctypes.get_last_error(), "Cannot enumerate Windows certificates"
                        )
                    break
                key, record = self.record(context)
                if key in entries:
                    raise ValueError("Duplicate certificates across Windows physical stores")
                entries[key] = record
                total += sum(len(value) for value in record.values())
                if len(entries) > 4096 or total > 16 * 1024 * 1024:
                    raise ValueError("Windows snapshot exceeds size limit")
        finally:
            if context:
                self.dll.CertFreeCertificateContext(context)
        return entries

    def validate_record(self, key, record):
        raw = base64.b64decode(record["serialized"], validate=True)
        context, kind = CONTEXT(), w.DWORD()
        self.check(
            self.dll.CertAddSerializedElementToStore(
                None, raw, len(raw), 1, 0, 2, ctypes.byref(kind), ctypes.byref(context)
            )
        )
        try:
            if kind.value != 1 or self.record(context) != (key, record):
                raise ValueError("Windows serialized certificate/properties did not round-trip")
        finally:
            self.dll.CertFreeCertificateContext(context)

    def add(self, handle, key, record):
        self.validate_record(key, record)
        raw = base64.b64decode(record["serialized"], validate=True)
        self.check(
            self.dll.CertAddSerializedElementToStore(handle, raw, len(raw), 1, 0, 2, None, None)
        )
        self.check(self.dll.CertControlStore(handle, 0, 3, None))  # COMMIT
        self.flush(handle)

    def delete(self, handle, key, record):
        context = None
        try:
            while True:
                context = self.dll.CertEnumCertificatesInStore(handle, context)
                if not context:
                    raise ValueError("Windows denial disappeared before deletion")
                found, actual = self.record(context)
                if found == key:
                    if actual != record:
                        raise ValueError("Windows denial properties changed before deletion")
                    to_delete, context = context, None  # Delete always consumes the context.
                    self.check(self.dll.CertDeleteCertificateFromStore(to_delete))
                    self.check(self.dll.CertControlStore(handle, 0, 3, None))
                    self.flush(handle)
                    return
        finally:
            if context:
                self.dll.CertFreeCertificateContext(context)
