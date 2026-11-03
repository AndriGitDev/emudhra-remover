"""Windows-only fixtures use unique custom stores; never Root or Disallowed."""

import base64
import ctypes
import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from emudhra_remover.windows_native import CryptoAPI

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows CryptoAPI required")


def certificate(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


@pytest.fixture
def native_store():
    api = CryptoAPI()
    name = "EmudhraFixture-" + uuid.uuid4().hex
    assert name.startswith("EmudhraFixture-")
    with api.open("CurrentUser", name, writable=True, physical=True, create=True) as handle:
        yield api, handle, name
    # Remove ONLY our random custom store, including its now-unused registry key.
    import winreg

    path = "Software\\Microsoft\\SystemCertificates\\" + name

    def delete_tree(parent, child):
        with winreg.OpenKey(parent, child, 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            while True:
                try:
                    nested = winreg.EnumKey(key, 0)
                except OSError:
                    break
                delete_tree(key, nested)
        winreg.DeleteKey(parent, child)

    delete_tree(winreg.HKEY_CURRENT_USER, path)


def test_plain_native_serialization_is_stable_across_persist_and_reopen(native_store):
    api, handle, name = native_store
    assert api.entries(handle) == {}
    der = certificate("Isolated native root")
    with api.certificate(der) as context:
        key, record = api.record(context)
    assert record["plain"] == record["serialized"]
    api.validate_record(key, record)
    api.add(handle, key, record)
    assert api.entries(handle) == {key: record}
    with api.open("CurrentUser", name, physical=True) as reopened:
        assert api.entries(reopened) == {key: record}
    api.delete(handle, key, record)
    assert api.entries(handle) == {}


def test_friendly_name_property_survives_serialized_roundtrip(native_store):
    from ctypes import wintypes as w

    class BLOB(ctypes.Structure):
        _fields_ = [("size", w.DWORD), ("data", ctypes.c_void_p)]

    api, handle, _ = native_store
    api.dll.CertSetCertificateContextProperty.argtypes = [
        ctypes.c_void_p,
        w.DWORD,
        w.DWORD,
        ctypes.c_void_p,
    ]
    api.dll.CertSetCertificateContextProperty.restype = w.BOOL
    der = certificate("Property-bearing fixture")
    value = "Fixture friendly name\x00".encode("utf-16-le")
    buffer = ctypes.create_string_buffer(value)
    blob = BLOB(len(value), ctypes.cast(buffer, ctypes.c_void_p))
    with api.certificate(der) as context:
        api.check(api.dll.CertSetCertificateContextProperty(context, 11, 0, ctypes.byref(blob)))
        key, record = api.record(context)
    assert record["serialized"] != record["plain"]
    api.validate_record(key, record)
    api.add(handle, key, record)
    assert api.entries(handle) == {key: record}
    api.delete(handle, key, record)
    api.add(handle, key, record)
    assert api.entries(handle) == {key: record}


def test_mismatched_serialized_certificate_rejected(native_store):
    api, _, _ = native_store
    with api.certificate(certificate("A")) as context:
        key, record = api.record(context)
    record["der"] = base64.b64encode(certificate("B")).decode()
    with pytest.raises(ValueError, match="round-trip"):
        api.validate_record(key, record)
