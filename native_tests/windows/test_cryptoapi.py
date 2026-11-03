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


def delete_fixture_store(name):
    import winreg

    assert name.startswith("EmudhraFixture-") and len(name) == len("EmudhraFixture-") + 32
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


@pytest.fixture
def store_factory():
    from contextlib import ExitStack

    api, names = CryptoAPI(), []
    try:
        with ExitStack() as stack:

            def create():
                name = "EmudhraFixture-" + uuid.uuid4().hex
                handle = stack.enter_context(
                    api.open("CurrentUser", name, writable=True, physical=True, create=True)
                )
                names.append(name)
                return api, handle, name

            yield create
    finally:
        for name in names:
            delete_fixture_store(name)


@pytest.fixture
def native_store(store_factory):
    return store_factory()


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


@pytest.mark.parametrize("recovery", ["forward", "rollback"])
def test_native_partial_denial_recovery(store_factory, recovery):
    from emudhra_remover import windows_remote
    from emudhra_remover.windows_policy import decode, encode, fingerprint

    api, source, _ = store_factory()
    _, denied, _ = store_factory()
    for label in ("Incident A", "Incident B", "Unrelated root"):
        with api.certificate(certificate(label)) as context:
            key, record = api.record(context)
        api.add(source, key, record)
    operation = windows_remote.StoreOperation(api, source, denied)
    before_data = operation.snapshot()
    after = decode(before_data)
    selected = list(after["source"])[:2]
    for key in selected:
        record = after["source"][key]
        after["denied"][key] = {**record, "serialized": record["plain"]}
    after_data = encode(after)
    # Simulate one completed addition before process loss; sources stay intact.
    api.add(denied, selected[0], after["denied"][selected[0]])
    desired, origin = (
        (after_data, before_data) if recovery == "forward" else (before_data, after_data)
    )
    operation.replace(
        {
            "data": base64.b64encode(desired).decode(),
            "expected_sha256": fingerprint(origin),
            "recovery_from": base64.b64encode(origin).decode(),
        }
    )
    assert operation.snapshot() == desired
    assert windows_remote.WRITE_STARTED


def test_native_conflicting_change_blocks_recovery(store_factory):
    from emudhra_remover.windows_policy import decode, encode, fingerprint
    from emudhra_remover.windows_remote import StoreOperation

    api, source, _ = store_factory()
    _, denied, _ = store_factory()
    with api.certificate(certificate("Incident")) as context:
        key, record = api.record(context)
    api.add(source, key, record)
    operation = StoreOperation(api, source, denied)
    before = operation.snapshot()
    after = decode(before)
    after["denied"][key] = {**record, "serialized": record["plain"]}
    with api.certificate(certificate("Administrator added denial")) as context:
        other_key, other_record = api.record(context)
    api.add(denied, other_key, other_record)
    changed = operation.snapshot()
    with pytest.raises(ValueError, match="conflict"):
        operation.replace(
            {
                "data": base64.b64encode(encode(after)).decode(),
                "expected_sha256": fingerprint(before),
                "recovery_from": base64.b64encode(before).decode(),
            }
        )
    assert operation.snapshot() == changed


def test_native_sid_and_mutex():
    from emudhra_remover.windows_remote import current_sid, operation_lock

    assert current_sid().startswith("S-1-")
    with operation_lock("CurrentUser"):
        pass


@pytest.mark.parametrize("selected", [0, 1])
def test_native_chain_distrust_in_process_private_registry(selected):
    import json
    import subprocess
    from pathlib import Path

    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    names = [
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
        for value in ("Private fixture root", "Private fixture issuer", "Private fixture leaf")
    ]
    chain = []
    for i in range(3):
        issuer = max(0, i - 1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(names[i])
            .issuer_name(names[issuer])
            .public_key(keys[i].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=i < 2, path_length=None), True)
            .sign(keys[issuer], hashes.SHA256())
        )
        chain.append(base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode())
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("isolated_chain_probe.py"))],
        input=json.dumps({"chain": chain, "selected": selected}).encode(),
        capture_output=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr.decode()
    observed = json.loads(result.stdout)
    if "isolation_unavailable" in observed:
        pytest.skip(observed["isolation_unavailable"])
    assert observed["before"] == 0 and observed["restored"] == 0
    assert observed["after"] & 0x04000000  # CERT_TRUST_IS_EXPLICIT_DISTRUST
