import struct
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.adapters.edk2 import filter_edk2
from emudhra_remover.p11_formats import EFI_CERT_X509, edk2_lists, edk2_records


def collection(entries):
    assert len({len(der) for _, der in entries}) == 1
    payload = b"".join(owner + der for owner, der in entries)
    return (
        EFI_CERT_X509 + struct.pack("<III", 28 + len(payload), 0, 16 + len(entries[0][1])) + payload
    )


async def test_native_export_apply_and_exact_rollback(service, fixture_bundle, p11_exports):
    app, path, _ = service
    raw = (p11_exports / "edk2-cacerts").read_bytes()
    path.write_bytes(raw)
    app.inventory.targets[0].adapter = "edk2-cacerts"
    original_lists = edk2_lists(raw)
    scan = await app.scan("test")
    assert scan["certificates_scanned"] == 2
    assert len(scan["matches"]) == 1
    plan = await app.plan("test")
    await app.apply(plan["plan_id"])
    good_der = x509.load_pem_x509_certificate(fixture_bundle[1]).public_bytes(Encoding.DER)
    survivor = edk2_records(path.read_bytes())
    assert len(survivor) == 1 and survivor[0][1] == good_der
    assert path.read_bytes() == next(
        raw for raw, entries in original_lists if entries[0][1] == good_der
    )
    assert (await app.scan("test"))["matches"] == []
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == raw


def test_partial_list_preserves_unmatched_entry_and_owner(fixture_bundle):
    bad = x509.load_pem_x509_certificate(fixture_bundle[0]).public_bytes(Encoding.DER)
    # Equal-sized certificate records share one EFI_SIGNATURE_LIST. A second cert
    # with exactly the same DER but a different owner is still an exact match.
    # Use another certificate as the unmatched member, generating until equal size.
    from conftest import certificate

    for _ in range(100):
        candidate = certificate("emSign Test Root")
        good = x509.load_pem_x509_certificate(candidate).public_bytes(Encoding.DER)
        if len(good) == len(bad):
            break
    else:
        pytest.fail("Could not create equal-sized synthetic DER certificates")
    first_owner, second_owner = uuid.uuid4().bytes_le, uuid.uuid4().bytes_le
    raw = collection([(first_owner, bad), (second_owner, good)])
    matches, output, count = filter_edk2(raw, fixture_bundle[2])
    assert count == 2 and len(matches) == 1
    assert edk2_records(output) == [(second_owner, good)]
    assert output == collection([(second_owner, good)])


def test_all_matching_duplicate_owners_auditable(fixture_bundle):
    bad = x509.load_pem_x509_certificate(fixture_bundle[0]).public_bytes(Encoding.DER)
    raw = collection([(uuid.uuid4().bytes_le, bad), (uuid.uuid4().bytes_le, bad)])
    matches, output, count = filter_edk2(raw, fixture_bundle[2])
    assert count == len(matches) == 2
    assert output == b""


async def test_all_matching_collection_cannot_be_emptied(service, fixture_bundle):
    app, path, _ = service
    bad = x509.load_pem_x509_certificate(fixture_bundle[0]).public_bytes(Encoding.DER)
    path.write_bytes(collection([(uuid.uuid4().bytes_le, bad)]))
    app.inventory.targets[0].adapter = "edk2-cacerts"
    with pytest.raises(ValueError, match="empty"):
        await app.plan("test")


@pytest.mark.parametrize(
    "corruption", ["guid", "header", "signature_size", "list_size", "trailing", "bad_der", "empty"]
)
def test_unsupported_edk2_structures_fail_closed(fixture_bundle, corruption):
    bad = x509.load_pem_x509_certificate(fixture_bundle[0]).public_bytes(Encoding.DER)
    raw = bytearray(collection([(uuid.uuid4().bytes_le, bad)]))
    if corruption == "guid":
        raw[:16] = uuid.uuid4().bytes_le
    elif corruption == "header":
        raw[20:24] = struct.pack("<I", 4)
    elif corruption == "signature_size":
        raw[24:28] = struct.pack("<I", 16)
    elif corruption == "list_size":
        raw[16:20] = struct.pack("<I", len(raw) + 1)
    elif corruption == "trailing":
        raw.extend(b"trailing data")
    elif corruption == "bad_der":
        raw[44] = 0xFF
    elif corruption == "empty":
        raw = bytearray()
    with pytest.raises(ValueError):
        filter_edk2(bytes(raw), fixture_bundle[2])
