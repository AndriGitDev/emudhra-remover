import copy
import plistlib
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.adapters.apple_profile import filter_apple_profile, load_profile


def profile_for(certificates, kind="com.apple.security.root"):
    payloads = []
    for i, pem in enumerate(certificates):
        payloads.append(
            {
                "PayloadType": kind,
                "PayloadVersion": 1,
                "PayloadUUID": str(uuid.uuid4()),
                "PayloadIdentifier": f"org.example.certificate.{i}",
                "PayloadDisplayName": f"Root {i}",
                "PayloadContent": pem
                if kind.endswith(".pem")
                else x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER),
            }
        )
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadIdentifier": "org.example.certificate-profile",
        "PayloadScope": "System",
        "PayloadRemovalDisallowed": True,
        "ConsentText": {"default": "Certificate profile fixture", "is": "Prófun"},
        "PayloadContent": payloads,
    }


@pytest.mark.parametrize("format", [plistlib.FMT_XML, plistlib.FMT_BINARY])
@pytest.mark.parametrize(
    "kind", ["com.apple.security.root", "com.apple.security.pkcs1", "com.apple.security.pem"]
)
def test_profile_exact_selection_and_payload_metadata_preservation(fixture_bundle, format, kind):
    profile = profile_for(fixture_bundle[:2], kind)
    original = plistlib.dumps(profile, fmt=format, sort_keys=False)
    matches, output, count = filter_apple_profile(original, fixture_bundle[2])
    expected = copy.deepcopy(profile)
    expected["PayloadContent"] = expected["PayloadContent"][1:]
    assert count == 2 and len(matches) == 1
    assert matches[0]["payload_uuid"] == profile["PayloadContent"][0]["PayloadUUID"]
    assert plistlib.loads(output) == expected
    assert output.startswith(b"bplist00") == (format == plistlib.FMT_BINARY)
    assert filter_apple_profile(output, fixture_bundle[2])[1] == output


@pytest.mark.parametrize("format", [plistlib.FMT_XML, plistlib.FMT_BINARY])
async def test_profile_file_roundtrip_rollback_and_conflict(service, fixture_bundle, format):
    app, path, _ = service
    app.inventory.targets[0].adapter = "apple-profile"
    original = plistlib.dumps(profile_for(fixture_bundle[:2]), fmt=format)
    path.write_bytes(original)
    plan = await app.plan("test")
    await app.apply(plan["plan_id"])
    assert (await app.scan("test"))["matches"] == []
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == original
    plan = await app.plan("test")
    changed = profile_for(fixture_bundle[:2])
    path.write_bytes(plistlib.dumps(changed, fmt=format))
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])


@pytest.mark.parametrize(
    "corruption",
    [
        "pkcs12",
        "wifi",
        "uuid",
        "identifier",
        "extra",
        "version",
        "missing",
        "cert-trailing",
        "pem-key",
    ],
)
def test_profile_rejects_unsupported_and_ambiguous_content(fixture_bundle, corruption):
    profile = profile_for(fixture_bundle[:2])
    first, second = profile["PayloadContent"]
    if corruption == "pkcs12":
        first["PayloadType"] = "com.apple.security.pkcs12"
    elif corruption == "wifi":
        first["PayloadType"] = "com.apple.wifi.managed"
    elif corruption == "uuid":
        second["PayloadUUID"] = first["PayloadUUID"].upper()
    elif corruption == "identifier":
        second["PayloadIdentifier"] = first["PayloadIdentifier"]
    elif corruption == "extra":
        first["IdentityCertificateUUID"] = second["PayloadUUID"]
    elif corruption == "version":
        first["PayloadVersion"] = True
    elif corruption == "missing":
        del first["PayloadUUID"]
    elif corruption == "cert-trailing":
        first["PayloadContent"] += b"trailing"
    elif corruption == "pem-key":
        first["PayloadType"] = "com.apple.security.pem"
        first["PayloadContent"] = fixture_bundle[0] + b"-----BEGIN PRIVATE KEY-----"
    with pytest.raises(ValueError):
        filter_apple_profile(plistlib.dumps(profile), fixture_bundle[2])


@pytest.mark.parametrize(
    "corruption", ["duplicate", "unknown-tag", "entity", "data-garbage", "nested-string"]
)
def test_profile_strict_xml_rejects_ignored_or_ambiguous_data(fixture_bundle, corruption):
    raw = plistlib.dumps(profile_for(fixture_bundle[:2]))
    if corruption == "duplicate":
        raw = raw.replace(b"<dict>", b"<dict><key>PayloadVersion</key><integer>1</integer>", 1)
    elif corruption == "unknown-tag":
        raw = raw.replace(b"<dict>", b"<dict><unknown>ignored</unknown>", 1)
    elif corruption == "entity":
        raw = raw.replace(
            b"<plist version=", b'<!DOCTYPE plist [<!ENTITY x "boom">]><plist version='
        )
    elif corruption == "data-garbage":
        raw = raw.replace(b"<data>", b"<data>!", 1)
    elif corruption == "nested-string":
        raw = raw.replace(b"<string>", b"<string><string>nested</string>", 1)
    with pytest.raises(ValueError):
        load_profile(raw)


async def test_profile_all_matching_is_auditable_but_cannot_empty(service, fixture_bundle):
    app, path, _ = service
    app.inventory.targets[0].adapter = "apple-profile"
    path.write_bytes(plistlib.dumps(profile_for(fixture_bundle[:1])))
    assert len((await app.scan("test"))["matches"]) == 1
    with pytest.raises(ValueError, match="empty"):
        await app.plan("test")


def test_signed_cms_profile_is_refused(fixture_bundle):
    from datetime import UTC, datetime, timedelta

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs7
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture profile signer")])
    signer = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.now(UTC))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    content = plistlib.dumps(profile_for(fixture_bundle[:2]))
    signed = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(content)
        .add_signer(signer, key, hashes.SHA256())
        .sign(Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    with pytest.raises(ValueError, match="unsigned"):
        filter_apple_profile(signed, fixture_bundle[2])


def test_binary_table_allocation_and_object_bounds_are_checked(fixture_bundle):
    import struct

    raw = plistlib.dumps(profile_for(fixture_bundle[:2]), fmt=plistlib.FMT_BINARY)
    huge = raw[:-24] + struct.pack(">Q", 2**60) + raw[-16:]
    with pytest.raises(ValueError, match="table"):
        load_profile(huge)
    # A binary data object claiming an excessive inline length must be rejected
    # before plistlib attempts its own allocation/read.
    offset_size, _, count, _, table = struct.unpack(">6xBBQQQ", raw[-32:])
    offsets = [
        int.from_bytes(raw[i : i + offset_size], "big")
        for i in range(table, table + count * offset_size, offset_size)
    ]
    position = next(i for i in offsets if raw[i] == 0x4F)
    malformed = bytearray(raw)
    malformed[position + 1] = 0x13
    malformed[position + 2 : position + 10] = (2**60).to_bytes(8, "big")
    with pytest.raises(ValueError, match="bounds"):
        load_profile(bytes(malformed))


def test_binary_duplicate_dictionary_keys_are_rejected(fixture_bundle):
    import struct

    raw = bytearray(plistlib.dumps(profile_for(fixture_bundle[:2]), fmt=plistlib.FMT_BINARY))
    offset_size, ref_size, _, root, table = struct.unpack(">6xBBQQQ", raw[-32:])
    position = int.from_bytes(
        raw[table + root * offset_size : table + (root + 1) * offset_size], "big"
    )
    assert raw[position] & 0xF0 == 0xD0 and raw[position] & 0x0F < 15
    position += 1
    raw[position + ref_size : position + 2 * ref_size] = raw[position : position + ref_size]
    with pytest.raises(ValueError, match="Duplicate|Invalid Apple configuration"):
        load_profile(bytes(raw))
