import hashlib
import os
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.p11_formats import edk2_records, jks_records, pem_records


def certificate_ders(fixture_bundle):
    return sorted(
        x509.load_pem_x509_certificate(p).public_bytes(Encoding.DER) for p in fixture_bundle[:2]
    )


def test_native_jks_checksum_aliases_and_certificates(p11_exports, fixture_bundle):
    raw = (p11_exports / "java-cacerts").read_bytes()
    records = jks_records(raw)
    assert sorted(der for _, der in records) == certificate_ders(fixture_bundle)
    assert len({alias for alias, _ in records}) == 2
    java = os.environ.get("EMUDHRA_JAVA")
    keytool = str(Path(java).with_name("keytool")) if java else "keytool"
    try:
        subprocess.run(
            [
                keytool,
                "-list",
                "-keystore",
                str(p11_exports / "java-cacerts"),
                "-storetype",
                "JKS",
                "-storepass",
                "changeit",
            ],
            capture_output=True,
            check=True,
            timeout=20,
        )
    except FileNotFoundError:
        pytest.skip("Native keytool unavailable for independent export validation")


def test_jks_timestamp_changes_normalize_but_bad_checksum_fails(p11_exports):
    raw = (p11_exports / "java-cacerts").read_bytes()
    changed = bytearray(raw)
    alias_length = int.from_bytes(raw[16:18], "big")
    timestamp_offset = 18 + alias_length
    changed[timestamp_offset : timestamp_offset + 8] = b"\x00" * 8
    with pytest.raises(ValueError, match="checksum"):
        jks_records(bytes(changed))
    changed[-20:] = hashlib.sha1(
        "changeit".encode("utf-16be") + b"Mighty Aphrodite" + changed[:-20]
    ).digest()
    assert jks_records(bytes(changed)) == jks_records(raw)
    with pytest.raises(ValueError, match="Trailing"):
        jks_records(raw + b"\x00")


def test_native_edk2_export_preserves_owner_and_der(p11_exports, fixture_bundle):
    records = edk2_records((p11_exports / "edk2-cacerts").read_bytes())
    assert sorted(der for _, der in records) == certificate_ders(fixture_bundle)
    assert all(len(owner) == 16 for owner, _ in records)


def test_native_pem_exports_and_hash_directory(p11_exports, fixture_bundle):
    plain = pem_records((p11_exports / "pem-bundle").read_bytes())
    assert sorted(der for _, der in plain) == certificate_ders(fixture_bundle)
    assert len(pem_records((p11_exports / "openssl-bundle").read_bytes())) == 2
    directory = p11_exports / "pem-directory-hash"
    for certificate in directory.glob("*.pem"):
        subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CAfile",
                "-no-CAstore",
                "-CApath",
                str(directory),
                str(certificate),
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )


@pytest.mark.parametrize(
    "bad",
    [
        b"unparsed data",
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
        b"-----BEGIN CERTIFICATE-----\nbroken",
    ],
)
def test_native_pem_reader_rejects_unparsed_content(bad):
    with pytest.raises(ValueError):
        pem_records(bad)
