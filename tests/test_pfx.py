import hashlib
import hmac
import shutil
import subprocess

import pytest
from asn1crypto import cms, pkcs12
from cryptography import x509
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding
from cryptography.hazmat.primitives.serialization import pkcs12 as native_pkcs12

from emudhra_remover.adapters.pfx import safe_contents, validate_java_pfx

PASSWORD = b"fixture-password"


def original(fixture_bundle):
    return native_pkcs12.serialize_java_truststore(
        [
            native_pkcs12.PKCS12Certificate(x509.load_pem_x509_certificate(cert), name)
            for cert, name in zip(fixture_bundle[:2], (b"bad", b"good"), strict=True)
        ],
        BestAvailableEncryption(PASSWORD),
    )


def plain_fixture(raw, mutate):
    """Rebuild a real password-authenticated PFX using OpenSSL's PKCS12 KDF."""
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL KDF required for adversarial authenticated fixtures")
    pfx = pkcs12.Pfx.load(raw)
    bags = []
    for item in pkcs12.AuthenticatedSafe.load(pfx["auth_safe"]["content"].native):
        bags.extend(pkcs12.SafeContents.load(safe_contents(item, PASSWORD)))
    mutate(bags)
    safe = pkcs12.AuthenticatedSafe(
        [cms.ContentInfo({"content_type": "data", "content": pkcs12.SafeContents(bags).dump()})]
    ).dump()
    salt = bytes(range(16))
    encoded_password = PASSWORD.decode().encode("utf-16-be") + b"\0\0"
    result = subprocess.run(
        [
            "openssl",
            "kdf",
            "-keylen",
            "32",
            "-kdfopt",
            "digest:SHA256",
            "-kdfopt",
            "hexpass:" + encoded_password.hex(),
            "-kdfopt",
            "hexsalt:" + salt.hex(),
            "-kdfopt",
            "id:3",
            "-kdfopt",
            "iter:2048",
            "PKCS12KDF",
        ],
        capture_output=True,
        check=True,
    )
    key = bytes.fromhex(result.stdout.decode().replace(":", ""))
    pfx["auth_safe"] = cms.ContentInfo({"content_type": "data", "content": safe})
    pfx["mac_data"] = pkcs12.MacData(
        {
            "mac": {
                "digest_algorithm": {"algorithm": "sha256"},
                "digest": hmac.new(key, safe, hashlib.sha256).digest(),
            },
            "mac_salt": salt,
            "iterations": 2048,
        }
    )
    return pfx.dump()


def test_authenticated_plain_and_encrypted_truststores_are_supported(fixture_bundle):
    encrypted = original(fixture_bundle)
    plain = plain_fixture(encrypted, lambda bags: None)
    assert validate_java_pfx(plain, PASSWORD) == validate_java_pfx(encrypted, PASSWORD)


def test_hidden_untagged_certificate_is_rejected(fixture_bundle):
    from conftest import certificate

    hidden = x509.load_pem_x509_certificate(certificate("Hidden")).public_bytes(Encoding.DER)

    def mutate(bags):
        bags.append(
            pkcs12.SafeBag(
                {
                    "bag_id": "cert_bag",
                    "bag_value": {"cert_id": "x509", "cert_value": x509_asn1(hidden)},
                }
            )
        )

    raw = plain_fixture(original(fixture_bundle), mutate)
    # Prove the independently authenticated fixture actually contains the extra cert.
    loaded = native_pkcs12.load_pkcs12(raw, PASSWORD)
    assert len(loaded.additional_certs) + (loaded.cert is not None) == 3
    with pytest.raises(ValueError, match="named Java trusted"):
        validate_java_pfx(raw, PASSWORD)


def x509_asn1(raw):
    from asn1crypto import x509 as asn1_x509

    return asn1_x509.Certificate.load(raw)


def test_missing_mac_is_rejected(fixture_bundle):
    pfx = pkcs12.Pfx.load(original(fixture_bundle))
    pfx["mac_data"] = None
    with pytest.raises(ValueError, match="password-authenticated"):
        validate_java_pfx(pfx.dump(), PASSWORD)


def test_duplicate_alias_bag_is_rejected(fixture_bundle):
    raw = plain_fixture(original(fixture_bundle), lambda bags: bags.append(bags[0].copy()))
    with pytest.raises(ValueError, match="Duplicate"):
        validate_java_pfx(raw, PASSWORD)


def test_unknown_bag_attribute_is_rejected(fixture_bundle):
    def mutate(bags):
        bags[0]["bag_attributes"].append(
            pkcs12.Attribute(
                {
                    "type": "local_key_id",
                    "values": [b"unsupported-identity-link"],
                }
            )
        )

    raw = plain_fixture(original(fixture_bundle), mutate)
    with pytest.raises(ValueError, match="bag attribute"):
        validate_java_pfx(raw, PASSWORD)
