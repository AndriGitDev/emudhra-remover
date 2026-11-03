import base64

import pytest
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs7

from emudhra_remover.adapters import capabilities
from emudhra_remover.adapters.pkcs7 import filter_pkcs7


@pytest.mark.parametrize("encoding", [serialization.Encoding.DER, serialization.Encoding.PEM])
async def test_pkcs7_workflow_preserves_certificate_and_restores_original(
    service, fixture_bundle, encoding
):
    app, path, _ = service
    bad, good, incident = fixture_bundle
    original = pkcs7.serialize_certificates(
        [x509.load_pem_x509_certificate(bad), x509.load_pem_x509_certificate(good)], encoding
    )
    path.write_bytes(original)
    app.inventory.targets[0].adapter = "pkcs7"
    scan = await app.scan("test")
    assert scan["certificates_scanned"] == 2 and len(scan["matches"]) == 1
    assert scan["coverage"] == "configured-pkcs7-collection-only"
    plan = await app.plan("test")
    await app.apply(plan["plan_id"])
    modified = path.read_bytes()
    load = (
        pkcs7.load_der_pkcs7_certificates
        if encoding == serialization.Encoding.DER
        else pkcs7.load_pem_pkcs7_certificates
    )
    survivors = load(modified)
    assert len(survivors) == 1
    assert survivors[0].public_bytes(serialization.Encoding.PEM) == good
    assert filter_pkcs7(modified, incident) == ([], modified, 1)
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == original


def collection(fixture_bundle):
    bad, good, _ = fixture_bundle
    return pkcs7.serialize_certificates(
        [x509.load_pem_x509_certificate(bad), x509.load_pem_x509_certificate(good)],
        serialization.Encoding.DER,
    )


def test_refuses_encapsulated_content(fixture_bundle):
    raw = collection(fixture_bundle)
    container = cms.ContentInfo.load(raw)
    container["content"]["encap_content_info"]["content"] = b"signed document"
    with pytest.raises(ValueError, match="Signed messages"):
        filter_pkcs7(container.dump(), fixture_bundle[2])


def test_refuses_digest_algorithms(fixture_bundle):
    container = cms.ContentInfo.load(collection(fixture_bundle))
    container["content"]["digest_algorithms"] = [{"algorithm": "sha256"}]
    with pytest.raises(ValueError, match="Signed messages"):
        filter_pkcs7(container.dump(), fixture_bundle[2])


@pytest.mark.parametrize("corruption", [b"trailing", b"\x00"])
def test_rejects_trailing_der(fixture_bundle, corruption):
    with pytest.raises(ValueError):
        filter_pkcs7(collection(fixture_bundle) + corruption, fixture_bundle[2])


def test_rejects_multiple_pem_objects(fixture_bundle):
    raw = collection(fixture_bundle)
    pem = b"-----BEGIN PKCS7-----\n" + base64.b64encode(raw) + b"\n-----END PKCS7-----\n"
    with pytest.raises(ValueError, match="exactly one"):
        filter_pkcs7(pem + pem, fixture_bundle[2])


async def test_all_matching_pkcs7_is_auditable_but_not_emptyable(service, fixture_bundle):
    app, path, _ = service
    raw = pkcs7.serialize_certificates(
        [x509.load_pem_x509_certificate(fixture_bundle[0])], serialization.Encoding.DER
    )
    path.write_bytes(raw)
    app.inventory.targets[0].adapter = "pkcs7"
    assert len((await app.scan("test"))["matches"]) == 1
    with pytest.raises(ValueError, match="empty"):
        await app.plan("test")


def test_capabilities_expose_only_implemented_adapters():
    assert {item["id"] for item in capabilities()} == {
        "pem-bundle",
        "pkcs7",
        "debian",
        "java-jks",
        "java-jceks",
        "java-pkcs12",
        "nss-sql",
        "openssl-trusted-bundle",
        "edk2-cacerts",
        "p11-kit",
        "windows-store",
        "windows-sst",
        "apple-profile",
    }
