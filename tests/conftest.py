from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from emudhra_remover.certificates import digest
from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State


def certificate(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def fixture_bundle():
    bad = certificate("emSign Test Root")
    good = certificate("Unrelated Root")
    cert = x509.load_pem_x509_certificate(bad)
    incident = {
        "id": "test-only",
        "certificates": [
            {
                "name": "test root",
                "kind": "trust-anchor",
                "sha256": cert.fingerprint(hashes.SHA256()).hex(),
            }
        ],
    }
    return bad, good, incident


@pytest.fixture
def service(tmp_path, fixture_bundle):
    bad, good, incident = fixture_bundle
    path = tmp_path / "bundle.pem"
    path.write_bytes(b"# managed test bundle\n" + bad + good)
    path.chmod(0o640)
    instance = Service(
        Inventory(targets=[Target(id="test", transport="local", path=str(path))]),
        State(tmp_path / "state"),
        write_enabled=True,
    )
    instance.incident = incident
    yield instance, path, digest(path.read_bytes())
    instance.state.close()


@pytest.fixture
def certificate_chain():
    """Synthetic root -> intermediate -> leaf for native path validation tests."""
    keys = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    subjects = [
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        for name in ("Fixture Root", "Fixture Intermediate", "Fixture Leaf")
    ]
    chain = []
    for i in range(3):
        issuer = max(0, i - 1)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subjects[i])
            .issuer_name(subjects[issuer])
            .public_key(keys[i].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=i < 2, path_length=None), critical=True)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(keys[i].public_key()), critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(keys[issuer].public_key()),
                critical=False,
            )
            .sign(keys[issuer], hashes.SHA256())
        )
        chain.append(cert.public_bytes(serialization.Encoding.PEM))
    return chain
