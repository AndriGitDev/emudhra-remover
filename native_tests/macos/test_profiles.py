"""Native plist validation only: never install profiles or modify a Keychain."""

import plistlib
import subprocess
import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from emudhra_remover.adapters.apple_profile import filter_apple_profile

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="Native macOS plutil required")


@pytest.mark.parametrize("kind", ["root", "pkcs1", "pem"])
@pytest.mark.parametrize("format", ["xml1", "binary1"])
def test_native_plutil_input_and_survivor_roundtrip(tmp_path, kind, format):
    payloads, fingerprints = [], []
    for i in range(2):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Profile fixture {i}")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(UTC) - timedelta(days=1))
            .not_valid_after(datetime.now(UTC) + timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256())
        )
        payloads.append(
            {
                "PayloadType": "com.apple.security." + kind,
                "PayloadVersion": 1,
                "PayloadIdentifier": f"org.example.fixture.{i}",
                "PayloadUUID": str(uuid.uuid4()),
                "PayloadContent": cert.public_bytes(
                    Encoding.PEM if kind == "pem" else Encoding.DER
                ),
            }
        )
        fingerprints.append(cert.fingerprint(hashes.SHA256()).hex())
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "org.example.fixture",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadContent": payloads,
    }
    source, output, converted = [
        tmp_path / name for name in ("source.mobileconfig", "output.mobileconfig", "native.xml")
    ]
    source.write_bytes(plistlib.dumps(profile))
    subprocess.run(
        ["/usr/bin/plutil", "-convert", format, str(source)], check=True, capture_output=True
    )
    matches, result, count = filter_apple_profile(
        source.read_bytes(), {"certificates": [{"sha256": fingerprints[0]}]}
    )
    assert count == 2 and len(matches) == 1
    output.write_bytes(result)
    subprocess.run(["/usr/bin/plutil", "-lint", str(output)], check=True, capture_output=True)
    subprocess.run(
        ["/usr/bin/plutil", "-convert", "xml1", "-o", str(converted), str(output)],
        check=True,
        capture_output=True,
    )
    expected = {**profile, "PayloadContent": payloads[1:]}
    assert plistlib.loads(converted.read_bytes()) == expected
