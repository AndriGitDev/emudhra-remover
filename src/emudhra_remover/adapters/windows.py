"""Exact certificate selection for persistent native Windows Disallowed entries."""

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..windows_policy import decode, encode, unbase, validate_transition


def filter_windows(data: bytes, incident: dict):
    snapshot = decode(data)
    policy = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches = []
    # Parse every record independently of the native fingerprint/serialization.
    for group in snapshot.values():
        for record in group.values():
            der = unbase(record["der"])
            if x509.load_der_x509_certificate(der).public_bytes(Encoding.DER) != der:
                raise ValueError("Noncanonical Windows X509 certificate")
    before = decode(data)
    for fingerprint, record in snapshot["source"].items():
        if fingerprint not in policy or fingerprint in snapshot["denied"]:
            continue
        cert = x509.load_der_x509_certificate(unbase(record["der"]))
        matches.append(
            {
                **policy[fingerprint],
                "subject": cert.subject.rfc4514_string(),
                "action": "windows-explicit-distrust",
            }
        )
        snapshot["denied"][fingerprint] = {**record, "serialized": record["plain"]}
    validate_transition(before, snapshot)
    return matches, encode(snapshot), len(snapshot["source"])
