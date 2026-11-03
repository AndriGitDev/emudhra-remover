"""Exact DER fingerprint matching; certificate names are never removal selectors."""

import hashlib
import json
import re
from importlib.resources import files

from cryptography import x509
from cryptography.hazmat.primitives import hashes

PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.S)


def policy() -> dict:
    return json.loads(files("emudhra_remover").joinpath("incident.json").read_text())


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def filter_bundle(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches = []
    pieces = []
    position = 0
    count = 0
    for match in PEM.finditer(data):
        # A malformed certificate fails the entire operation, never a partial audit.
        cert = x509.load_pem_x509_certificate(match.group())
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        entry = entries.get(fingerprint)
        pieces.append(data[position : match.start()])
        if entry:
            matches.append({**entry, "subject": cert.subject.rfc4514_string()})
        else:
            pieces.append(match.group())
        position = match.end()
        count += 1
    pieces.append(data[position:])
    # Reject unparsed PEM objects (trusted certs, private keys, broken delimiters).
    remainder = PEM.sub(b"", data)
    if not count or b"-----BEGIN" in remainder or b"-----END" in remainder:
        raise ValueError("Expected a valid, ordinary PEM certificate bundle")
    return matches, b"".join(pieces), count
