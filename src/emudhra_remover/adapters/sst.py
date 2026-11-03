"""Strict exported Windows SST positive-anchor collection files, not live stores."""

import hashlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..certificates import digest

HEADER = b"\x00\x00\x00\x00CERT"
END = bytes(12)
HASH_PROPERTIES = {3: "sha1", 4: "md5", 107: "sha256"}
TEXT_PROPERTIES = {11, 13}  # Friendly name and description, UTF-16LE with NUL.
ALLOWED_PROPERTIES = set(HASH_PROPERTIES) | TEXT_PROPERTIES | {129}


def validate_properties(properties, der):
    for identifier, value in properties.items():
        if identifier in HASH_PROPERTIES:
            expected = hashlib.new(HASH_PROPERTIES[identifier], der, usedforsecurity=False).digest()
            if value != expected:
                raise ValueError("SST certificate hash property mismatch")
        elif identifier == 129:
            if (
                value
                != hashlib.sha1(der, usedforsecurity=False).digest() + hashlib.sha256(der).digest()
            ):
                raise ValueError("SST combined certificate hash property mismatch")
        else:
            if not 2 <= len(value) <= 65536 or len(value) % 2:
                raise ValueError("Invalid SST text property length")
            try:
                text = value.decode("utf-16-le")
            except UnicodeDecodeError as error:
                raise ValueError("Invalid SST text property encoding") from error
            if not text.endswith("\0") or "\0" in text[:-1]:
                raise ValueError("SST text property must have one terminal NUL")


def read_sst(data):
    """Return ordered (certificate, original complete group) with no data loss."""
    if not 20 <= len(data) <= 16 * 1024 * 1024 or not data.startswith(HEADER):
        raise ValueError("Expected a bounded version-zero Windows SST collection")
    groups, fingerprints, properties = [], set(), {}
    position = start = len(HEADER)
    while position < len(data):
        if len(data) - position < 12:
            raise ValueError("Truncated SST property header")
        identifier, encoding, size = struct.unpack_from("<III", data, position)
        end = position + 12 + size
        if identifier == 0:
            if data[position:] != END or properties:
                raise ValueError("Invalid SST end marker, orphan properties or trailing content")
            return groups
        if encoding != 1 or end > len(data):
            raise ValueError("Invalid SST property encoding or length")
        value = data[position + 12 : end]
        position = end
        if identifier == 32:
            certificate = x509.load_der_x509_certificate(value)
            if certificate.public_bytes(Encoding.DER) != value:
                raise ValueError("SST entry must contain exactly one canonical DER certificate")
            fingerprint = digest(value)
            if fingerprint in fingerprints or len(groups) >= 4096:
                raise ValueError("Duplicate or excessive SST certificates")
            fingerprints.add(fingerprint)
            validate_properties(properties, value)
            groups.append((certificate, data[start:end]))
            start, properties = end, {}
        else:
            if identifier not in ALLOWED_PROPERTIES:
                raise ValueError(
                    "SST contains unsupported policy, archive, identity, CRL/CTL or properties"
                )
            if identifier in properties:
                raise ValueError("Duplicate SST property")
            properties[identifier] = value
    raise ValueError("SST end marker is missing")


def filter_sst(data: bytes, incident: dict):
    groups = read_sst(data)
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches, retained = [], []
    for certificate, raw in groups:
        fingerprint = digest(certificate.public_bytes(Encoding.DER))
        entry = entries.get(fingerprint)
        if entry:
            matches.append({**entry, "subject": certificate.subject.rfc4514_string()})
        else:
            retained.append(raw)
    if not matches:
        return [], data, len(groups)
    output = HEADER + b"".join(retained) + END
    if [raw for _, raw in read_sst(output)] != retained:
        raise ValueError("SST survivor verification failed")
    return matches, output, len(groups)
