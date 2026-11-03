"""Strict BKS v2 certificate-only stores; no key decoding or Java loading.

The format and PKCS12/SHA-1 MAC derivation follow Bouncy Castle BcKeyStoreSpi.
Complete entry slices are retained so aliases, timestamps and ordering survive.
"""

import hashlib
import hmac
import os

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..certificates import digest
from .jks import Reader


def mac_key(password, salt, iterations):
    """PKCS#12 diversifier 3, SHA-1, one 20-byte output block (BKS v2)."""
    try:
        encoded = password.encode("utf-16-be") + b"\0\0" if password else b""
    except UnicodeEncodeError as error:
        raise ValueError("BKS password must be valid Unicode") from error
    if len(encoded) > 65536:
        raise ValueError("BKS password exceeds the input limit")
    if not 1 <= iterations <= 1_000_000 or len(salt) != 20:
        raise ValueError("Unsupported BKS salt or iteration count")

    def repeat(value):
        length = 64 * ((len(value) + 63) // 64)
        return (value * ((length + len(value) - 1) // len(value)))[:length] if value else b""

    block = b"\x03" * 64 + repeat(salt) + repeat(encoded)
    for _ in range(iterations):
        block = hashlib.sha1(block).digest()
    return block


def parse_bks(data, password):
    if not 53 <= len(data) <= 16 * 1024 * 1024:
        raise ValueError("BKS store exceeds size limits or is truncated")
    reader = Reader(data)
    if reader.integer() != 2:
        raise ValueError("Only BKS version 2 is supported; BKS v0/v1 and UBER are refused")
    if reader.integer() != 20:
        raise ValueError("Only the native 20-byte BKS salt is supported")
    salt, iterations = reader.take(20), reader.integer()
    header = data[: reader.position]
    key = mac_key(password, salt, iterations)
    body, checksum = data[reader.position : -20], data[-20:]
    if not hmac.compare_digest(hmac.digest(key, body, "sha1"), checksum):
        raise ValueError("BKS integrity failed: check password, format and checksum")
    reader = Reader(body)
    entries, aliases = [], set()
    while True:
        start = reader.position
        kind = reader.take(1)[0]
        if kind == 0:
            break
        if kind != 1:
            raise ValueError("BKS adapter refuses private, secret, sealed and unknown key entries")
        if len(entries) >= 4096:
            raise ValueError("BKS store has too many entries")
        alias = reader.text()
        if not alias or alias in aliases:
            raise ValueError("Empty or duplicate BKS alias")
        aliases.add(alias)
        timestamp = reader.take(8)
        if reader.integer() != 0:
            raise ValueError("Certificate entries with attached BKS chains are unsupported")
        if reader.text() != "X.509":
            raise ValueError("Only X.509 BKS certificates are supported")
        der = reader.take(reader.integer())
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(Encoding.DER) != der:
            raise ValueError("BKS entry must contain exactly one canonical DER certificate")
        entries.append((alias, timestamp, der, body[start : reader.position]))
    if reader.position != len(body):
        raise ValueError("Trailing or hidden BKS store content")
    return header, key, entries


def filter_bks(data, incident, target):
    if target.password_env not in os.environ:
        raise ValueError("Required operator password environment variable is not set")
    password = os.environ[target.password_env]
    header, key, records = parse_bks(data, password)
    denied = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches, survivors = [], []
    for alias, timestamp, der, raw in records:
        entry = denied.get(digest(der))
        if entry is None:
            survivors.append((alias, timestamp, der, raw))
        else:
            matches.append(
                {
                    **entry,
                    "alias": alias,
                    "subject": x509.load_der_x509_certificate(der).subject.rfc4514_string(),
                }
            )
    if not matches:
        return [], data, len(records)
    body = b"".join(record[3] for record in survivors) + b"\0"
    output = header + body + hmac.digest(key, body, "sha1")
    if parse_bks(output, password)[2] != survivors:
        raise ValueError("BKS survivor verification failed")
    return matches, output, len(records)
