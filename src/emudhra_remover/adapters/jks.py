"""Bounded JKS/JCEKS certificate-only preflight, before native Java loading.

In particular, JCEKS secret entries must never reach Java deserialization. The
independent entry map also detects content hidden by a native alias-map overwrite.
"""

import hashlib
import hmac
import struct

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

MAGIC = {"java-jks": 0xFEEDFEED, "java-jceks": 0xCECECECE}


class Reader:
    def __init__(self, data):
        self.data, self.position = data, 0

    def take(self, length):
        if length < 0 or length > len(self.data) - self.position:
            raise ValueError("Truncated Java certificate store")
        result = self.data[self.position : self.position + length]
        self.position += length
        return result

    def integer(self):
        return struct.unpack(">I", self.take(4))[0]

    def text(self):
        return modified_utf8(self.take(struct.unpack(">H", self.take(2))[0]))


def modified_utf8(data):
    """Decode canonical DataInput UTF, including NUL and UTF-16 surrogate pairs."""
    units, position = bytearray(), 0
    while position < len(data):
        first = data[position]
        position += 1
        if 1 <= first <= 0x7F:
            value, following = first, 0
        elif 0xC0 <= first <= 0xDF:
            value, following = first & 0x1F, 1
        elif 0xE0 <= first <= 0xEF:
            value, following = first & 0x0F, 2
        else:
            raise ValueError("Invalid modified UTF-8 in Java store")
        if position + following > len(data):
            raise ValueError("Truncated modified UTF-8 in Java store")
        for _ in range(following):
            byte = data[position]
            position += 1
            if byte & 0xC0 != 0x80:
                raise ValueError("Invalid modified UTF-8 continuation in Java store")
            value = (value << 6) | (byte & 0x3F)
        if (following == 1 and value < 0x80 and value != 0) or (following == 2 and value < 0x800):
            raise ValueError("Noncanonical modified UTF-8 in Java store")
        units.extend(value.to_bytes(2, "big"))
    try:
        return units.decode("utf-16-be")
    except UnicodeDecodeError as error:
        raise ValueError("Unpaired surrogate in Java store alias") from error


def read_certificates(data, password, adapter):
    """Return alias -> (exact DER, creation timestamp bytes), verifying integrity."""
    if not 32 <= len(data) <= 16 * 1024 * 1024:
        raise ValueError("Java certificate store exceeds size limits")
    body, checksum = data[:-20], data[-20:]
    expected = hashlib.sha1(password.encode("utf-16-be") + b"Mighty Aphrodite" + body).digest()
    if not hmac.compare_digest(checksum, expected):
        raise ValueError("Java store integrity failed: check format, password and checksum")
    reader = Reader(body)
    magic, version, count = reader.integer(), reader.integer(), reader.integer()
    if magic != MAGIC[adapter] or version not in (1, 2):
        raise ValueError("Unsupported Java store: check format, password and version")
    if count > 4096:
        raise ValueError("Java certificate store has too many entries")
    entries, normalized_aliases = {}, set()
    for _ in range(count):
        if reader.integer() != 2:
            raise ValueError("Java adapter refuses private or secret key entries and unknown tags")
        alias = reader.text()
        if not alias or alias.lower() in normalized_aliases:
            raise ValueError("Empty, duplicate or case-colliding Java alias")
        normalized_aliases.add(alias.lower())
        timestamp = reader.take(8)
        if version == 2 and reader.text() != "X.509":
            raise ValueError("Only X.509 certificates are supported in Java stores")
        der = reader.take(reader.integer())
        certificate = x509.load_der_x509_certificate(der)
        if certificate.public_bytes(Encoding.DER) != der:
            raise ValueError("Java entry must contain exactly one canonical DER certificate")
        entries[alias] = (der, timestamp)
    if reader.position != len(body):
        raise ValueError("Trailing or hidden Java store content")
    return entries
