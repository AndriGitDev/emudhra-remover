"""Strict, stdlib-only readers for native p11-kit export verification.

These readers do not implement Java keystore mutations or firmware-variable writes.
They preserve all certificate/owner bytes when comparing native generated outputs.
"""

import base64
import hashlib
import hmac
import re
import struct
import uuid

MAX_EXPORT_BYTES = 16 * 1024 * 1024
MAX_EXPORT_CERTIFICATES = 4096
EFI_CERT_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le


class Reader:
    def __init__(self, data):
        if len(data) > MAX_EXPORT_BYTES:
            raise ValueError("Native export exceeds size limit")
        self.data = data
        self.position = 0

    def take(self, size):
        if size < 0 or size > len(self.data) - self.position:
            raise ValueError("Truncated native export")
        result = self.data[self.position : self.position + size]
        self.position += size
        return result

    def number(self, format):
        return struct.unpack(format, self.take(struct.calcsize(format)))[0]

    def string(self):
        return self.take(self.number(">H"))


def jks_records(data):
    """Validate a native p11-kit JKS export, ignoring only entry timestamps.

    p11-kit uses the public cacerts password 'changeit'. This parser is only for
    its generated outputs; arbitrary user keystores use the native Java adapter.
    """
    reader = Reader(data)
    if reader.take(4) != b"\xfe\xed\xfe\xed" or reader.number(">I") != 2:
        raise ValueError("Expected a version 2 native JKS export")
    count = reader.number(">I")
    if count > MAX_EXPORT_CERTIFICATES:
        raise ValueError("Too many native JKS entries")
    records, aliases = [], set()
    for _ in range(count):
        if reader.number(">I") != 2:
            raise ValueError("Native JKS export contains a non-certificate entry")
        alias = reader.string()
        # Native p11-kit produces lowercase printable ASCII aliases. Refusing
        # other aliases avoids ambiguous Java modified-UTF8/case collisions.
        if not alias or any(c < 33 or c > 126 for c in alias) or alias.lower() != alias:
            raise ValueError("Unsupported native JKS alias")
        if alias in aliases:
            raise ValueError("Duplicate native JKS alias")
        aliases.add(alias)
        reader.take(8)  # Regeneration timestamps do not change trust semantics.
        if reader.string() != b"X.509":
            raise ValueError("Unsupported native JKS certificate type")
        certificate = reader.take(reader.number(">I"))
        if not certificate:
            raise ValueError("Empty native JKS certificate")
        records.append((alias, certificate))
    body = data[: reader.position]
    checksum = reader.take(20)
    if reader.position != len(data):
        raise ValueError("Trailing native JKS data")
    expected = hashlib.sha1(
        "changeit".encode("utf-16be") + b"Mighty Aphrodite" + body,
        usedforsecurity=False,
    ).digest()
    if not hmac.compare_digest(checksum, expected):
        raise ValueError("Native JKS checksum mismatch")
    return sorted(records)


def edk2_lists(data):
    """Read X509-only EFI_SIGNATURE_LIST collections used by EDK2 HTTPS.

    Authentication envelopes, EFI variable attributes, non-X509 signatures, and
    signature headers are outside this format and are deliberately rejected.
    """
    reader = Reader(data)
    result, count = [], 0
    while reader.position < len(data):
        start = reader.position
        kind = reader.take(16)
        size, header_size, signature_size = struct.unpack("<III", reader.take(12))
        if kind != EFI_CERT_X509 or header_size != 0:
            raise ValueError("Only headerless X509 EDK2 certificate lists are supported")
        if signature_size <= 16 or size < 28 + signature_size:
            raise ValueError("Invalid EDK2 signature/list size")
        if (size - 28) % signature_size:
            raise ValueError("EDK2 signature/list sizes are inconsistent")
        payload = Reader(reader.take(size - 28))
        entries = []
        while payload.position < len(payload.data):
            owner = payload.take(16)
            certificate = payload.take(signature_size - 16)
            entries.append((owner, certificate))
            count += 1
            if count > MAX_EXPORT_CERTIFICATES:
                raise ValueError("Too many EDK2 certificates")
        result.append((data[start : reader.position], entries))
    return result


def edk2_records(data):
    return sorted(record for _, records in edk2_lists(data) for record in records)


EXPORT_PEM = re.compile(
    rb"-----BEGIN (?P<label>(?:TRUSTED )?CERTIFICATE)-----\s+"
    rb"(?P<body>.*?)-----END (?P=label)-----",
    re.S,
)


def pem_records(data):
    if len(data) > MAX_EXPORT_BYTES:
        raise ValueError("Native export exceeds size limit")
    remainder = EXPORT_PEM.sub(b"", data)
    # Native exports may contain comments and whitespace, but no unparsed bytes.
    if any(line.strip() and not line.startswith(b"#") for line in remainder.split(b"\n")):
        raise ValueError("Unexpected content outside native PEM objects")
    records = []
    for match in EXPORT_PEM.finditer(data):
        raw = base64.b64decode(re.sub(rb"\s", b"", match["body"]), validate=True)
        if not raw:
            raise ValueError("Empty native PEM object")
        records.append((match["label"], raw))
        if len(records) > MAX_EXPORT_CERTIFICATES:
            raise ValueError("Too many native PEM objects")
    return sorted(records)


def certificate_der(raw):
    """Split one DER certificate from an optional OpenSSL AUX suffix."""
    if len(raw) < 2 or raw[0] != 0x30:
        raise ValueError("Expected a DER certificate sequence")
    size, header = raw[1], 2
    if size & 0x80:
        count = size & 0x7F
        if not 1 <= count <= 4 or len(raw) < 2 + count or raw[2] == 0:
            raise ValueError("Invalid DER certificate length")
        size = int.from_bytes(raw[2 : 2 + count], "big")
        header += count
        if size < 128:
            raise ValueError("Noncanonical DER certificate length")
    if size == 0 or header + size > len(raw):
        raise ValueError("Truncated DER certificate")
    return raw[: header + size]


def certificate_records(data):
    result = []
    for label, raw in pem_records(data):
        der = certificate_der(raw)
        if label == b"CERTIFICATE" and der != raw:
            raise ValueError("Unexpected auxiliary bytes in ordinary PEM certificate")
        result.append((hashlib.sha256(der).hexdigest(), label, raw))
    return sorted(result)
