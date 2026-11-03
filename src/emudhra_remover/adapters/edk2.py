"""EDK2 HTTPS certificate collection files; no firmware-variable access."""

import struct

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..certificates import digest
from ..p11_formats import EFI_CERT_X509, edk2_lists


def filter_edk2(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    policy = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches, pieces, count = [], [], 0
    for raw, entries in edk2_lists(data):
        retained = []
        for owner, der in entries:
            cert = x509.load_der_x509_certificate(der)
            if cert.public_bytes(Encoding.DER) != der:
                raise ValueError("EDK2 entries must contain exactly one DER certificate")
            entry = policy.get(digest(der))
            count += 1
            if entry:
                matches.append(
                    {
                        **entry,
                        "subject": cert.subject.rfc4514_string(),
                        "signature_owner": owner.hex(),
                    }
                )
            else:
                retained.append(owner + der)
        if len(retained) == len(entries):
            pieces.append(raw)
        elif retained:
            payload = b"".join(retained)
            pieces.append(
                EFI_CERT_X509
                + struct.pack("<III", 28 + len(payload), 0, len(retained[0]))
                + payload
            )
    if not count:
        raise ValueError("EDK2 collection contains no certificates")
    return matches, b"".join(pieces), count
