"""Edit only degenerate SignedData certificate collections, never signed messages."""

import base64
import re

from asn1crypto import cms
from cryptography import x509

from ..certificates import digest

ARMOR = re.compile(rb"\s*-----BEGIN PKCS7-----\s+([A-Za-z0-9+/=\s]+)-----END PKCS7-----\s*")


def filter_pkcs7(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    armored = data.lstrip().startswith(b"-----BEGIN")
    if armored:
        match = ARMOR.fullmatch(data)
        if not match:
            raise ValueError("Expected exactly one PKCS7 PEM object")
        raw = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
    else:
        raw = data
    try:
        envelope = cms.ContentInfo.load(raw, strict=True)
        if envelope["content_type"].native != "signed_data":
            raise ValueError("Expected a certificates-only PKCS7 SignedData collection")
        content = envelope["content"]
        if (
            len(content["signer_infos"])
            or len(content["digest_algorithms"])
            or content["encap_content_info"]["content"].native is not None
            or content["encap_content_info"]["content_type"].native != "data"
            or content["crls"].native is not None
        ):
            raise ValueError("Signed messages, content and CRLs are not supported")
        certificates = content["certificates"]
        if not len(certificates):
            raise ValueError("PKCS7 collection contains no certificates")
        entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
        matches, retained = [], []
        for choice in certificates:
            if choice.name != "certificate":
                raise ValueError("Only ordinary X.509 certificates are supported")
            der = choice.chosen.dump()
            certificate = x509.load_der_x509_certificate(der)
            entry = entries.get(digest(der))
            if entry:
                matches.append({**entry, "subject": certificate.subject.rfc4514_string()})
            else:
                retained.append(choice)
        count = len(certificates)
        if not matches:
            return [], data, count
        content["certificates"] = cms.CertificateSet(retained)
        output = envelope.dump()
    except (TypeError, KeyError, IndexError) as error:
        raise ValueError("Malformed PKCS7 certificate collection") from error
    if armored:
        encoded = base64.b64encode(output)
        output = (
            b"-----BEGIN PKCS7-----\n"
            + b"\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
            + b"\n-----END PKCS7-----\n"
        )
    return matches, output, count
