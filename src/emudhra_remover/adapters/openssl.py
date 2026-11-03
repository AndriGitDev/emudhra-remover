"""OpenSSL X509_AUX bundles: preserve certificates and add explicit distrust."""

import base64
import re

from asn1crypto import algos, core, parser
from cryptography import x509
from cryptography.hazmat.primitives import hashes

OBJECT = re.compile(
    rb"-----BEGIN (?P<label>(?:TRUSTED )?CERTIFICATE)-----\s+"
    rb"(?P<body>.*?)-----END (?P=label)-----",
    re.S,
)
ANY_PURPOSE = "2.5.29.37.0"


class Purposes(core.SequenceOf):
    _child_spec = core.ObjectIdentifier


class Algorithms(core.SequenceOf):
    _child_spec = algos.AlgorithmIdentifier


class CertificateAux(core.Sequence):
    # OpenSSL crypto/x509/x_x509a.c, ASN1_SEQUENCE(X509_CERT_AUX).
    _fields = [
        ("trust", Purposes, {"optional": True}),
        ("reject", Purposes, {"implicit": 0, "optional": True}),
        ("alias", core.UTF8String, {"optional": True}),
        ("keyid", core.OctetString, {"optional": True}),
        ("other", Algorithms, {"implicit": 1, "optional": True}),
    ]


def decode_object(match):
    raw = base64.b64decode(re.sub(rb"\s", b"", match["body"]), validate=True)
    end = parser.peek(raw)
    der, suffix = raw[:end], raw[end:]
    cert = x509.load_der_x509_certificate(der)
    aux = None
    if suffix:
        if match["label"] != b"TRUSTED CERTIFICATE":
            raise ValueError("Ordinary certificates cannot contain auxiliary data")
        aux = CertificateAux.load(suffix, strict=True)
        # Trigger lazy child parsing, reject unknown fields and non-DER encodings.
        _ = aux.native
        if len(aux) > len(CertificateAux._fields) or aux.dump(force=True) != suffix:
            raise ValueError("Unsupported OpenSSL certificate auxiliary data")
    return cert, der, aux


def filter_openssl(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    matches, pieces, count, position = [], [], 0, 0
    remainder = OBJECT.sub(b"", data)
    if b"-----BEGIN" in remainder or b"-----END" in remainder:
        raise ValueError("Expected an OpenSSL certificate-only PEM bundle")
    for match in OBJECT.finditer(data):
        try:
            cert, der, aux = decode_object(match)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError("Malformed OpenSSL certificate or auxiliary data") from error
        count += 1
        entry = entries.get(cert.fingerprint(hashes.SHA256()).hex())
        rejected = [] if aux is None else (aux["reject"].native or [])
        pieces.append(data[position : match.start()])
        if entry and ANY_PURPOSE not in rejected:
            if aux is None:
                aux = CertificateAux({"reject": [ANY_PURPOSE]})
            else:
                aux["trust"] = None
                aux["reject"] = list(dict.fromkeys([*rejected, ANY_PURPOSE]))
            body = base64.b64encode(der + aux.dump())
            block = b"\n".join(body[i : i + 64] for i in range(0, len(body), 64))
            pieces.append(
                b"-----BEGIN TRUSTED CERTIFICATE-----\n"
                + block
                + b"\n-----END TRUSTED CERTIFICATE-----"
            )
            matches.append(
                {
                    **entry,
                    "subject": cert.subject.rfc4514_string(),
                    "action": "reject-all-purposes",
                    "previous_rejected_purposes": rejected,
                }
            )
        else:
            pieces.append(match.group())
        position = match.end()
    if not count:
        raise ValueError("Expected an OpenSSL certificate-only PEM bundle")
    pieces.append(data[position:])
    return matches, b"".join(pieces), count
