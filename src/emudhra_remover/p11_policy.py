"""Bound source-copy preparation and native p11-kit transition verification."""

import base64
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from .p11_formats import certificate_records, edk2_records, jks_records, pem_records

POLICY_NAME = "emudhra-remover.p11-kit"
PLAIN_EXPORTS = ("pem/tls-ca-bundle.pem", "pem/email-ca-bundle.pem", "pem/objsign-ca-bundle.pem")
OPENSSL_EXPORT = "openssl/ca-bundle.trust.crt"


def p11_encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def p11_materialize(snapshot, destination):
    directories = []
    total, count = 0, 0
    if not 1 <= len(snapshot["sources"]) <= 4:
        raise ValueError("Invalid p11-kit source snapshot")
    for i, entries in enumerate(snapshot["sources"]):
        directory = Path(destination) / str(i)
        directory.mkdir()
        directories.append(directory)
        for name, encoded in entries.items():
            if not re.fullmatch(r"[A-Za-z0-9._+-]+(?:/[A-Za-z0-9._+-]+)?", name):
                raise ValueError("Unsafe p11-kit source name")
            parts = name.split("/")
            if (
                any(part in (".", "..") for part in parts)
                or (len(parts) == 2 and parts[0] not in ("anchors", "blocklist", "blacklist"))
                or (i == 0 and name == POLICY_NAME)
            ):
                raise ValueError("Unsupported p11-kit source snapshot path")
            data = base64.b64decode(encoded, validate=True)
            count += 1
            total += len(data)
            if count > 4096 or total > 16 * 1024 * 1024:
                raise ValueError("p11-kit source snapshot exceeds limits")
            path = directory / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(data)
    policy = base64.b64decode(snapshot["policy"], validate=True)
    if total + len(policy) > 16 * 1024 * 1024:
        raise ValueError("p11-kit source snapshot exceeds limits")
    (directories[0] / POLICY_NAME).write_bytes(policy)
    return directories


def p11_denied(files):
    return {fingerprint for fingerprint, _, _ in certificate_records(files["audit/blocked.pem"])}


def p11_source_view(files):
    return {
        "certificates": [
            [fingerprint, label.decode("ascii"), base64.b64encode(raw).decode()]
            for fingerprint, label, raw in certificate_records(files[OPENSSL_EXPORT])
        ],
        "denied": sorted(p11_denied(files)),
    }


def p11_verify_denials(files):
    tls = Counter(der for _, der in pem_records(files["pem/tls-ca-bundle.pem"]))
    hashed = Counter(
        der
        for name, raw in files.items()
        if name.startswith("pem/directory-hash/")
        for _, der in pem_records(raw)
    )
    if hashed != tls:
        raise ValueError("Native hash-directory anchors differ from the TLS bundle")
    denied = p11_denied(files)
    actual = Counter(certificate_records(files[OPENSSL_EXPORT]))
    expected = Counter(certificate_records(files["audit/policy.pem"]))
    for fingerprint in denied:
        observed = Counter({r: n for r, n in actual.items() if r[0] == fingerprint})
        wanted = Counter({r: n for r, n in expected.items() if r[0] == fingerprint})
        if not wanted or observed != wanted:
            raise ValueError("Native OpenSSL export loses p11-kit distrust information")
    return denied


def p11_verify_transition(before, after, selected):
    before_denied, after_denied = p11_verify_denials(before), p11_verify_denials(after)
    if after_denied != before_denied | selected:
        raise ValueError("Native p11-kit blocklist transition differs from selected certificates")
    old = [r for r in certificate_records(before[OPENSSL_EXPORT]) if r[0] not in selected]
    new = [r for r in certificate_records(after[OPENSSL_EXPORT]) if r[0] not in selected]
    if old != new:
        raise ValueError("Native p11-kit changed unrelated OpenSSL trust metadata")
    if {r[0] for r in certificate_records(after[OPENSSL_EXPORT])} != {
        r[0] for r in certificate_records(before[OPENSSL_EXPORT])
    }:
        raise ValueError("Native p11-kit changed the certificate collection")
    for name in PLAIN_EXPORTS:
        expected = [
            r for r in pem_records(before[name]) if hashlib.sha256(r[1]).hexdigest() not in selected
        ]
        if pem_records(after[name]) != expected:
            raise ValueError("Native p11-kit changed unrelated purpose anchors")
    for name, parse in (("java/cacerts", jks_records), ("edk2/cacerts.bin", edk2_records)):
        expected = [
            r for r in parse(before[name]) if hashlib.sha256(r[1]).hexdigest() not in selected
        ]
        if parse(after[name]) != expected:
            raise ValueError("Native p11-kit changed unrelated Java aliases or EDK2 owners")


def p11_semantics(files, links):
    """Canonical generated content, ignoring comments and native JKS timestamps."""
    result = {}
    for name in (OPENSSL_EXPORT, *PLAIN_EXPORTS):
        result[name] = pem_records(files[name])
    result["java/cacerts"] = jks_records(files["java/cacerts"])
    result["edk2/cacerts.bin"] = edk2_records(files["edk2/cacerts.bin"])
    hash_files = {
        name: pem_records(raw)
        for name, raw in files.items()
        if name.startswith("pem/directory-hash/")
    }
    result["hash-files"] = hash_files
    result["hash-links"] = links
    return result


def p11_extra_anchors(actual, expected, root):
    """Report unexpected certificate/trust records in stale generated outputs."""
    findings = []
    for name, raw in actual.items():
        if name == "java/cacerts":
            parse = jks_records
        elif name == "edk2/cacerts.bin":
            parse = edk2_records
        else:
            parse = pem_records
        planned = set(parse(expected.get(name, b""))) if name in expected else set()
        for record in set(parse(raw)) - planned:
            from .p11_formats import certificate_der

            der = certificate_der(record[1])
            findings.append(
                {
                    "sha256": hashlib.sha256(der).hexdigest(),
                    "source": str(Path(root) / name),
                    "reason": "Stale or unmanaged p11-kit generated certificate/trust record",
                }
            )
    return sorted(findings, key=lambda item: (item["source"], item["sha256"]))
