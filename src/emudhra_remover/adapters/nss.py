"""NSS trust-only SQL stores, transformed with native certutil on private copies."""

import base64
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
from pathlib import Path

from cryptography import x509

from ..certificates import digest


def native(directory: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            [
                os.environ.get("EMUDHRA_CERTUTIL", "certutil"),
                *arguments,
                "-d",
                "sql:" + str(directory),
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"},
        )
    except FileNotFoundError as error:
        raise ValueError("NSS adapter requires controller NSS certutil (libnss3-tools)") from error
    except subprocess.TimeoutExpired as error:
        raise ValueError("NSS processing timed out") from error
    if process.returncode:
        raise ValueError(
            "NSS operation failed; only empty-password trust-only SQL stores supported"
        )
    return process.stdout


def public_rows(path: Path) -> dict[int, dict]:
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    db.row_factory = sqlite3.Row
    try:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("NSS certificate database integrity check failed")
        objects = db.execute(
            "SELECT name, type FROM sqlite_master WHERE type != 'index'"
        ).fetchall()
        if [(row[0], row[1]) for row in objects] != [("nssPublic", "table")]:
            raise ValueError("Unsupported NSS certificate database schema")
        rows = {row["id"]: dict(row) for row in db.execute("SELECT * FROM nssPublic")}
        if any(
            row["a0"] not in (b"\x00\x00\x00\x01", bytes.fromhex("ce534353"))
            for row in rows.values()
        ):
            raise ValueError("Only NSS certificate and trust objects are supported")
        return rows
    finally:
        db.close()


def trust_flags(directory: Path, aliases: set[str]) -> dict[str, str]:
    output = native(directory, "-L").decode("utf-8")
    flags = {}
    for line in output.splitlines():
        match = re.fullmatch(r"(.+?)\s+([pPcCTuwg]*,[pPcCTuwg]*,[pPcCTuwg]*)\s*", line)
        if match:
            alias = match[1].rstrip()
            if alias not in aliases or alias in flags:
                raise ValueError("Unexpected NSS nickname or duplicate output")
            flags[alias] = match[2]
    if set(flags) != aliases:
        raise ValueError("NSS certificate enumeration is incomplete")
    return flags


TRUST_CLASS = bytes.fromhex("ce534353")
DENIED = bytes.fromhex("ce53435a")
TRUST_COLUMNS = {"ace536358", "ace536359", "ace53635a", "ace53635b"}
SIGNED_COLUMNS = TRUST_COLUMNS | {"ace536360", "ace5363b4", "ace5363b5"}


def associated(trust, cert):
    return (
        trust["a0"] == TRUST_CLASS
        and trust["ace5363b4"] == hashlib.sha1(cert["a11"], usedforsecurity=False).digest()
        and trust["a81"] == cert["a81"]
        and trust["a82"] == cert["a82"]
    )


def key_metadata(path):
    db = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("NSS companion database integrity check failed")
        schema = set(db.execute("SELECT name,type FROM sqlite_master WHERE type != 'index'"))
        if schema != {("nssPrivate", "table"), ("metaData", "table")}:
            raise ValueError("Unsupported NSS companion database schema")
        if db.execute("SELECT COUNT(*) FROM nssPrivate").fetchone()[0]:
            raise ValueError("NSS adapter refuses private-key records")
        return {row[0]: row[1:] for row in db.execute("SELECT id,item1,item2 FROM metaData")}
    finally:
        db.close()


def filter_nss(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    snapshot = json.loads(data)
    cert = base64.b64decode(snapshot["cert9"], validate=True)
    key = base64.b64decode(snapshot["key4"], validate=True)
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    with tempfile.TemporaryDirectory(prefix="emudhra-nss-") as temporary:
        directory = Path(temporary)
        # Never load target pkcs11.txt or any external modules it might reference.
        native(directory, "-N", "--empty-password")
        certpath, keypath = directory / "cert9.db", directory / "key4.db"
        certpath.write_bytes(cert)
        keypath.write_bytes(key)
        old_metadata = key_metadata(keypath)
        password = directory / "empty-password"
        password.write_bytes(b"\n\n")
        native(directory, "-W", "-f", str(password), "-@", str(password))
        certpath.write_bytes(cert)
        keypath.write_bytes(key)
        before = public_rows(certpath)
        certificates, aliases = {}, set()
        for object_id, row in before.items():
            if row["a0"] != b"\x00\x00\x00\x01":
                continue
            if not isinstance(row["a3"], bytes) or not isinstance(row["a11"], bytes):
                raise ValueError("NSS certificate requires a nickname and DER value")
            alias = row["a3"].decode("utf-8")
            if not alias or alias.strip() != alias or not alias.isprintable() or ":" in alias:
                raise ValueError("Unsupported NSS nickname")
            if alias in aliases:
                raise ValueError("Duplicate NSS nickname")
            aliases.add(alias)
            certificates[object_id] = row
            x509.load_der_x509_certificate(row["a11"])
        if not aliases:
            raise ValueError("NSS store contains no certificates")
        original_flags = trust_flags(directory, aliases)
        selected, matches = {}, []
        for oid, row in certificates.items():
            alias = row["a3"].decode()
            entry = entries.get(digest(row["a11"]))
            trust_rows = [trust for trust in before.values() if associated(trust, row)]
            raw_denied = bool(trust_rows) and all(
                trust[column] == DENIED for trust in trust_rows for column in TRUST_COLUMNS
            )
            if entry and not (original_flags[alias] == "p,p,p" and raw_denied):
                selected[oid] = row
                matches.append(
                    {
                        **entry,
                        "alias": alias,
                        "subject": x509.load_der_x509_certificate(
                            row["a11"]
                        ).subject.rfc4514_string(),
                        "action": "distrust-ssl-email-object-signing",
                        "previous_trust": original_flags[alias],
                    }
                )
        if not matches:
            return [], data, len(aliases)
        for row in selected.values():
            native(directory, "-M", "-n", row["a3"].decode(), "-t", "p,p,p", "-f", str(password))
        after = public_rows(certpath)
        affected = set()
        for oid in before.keys() | after.keys():
            old, new = before.get(oid), after.get(oid)
            if new is None:
                raise ValueError("NSS distrust unexpectedly removed a database object")
            if new["a0"] == TRUST_CLASS and any(associated(new, c) for c in selected.values()):
                if any(associated(new, c) for k, c in certificates.items() if k not in selected):
                    raise ValueError("Ambiguous NSS trust association")
                if any(new[column] != DENIED for column in TRUST_COLUMNS):
                    raise ValueError("NSS did not set explicit distrust")
                if old is not None and any(old[k] != new[k] for k in old if k not in TRUST_COLUMNS):
                    raise ValueError("NSS changed unrelated attributes of a selected trust object")
                affected.add(oid)
            elif old != new:
                raise ValueError("NSS distrust changed unrelated certificate/trust objects")
        new_metadata = key_metadata(keypath)
        allowed = {
            f"sig_cert_{oid:08x}_{column[1:]}" for oid in affected for column in SIGNED_COLUMNS
        }
        if any(
            old_metadata.get(k) != new_metadata.get(k)
            for k in old_metadata.keys() | new_metadata.keys()
            if k not in allowed
        ):
            raise ValueError("NSS distrust changed unrelated companion metadata")
        expected_flags = dict(original_flags)
        expected_flags.update({entry["alias"]: "p,p,p" for entry in matches})
        if trust_flags(directory, aliases) != expected_flags:
            raise ValueError("NSS post-distrust trust verification failed")
        snapshot["cert9"] = base64.b64encode(certpath.read_bytes()).decode()
        snapshot["key4"] = base64.b64encode(keypath.read_bytes()).decode()
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("NSS output snapshot exceeds size limit")
    return matches, encoded, len(aliases)
