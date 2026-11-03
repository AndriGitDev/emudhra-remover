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


def filter_nss(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    snapshot = json.loads(data)
    cert = base64.b64decode(snapshot["cert9"], validate=True)
    key = base64.b64decode(snapshot["key4"], validate=True)
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    with tempfile.TemporaryDirectory(prefix="emudhra-nss-") as temporary:
        directory = Path(temporary)
        # Generate our own internal-module configuration; never load the target's
        # pkcs11.txt, which could load external modules or point at other stores.
        native(directory, "-N", "--empty-password")
        certpath, keypath = directory / "cert9.db", directory / "key4.db"
        certpath.write_bytes(cert)
        keypath.write_bytes(key)
        with sqlite3.connect(keypath) as db:
            if db.execute("SELECT COUNT(*) FROM nssPrivate").fetchone()[0]:
                raise ValueError("NSS adapter refuses private-key records")
        password = directory / "empty-password"
        password.write_bytes(b"\n\n")
        # Prove the source token accepts an empty password using a change-to-same
        # operation on the private copy. Restore both original copies immediately.
        native(directory, "-W", "-f", str(password), "-@", str(password))
        certpath.write_bytes(cert)
        keypath.write_bytes(key)
        before = public_rows(certpath)
        matches, aliases, selected = [], set(), set()
        selected_certificates = []
        for object_id, row in before.items():
            if row["a0"] != b"\x00\x00\x00\x01":
                continue
            alias = row["a3"].decode("utf-8")
            if not alias or alias.strip() != alias or not alias.isprintable() or ":" in alias:
                raise ValueError("Unsupported NSS nickname")
            if alias in aliases:
                raise ValueError("Duplicate NSS nickname")
            aliases.add(alias)
            der = row["a11"]
            certificate = x509.load_der_x509_certificate(der)
            entry = entries.get(digest(der))
            if entry:
                matches.append(
                    {**entry, "alias": alias, "subject": certificate.subject.rfc4514_string()}
                )
                selected.add(object_id)
                selected_certificates.append(row)
        if not aliases:
            raise ValueError("NSS store contains no certificates")
        original_flags = trust_flags(directory, aliases)
        if not matches:
            return [], data, len(aliases)
        for row in selected_certificates:
            native(directory, "-D", "-n", row["a3"].decode(), "-f", str(password))
        for object_id, row in before.items():
            if row["a0"] == bytes.fromhex("ce534353") and any(
                row["ace5363b4"] == hashlib.sha1(c["a11"], usedforsecurity=False).digest()
                and row["a81"] == c["a81"]
                and row["a82"] == c["a82"]
                for c in selected_certificates
            ):
                selected.add(object_id)
        expected = {oid: row for oid, row in before.items() if oid not in selected}
        if public_rows(certpath) != expected:
            raise ValueError("NSS deletion changed unrelated certificate/trust objects")
        # Native deletion removes companion signature metadata. Preserve the target
        # key file and verify with that original: unused signature rows are inert.
        keypath.write_bytes(key)
        remaining = aliases - {entry["alias"] for entry in matches}
        if trust_flags(directory, remaining) != {a: original_flags[a] for a in remaining}:
            raise ValueError("NSS unrelated trust flags were not preserved")
        snapshot["cert9"] = base64.b64encode(certpath.read_bytes()).decode()
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("NSS output snapshot exceeds size limit")
    return matches, encoded, len(aliases)
