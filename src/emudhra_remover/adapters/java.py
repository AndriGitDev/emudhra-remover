"""Native Java API transformations on private controller-side copies only."""

import base64
import os
import subprocess
import tempfile
from collections import Counter
from importlib.resources import files
from pathlib import Path

from cryptography import x509

from ..certificates import digest
from ..config import Target
from .jks import read_certificates
from .pfx import validate_java_pfx


def filter_java(data: bytes, incident: dict, target: Target) -> tuple[list[dict], bytes, int]:
    if target.password_env not in os.environ:
        raise ValueError("Required operator password environment variable is not set")
    password = os.environ[target.password_env]
    try:
        password_bytes = password.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Java store password must be valid Unicode") from None
    if len(password_bytes) > 65536:
        raise ValueError("Java store password exceeds the input limit")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "HOME", "JAVA_HOME", "TMPDIR", "LANG", "LC_ALL")
    }
    all_certificates = None
    binary_entries = None
    if target.adapter in ("java-jks", "java-jceks"):
        binary_entries = read_certificates(data, password, target.adapter)
    if target.adapter == "java-pkcs12":
        try:
            all_certificates = validate_java_pfx(data, password_bytes)
        except (ValueError, TypeError, KeyError) as error:
            raise ValueError(
                "Unsupported Java PKCS12 layout or credentials; check format, password and bags"
            ) from error
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    with tempfile.TemporaryDirectory(prefix="emudhra-java-") as directory:
        root = Path(directory)
        original, output, denylist = root / "input.store", root / "output.store", root / "denylist"
        original.write_bytes(data)
        denylist.write_text("\n".join(entries))
        source = root / "TrustStore.java"
        source.write_bytes(
            files("emudhra_remover.adapters").joinpath("TrustStore.java").read_bytes()
        )
        try:
            result = subprocess.run(
                [
                    os.environ.get("EMUDHRA_JAVA", "java"),
                    "-Xmx128m",
                    str(source),
                    {"java-jks": "JKS", "java-jceks": "JCEKS", "java-pkcs12": "PKCS12"}[
                        target.adapter
                    ],
                    str(original),
                    str(output),
                    str(denylist),
                ],
                env=environment,
                input=password_bytes,
                capture_output=True,
                timeout=45,
                check=False,
            )
        except FileNotFoundError as error:
            raise ValueError(
                "Java adapter requires a controller JDK 17+; set EMUDHRA_JAVA"
            ) from error
        except subprocess.TimeoutExpired as error:
            raise ValueError("Java trust-store processing timed out") from error
        if result.returncode:
            if b"KEY_ENTRIES_UNSUPPORTED" in result.stderr:
                raise ValueError(
                    "Java adapter refuses stores containing private or secret key entries"
                )
            raise ValueError("Java store could not be processed: check format, password and JDK")
        lines = result.stdout.splitlines()
        if not lines or lines.pop() != b"OK":
            raise ValueError("Invalid Java helper response")
        matches, count = [], 0
        aliases = set()
        observed_certificates = Counter()
        observed_entries = {}
        for line in lines:
            kind, encoded_alias, encoded_cert = line.split(b"\t")
            if kind != b"ENTRY":
                raise ValueError("Unexpected Java helper record")
            alias = base64.b64decode(encoded_alias, validate=True).decode("utf-8")
            if alias in aliases:
                raise ValueError("Duplicate Java alias")
            aliases.add(alias)
            der = base64.b64decode(encoded_cert, validate=True)
            cert = x509.load_der_x509_certificate(der)
            count += 1
            observed_certificates[der] += 1
            observed_entries[alias] = der
            entry = entries.get(digest(der))
            if entry:
                matches.append({**entry, "alias": alias, "subject": cert.subject.rfc4514_string()})
        if all_certificates is not None and observed_certificates != all_certificates:
            raise ValueError("PKCS12 contains certificates not visible as Java trusted entries")
        if binary_entries is not None and observed_entries != {
            alias: record[0] for alias, record in binary_entries.items()
        }:
            raise ValueError("Java alias/certificate inventory differs from the complete store")
        replacement = output.read_bytes()
        if not replacement or len(replacement) > 16 * 1024 * 1024:
            raise ValueError("Invalid Java output size")
        if binary_entries is not None:
            surviving = {
                alias: record
                for alias, record in binary_entries.items()
                if digest(record[0]) not in entries
            }
            if read_certificates(replacement, password, target.adapter) != surviving:
                raise ValueError("Java certificate, alias or timestamp preservation failed")
        return matches, replacement, count
