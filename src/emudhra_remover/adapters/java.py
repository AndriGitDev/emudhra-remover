"""Native Java API transformations on private controller-side copies only."""

import base64
import os
import subprocess
import tempfile
from importlib.resources import as_file, files
from pathlib import Path

from cryptography import x509

from ..certificates import digest
from ..config import Target


def filter_java(data: bytes, incident: dict, target: Target) -> tuple[list[dict], bytes, int]:
    if target.password_env not in os.environ:
        raise ValueError("Required operator password environment variable is not set")
    environment = {
        key: value
        for key, value in os.environ.items()
        if key in ("PATH", "HOME", "JAVA_HOME", "TMPDIR", "LANG", "LC_ALL")
    }
    environment["EMUDHRA_JAVA_STORE_PASSWORD"] = os.environ[target.password_env]
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    with tempfile.TemporaryDirectory(prefix="emudhra-java-") as directory:
        root = Path(directory)
        original, output, denylist = root / "input.store", root / "output.store", root / "denylist"
        original.write_bytes(data)
        denylist.write_text("\n".join(entries))
        with as_file(files("emudhra_remover.adapters").joinpath("TrustStore.java")) as source:
            try:
                result = subprocess.run(
                    [
                        os.environ.get("EMUDHRA_JAVA", "java"),
                        "-Xmx128m",
                        str(source),
                        "JKS" if target.adapter == "java-jks" else "PKCS12",
                        str(original),
                        str(output),
                        str(denylist),
                    ],
                    env=environment,
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
            entry = entries.get(digest(der))
            if entry:
                matches.append({**entry, "alias": alias, "subject": cert.subject.rfc4514_string()})
        replacement = output.read_bytes()
        if not replacement or len(replacement) > 16 * 1024 * 1024:
            raise ValueError("Invalid Java output size")
        return matches, replacement, count
