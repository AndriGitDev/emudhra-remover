"""Persistent p11-kit distrust objects, previewed with the native trust module."""

import base64
import json
import os
import shutil
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ..p11_formats import certificate_der, certificate_records
from ..p11_native import p11_generate, p11_output_tree
from ..p11_policy import (
    OPENSSL_EXPORT,
    p11_denied,
    p11_encode,
    p11_materialize,
    p11_source_view,
    p11_verify_transition,
)


def controller_runtime():
    binary = os.environ.get("EMUDHRA_TRUST") or shutil.which("trust")
    module = os.environ.get("EMUDHRA_P11_MODULE")
    if module is None:
        module = next(
            (
                p
                for p in (
                    "/usr/lib64/pkcs11/p11-kit-trust.so",
                    "/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so",
                    "/usr/lib/aarch64-linux-gnu/pkcs11/p11-kit-trust.so",
                )
                if Path(p).is_file()
            ),
            None,
        )
    if not binary or not module:
        raise ValueError(
            "p11-kit requires controller trust and p11-kit-trust.so; "
            "set EMUDHRA_TRUST/EMUDHRA_P11_MODULE"
        )
    return binary, module


def cleanup_staging(root):
    # p11-kit creates read-only hash directories. Only call on private generated
    # staging trees, never on configured target paths.
    for current, directories, _ in os.walk(root, followlinks=False):
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o700)


def filter_p11(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    snapshot = json.loads(data)
    runtime = controller_runtime()
    entries = {entry["sha256"].lower(): entry for entry in incident["certificates"]}
    with tempfile.TemporaryDirectory(prefix="emudhra-p11-preview-") as temporary:
        root = Path(temporary)
        try:
            source = root / "sources"
            source.mkdir()
            directories = p11_materialize(snapshot, source)
            p11_generate(*runtime, directories, root / "before")
            before, _ = p11_output_tree(root / "before")
            if p11_source_view(before) != snapshot["source_view"]:
                raise ValueError("Controller and target p11-kit native certificate views differ")
            denied = p11_denied(before)
            records = certificate_records(before[OPENSSL_EXPORT])
            if not records:
                raise ValueError("p11-kit configured sources contain no certificates")
            matches, additions, selected = [], [], set()
            for fingerprint, _, raw in records:
                if fingerprint not in entries or fingerprint in denied or fingerprint in selected:
                    continue
                der = certificate_der(raw)
                cert = x509.load_der_x509_certificate(der)
                selected.add(fingerprint)
                matches.append(
                    {
                        **entries[fingerprint],
                        "subject": cert.subject.rfc4514_string(),
                        "action": "persistent-p11-kit-distrust",
                    }
                )
                additions.append(
                    b"\n[p11-kit-object-v1]\nclass: certificate\ncertificate-type: x-509\n"
                    b"trusted: false\nx-distrusted: true\n" + cert.public_bytes(Encoding.PEM)
                )
            if not selected:
                return [], data, len(records)
            policy = base64.b64decode(snapshot["policy"], validate=True) + b"".join(additions)
            snapshot["policy"] = base64.b64encode(policy).decode()
            (directories[0] / "emudhra-remover.p11-kit").write_bytes(policy)
            p11_generate(*runtime, directories, root / "after")
            after, _ = p11_output_tree(root / "after")
            p11_verify_transition(before, after, selected)
            snapshot["source_view"] = p11_source_view(after)
            output = p11_encode(snapshot)
            if len(output) > 16 * 1024 * 1024:
                raise ValueError("p11-kit replacement snapshot exceeds size limit")
            return matches, output, len(records)
        finally:
            cleanup_staging(root)
