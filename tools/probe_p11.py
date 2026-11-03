"""Probe native p11-kit behavior using synthetic certificates and private fixtures.

No host trust paths are written. Explicit module paths and fresh user configuration
select only temporary sources. This is adapter research, not a remediation command.

uv run python tools/probe_p11.py --trust /usr/bin/trust --module /path/p11-kit-trust.so
"""

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from emudhra_remover.adapters.openssl import OBJECT, decode_object
from emudhra_remover.certificates import digest, filter_bundle


def synthetic_ca(name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.PEM)
    )


def probe(trust: str, module: str, *, same_source: bool = False):
    trust = str(Path(trust).resolve(strict=True))
    module = str(Path(module).resolve(strict=True))
    if "\n" in module or "\r" in module:
        raise ValueError("Invalid module path")
    openssl = shutil.which("openssl")
    if openssl is None:
        raise ValueError("Native OpenSSL is required for independent verification")
    with tempfile.TemporaryDirectory(prefix="emudhra-p11-probe-") as temporary:
        root = Path(temporary)
        config = root / "config" / "pkcs11"
        (config / "modules").mkdir(parents=True)
        local, vendor = root / "local", root / "vendor"
        local.mkdir()
        (vendor / "anchors").mkdir(parents=True)
        (config / "pkcs11.conf").write_text("user-config: only\n")
        (config / "modules" / "emudhra-probe.module").write_text(
            f"module: {module}\ncritical: yes\ntrust-policy: yes\n"
            f"x-init-reserved: paths={local}:{vendor}\n"
        )
        env = {
            "PATH": os.defpath,
            "LC_ALL": "C",
            "HOME": temporary,
            "XDG_CONFIG_HOME": str(root / "config"),
        }

        def run(*args):
            return subprocess.run(
                [trust, *args], env=env, capture_output=True, timeout=20, check=True
            ).stdout

        # System modules or disabled user configuration must not be mistaken for
        # successful isolation. A nonempty baseline is never accepted.
        if run("list", "--filter=certificates").strip():
            raise ValueError("p11-kit configuration is not isolated")
        bad, good = synthetic_ca("P11 fixture selected"), synthetic_ca("P11 fixture survivor")
        bad_path, good_path = vendor / "anchors" / "bad.pem", vendor / "anchors" / "good.pem"
        bad_path.write_bytes(bad)
        good_path.write_bytes(good)
        bad_hash = x509.load_pem_x509_certificate(bad).fingerprint(hashes.SHA256()).hex()
        good_hash = x509.load_pem_x509_certificate(good).fingerprint(hashes.SHA256()).hex()

        def exported(filename, format, filter):
            path = root / filename
            run("extract", f"--format={format}", f"--filter={filter}", "--overwrite", str(path))
            return path

        baseline = exported("before.pem", "pem-bundle", "ca-anchors")
        _, _, count = filter_bundle(baseline.read_bytes(), {"certificates": []})
        observed = {
            decode_object(m)[0].fingerprint(hashes.SHA256()).hex()
            for m in OBJECT.finditer(baseline.read_bytes())
        }
        if count != 2 or observed != {bad_hash, good_hash}:
            raise ValueError("Native module did not load exactly the synthetic source anchors")
        result = {
            "deny_source": "same-source" if same_source else "higher-priority-source",
            "native_binaries": {
                "trust_sha256": digest(Path(trust).read_bytes()),
                "module_sha256": digest(Path(module).read_bytes()),
            },
            "directory_policies": {},
        }
        for directory in ("blocklist", "blacklist"):
            destination = (vendor if same_source else local) / directory
            destination.mkdir()
            (destination / "selected.pem").write_bytes(bad)
            try:
                tls = exported("tls.pem", "pem-bundle", "ca-anchors")
                observed = {
                    decode_object(m)[0].fingerprint(hashes.SHA256()).hex()
                    for m in OBJECT.finditer(tls.read_bytes())
                }
                formats = {}
                for selection in ("certificates", "trust-policy"):
                    bundle = exported("extended.pem", "openssl-bundle", selection)
                    rejected = {}
                    for purpose in ("sslserver", "any"):
                        check = subprocess.run(
                            [
                                openssl,
                                "verify",
                                "-no-CApath",
                                "-no-CAstore",
                                "-purpose",
                                purpose,
                                "-CAfile",
                                str(bundle),
                                str(bad_path),
                            ],
                            capture_output=True,
                            timeout=10,
                        )
                        if check.returncode and b"certificate rejected" not in check.stderr:
                            raise ValueError(
                                "Native OpenSSL failed for a reason other than rejection"
                            )
                        rejected[purpose] = check.returncode != 0
                    formats[selection] = rejected
                result["directory_policies"][directory] = {
                    "tls_excludes_selected": bad_hash not in observed,
                    "tls_preserves_survivor": good_hash in observed,
                    "openssl_rejects_selected": formats,
                }
            finally:
                (destination / "selected.pem").unlink()
                destination.rmdir()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trust", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--same-source", action="store_true")
    args = parser.parse_args()
    print(json.dumps(probe(args.trust, args.module, same_source=args.same_source), indent=2))


if __name__ == "__main__":
    main()
