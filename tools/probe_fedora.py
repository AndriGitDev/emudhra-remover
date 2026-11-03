"""Exercise Fedora's native updater and MCP workflow only in a disposable rootfs.

Requires a prepared Fedora rootfs under /tmp with Python, OpenSSL, p11-kit and
update-ca-trust, plus current PRoot. Never downloads or installs anything. All CA
sources are copied into a new fixture; package-managed trust stores remain intact.
"""

import argparse
import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from emudhra_remover.adapters.p11 import cleanup_staging
from emudhra_remover.config import Inventory, P11Paths, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State


def synthetic_root():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Isolated Fedora probe root")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=3))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )


async def probe(rootfs, proot):
    if rootfs != rootfs.resolve() or not rootfs.is_relative_to(Path(tempfile.gettempdir())):
        raise ValueError("Fedora rootfs must be a canonical disposable directory under /tmp")
    if (rootfs / ".emudhra-fixture-root").read_text() != "disposable emudhra fixture\n":
        raise ValueError("Missing disposable rootfs marker")
    if "\nID=fedora\n" not in (rootfs / "etc/os-release").read_text():
        raise ValueError("Expected a Fedora userspace")
    if (rootfs / "tmp").resolve() != rootfs / "tmp":
        raise ValueError("Fixture temporary directory cannot be symlinked")
    environment = {**os.environ, "PROOT_NO_SECCOMP": "1"}
    prefix = [
        str(proot),
        "-r",
        str(rootfs),
        "-b",
        "/dev/null",
        "-b",
        "/dev/urandom",
        "-b",
        "/dev/random",
        "-b",
        "/proc",
        "-w",
        "/",
    ]
    original_exec = asyncio.create_subprocess_exec

    async def guest_helper(*arguments, **kwargs):
        if arguments[0] != sys.executable or arguments[1:3] != ("-I", "-c"):
            raise ValueError("Unexpected helper command in isolated fixture")
        return await original_exec(
            *prefix, "/usr/bin/python3", *arguments[1:], env=environment, **kwargs
        )

    def run(*arguments, bindings=()):
        command = [*prefix[:-2], *bindings, "-w", "/", *arguments]
        return subprocess.run(
            command, env=environment, capture_output=True, timeout=120, check=True
        )

    packages = (
        run(
            "/usr/bin/rpm",
            "-q",
            "python3",
            "openssl",
            "p11-kit",
            "p11-kit-trust",
            "ca-certificates",
        )
        .stdout.decode()
        .splitlines()
    )
    with tempfile.TemporaryDirectory(prefix="emudhra-native-", dir=rootfs / "tmp") as temporary:
        fixture = Path(temporary)
        guest = "/" + fixture.relative_to(rootfs).as_posix()
        state = None
        try:
            links = {}
            for name, source in (
                ("local", "etc/pki/ca-trust/source"),
                ("vendor", "usr/share/pki/ca-trust-source"),
            ):
                shutil.copytree(rootfs / source, fixture / name, symlinks=True)
                for link in (fixture / name).rglob("*"):
                    if not link.is_symlink():
                        continue
                    original = rootfs / source / link.relative_to(fixture / name)
                    destination = original.resolve()
                    if not destination.is_relative_to(rootfs) or not destination.is_file():
                        raise ValueError("Packaged source link escapes the disposable rootfs")
                    copied = fixture / f"linked-source-{len(links)}.crt"
                    copied.write_bytes(destination.read_bytes())
                    guest_destination = guest + "/" + copied.name
                    link.unlink()
                    link.symlink_to(guest_destination)
                    links[guest + "/" + link.relative_to(fixture).as_posix()] = guest_destination
            policy = fixture / "local/emudhra-remover.p11-kit"
            policy.touch(exist_ok=True)
            cert = synthetic_root()
            anchor = fixture / "local/anchors/emudhra-probe.pem"
            anchor.parent.mkdir(exist_ok=True)
            anchor.write_bytes(cert.public_bytes(Encoding.PEM))
            bindings = [
                "-b",
                str(fixture / "local") + ":/etc/pki/ca-trust/source",
                "-b",
                str(fixture / "vendor") + ":/usr/share/pki/ca-trust-source",
            ]
            updater = ["/usr/bin/update-ca-trust", "extract", "-o", guest + "/extracted"]
            run(*updater, bindings=bindings)
            target = Target(
                id="fedora-fixture",
                transport="local",
                adapter="p11-kit",
                path=guest + "/local/emudhra-remover.p11-kit",
                p11=P11Paths(
                    source_dirs=[guest + "/local", guest + "/vendor"],
                    output_dir=guest + "/extracted",
                    source_symlinks=links,
                ),
            )
            state = State(fixture / "controller-state")
            app = Service(Inventory(targets=[target]), state, write_enabled=True)
            app.incident = {
                "id": "synthetic-fedora-probe",
                "certificates": [{"sha256": cert.fingerprint(hashes.SHA256()).hex()}],
            }
            verify = [
                "/usr/bin/openssl",
                "verify",
                "-no-CAfile",
                "-no-CApath",
                "-no-CAstore",
                "-purpose",
                "sslserver",
                "-CAfile",
                guest + "/extracted/pem/tls-ca-bundle.pem",
                guest + "/local/anchors/emudhra-probe.pem",
            ]
            run(*verify)
            with patch("emudhra_remover.transport.asyncio.create_subprocess_exec", guest_helper):
                before = await app.transport.read(target)
                scan = await app.scan(target.id)
                assert scan["verification"]["verified"] and len(scan["matches"]) == 1
                plan = await app.plan(target.id)
                await app.apply(plan["plan_id"])
                run(*updater, bindings=bindings)
                scan_after = await app.scan(target.id)
                assert scan_after["verification"]["verified"] and not scan_after["matches"]
                try:
                    run(*verify)
                except subprocess.CalledProcessError as error:
                    diagnostic = error.stderr.decode(errors="replace")
                    assert error.returncode == 2 and "error 18 at 0 depth lookup" in diagnostic, (
                        "Expected an untrusted self-signed fixture root, got: " + diagnostic
                    )
                else:
                    raise AssertionError("Native OpenSSL still accepts the selected fixture anchor")
                await app.rollback(plan["plan_id"])
                assert await app.transport.read(target) == before
                run(*verify)
                for recovery in ("resume", "rollback"):
                    plan = await app.plan(target.id)
                    saved = state.get(plan["plan_id"])
                    policy.write_bytes(base64.b64decode(json.loads(saved["after"])["policy"]))
                    state.finish(plan["plan_id"], "apply-uncertain")
                    await getattr(app, recovery)(plan["plan_id"])
                    if recovery == "resume":
                        await app.rollback(plan["plan_id"])
                    assert await app.transport.read(target) == before
            return {
                "packages": packages,
                "certificates_scanned": scan["certificates_scanned"],
                "source_links": len(links),
                "native_update_preserved_distrust": True,
                "openssl_rejection_and_rollback": True,
                "resume_and_rollback_recovery": True,
                "selinux_enforcement_tested": False,
            }
        finally:
            if state is not None:
                state.close()
            cleanup_staging(fixture)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--proot", type=Path, required=True)
    arguments = parser.parse_args()
    print(json.dumps(asyncio.run(probe(arguments.rootfs, arguments.proot)), indent=2))
