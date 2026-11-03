"""Native p11-kit export staging using isolated, explicit module configuration.

This module is stdlib-only so the same fixed code can run in a target helper. It
never invokes system update hooks or writes a configured source/trust directory.
"""

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

# Relative output, native format, selection, purpose. Match the consolidated
# Fedora-family output layout while keeping every command explicit and fixed.
P11_EXPORTS = (
    ("openssl/ca-bundle.trust.crt", "openssl-bundle", "certificates", None),
    ("pem/tls-ca-bundle.pem", "pem-bundle", "ca-anchors", "server-auth"),
    ("pem/email-ca-bundle.pem", "pem-bundle", "ca-anchors", "email"),
    ("pem/objsign-ca-bundle.pem", "pem-bundle", "ca-anchors", "code-signing"),
    ("java/cacerts", "java-cacerts", "ca-anchors", "server-auth"),
    ("edk2/cacerts.bin", "edk2-cacerts", "ca-anchors", "server-auth"),
    ("pem/directory-hash", "pem-directory-hash", "ca-anchors", "server-auth"),
    ("audit/blocked.pem", "pem-bundle", "blocklist", None),
    ("audit/policy.pem", "openssl-bundle", "trust-policy", None),
)


def p11_path(value):
    path = os.fspath(value)
    if not re.fullmatch(r"/[A-Za-z0-9._/-]+", path) or os.path.realpath(path) != path:
        raise ValueError(
            "p11-kit paths must be canonical absolute paths without special characters"
        )
    return path


def p11_generate(binary, module, sources, destination):
    """Produce exports below a fresh private staging path; do not modify sources."""
    binary, module = p11_path(binary), p11_path(module)
    sources = [p11_path(source) for source in sources]
    if not 1 <= len(sources) <= 4 or len(set(sources)) != len(sources):
        raise ValueError("p11-kit requires one to four distinct source directories")
    if any(not os.path.isdir(source) for source in sources):
        raise ValueError("p11-kit source directories must exist")
    destination = Path(p11_path(destination))
    destination.mkdir(mode=0o700)
    with tempfile.TemporaryDirectory(prefix="emudhra-p11-config-") as temporary:
        root = Path(temporary)
        config = root / "config/pkcs11"
        (config / "modules").mkdir(parents=True)
        empty = root / "empty"
        empty.mkdir()
        (config / "pkcs11.conf").write_text("user-config: only\n")
        module_config = config / "modules/emudhra-native.module"
        env = {
            "PATH": os.defpath,
            "LC_ALL": "C",
            "HOME": temporary,
            "XDG_CONFIG_HOME": str(root / "config"),
        }

        def configure(paths):
            module_config.write_text(
                f"module: {module}\ncritical: yes\ntrust-policy: yes\n"
                + "x-init-reserved: paths="
                + ":".join(paths)
                + "\n"
            )

        def run(*args):
            try:
                process = subprocess.run(
                    [binary, *args],
                    stdin=subprocess.DEVNULL,
                    env=env,
                    capture_output=True,
                    timeout=30,
                )
            except (FileNotFoundError, subprocess.TimeoutExpired) as error:
                raise ValueError("Native p11-kit unavailable or timed out") from error
            if process.returncode:
                raise ValueError("Native p11-kit export failed")
            return process.stdout

        configure([str(empty)])
        if run("list", "--filter=certificates").strip():
            raise ValueError("Native p11-kit configuration is not isolated")
        configure(sources)
        for relative, format, selection, purpose in P11_EXPORTS:
            output = destination / relative
            output.parent.mkdir(parents=True, exist_ok=True)
            arguments = ["extract", "--format=" + format, "--filter=" + selection]
            if purpose:
                arguments.append("--purpose=" + purpose)
            run(*arguments, str(output))
        hashed = destination / "pem/directory-hash"
        mode = stat.S_IMODE(hashed.stat().st_mode)
        hashed.chmod(mode | 0o700)
        for alias in ("ca-certificates.crt", "ca-bundle.crt"):
            (hashed / alias).symlink_to("../tls-ca-bundle.pem")
        hashed.chmod(mode)


def p11_output_tree(directory):
    """Read bounded staged exports, preserving relative links without following them."""
    root = Path(directory)
    files, links, total = {}, {}, 0
    for current, directories, names in os.walk(root, followlinks=False):
        if any((Path(current) / name).is_symlink() for name in directories):
            raise ValueError("Unexpected directory symlink in p11-kit exports")
        for name in sorted(names):
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(path)
                if relative not in (
                    "pem/directory-hash/ca-certificates.crt",
                    "pem/directory-hash/ca-bundle.crt",
                ) and (os.path.basename(link) != link or link in (".", "..")):
                    raise ValueError("Unsafe p11-kit certificate link")
                if (
                    relative.endswith(("/ca-certificates.crt", "/ca-bundle.crt"))
                    and link != "../tls-ca-bundle.pem"
                ):
                    raise ValueError("Unexpected p11-kit compatibility link")
                links[relative] = link
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                with path.open("rb") as stream:
                    data = stream.read(16 * 1024 * 1024 + 1)
                if len(data) > 16 * 1024 * 1024:
                    raise ValueError("Native export file exceeds size limit")
                files[relative] = data
                total += len(data)
            else:
                raise ValueError("Unexpected p11-kit export filesystem object")
            if len(files) + len(links) > 8192 or total > 128 * 1024 * 1024:
                raise ValueError("Native exports exceed aggregate limit")
    return files, links
