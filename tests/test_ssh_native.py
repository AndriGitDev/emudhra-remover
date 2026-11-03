"""Loopback-only SSH transport integration with disposable keys and host pinning."""

import asyncio
import os
import pwd
import shutil
import socket
import subprocess
from pathlib import Path

import pytest
from test_p11_workflow import p11_service as p11_service

from emudhra_remover import transport


@pytest.fixture
async def ssh_fixture(tmp_path, monkeypatch):
    sshd = os.environ.get("EMUDHRA_TEST_SSHD")
    if not sshd or not Path(sshd).is_file():
        pytest.skip("Explicit native SSH server fixture unavailable")
    if not shutil.which("ssh-keygen"):
        pytest.skip("Native SSH key generator unavailable")
    root = tmp_path / "ssh-fixture"
    root.mkdir(mode=0o700)
    for name in ("host", "client", "untrusted-host"):
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name)],
            capture_output=True,
            check=True,
            timeout=15,
        )
    authorized = root / "authorized_keys"
    authorized.write_bytes((root / "client.pub").read_bytes())
    authorized.chmod(0o600)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    user = pwd.getpwuid(os.getuid()).pw_name
    config = root / "sshd_config"
    # The temporary tree is private; /tmp itself fails sshd StrictModes ancestry.
    # This setting is confined to the disposable loopback server configuration.
    config.write_text(
        f"ListenAddress 127.0.0.1\nPort {port}\nHostKey {root / 'host'}\n"
        f"PidFile {root / 'pid'}\nAuthorizedKeysFile {authorized}\nAllowUsers {user}\n"
        "UsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\nAuthenticationMethods publickey\nStrictModes no\n"
        "DisableForwarding yes\nPermitTTY no\nLogLevel VERBOSE\n"
    )
    known_hosts = root / "known_hosts"
    known_hosts.write_text(f"[127.0.0.1]:{port} " + (root / "host.pub").read_text())
    base_command = transport.ssh_command

    def fixture_command(target, command):
        original = base_command(target, command)
        return [
            original[0],
            "-i",
            str(root / "client"),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "UserKnownHostsFile=" + str(known_hosts),
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            *original[1:],
        ]

    monkeypatch.setattr(transport, "ssh_command", fixture_command)
    with (root / "server.log").open("wb") as log:
        server = subprocess.Popen([sshd, "-D", "-e", "-f", str(config)], stdout=log, stderr=log)
        try:
            for _ in range(100):
                if server.poll() is not None:
                    pytest.fail((root / "server.log").read_text())
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.02)
            else:
                pytest.fail("Disposable SSH server did not start")
            from emudhra_remover.config import Target

            probe_target = Target(
                id="ssh-probe", host="127.0.0.1", user=user, port=port, path="/unused"
            )
            probe = await asyncio.create_subprocess_exec(
                *fixture_command(probe_target, "true"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, diagnostic = await asyncio.wait_for(probe.communicate(), timeout=10)
            assert probe.returncode == 0, diagnostic.decode() + (root / "server.log").read_text()
            yield user, port, known_hosts, root
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


async def test_real_ssh_apply_rollback_and_host_key_failure(service, ssh_fixture):
    app, path, _ = service
    user, port, known_hosts, root = ssh_fixture
    target = app.inventory.targets[0]
    target.transport, target.host, target.user, target.port = "ssh", "127.0.0.1", user, port
    original = path.read_bytes()
    assert len((await app.scan(target.id))["matches"]) == 1
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert not (await app.scan(target.id))["matches"]
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == original
    known_hosts.write_text(f"[127.0.0.1]:{port} " + (root / "untrusted-host.pub").read_text())
    with pytest.raises(ValueError):
        await app.scan(target.id)
    assert path.read_bytes() == original


async def test_real_ssh_p11_native_apply_rollback_and_source_conflict(p11_service, ssh_fixture):
    app, target, policy = p11_service
    user, port, _, _ = ssh_fixture
    target.transport, target.host, target.user, target.port = "ssh", "127.0.0.1", user, port
    before = await app.transport.read(target)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    scan = await app.scan(target.id)
    assert scan["verification"]["verified"] and not scan["matches"]
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == before
    plan = await app.plan(target.id)
    source = Path(target.p11.source_dirs[1]) / "anchors/survivor.pem"
    source.write_bytes(source.read_bytes() + b"\n# concurrent fixture source edit\n")
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"
