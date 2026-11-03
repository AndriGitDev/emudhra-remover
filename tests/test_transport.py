import asyncio
import base64
import json
import shlex
from unittest.mock import AsyncMock

import pytest

from emudhra_remover.config import Target
from emudhra_remover.transport import Transport


async def test_ssh_command_uses_fixed_helper_and_json_stdin(monkeypatch):
    process = AsyncMock()
    process.returncode = 0
    process.communicate.return_value = (json.dumps({"data": "eA=="}).encode(), b"")
    spawn = AsyncMock(return_value=process)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", spawn)
    target = Target(
        id="remote",
        host="192.0.2.1",
        user="admin",
        sudo=True,
        path="/opt/roots $(touch pwned); 'quoted'.pem",
    )
    assert await Transport().read(target) == b"x"
    args = spawn.call_args.args
    assert args[0] == "ssh"
    assert "StrictHostKeyChecking=yes" in args
    assert "BatchMode=yes" in args and "ForwardAgent=no" in args
    assert args[-2] == target.host
    remote = shlex.split(args[-1])
    assert remote[:5] == ["sudo", "-n", "python3", "-I", "-c"]
    assert "\n" not in remote[5]
    assert b"def perform(request):" in base64.b64decode(remote[5].split("'")[1])
    assert target.path not in args[-1]
    request = json.loads(process.communicate.call_args.args[0])
    assert request == {"path": target.path, "operation": "read"}


async def test_timeout_kills_child(monkeypatch):
    process = AsyncMock()
    process.returncode = None
    process.communicate.side_effect = TimeoutError
    process.kill = lambda: None
    monkeypatch.setattr(asyncio, "create_subprocess_exec", AsyncMock(return_value=process))
    target = Target(id="remote", host="192.0.2.1", user="admin", path="/opt/roots.pem")
    with pytest.raises(TimeoutError):
        await Transport().read(target)
    process.wait.assert_awaited_once()


async def test_replace_encodes_bytes_without_shell(monkeypatch):
    transport = Transport()
    transport.request = AsyncMock(return_value={"sha256": "done"})
    target = Target(id="local", transport="local", path="/opt/roots.pem")
    await transport.replace(target, "expected", b"data\x00\xff")
    assert transport.request.call_args.kwargs == {
        "expected_sha256": "expected",
        "data": base64.b64encode(b"data\x00\xff").decode(),
    }
