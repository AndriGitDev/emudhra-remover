import asyncio
import base64
import json
import shlex
import sys
from importlib.resources import files

from .config import Target


class WriteRejected(ValueError):
    """The helper confirmed that replacement was never attempted."""


class Transport:
    async def request(self, target: Target, operation: str, **payload) -> dict:
        request = {"operation": operation, "path": target.path, **payload}
        source = files("emudhra_remover").joinpath("remote.py").read_text()
        if target.adapter == "debian":
            request.update(adapter="debian", debian=target.debian.model_dump())
            extension = files("emudhra_remover").joinpath("debian_remote.py").read_text()
            source = source.rsplit('\nif __name__ == "__main__":', 1)[0]
            source += "\n" + extension + "\nmain()\n"

        if target.transport == "local":
            command = [sys.executable, "-I", "-c", source]
        else:
            # SSH always passes the command through a remote shell. Quote the helper
            # and use JSON stdin for all variable paths/data, never shell interpolation.
            remote = ["sudo", "-n"] if target.sudo else []
            # Keep the login-shell command on one line, including for csh/tcsh.
            encoded = base64.b64encode(source.encode()).decode()
            loader = f"import base64;exec(base64.b64decode('{encoded}'))"
            remote.extend(["python3", "-I", "-c", loader])
            command = [
                "ssh",
                "-T",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UpdateHostKeys=no",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ForwardAgent=no",
                "-o",
                "ClearAllForwardings=yes",
                "-p",
                str(target.port),
                "-l",
                target.user,
                "--",
                target.host,
                shlex.join(remote),
            ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(
                process.communicate(json.dumps(request).encode()),
                timeout=120 if target.adapter == "debian" else 45,
            )
        except BaseException:
            if process.returncode is None:
                process.kill()
            await process.wait()
            raise
        try:
            result = json.loads(stdout)
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError(
                "Target helper unavailable: check SSH, known_hosts, Python 3 and permissions"
            ) from error
        if process.returncode or "error" in result:
            if operation == "replace" and result.get("write_may_have_occurred") is False:
                raise WriteRejected(result.get("error", "Write rejected"))
            raise ValueError(result.get("error", "Target helper failed"))
        return result

    async def read(self, target: Target) -> bytes:
        result = await self.request(target, "read")
        return base64.b64decode(result["data"], validate=True)

    async def replace(self, target: Target, expected: str, data: bytes) -> dict:
        return await self.request(
            target,
            "replace",
            expected_sha256=expected,
            data=base64.b64encode(data).decode(),
        )

    async def verify(self, target: Target) -> dict:
        if target.adapter == "debian":
            return await self.request(target, "verify")
        return {"verified": True}

    async def reconcile(self, target: Target, expected: str):
        if target.adapter == "debian":
            await self.request(target, "reconcile", expected_sha256=expected)
