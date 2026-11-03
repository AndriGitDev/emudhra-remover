import asyncio
import base64
import json
import shlex
import sys
from importlib.resources import files

from .config import Target


class WriteRejected(ValueError):
    """The helper confirmed that replacement was never attempted."""


def ssh_command(target, remote_command):
    return [
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
        remote_command,
    ]


class Transport:
    async def request(self, target: Target, operation: str, **payload) -> dict:
        if target.adapter == "windows-store":
            from .windows_transport import request_windows

            return await request_windows(target, operation, **payload)
        request = {"operation": operation, "path": target.path, **payload}
        source = files("emudhra_remover").joinpath("remote.py").read_text()
        if target.adapter == "p11-kit":
            request.update(adapter="p11-kit", p11=target.p11.model_dump())
            source = source.rsplit('\nif __name__ == "__main__":', 1)[0]
            source += "\nimport types\n_helper_pkg=types.ModuleType('_emudhra_helpers')\n"
            source += "_helper_pkg.__path__=[]\nsys.modules['_emudhra_helpers']=_helper_pkg\n"
            for name in ("p11_formats", "p11_native", "p11_policy"):
                module_source = files("emudhra_remover").joinpath(name + ".py").read_text()
                source += f"_m=types.ModuleType('_emudhra_helpers.{name}')\n"
                source += "_m.__package__='_emudhra_helpers'\nsys.modules[_m.__name__]=_m\n"
                source += f"exec({module_source!r}, _m.__dict__)\n"
            source += files("emudhra_remover").joinpath("p11_remote.py").read_text() + "\nmain()\n"
        if target.adapter == "debian":
            request.update(adapter="debian", debian=target.debian.model_dump())
            extension = files("emudhra_remover").joinpath("debian_remote.py").read_text()
            source = source.rsplit('\nif __name__ == "__main__":', 1)[0]
            source += "\n" + extension + "\nmain()\n"

        if target.adapter == "nss-sql":
            request["adapter"] = "nss-sql"
            extension = files("emudhra_remover").joinpath("nss_remote.py").read_text()
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
            command = ssh_command(target, shlex.join(remote))
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, _stderr = await asyncio.wait_for(
                process.communicate(json.dumps(request).encode()),
                timeout=240
                if target.adapter == "p11-kit"
                else (120 if target.adapter == "debian" else 45),
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

    async def replace(
        self, target: Target, expected: str, data: bytes, *, recovery_from: bytes | None = None
    ) -> dict:
        recovery = {}
        if recovery_from is not None:
            recovery["recovery_from"] = base64.b64encode(recovery_from).decode()
        return await self.request(
            target,
            "replace",
            expected_sha256=expected,
            data=base64.b64encode(data).decode(),
            **recovery,
        )

    async def verify(self, target: Target, *, require: bool = True) -> dict:
        if target.adapter == "windows-store":
            from .windows_policy import decode

            decode(await self.read(target))
            return {"snapshot_verified": True, "chain_validation": "not-performed"}
        if target.adapter in ("debian", "p11-kit"):
            result = await self.request(target, "verify")
            if require and not result["verified"]:
                raise ValueError("; ".join(result["issues"]))
            return result
        return {"verified": True}

    async def reconcile(self, target: Target, expected: str, *, recovery_from: bytes | None = None):
        if target.adapter in ("debian", "p11-kit"):
            recovery = {}
            if recovery_from is not None:
                recovery["recovery_from"] = base64.b64encode(recovery_from).decode()
            await self.request(target, "reconcile", expected_sha256=expected, **recovery)
