"""Linux-controller SSH transport for the fixed Windows Python/CryptoAPI helper."""

import asyncio
import json
from importlib.resources import files

# Valid under both Windows cmd.exe and PowerShell default SSH shells. The helper
# and all operator data travel through stdin, avoiding Windows command-size limits.
BOOTSTRAP = (
    'python -I -c "import sys,json;'
    "request=json.loads(sys.stdin.buffer.read(50331649));"
    "exec(request.pop('helper'))\""
)


def helper_source():
    source = "import types,sys\n_pkg=types.ModuleType('_emudhra_windows')\n"
    source += "_pkg.__path__=[]\nsys.modules['_emudhra_windows']=_pkg\n"
    for name in ("windows_serialized", "windows_policy", "windows_native", "windows_remote"):
        code = files("emudhra_remover").joinpath(name + ".py").read_text()
        source += f"_m=types.ModuleType('_emudhra_windows.{name}')\n"
        source += "_m.__package__='_emudhra_windows'\nsys.modules[_m.__name__]=_m\n"
        source += f"exec({code!r}, _m.__dict__)\n"
    return source + "_m.main(request)\n"


async def request_windows(target, operation, **payload):
    from .transport import WriteRejected, ssh_command

    request = {"operation": operation, "path": target.path, **payload, "helper": helper_source()}
    encoded = json.dumps(request).encode()
    if len(encoded) > 48 * 1024 * 1024:
        raise ValueError("Windows helper request exceeds size limit")
    process = await asyncio.create_subprocess_exec(
        *ssh_command(target, BOOTSTRAP),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, _ = await asyncio.wait_for(process.communicate(encoded), timeout=120)
    except BaseException:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    try:
        result = json.loads(stdout)
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(
            "Windows helper unavailable: check SSH, Python and store permissions"
        ) from error
    if process.returncode or "error" in result:
        if operation == "replace" and result.get("write_may_have_occurred") is False:
            raise WriteRejected(result.get("error", "Windows write rejected"))
        raise ValueError(result.get("error", "Windows helper failed"))
    return result
