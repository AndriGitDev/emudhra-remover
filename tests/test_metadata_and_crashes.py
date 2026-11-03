import base64
import json
import os
import shutil
import stat
import subprocess
import sys

import pytest

from emudhra_remover import remote
from emudhra_remover.certificates import digest


@pytest.mark.skipif(not shutil.which("setfacl"), reason="setfacl unavailable")
async def test_inherited_acl_is_not_added_to_replacement(service):
    app, path, _ = service
    before = path.stat()
    attrs = remote.xattrs(path)
    subprocess.run(["setfacl", "-d", "-m", "u:nobody:rwx", str(path.parent)], check=True)
    plan_id = (await app.plan("test"))["plan_id"]
    await app.apply(plan_id)
    after = path.stat()
    assert (after.st_uid, after.st_gid) == (before.st_uid, before.st_gid)
    assert stat.S_IMODE(after.st_mode) == stat.S_IMODE(before.st_mode)
    assert remote.xattrs(path) == attrs
    await app.rollback(plan_id)
    assert remote.xattrs(path) == attrs


@pytest.mark.skipif(not shutil.which("setfacl"), reason="setfacl unavailable")
async def test_existing_acl_and_user_xattr_are_preserved(service):
    app, path, _ = service
    subprocess.run(["setfacl", "-m", "u:nobody:r", str(path)], check=True)
    os.setxattr(path, "user.emudhra-test", b"preserved")
    original_mode = stat.S_IMODE(path.stat().st_mode)
    attrs = remote.xattrs(path)
    plan_id = (await app.plan("test"))["plan_id"]
    await app.apply(plan_id)
    assert remote.xattrs(path) == attrs
    assert stat.S_IMODE(path.stat().st_mode) == original_mode
    await app.rollback(plan_id)
    assert remote.xattrs(path) == attrs


async def test_actual_helper_exit_leaves_temp_only_inside_private_workspace(service):
    app, path, original_hash = service
    plan_id = (await app.plan("test"))["plan_id"]
    plan = app.state.get(plan_id)
    await app.apply(plan_id)
    modified_hash = digest(path.read_bytes())
    request = {
        "operation": "replace",
        "path": str(path),
        "expected_sha256": modified_hash,
        "data": base64.b64encode(plan["before"]).decode(),
    }
    # Simulate process death after fsync of temporary bytes, just before rename.
    script = (
        "import json,os,sys;from emudhra_remover import remote;"
        "remote.os.replace=lambda *args:os._exit(86);"
        "remote.perform(json.load(sys.stdin))"
    )
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(request).encode())
    assert result.returncode == 86
    workspace = path.with_name(path.name + ".emudhra-work")
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert len(list(workspace.glob("pending-*"))) == 1
    assert digest(path.read_bytes()) == modified_hash
    assert next(workspace.glob("pending-*")).read_bytes() == plan["before"]
    assert not list(path.parent.glob(".emudhra-*"))
    await app.rollback(plan_id)
    assert digest(path.read_bytes()) == original_hash
    assert not list(workspace.glob("pending-*"))


def test_metadata_error_leaves_original_and_removes_temp(service, monkeypatch):
    app, path, original_hash = service
    os.setxattr(path, "user.emudhra-test", b"x")

    def fail(*args):
        raise PermissionError("metadata denied")

    monkeypatch.setattr(remote.os, "setxattr", fail)
    with pytest.raises(PermissionError):
        remote.perform(
            {
                "operation": "replace",
                "path": str(path),
                "expected_sha256": original_hash,
                "data": base64.b64encode(b"replacement").decode(),
            }
        )
    assert remote.WRITE_STARTED is False
    assert digest(path.read_bytes()) == original_hash
    assert not list(path.with_name(path.name + ".emudhra-work").glob("pending-*"))


def test_busy_target_lock_refuses_write(service):
    _, path, original_hash = service
    with remote.lock(str(path)), pytest.raises(BlockingIOError):
        remote.perform(
            {
                "operation": "replace",
                "path": str(path),
                "expected_sha256": original_hash,
                "data": base64.b64encode(b"replacement").decode(),
            }
        )
    assert digest(path.read_bytes()) == original_hash
