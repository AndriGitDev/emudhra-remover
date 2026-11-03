import base64
import json
import shutil

import pytest

from emudhra_remover.certificates import digest
from emudhra_remover.config import DebianPaths, Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State

pytestmark = pytest.mark.skipif(
    not shutil.which("update-ca-certificates"), reason="Debian native utility unavailable"
)


@pytest.fixture
async def debian_service(tmp_path, fixture_bundle):
    certs, local, output = [tmp_path / name for name in ("certs", "local", "output")]
    for directory in (certs, local, output):
        directory.mkdir()
    bad, good, policy = fixture_bundle
    (certs / "bad.crt").write_bytes(bad)
    (certs / "good.crt").write_bytes(good)
    config = tmp_path / "ca-certificates.conf"
    config.write_bytes(b"# operator comment\nbad.crt\ngood.crt\n")
    target = Target(
        id="debian",
        transport="local",
        adapter="debian",
        path=str(config),
        debian=DebianPaths(
            certs_dir=str(certs), local_certs_dir=str(local), output_dir=str(output)
        ),
    )
    service = Service(Inventory(targets=[target]), State(tmp_path / "state"), write_enabled=True)
    service.incident = policy
    initial = await service.transport.read(target)
    await service.transport.reconcile(target, digest(initial))
    yield service, target, config
    service.state.close()


async def test_native_persistent_removal_and_exact_config_rollback(debian_service, fixture_bundle):
    service, target, config = debian_service
    original = config.read_bytes()
    scan = await service.scan(target.id)
    assert len(scan["matches"]) == 1
    assert scan["matches"][0]["source"] == "bad.crt"
    plan = await service.plan(target.id)
    await service.apply(plan["plan_id"])
    assert config.read_bytes() == b"# operator comment\n!bad.crt\ngood.crt\n"
    assert (await service.scan(target.id))["matches"] == []
    # Subsequent native regeneration retains the persistent distrust selection.
    snapshot = await service.transport.read(target)
    await service.transport.reconcile(target, digest(snapshot))
    assert not (await service.scan(target.id))["matches"]
    await service.rollback(plan["plan_id"])
    assert config.read_bytes() == original
    assert len((await service.scan(target.id))["matches"]) == 1


async def test_changed_source_rejects_plan(debian_service, fixture_bundle):
    service, target, config = debian_service
    plan = await service.plan(target.id)
    from pathlib import Path

    (Path(target.debian.certs_dir) / "good.crt").write_bytes(fixture_bundle[1] + b"\n")
    with pytest.raises(ValueError, match="changed since planning"):
        await service.apply(plan["plan_id"])
    assert service.state.get(plan["plan_id"])["status"] == "apply-failed"
    assert b"!bad.crt" not in config.read_bytes()


async def test_local_copy_is_reported_and_blocks_removal(debian_service, fixture_bundle):
    service, target, _ = debian_service
    from pathlib import Path

    (Path(target.debian.local_certs_dir) / "local-copy.crt").write_bytes(fixture_bundle[0])
    raw = await service.transport.read(target)
    await service.transport.reconcile(target, digest(raw))
    scan = await service.scan(target.id)
    assert len(scan["matches"]) == 2
    assert any(m["removable"] is False for m in scan["matches"])
    with pytest.raises(ValueError, match="local anchors"):
        await service.plan(target.id)


async def test_interrupted_config_write_can_be_rolled_back(debian_service):
    service, target, config = debian_service
    original = config.read_bytes()
    plan = await service.plan(target.id)
    saved = service.state.get(plan["plan_id"])
    # Crash after atomic config update, before native bundle regeneration.
    config.write_bytes(base64.b64decode(json.loads(saved["after"])["config"]))
    service.state.finish(plan["plan_id"], "applying")
    assert (await service.scan(target.id))["verification"]["verified"] is False
    await service.rollback(plan["plan_id"])
    assert config.read_bytes() == original
    assert len((await service.scan(target.id))["matches"]) == 1


async def test_interrupted_rollback_regenerates_even_if_config_already_original(debian_service):
    service, target, config = debian_service
    original = config.read_bytes()
    plan = await service.plan(target.id)
    await service.apply(plan["plan_id"])
    config.write_bytes(original)
    service.state.finish(plan["plan_id"], "rolling-back")
    await service.rollback(plan["plan_id"])
    assert len((await service.scan(target.id))["matches"]) == 1


async def test_unsafe_source_path_rejected_before_command(debian_service):
    service, target, config = debian_service
    config.write_text("../outside.crt\n")
    with pytest.raises(ValueError, match="unsafe"):
        await service.scan(target.id)


async def test_inspect_plan_reports_partial_generated_state(debian_service):
    service, target, config = debian_service
    plan = await service.plan(target.id)
    saved = service.state.get(plan["plan_id"])
    config.write_bytes(base64.b64decode(json.loads(saved["after"])["config"]))
    service.state.finish(plan["plan_id"], "apply-uncertain")
    status = await service.status(plan["plan_id"])
    assert status["observed_state"] == "modified"
    assert status["verification"]["verified"] is False


async def test_source_symlink_rejected(debian_service):
    from pathlib import Path

    service, target, _ = debian_service
    bad = Path(target.debian.certs_dir) / "bad.crt"
    moved = bad.with_name("moved.crt")
    bad.rename(moved)
    bad.symlink_to(moved)
    with pytest.raises(ValueError, match="Symlinked"):
        await service.scan(target.id)


@pytest.mark.parametrize("filename", ["admin-copy.crt", "admin-copy.cer", "1234abcd.0"])
async def test_unmanaged_capath_root_blocks_plan(debian_service, fixture_bundle, filename):
    from pathlib import Path

    service, target, _ = debian_service
    (Path(target.debian.output_dir) / filename).write_bytes(fixture_bundle[0])
    scan = await service.scan(target.id)
    assert scan["verification"]["verified"] is False
    assert any(m.get("removable") is False and m["source"] == filename for m in scan["matches"])
    with pytest.raises(ValueError, match="Unmanaged CApath"):
        await service.plan(target.id)


async def test_unrelated_extra_pem_does_not_hide_audit_findings(debian_service):
    from pathlib import Path

    from conftest import certificate

    service, target, _ = debian_service
    (Path(target.debian.output_dir) / "snakeoil.pem").write_bytes(certificate("Unrelated"))
    scan = await service.scan(target.id)
    assert scan["verification"]["verified"] is False
    assert len(scan["matches"]) == 1


async def test_missing_disabled_source_is_allowed(debian_service):
    service, target, config = debian_service
    config.write_bytes(config.read_bytes() + b"!no-longer-installed.crt\n")
    assert len((await service.scan(target.id))["matches"]) == 1
    plan = await service.plan(target.id)
    await service.apply(plan["plan_id"])
    await service.rollback(plan["plan_id"])


@pytest.mark.parametrize("separator", ["\r", "\x0b", "\x85", "\u2028"])
async def test_config_non_lf_separators_fail_closed(debian_service, separator):
    service, target, config = debian_service
    config.write_text("# comment" + separator + "bad.crt\ngood.crt\n")
    with pytest.raises(ValueError, match="ASCII"):
        await service.scan(target.id)


def test_directory_glob_characters_rejected():
    with pytest.raises(ValueError, match="glob"):
        DebianPaths(certs_dir="/tmp/ca*[x]")


@pytest.mark.parametrize("operation", ["read", "verify", "reconcile"])
async def test_regeneration_guard_blocks_other_operations(debian_service, operation):
    import fcntl
    import os

    service, target, config = debian_service
    original = await service.transport.read(target)
    descriptor = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="operation busy"):
            await service.transport.request(target, operation, expected_sha256=digest(original))
    finally:
        os.close(descriptor)
    assert await service.transport.read(target) == original


async def test_shared_audit_guard_allows_reads_but_rejects_writes(debian_service):
    import fcntl
    import os

    service, target, config = debian_service
    original = config.read_bytes()
    plan = await service.plan(target.id)
    descriptor = os.open(config.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        assert len((await service.scan(target.id))["matches"]) == 1
        with pytest.raises(ValueError, match="operation busy"):
            await service.apply(plan["plan_id"])
    finally:
        os.close(descriptor)
    assert config.read_bytes() == original
    assert service.state.get(plan["plan_id"])["status"] == "apply-failed"
