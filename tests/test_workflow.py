import asyncio
import json
import os
import stat
import time

import pytest

from emudhra_remover.certificates import digest, filter_bundle, policy
from emudhra_remover.config import Inventory, Target
from emudhra_remover.state import State


async def test_round_trip_preserves_unrelated_certificates_and_metadata(service, fixture_bundle):
    app, path, original_hash = service
    bad, good, _ = fixture_bundle
    original = path.read_bytes()
    scan = await app.scan("test")
    assert scan["certificates_scanned"] == 2
    assert len(scan["matches"]) == 1
    plan = await app.plan("test")
    assert path.read_bytes() == original
    result = await app.apply(plan["plan_id"])
    assert result["status"] == "applied"
    assert bad not in path.read_bytes() and good in path.read_bytes()
    assert path.read_bytes().startswith(b"# managed test bundle\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert not (await app.scan("test"))["matches"]
    assert (await app.status(plan["plan_id"]))["observed_state"] == "modified"
    await app.rollback(plan["plan_id"])
    assert digest(path.read_bytes()) == original_hash
    assert path.read_bytes() == original


async def test_write_gate_and_expiry(service):
    app, path, original = service
    plan_id = (await app.plan("test"))["plan_id"]
    app.write_enabled = False
    with pytest.raises(ValueError, match="Writes disabled"):
        await app.apply(plan_id)
    with pytest.raises(ValueError, match="Writes disabled"):
        await app.rollback(plan_id)
    app.write_enabled = True
    with app.state.connect() as db:
        db.execute("UPDATE plans SET created=? WHERE id=?", (time.time() - 1000, plan_id))
    with pytest.raises(ValueError, match="expired"):
        await app.apply(plan_id)
    assert digest(path.read_bytes()) == original


async def test_changed_input_is_never_overwritten(service):
    app, path, _ = service
    plan_id = (await app.plan("test"))["plan_id"]
    changed = path.read_bytes() + b"\n# changed externally\n"
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan_id)
    assert path.read_bytes() == changed
    assert (await app.status(plan_id))["observed_state"] == "conflict"
    with pytest.raises(ValueError, match="incompatible"):
        await app.rollback(plan_id)
    assert path.read_bytes() == changed


async def test_concurrent_apply_and_replay(service):
    app, _path, _ = service
    plan_id = (await app.plan("test"))["plan_id"]
    results = await asyncio.gather(app.apply(plan_id), app.apply(plan_id), return_exceptions=True)
    assert sum(isinstance(r, dict) for r in results) == 1
    assert sum(isinstance(r, ValueError) for r in results) == 1


async def test_disconnect_after_write_is_recoverable(service, monkeypatch):
    app, path, original_hash = service
    plan_id = (await app.plan("test"))["plan_id"]
    replace = app.transport.replace

    async def disconnect(*args):
        await replace(*args)
        raise TimeoutError("connection lost after write")

    monkeypatch.setattr(app.transport, "replace", disconnect)
    with pytest.raises(TimeoutError):
        await app.apply(plan_id)
    observed = await app.status(plan_id)
    assert observed["status"] == "apply-uncertain"
    assert observed["observed_state"] == "modified"
    monkeypatch.setattr(app.transport, "replace", replace)
    await app.rollback(plan_id)
    assert digest(path.read_bytes()) == original_hash


async def test_restart_recovers_in_flight_plan(service):
    app, path, original_hash = service
    plan_id = (await app.plan("test"))["plan_id"]
    await app.apply(plan_id)
    app.state.finish(plan_id, "applying")  # crash after rename, before journal completion
    directory = app.state.path.parent
    app.state.close()
    app.state = State(directory)
    await app.rollback(plan_id)
    assert digest(path.read_bytes()) == original_hash


async def test_plan_bound_to_inventory(service):
    app, _path, _ = service
    plan_id = (await app.plan("test"))["plan_id"]
    app.inventory.targets[0].path = "/different-store.pem"
    with pytest.raises(ValueError, match="Inventory changed"):
        await app.apply(plan_id)


async def test_symlinks_and_hardlinks_rejected(service, tmp_path):
    app, path, _ = service
    link = tmp_path / "link.pem"
    link.symlink_to(path)
    app.inventory.targets[0].path = str(link)
    with pytest.raises(ValueError, match="Symlinked"):
        await app.scan("test")
    app.inventory.targets[0].path = str(path)
    link.unlink()
    os.link(path, link)
    with pytest.raises(ValueError, match="one link"):
        await app.scan("test")


def test_fail_closed_and_names_are_not_selectors(fixture_bundle):
    bad, good, incident = fixture_bundle
    assert filter_bundle(good, incident)[0] == []
    assert len(filter_bundle(bad, incident)[0]) == 1
    with pytest.raises(ValueError):
        filter_bundle(b"-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----", incident)
    with pytest.raises(ValueError):
        filter_bundle(good + b"-----BEGIN TRUSTED CERTIFICATE-----\nx", incident)
    assert not filter_bundle(bad + good, {"certificates": []})[0]


def test_incident_manifest():
    incident = policy()
    entries = incident["certificates"]
    assert len(entries) == len({e["sha256"] for e in entries}) == 23
    assert sum(e["kind"] == "trust-anchor" for e in entries) == 7
    assert "0fc6bfef5a36c073db756748e945b334bc87ba1f" in incident["source"]
    assert all(len(bytes.fromhex(e["sha256"])) == 32 for e in entries)


def test_state_permissions_and_single_writer(service, tmp_path):
    app, _, _ = service
    assert stat.S_IMODE(app.state.path.stat().st_mode) == 0o600
    with pytest.raises(BlockingIOError):
        State(app.state.path.parent)
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="0700"):
        State(unsafe)


@pytest.mark.parametrize("field,value", [("host", "-oProxyCommand=id"), ("user", "a;id")])
def test_ssh_arguments_reject_options(field, value):
    values = {"id": "x", "path": "/tmp/ca.pem", "host": "host", "user": "admin", field: value}
    with pytest.raises(ValueError):
        Target(**values)


def test_inventory_validation(tmp_path):
    file = tmp_path / "inventory.json"
    file.write_text(
        json.dumps({"targets": [{"id": "x", "transport": "local", "path": "relative"}]})
    )
    with pytest.raises(ValueError):
        Inventory.load(file)


async def test_audit_reports_all_matches_but_planning_refuses_empty_store(service, fixture_bundle):
    app, path, _ = service
    path.write_bytes(fixture_bundle[0])
    assert len((await app.scan("test"))["matches"]) == 1
    with pytest.raises(ValueError, match="empty"):
        await app.plan("test")


async def test_rejected_plan_cannot_rollback_another_plans_write(service):
    app, path, _ = service
    first = (await app.plan("test"))["plan_id"]
    second = (await app.plan("test"))["plan_id"]
    await app.apply(first)
    modified = path.read_bytes()
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(second)
    assert app.state.get(second)["status"] == "apply-failed"
    with pytest.raises(ValueError, match="incompatible"):
        await app.rollback(second)
    assert path.read_bytes() == modified


async def test_additive_inventory_defaults_do_not_break_saved_backups(service):
    import json

    app, path, _ = service
    original = path.read_bytes()
    plan = await app.plan("test")
    saved = app.state.get(plan["plan_id"])
    old_target = json.loads(saved["target"])
    old_target.pop("p11")  # Field absent in pre-p11-kit inventories.
    old_id = app.state.save(
        old_target, saved["before"], saved["after"], json.loads(saved["report"])
    )
    await app.apply(old_id)
    await app.rollback(old_id)
    assert path.read_bytes() == original
