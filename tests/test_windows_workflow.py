"""Journal/recovery integration with the native operation class and fixture API.

CryptoAPI itself is covered separately on Windows using real temporary stores.
"""

import copy
from contextlib import nullcontext

import pytest
from test_windows_policy import snapshot_for

from emudhra_remover import windows_remote
from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State
from emudhra_remover.transport import Transport, WriteRejected


@pytest.fixture
def windows_service(tmp_path, fixture_bundle, monkeypatch):
    snapshot = snapshot_for(fixture_bundle[:2])

    class FixtureAPI:
        fail_after_add = False

        def open(self, _location, name, **_):
            return nullcontext("source" if name == "Root" else "denied")

        def entries(self, handle):
            return copy.deepcopy(snapshot[handle])

        def validate_record(self, key, record):
            pass  # exercised with actual CryptoAPI by the Windows job

        def add(self, handle, key, record):
            snapshot[handle][key] = copy.deepcopy(record)
            if self.fail_after_add:
                raise OSError("Fixture disconnect after persisted addition")

        def delete(self, handle, key, record):
            assert snapshot[handle][key] == record
            del snapshot[handle][key]

    api = FixtureAPI()
    monkeypatch.setattr(windows_remote, "CryptoAPI", lambda: api)
    monkeypatch.setattr(windows_remote, "operation_lock", lambda _: nullcontext())
    monkeypatch.setattr(windows_remote, "current_sid", lambda: "S-1-fixture")

    class FixtureTransport(Transport):
        async def request(self, target, operation, **payload):
            try:
                return windows_remote.perform(
                    {"path": target.path, "operation": operation, **payload}
                )
            except Exception as error:
                if operation == "replace" and windows_remote.WRITE_STARTED is False:
                    raise WriteRejected(str(error)) from error
                raise ValueError(str(error)) from error

    target = Target(
        id="windows",
        adapter="windows-store",
        host="192.0.2.9",
        user="admin",
        path="cert://CurrentUser/Root",
    )
    app = Service(Inventory(targets=[target]), State(tmp_path / "state"), write_enabled=True)
    app.transport, app.incident = FixtureTransport(), copy.deepcopy(fixture_bundle[2])
    yield app, target, snapshot, api
    app.state.close()


async def test_windows_apply_and_rollback_preserve_source_and_existing_denial(windows_service):
    app, target, snapshot, _ = windows_service
    survivor = list(snapshot["source"])[1]
    snapshot["denied"][survivor] = copy.deepcopy(snapshot["source"][survivor])
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert len(snapshot["denied"]) == 2 and len(snapshot["source"]) == 2
    assert (await app.scan(target.id))["matches"] == []
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original


@pytest.mark.parametrize("recovery", ["resume", "rollback"])
async def test_windows_interrupted_multicertificate_apply_recovers(windows_service, recovery):
    app, target, snapshot, api = windows_service
    app.incident["certificates"] = [{"sha256": key} for key in snapshot["source"]]
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    api.fail_after_add = True
    with pytest.raises(ValueError, match="disconnect"):
        await app.apply(plan["plan_id"])
    assert (await app.status(plan["plan_id"]))["observed_state"] == "partially-modified"
    api.fail_after_add = False
    await getattr(app, recovery)(plan["plan_id"])
    expected = original if recovery == "rollback" else app.state.get(plan["plan_id"])["after"]
    assert await app.transport.read(target) == expected


async def test_windows_external_source_change_rejected_before_write(windows_service):
    app, target, snapshot, _ = windows_service
    plan = await app.plan(target.id)
    snapshot["source"].pop(next(iter(snapshot["source"])))
    with pytest.raises(WriteRejected, match="changed since planning"):
        await app.apply(plan["plan_id"])
    assert not snapshot["denied"]
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"


@pytest.mark.parametrize("recovery", ["resume", "rollback"])
async def test_windows_recovery_preserves_read_only_source_drift(
    windows_service, fixture_bundle, recovery
):
    from conftest import certificate

    app, target, snapshot, api = windows_service
    app.incident["certificates"] = [{"sha256": key} for key in snapshot["source"]]
    plan = await app.plan(target.id)
    api.fail_after_add = True
    with pytest.raises(ValueError):
        await app.apply(plan["plan_id"])
    api.fail_after_add = False
    extra = snapshot_for([certificate("Automatic root update")])["source"]
    snapshot["source"].update(extra)
    # The old planned certificate can disappear from the read-only source too.
    snapshot["source"].pop(next(iter(snapshot["denied"])))
    sources = copy.deepcopy(snapshot["source"])
    status = await app.status(plan["plan_id"])
    assert status["observed_state"] == "partially-modified" and status["read_only_source_changed"]
    await getattr(app, recovery)(plan["plan_id"])
    assert snapshot["source"] == sources
    assert len(snapshot["denied"]) == (2 if recovery == "resume" else 0)
    status = await app.status(plan["plan_id"])
    assert status["observed_state"] == ("modified" if recovery == "resume" else "original")
    assert status["read_only_source_changed"]
    assert status["verification"] == {
        "snapshot_verified": True,
        "chain_validation": "not-performed",
    }


async def test_windows_archived_denial_blocks_planning(windows_service):
    import base64
    import struct

    app, target, snapshot, _ = windows_service
    key = next(iter(snapshot["source"]))
    archived = copy.deepcopy(snapshot["source"][key])
    archived["serialized"] = base64.b64encode(
        struct.pack("<III", 19, 1, 0) + base64.b64decode(archived["serialized"])
    ).decode()
    snapshot["denied"][key] = archived
    scan = await app.scan(target.id)
    assert scan["matches"][0]["removable"] is False
    assert "verified" not in scan["verification"]
    with pytest.raises(ValueError, match="manual remediation"):
        await app.plan(target.id)
