import shutil
import sqlite3

import pytest

from emudhra_remover.adapters.nss import native, trust_flags
from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State

pytestmark = pytest.mark.skipif(not shutil.which("certutil"), reason="NSS certutil unavailable")


@pytest.fixture
async def nss_service(tmp_path, fixture_bundle):
    directory = tmp_path / "nss"
    directory.mkdir()
    native(directory, "-N", "--empty-password")
    for alias, raw in zip(("bad", "good"), fixture_bundle[:2], strict=True):
        file = tmp_path / (alias + ".pem")
        file.write_bytes(raw)
        native(directory, "-A", "-n", alias, "-t", "CT,C,C", "-a", "-i", str(file))
    target = Target(
        id="nss",
        transport="local",
        adapter="nss-sql",
        nss_offline=True,
        path=str(directory / "cert9.db"),
    )
    app = Service(Inventory(targets=[target]), State(tmp_path / "state"), write_enabled=True)
    app.incident = fixture_bundle[2]
    yield app, target, directory
    app.state.close()


async def test_nss_removal_preserves_companion_and_other_trust(nss_service):
    app, target, directory = nss_service
    original = (directory / "cert9.db").read_bytes()
    companion = (directory / "key4.db").read_bytes()
    scan = await app.scan(target.id)
    assert scan["matches"][0]["alias"] == "bad"
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert (await app.scan(target.id))["matches"] == []
    assert trust_flags(directory, {"good"}) == {"good": "CT,C,C"}
    assert (directory / "key4.db").read_bytes() == companion
    await app.rollback(plan["plan_id"])
    assert (directory / "cert9.db").read_bytes() == original
    assert (directory / "key4.db").read_bytes() == companion
    assert trust_flags(directory, {"good", "bad"}) == {"good": "CT,C,C", "bad": "CT,C,C"}


@pytest.mark.parametrize(
    "marker", ["parent.lock", ".parentlock", "lock", "cert9.db-wal", "key4.db-journal"]
)
async def test_profile_and_sidecar_guards(nss_service, marker):
    app, target, directory = nss_service
    (directory / marker).write_bytes(b"")
    with pytest.raises(ValueError, match="lock|sidecar"):
        await app.scan(target.id)


async def test_companion_change_rejects_saved_plan(nss_service):
    app, target, directory = nss_service
    plan = await app.plan(target.id)
    with sqlite3.connect(directory / "key4.db") as db:
        db.execute("INSERT INTO metaData(id, item1) VALUES ('operator-change', ?)", (b"x",))
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"


async def test_private_records_rejected_before_snapshot(nss_service):
    app, target, directory = nss_service
    with sqlite3.connect(directory / "key4.db") as db:
        db.execute("INSERT INTO nssPrivate(id) VALUES (123)")
    with pytest.raises(ValueError, match="private-key"):
        await app.transport.read(target)


async def test_external_sqlite_transaction_blocks_replace(nss_service):
    app, target, directory = nss_service
    plan = await app.plan(target.id)
    # A read transaction acquires SQLite shared byte-range locks without sidecars.
    db = sqlite3.connect(directory / "cert9.db")
    try:
        db.execute("BEGIN")
        db.execute("SELECT COUNT(*) FROM nssPublic").fetchone()
        with pytest.raises(ValueError):
            await app.apply(plan["plan_id"])
        assert app.state.get(plan["plan_id"])["status"] == "apply-failed"
    finally:
        db.close()


async def test_target_module_configuration_never_loaded(nss_service, tmp_path):
    app, target, directory = nss_service
    original = (directory / "pkcs11.txt").read_bytes()
    (directory / "pkcs11.txt").write_text("library=/invalid/never-load-this.so\n")
    scan = await app.scan(target.id)
    assert len(scan["matches"]) == 1
    assert (directory / "pkcs11.txt").read_text().startswith("library=/invalid/")
    (directory / "pkcs11.txt").write_bytes(original)


def test_nss_requires_offline_declaration(tmp_path):
    with pytest.raises(ValueError, match="nss_offline"):
        Target(id="nss", transport="local", adapter="nss-sql", path=str(tmp_path / "cert9.db"))


async def test_password_protected_token_is_rejected(nss_service, tmp_path):
    app, target, directory = nss_service
    old = tmp_path / "empty-password"
    new = tmp_path / "protected-password"
    old.write_bytes(b"\n\n")
    new.write_bytes(b"test-password\ntest-password\n")
    native(directory, "-W", "-f", str(old), "-@", str(new))
    original_cert = (directory / "cert9.db").read_bytes()
    original_key = (directory / "key4.db").read_bytes()
    with pytest.raises(ValueError, match="empty-password"):
        await app.plan(target.id)
    assert (directory / "cert9.db").read_bytes() == original_cert
    assert (directory / "key4.db").read_bytes() == original_key
