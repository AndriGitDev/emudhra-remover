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


async def test_nss_distrust_preserves_other_trust_and_exact_pair_rollback(nss_service):
    app, target, directory = nss_service
    original = (directory / "cert9.db").read_bytes()
    companion = (directory / "key4.db").read_bytes()
    scan = await app.scan(target.id)
    assert scan["matches"][0]["alias"] == "bad"
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert (await app.scan(target.id))["matches"] == []
    assert trust_flags(directory, {"good", "bad"}) == {"good": "CT,C,C", "bad": "p,p,p"}
    assert (directory / "key4.db").read_bytes() != companion
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


@pytest.mark.parametrize("already_denied", [False, True])
async def test_server_supplied_intermediate_stays_blocked(
    nss_service, certificate_chain, tmp_path, already_denied
):
    import subprocess

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    if not shutil.which("vfychain"):
        pytest.skip("Native NSS vfychain unavailable")
    app, target, directory = nss_service
    paths = []
    for alias, data, flags in zip(
        ("chain-root", "chain-intermediate", "chain-leaf"),
        certificate_chain,
        ("CT,C,C", "p,p,p" if already_denied else ",,", None),
        strict=True,
    ):
        path = tmp_path / (alias + ".pem")
        path.write_bytes(data)
        paths.append(path)
        if flags is not None:
            native(directory, "-A", "-n", alias, "-t", flags, "-a", "-i", str(path))
    app.incident = {
        "id": "synthetic-chain",
        "certificates": [
            {
                "sha256": x509.load_pem_x509_certificate(certificate_chain[1])
                .fingerprint(hashes.SHA256())
                .hex(),
                "name": "Fixture Intermediate",
                "kind": "intermediate",
            }
        ],
    }

    def validates():
        result = subprocess.run(
            [
                "vfychain",
                "-d",
                "sql:" + str(directory),
                "-u",
                "1",
                "-a",
                str(paths[2]),
                str(paths[1]),
            ],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0

    original = await app.transport.read(target)
    assert validates() is not already_denied
    plan = await app.plan(target.id)
    if already_denied:
        assert plan["status"] == "no-matches"
        assert await app.transport.read(target) == original
    else:
        await app.apply(plan["plan_id"])
    assert not validates()
    assert (await app.plan(target.id))["status"] == "no-matches"
    if not already_denied:
        await app.rollback(plan["plan_id"])
        assert validates()
        assert await app.transport.read(target) == original


@pytest.mark.parametrize("changed_member", ["cert9", "key4"])
async def test_mixed_pair_after_interruption_recovers(nss_service, changed_member):
    import base64
    import json

    app, target, directory = nss_service
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    saved = app.state.get(plan["plan_id"])
    after = json.loads(saved["after"])
    (directory / (changed_member + ".db")).write_bytes(base64.b64decode(after[changed_member]))
    app.state.finish(plan["plan_id"], "apply-uncertain")
    status = await app.status(plan["plan_id"])
    assert status["observed_state"] == "partially-modified"
    assert status["verification"]["verified"] is False
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original


async def test_second_file_failure_is_uncertain_and_recoverable(nss_service):
    import fcntl

    app, target, directory = nss_service
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    workspace = directory / "key4.db.emudhra-work"
    workspace.mkdir(mode=0o700)
    with (workspace / "lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError):
            await app.apply(plan["plan_id"])
        assert app.state.get(plan["plan_id"])["status"] == "apply-uncertain"
    assert await app.transport.read(target) != original
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original


async def test_recovery_refuses_unrelated_pair_changes(nss_service):
    app, target, directory = nss_service
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    with sqlite3.connect(directory / "key4.db") as db:
        db.execute("INSERT INTO metaData(id,item1) VALUES ('unrelated-change', ?)", (b"x",))
    changed = await app.transport.read(target)
    with pytest.raises(ValueError, match="conflicts"):
        await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == changed


async def test_legacy_deletion_plan_cannot_be_applied(nss_service):
    import json

    app, target, _ = nss_service
    before = await app.transport.read(target)
    current = await app.plan(target.id)
    saved = app.state.get(current["plan_id"])
    report = json.loads(saved["report"])
    report.pop("adapter_revision")
    old_id = app.state.save(target.model_dump(), before, saved["after"], report)
    with pytest.raises(ValueError, match="behavior changed"):
        await app.apply(old_id)
    assert await app.transport.read(target) == before


async def test_invalid_second_member_rejected_before_first_write(nss_service):
    import base64
    import json

    from emudhra_remover.certificates import digest
    from emudhra_remover.transport import WriteRejected

    app, target, _ = nss_service
    before = await app.transport.read(target)
    plan = await app.plan(target.id)
    candidate = json.loads(app.state.get(plan["plan_id"])["after"])
    candidate["key4"] = base64.b64encode(b"invalid SQLite database").decode()
    with pytest.raises(WriteRejected):
        await app.transport.replace(target, digest(before), json.dumps(candidate).encode())
    assert await app.transport.read(target) == before


async def test_missing_certificate_nickname_fails_clearly(nss_service):
    app, target, directory = nss_service
    with sqlite3.connect(directory / "cert9.db") as db:
        db.execute("UPDATE nssPublic SET a3=NULL WHERE a0=?", (b"\x00\x00\x00\x01",))
    with pytest.raises(ValueError, match="nickname"):
        await app.scan(target.id)
