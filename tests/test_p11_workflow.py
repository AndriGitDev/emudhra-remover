import os
from pathlib import Path

import pytest

from emudhra_remover.config import Inventory, P11Paths, Target
from emudhra_remover.p11_native import p11_generate
from emudhra_remover.service import Service
from emudhra_remover.state import State


@pytest.fixture
async def p11_service(tmp_path, fixture_bundle, monkeypatch):
    binary, module = os.environ.get("EMUDHRA_TEST_TRUST"), os.environ.get("EMUDHRA_TEST_P11_MODULE")
    if not binary or not module:
        pytest.skip("Explicit native p11-kit paths unavailable")
    monkeypatch.setenv("EMUDHRA_TRUST", binary)
    monkeypatch.setenv("EMUDHRA_P11_MODULE", module)
    local, vendor, output = [tmp_path / name for name in ("local", "vendor", "extracted")]
    local.mkdir()
    (vendor / "anchors").mkdir(parents=True)
    for name, data in zip(("selected", "survivor"), fixture_bundle[:2], strict=True):
        (vendor / "anchors" / (name + ".pem")).write_bytes(data)
    policy = local / "emudhra-remover.p11-kit"
    policy.write_bytes(b"")
    p11_generate(binary, module, [local, vendor], output)
    target = Target(
        id="p11",
        transport="local",
        adapter="p11-kit",
        path=str(policy),
        p11=P11Paths(
            source_dirs=[str(local), str(vendor)],
            output_dir=str(output),
            trust_binary=binary,
            module_path=module,
        ),
    )
    app = Service(Inventory(targets=[target]), State(tmp_path / "state"), write_enabled=True)
    app.incident = fixture_bundle[2]
    yield app, target, policy
    app.state.close()
    for current, directories, _ in os.walk(tmp_path, followlinks=False):
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o700)


async def test_persistent_native_policy_and_verified_rollback(p11_service):
    app, target, policy = p11_service
    before = await app.transport.read(target)
    assert (await app.scan(target.id))["verification"]["verified"]
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert b"x-distrusted: true" in policy.read_bytes()
    scan = await app.scan(target.id)
    assert scan["verification"]["verified"] and scan["matches"] == []
    await app.rollback(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert await app.transport.read(target) == before
    assert len((await app.scan(target.id))["matches"]) == 1


async def test_native_regeneration_keeps_distrust_and_each_output(p11_service):
    import subprocess

    from emudhra_remover.certificates import digest
    from emudhra_remover.p11_formats import edk2_records, jks_records, pem_records

    app, target, _ = p11_service
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    current = await app.transport.read(target)
    await app.transport.reconcile(target, digest(current))
    output = Path(target.p11.output_dir)
    for name in ("pem/tls-ca-bundle.pem", "pem/email-ca-bundle.pem", "pem/objsign-ca-bundle.pem"):
        assert len(pem_records((output / name).read_bytes())) == 1
    assert len(jks_records((output / "java/cacerts").read_bytes())) == 1
    assert len(edk2_records((output / "edk2/cacerts.bin").read_bytes())) == 1
    selected = Path(target.p11.source_dirs[1]) / "anchors/selected.pem"
    for arguments in (
        ["-CAfile", str(output / "openssl/ca-bundle.trust.crt")],
        ["-CAfile", str(output / "pem/tls-ca-bundle.pem")],
        ["-CApath", str(output / "pem/directory-hash")],
    ):
        result = subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CAfile",
                "-no-CApath",
                "-no-CAstore",
                "-purpose",
                "sslserver",
                *arguments,
                str(selected),
            ],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode != 0
    assert (await app.scan(target.id))["matches"] == []


async def test_source_change_rejects_apply_without_policy_write(p11_service):
    app, target, policy = p11_service
    plan = await app.plan(target.id)
    source = Path(target.p11.source_dirs[1]) / "anchors/survivor.pem"
    source.write_bytes(source.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"


async def test_unmanaged_generated_edit_is_never_overwritten(p11_service, fixture_bundle):
    app, target, policy = p11_service
    plan = await app.plan(target.id)
    bundle = Path(target.p11.output_dir) / "pem/tls-ca-bundle.pem"
    bundle.chmod(0o644)
    from conftest import certificate

    bundle.write_bytes(certificate("External administrator root"))
    bundle.chmod(0o444)
    changed = bundle.read_bytes()
    with pytest.raises(ValueError, match="conflict"):
        await app.apply(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert bundle.read_bytes() == changed


@pytest.mark.parametrize("recovery", ["resume", "rollback"])
async def test_policy_only_interruption_can_recover(p11_service, recovery):
    import base64
    import json

    app, target, policy = p11_service
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    saved = app.state.get(plan["plan_id"])
    policy.write_bytes(base64.b64decode(json.loads(saved["after"])["policy"]))
    app.state.finish(plan["plan_id"], "apply-uncertain")
    assert (await app.status(plan["plan_id"]))["verification"]["verified"] is False
    await getattr(app, recovery)(plan["plan_id"])
    assert (await app.transport.verify(target))["verified"]
    expected = saved["after"] if recovery == "resume" else original
    assert await app.transport.read(target) == expected


async def test_interrupted_rollback_regenerates_after_policy_restored(p11_service):
    app, target, policy = p11_service
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    policy.write_bytes(b"")
    app.state.finish(plan["plan_id"], "rollback-uncertain")
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original
    assert (await app.transport.verify(target))["verified"]


async def test_locked_export_fails_preflight_before_policy_write(p11_service):
    import fcntl

    app, target, policy = p11_service
    plan = await app.plan(target.id)
    root = Path(target.p11.output_dir)
    # The first consolidated output cannot acquire its base-writer lock. This
    # is now detected in preflight, before policy replacement.
    workspace = root / "openssl/ca-bundle.trust.crt.emudhra-work"
    workspace.mkdir(mode=0o700)
    with (workspace / "lock").open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError):
            await app.apply(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"


async def test_nonuniform_hash_metadata_refused(p11_service):
    app, target, _ = p11_service
    hashed = Path(target.p11.output_dir) / "pem/directory-hash"
    next(hashed.glob("*.pem")).chmod(0o640)
    with pytest.raises(ValueError, match="share the TLS"):
        await app.plan(target.id)


async def test_output_xattrs_are_preserved_on_apply_and_rollback(p11_service):
    app, target, _ = p11_service
    bundle = Path(target.p11.output_dir) / "java/cacerts"
    bundle.chmod(0o644)
    try:
        os.setxattr(bundle, "user.emudhra-test", b"preserve")
    except OSError:
        pytest.skip("Filesystem does not support user xattrs")
    finally:
        bundle.chmod(0o444)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert os.getxattr(bundle, "user.emudhra-test") == b"preserve"
    await app.rollback(plan["plan_id"])
    assert os.getxattr(bundle, "user.emudhra-test") == b"preserve"


async def test_all_incident_store_can_be_distrusted_and_restored(p11_service, fixture_bundle):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    app, target, _ = p11_service
    app.incident["certificates"].append(
        {
            "sha256": x509.load_pem_x509_certificate(fixture_bundle[1])
            .fingerprint(hashes.SHA256())
            .hex()
        }
    )
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert (await app.scan(target.id))["matches"] == []
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original


def test_overlapping_source_output_paths_rejected():
    with pytest.raises(ValueError, match="overlap"):
        P11Paths(source_dirs=["/tmp/source"], output_dir="/tmp/source/output")


async def test_abandoned_hash_exchange_and_generation_are_cleaned(p11_service):
    import json

    from emudhra_remover.certificates import digest

    app, target, _ = p11_service
    root = Path(target.p11.output_dir)
    workspace = root / ".emudhra-p11.emudhra-work"
    workspace.mkdir(mode=0o700)
    abandoned = workspace / "generation-crashed"
    abandoned.mkdir(mode=0o700)
    (abandoned / "certificate-copy").write_bytes(b"staging bytes")
    pending = root / "pem/.emudhra-hash-crashed"
    pending.mkdir(mode=0o700)
    (pending / "old-generated-file").write_bytes(b"old output")
    info = pending.stat()
    marker = workspace / "hash-pending.json"
    marker.write_text(
        json.dumps({"name": pending.name, "identities": [[info.st_dev, info.st_ino]]})
    )
    original = await app.transport.read(target)
    await app.transport.reconcile(target, digest(original))
    assert not pending.exists() and not abandoned.exists() and not marker.exists()
    assert await app.transport.read(target) == original


async def test_staging_identity_conflict_refuses_cleanup(p11_service):
    import json

    app, target, policy = p11_service
    root = Path(target.p11.output_dir)
    plan = await app.plan(target.id)
    workspace = root / ".emudhra-p11.emudhra-work"
    workspace.mkdir(mode=0o700)
    pending = root / "pem/.emudhra-hash-conflict"
    pending.mkdir(mode=0o700)
    marker = workspace / "hash-pending.json"
    marker.write_text(json.dumps({"name": pending.name, "identities": [[0, 0]]}))
    with pytest.raises(ValueError, match="identity conflict"):
        await app.apply(plan["plan_id"])
    assert policy.read_bytes() == b""
    assert pending.is_dir() and marker.exists()


async def test_missing_source_directory_fails_closed(p11_service):
    app, target, _ = p11_service
    source = Path(target.p11.source_dirs[1])
    source.rename(source.with_name("moved-source"))
    with pytest.raises(ValueError, match="must exist"):
        await app.scan(target.id)


async def test_target_refuses_native_view_mismatch_before_policy_write(p11_service):
    import json

    from emudhra_remover.certificates import digest
    from emudhra_remover.p11_policy import p11_encode
    from emudhra_remover.transport import WriteRejected

    app, target, policy = p11_service
    before = await app.transport.read(target)
    plan = await app.plan(target.id)
    candidate = json.loads(app.state.get(plan["plan_id"])["after"])
    candidate["source_view"]["denied"] = []
    with pytest.raises(WriteRejected, match="interpretation differs"):
        await app.transport.replace(target, digest(before), p11_encode(candidate))
    assert policy.read_bytes() == b""


async def test_controller_refuses_different_target_interpretation(p11_service):
    import json

    from emudhra_remover.adapters.p11 import filter_p11
    from emudhra_remover.p11_policy import p11_encode

    app, target, policy = p11_service
    snapshot = json.loads(await app.transport.read(target))
    snapshot["source_view"]["certificates"] = []
    with pytest.raises(ValueError, match="native certificate views differ"):
        filter_p11(p11_encode(snapshot), app.incident)
    assert policy.read_bytes() == b""


async def test_uniform_hash_xattrs_survive_deletion_and_restoration(p11_service):
    app, target, _ = p11_service
    root = Path(target.p11.output_dir)
    hashed = root / "pem/directory-hash"
    files = [root / "pem/tls-ca-bundle.pem", *hashed.glob("*.pem")]
    for path in files:
        path.chmod(0o644)
        os.setxattr(path, "user.emudhra-test", b"uniform metadata")
        path.chmod(0o444)
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert all(
        os.getxattr(p, "user.emudhra-test") == b"uniform metadata" for p in hashed.glob("*.pem")
    )
    await app.rollback(plan["plan_id"])
    assert await app.transport.read(target) == original
    assert len(list(hashed.glob("*.pem"))) == 2


async def test_parallel_regeneration_guard_blocks_audits(p11_service):
    import fcntl

    app, target, _ = p11_service
    descriptor = os.open(target.p11.output_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(ValueError, match="operation busy"):
            await app.scan(target.id)
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("changed", ["file", "hash"])
async def test_late_generated_edit_during_staging_is_not_overwritten(
    p11_service, monkeypatch, changed
):
    import base64
    import sys
    import types

    from emudhra_remover import p11_formats, p11_native, p11_policy, remote
    from emudhra_remover.certificates import digest

    app, target, _ = p11_service
    original = await app.transport.read(target)
    plan = await app.plan(target.id)
    saved = app.state.get(plan["plan_id"])
    # Execute the same fixed helper with a deterministic competing-writer hook;
    # actual native staging and writes still operate only on the fixture tree.
    package = types.ModuleType("_emudhra_helpers")
    package.__path__ = []
    monkeypatch.setitem(sys.modules, "_emudhra_helpers", package)
    for module in (p11_formats, p11_native, p11_policy):
        monkeypatch.setitem(
            sys.modules, "_emudhra_helpers." + module.__name__.rsplit(".", 1)[1], module
        )
    namespace = {"__name__": "p11_fixture_helper"}
    exec(Path(remote.__file__).read_text(), namespace)
    extension = Path(remote.__file__).with_name("p11_remote.py").read_text()
    exec(extension, namespace)
    prepare = namespace["p11_prepare_hash"]
    root = Path(target.p11.output_dir)
    edited = (
        root / "openssl/ca-bundle.trust.crt"
        if changed == "file"
        else next((root / "pem/directory-hash").glob("*.pem"))
    )

    def competing_write(*args):
        prepare(*args)
        edited.chmod(0o644)
        edited.write_bytes(edited.read_bytes() + b"\n# concurrent administrative edit\n")
        edited.chmod(0o444)

    namespace["p11_prepare_hash"] = competing_write
    with pytest.raises(ValueError, match="Concurrent p11-kit"):
        namespace["perform"](
            {
                "adapter": "p11-kit",
                "operation": "replace",
                "path": target.path,
                "p11": target.p11.model_dump(),
                "expected_sha256": digest(original),
                "data": base64.b64encode(saved["after"]).decode(),
            }
        )
    assert b"concurrent administrative edit" in edited.read_bytes()
    assert namespace["WRITE_STARTED"] is True  # policy was written; recovery is required


async def test_noop_reconcile_keeps_java_and_hash_inodes(p11_service):
    from emudhra_remover.certificates import digest

    app, target, _ = p11_service
    root = Path(target.p11.output_dir)
    paths = [root / "java/cacerts", root / "pem/directory-hash"]
    inodes = [p.stat().st_ino for p in paths]
    current = await app.transport.read(target)
    await app.transport.reconcile(target, digest(current))
    assert [p.stat().st_ino for p in paths] == inodes


async def test_unwritable_output_parent_fails_before_policy_write(p11_service):
    app, target, policy = p11_service
    plan = await app.plan(target.id)
    parent = Path(target.p11.output_dir) / "java"
    parent.chmod(0o555)
    try:
        if os.access(parent, os.W_OK):
            pytest.skip("Account bypasses directory write permissions")
        with pytest.raises(ValueError):
            await app.apply(plan["plan_id"])
        assert policy.read_bytes() == b""
        assert app.state.get(plan["plan_id"])["status"] == "apply-failed"
    finally:
        parent.chmod(0o755)


async def test_stale_generated_incident_certificates_are_reported(p11_service):
    app, target, _ = p11_service
    selected = Path(target.p11.source_dirs[1]) / "anchors/selected.pem"
    selected.unlink()
    scan = await app.scan(target.id)
    assert scan["verification"]["verified"] is False
    assert scan["matches"] and all(item["removable"] is False for item in scan["matches"])
    assert any(item["source"].endswith("tls-ca-bundle.pem") for item in scan["matches"])
    with pytest.raises(ValueError, match="outputs differ"):
        await app.plan(target.id)


async def test_crash_before_staging_move_leaves_no_orphan_directory(p11_service, monkeypatch):
    from emudhra_remover import transport

    app, target, _ = p11_service
    plan = await app.plan(target.id)
    real_files = transport.files

    class Resource:
        def __init__(self, name):
            self.name = name

        def read_text(self):
            source = real_files("emudhra_remover").joinpath(self.name).read_text()
            if self.name == "p11_remote.py":
                source += (
                    "\n_original_rename=p11_rename\ndef p11_rename(a,b,flags):\n"
                    "    if flags == 1: os._exit(91)\n"
                    "    return _original_rename(a,b,flags)\n"
                )
            return source

    class Package:
        def joinpath(self, name):
            return Resource(name)

    with monkeypatch.context() as context:
        context.setattr(transport, "files", lambda _: Package())
        with pytest.raises(ValueError):
            await app.apply(plan["plan_id"])
    root = Path(target.p11.output_dir)
    assert app.state.get(plan["plan_id"])["status"] == "apply-uncertain"
    assert not list((root / "pem").glob(".emudhra-hash-*"))
    await app.resume(plan["plan_id"])
    assert not list((root / "pem").glob(".emudhra-hash-*"))
    assert (await app.transport.verify(target))["verified"]
