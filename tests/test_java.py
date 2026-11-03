import os
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from emudhra_remover.adapters.java import filter_java
from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State

JAVA = os.environ.get("EMUDHRA_JAVA", shutil.which("java") or "")
KEYTOOL = str(Path(JAVA).with_name("keytool")) if JAVA else ""
pytestmark = pytest.mark.skipif(not JAVA or not Path(KEYTOOL).is_file(), reason="JDK unavailable")


def keytool(*arguments, env):
    result = subprocess.run(
        [KEYTOOL, *arguments],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode()
    return result.stdout


@pytest.fixture(params=["JKS", "PKCS12"])
def java_service(request, tmp_path, fixture_bundle, monkeypatch):
    password_name = "EMUDHRA_TEST_STORE_PASSWORD"
    monkeypatch.setenv(password_name, "fixture-password")
    monkeypatch.setenv("EMUDHRA_JAVA", JAVA)
    store = tmp_path / "trust.store"
    for alias, raw in zip(("bad-alias", "good-alias"), fixture_bundle[:2], strict=True):
        certificate = tmp_path / f"{alias}.pem"
        certificate.write_bytes(raw)
        keytool(
            "-importcert",
            "-noprompt",
            "-alias",
            alias,
            "-file",
            str(certificate),
            "-keystore",
            str(store),
            "-storetype",
            request.param,
            "-storepass:env",
            password_name,
            env=os.environ,
        )
    target = Target(
        id="java",
        adapter="java-" + request.param.lower(),
        transport="local",
        path=str(store),
        password_env=password_name,
    )
    app = Service(Inventory(targets=[target]), State(tmp_path / "state"), write_enabled=True)
    app.incident = fixture_bundle[2]
    yield app, target, store
    app.state.close()


async def test_java_native_removal_and_byte_exact_rollback(java_service, fixture_bundle):
    app, target, store = java_service
    original = store.read_bytes()
    scan = await app.scan(target.id)
    assert scan["matches"][0]["alias"] == "bad-alias"
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert (await app.scan(target.id))["matches"] == []
    exported = keytool(
        "-exportcert",
        "-alias",
        "good-alias",
        "-keystore",
        str(store),
        "-storetype",
        target.adapter.removeprefix("java-").upper(),
        "-storepass:env",
        target.password_env,
        env=os.environ,
    )
    assert (
        x509.load_der_x509_certificate(exported).public_bytes(serialization.Encoding.PEM)
        == fixture_bundle[1]
    )
    await app.rollback(plan["plan_id"])
    assert store.read_bytes() == original
    assert len((await app.scan(target.id))["matches"]) == 1


async def test_wrong_password_no_plan_or_write(java_service, monkeypatch):
    app, target, store = java_service
    original = store.read_bytes()
    monkeypatch.setenv(target.password_env, "wrong-password-do-not-log")
    with pytest.raises(ValueError, match="check format, password") as raised:
        await app.plan(target.id)
    assert "wrong-password-do-not-log" not in str(raised.value)
    assert store.read_bytes() == original
    with app.state.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM plans").fetchone()[0] == 0


async def test_missing_password_fails_closed(java_service, monkeypatch):
    app, target, _ = java_service
    monkeypatch.delenv(target.password_env)
    with pytest.raises(ValueError, match="not set"):
        await app.scan(target.id)


async def test_private_key_store_rejected(java_service):
    app, target, store = java_service
    keytool(
        "-genkeypair",
        "-alias",
        "identity",
        "-keyalg",
        "EC",
        "-dname",
        "CN=Fixture",
        "-keystore",
        str(store),
        "-storepass:env",
        target.password_env,
        "-keypass:env",
        target.password_env,
        env=os.environ,
    )
    with pytest.raises(ValueError, match="private or secret|PKCS12 layout"):
        await app.plan(target.id)


def test_no_match_keeps_exact_bytes(java_service):
    _, target, store = java_service
    original = store.read_bytes()
    matches, output, count = filter_java(original, {"certificates": []}, target)
    assert matches == [] and output == original and count == 2


async def test_password_value_never_in_plan_or_inventory(java_service):
    app, target, _ = java_service
    plan = await app.plan(target.id)
    saved = app.state.get(plan["plan_id"])
    assert "fixture-password" not in saved["target"]
    assert "fixture-password" not in saved["report"]
    assert "fixture-password" not in str(app.list_targets())


async def test_unusual_alias_survives_removal(java_service):
    app, target, store = java_service
    unusual = "ca\nüñícode,alias"
    keytool(
        "-changealias",
        "-alias",
        "good-alias",
        "-destalias",
        unusual,
        "-keystore",
        str(store),
        "-storepass:env",
        target.password_env,
        env=os.environ,
    )
    plan = await app.plan(target.id)
    await app.apply(plan["plan_id"])
    assert keytool(
        "-exportcert",
        "-alias",
        unusual,
        "-keystore",
        str(store),
        "-storepass:env",
        target.password_env,
        env=os.environ,
    )


async def test_format_mismatch_is_rejected(java_service):
    app, target, _ = java_service
    target.adapter = "java-pkcs12" if target.adapter == "java-jks" else "java-jks"
    with pytest.raises(ValueError, match="check format"):
        await app.scan(target.id)


async def test_secret_key_entry_is_rejected(java_service):
    app, target, store = java_service
    if target.adapter != "java-pkcs12":
        pytest.skip("JKS cannot contain secret keys")
    keytool(
        "-genseckey",
        "-alias",
        "secret",
        "-keyalg",
        "AES",
        "-keysize",
        "128",
        "-keystore",
        str(store),
        "-storepass:env",
        target.password_env,
        env=os.environ,
    )
    with pytest.raises(ValueError, match="private or secret|PKCS12 layout"):
        await app.plan(target.id)
