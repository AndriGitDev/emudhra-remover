import hmac
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from test_jks import utf

from emudhra_remover.adapters.bks import filter_bks, mac_key, parse_bks
from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State

PASSWORD = "fixture-password"
JAVA = os.environ.get("EMUDHRA_JAVA", shutil.which("java") or "")
JAR = os.environ.get("EMUDHRA_TEST_BC_JAR", "")
SALT = bytes(range(20))
HEADER = struct.pack(">II", 2, 20) + SALT + struct.pack(">I", 1024)


def signed(body, password=PASSWORD, header=HEADER):
    key = mac_key(password, header[8:28], int.from_bytes(header[28:32], "big"))
    return header + body + hmac.digest(key, body, "sha1")


def entry(alias, certificate, *, kind=1, chain=0, cert_type="X.509"):
    return (
        bytes([kind])
        + utf(alias)
        + struct.pack(">qI", 1700000000123, chain)
        + utf(cert_type)
        + struct.pack(">I", len(certificate))
        + certificate
    )


@pytest.fixture
def bks_fixture(tmp_path, fixture_bundle, monkeypatch):
    monkeypatch.setenv("BKS_FIXTURE_PASSWORD", PASSWORD)
    certs = [
        x509.load_pem_x509_certificate(raw).public_bytes(Encoding.DER) for raw in fixture_bundle[:2]
    ]
    target = Target(
        id="bks",
        transport="local",
        adapter="bks",
        path=str(tmp_path / "trust.bks"),
        password_env="BKS_FIXTURE_PASSWORD",
    )
    raw = signed(entry("Bad", certs[0]) + entry("Good", certs[1]) + b"\0")
    return target, raw, certs, fixture_bundle[2]


def test_exact_records_and_no_match_identity(bks_fixture):
    target, raw, _, incident = bks_fixture
    matches, output, count = filter_bks(raw, incident, target)
    assert count == 2 and matches[0]["alias"] == "Bad"
    assert parse_bks(output, PASSWORD)[2] == parse_bks(raw, PASSWORD)[2][1:]
    assert filter_bks(output, incident, target) == ([], output, 1)


@pytest.mark.parametrize("kind", [2, 3, 4, 5, 255])
def test_all_key_and_unknown_tags_refused(bks_fixture, kind):
    target, _, certs, incident = bks_fixture
    raw = signed(entry("key", certs[0], kind=kind) + b"\0")
    with pytest.raises(ValueError, match="key entries"):
        filter_bks(raw, incident, target)


@pytest.mark.parametrize(
    "case",
    [
        "duplicate",
        "empty-alias",
        "chain",
        "type",
        "der-tail",
        "hidden",
        "missing-end",
        "truncated",
        "bad-mac",
        "bad-version",
        "salt",
        "iterations",
        "many",
    ],
)
def test_ambiguous_and_malformed_stores_refused(bks_fixture, case):
    target, raw, certs, incident = bks_fixture
    one = entry("one", certs[0])
    if case == "duplicate":
        raw = signed(one + entry("one", certs[1]) + b"\0")
    elif case == "empty-alias":
        raw = signed(entry("", certs[0]) + b"\0")
    elif case == "chain":
        raw = signed(entry("one", certs[0], chain=1) + b"\0")
    elif case == "type":
        raw = signed(entry("one", certs[0], cert_type="RAW") + b"\0")
    elif case == "der-tail":
        raw = signed(entry("one", certs[0] + b"hidden") + b"\0")
    elif case == "hidden":
        raw = signed(one + b"\0" + entry("hidden", certs[1]))
    elif case == "missing-end":
        raw = signed(one)
    elif case == "truncated":
        raw = signed(one[:-5] + b"\0")
    elif case == "bad-mac":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    elif case == "bad-version":
        raw = b"\0\0\0\1" + raw[4:]
    elif case == "salt":
        raw = raw[:4] + struct.pack(">I", 0xFFFFFFFF) + raw[8:]
    elif case == "iterations":
        raw = raw[:28] + struct.pack(">I", 0xFFFFFFFF) + raw[32:]
    elif case == "many":
        raw = signed(b"".join(entry(str(i), certs[0]) for i in range(4097)) + b"\0")
    with pytest.raises(ValueError):
        filter_bks(raw, incident, target)


@pytest.mark.parametrize("password", ["", "fïxture-🔒", "a" * 100])
def test_password_encodings_and_unusual_case_sensitive_aliases(bks_fixture, monkeypatch, password):
    target, _, certs, incident = bks_fixture
    monkeypatch.setenv(target.password_env, password)
    alias = "Good\0\nü🔒"
    raw = signed(
        entry("Bad", certs[0]) + entry(alias, certs[1]) + entry("good", certs[1]) + b"\0", password
    )
    _, output, count = filter_bks(raw, incident, target)
    assert count == 3
    assert [r[0] for r in parse_bks(output, password)[2]] == [alias, "good"]


@pytest.mark.parametrize("password", ["", PASSWORD, "fïxture-🔒", "a" * 100])
def test_mac_derivation_matches_independent_openssl(password):
    encoded = password.encode("utf-16-be") + b"\0\0" if password else b""
    result = subprocess.run(
        [
            "openssl",
            "kdf",
            "-keylen",
            "20",
            "-kdfopt",
            "digest:SHA1",
            "-kdfopt",
            "hexpass:" + encoded.hex(),
            "-kdfopt",
            "hexsalt:" + SALT.hex(),
            "-kdfopt",
            "id:3",
            "-kdfopt",
            "iter:1024",
            "PKCS12KDF",
        ],
        capture_output=True,
        check=True,
        timeout=10,
    )
    expected = bytes.fromhex(result.stdout.decode().replace(":", ""))
    assert mac_key(password, SALT, 1024) == expected


def test_empty_password_still_requires_valid_mac(bks_fixture, monkeypatch):
    target, _, certs, incident = bks_fixture
    monkeypatch.setenv(target.password_env, "")
    raw = signed(entry("Good", certs[1]) + b"\0", password="")
    corrupted = raw[:-1] + bytes([raw[-1] ^ 1])
    with pytest.raises(ValueError, match="integrity"):
        filter_bks(corrupted, incident, target)


def test_invalid_unicode_password_has_no_chained_secret_exception(bks_fixture, monkeypatch):
    target, raw, _, incident = bks_fixture
    monkeypatch.setenv(target.password_env, "fixture-secret\udcff-value")
    with pytest.raises(ValueError, match="valid Unicode") as raised:
        filter_bks(raw, incident, target)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True


async def test_service_backup_conflicts_empty_and_password_privacy(
    bks_fixture, tmp_path, monkeypatch
):
    target, raw, certs, incident = bks_fixture
    path = Path(target.path)
    path.write_bytes(raw)
    state = State(tmp_path / "state")
    try:
        app = Service(Inventory(targets=[target]), state, write_enabled=True)
        app.incident = incident
        plan = await app.plan(target.id)
        saved = state.get(plan["plan_id"])
        assert PASSWORD not in str(saved)
        await app.apply(plan["plan_id"])
        assert (await app.scan(target.id))["matches"] == []
        await app.rollback(plan["plan_id"])
        assert path.read_bytes() == raw
        plan = await app.plan(target.id)
        path.write_bytes(signed(entry("Other", certs[1]) + b"\0"))
        with pytest.raises(ValueError, match="changed|conflict"):
            await app.apply(plan["plan_id"])
        path.write_bytes(signed(entry("Bad", certs[0]) + b"\0"))
        with pytest.raises(ValueError, match="Refusing to empty"):
            await app.plan(target.id)
        monkeypatch.setenv(target.password_env, "wrong-secret-do-not-log")
        with pytest.raises(ValueError, match="integrity") as error:
            await app.plan(target.id)
        assert "wrong-secret-do-not-log" not in str(error.value)
        monkeypatch.delenv(target.password_env)
        with pytest.raises(ValueError, match="not set"):
            await app.scan(target.id)
    finally:
        state.close()


def native(*arguments, env):
    if not JAVA or not JAR:
        pytest.skip("Explicit Bouncy Castle provider and JDK unavailable")
    result = subprocess.run(
        [
            str(Path(JAVA).with_name("keytool")),
            "-providerclass",
            "org.bouncycastle.jce.provider.BouncyCastleProvider",
            "-providerpath",
            JAR,
            "-storetype",
            "BKS",
            *arguments,
        ],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result.stdout


def test_native_bouncy_castle_roundtrip_and_key_refusal(bks_fixture, tmp_path):
    target, _, certs, incident = bks_fixture
    path = Path(target.path)
    for alias, der in zip(("Bad", "Good"), certs, strict=True):
        certfile = tmp_path / (alias + ".cer")
        certfile.write_bytes(der)
        native(
            "-importcert",
            "-noprompt",
            "-alias",
            alias,
            "-file",
            str(certfile),
            "-keystore",
            str(path),
            "-storepass:env",
            target.password_env,
            env=os.environ,
        )
    raw = path.read_bytes()
    before = parse_bks(raw, PASSWORD)[2]
    matches, output, count = filter_bks(raw, incident, target)
    assert matches[0]["alias"] == "Bad" and count == 2
    assert parse_bks(output, PASSWORD)[2] == [r for r in before if r[0] == "Good"]
    path.write_bytes(output)
    exported = native(
        "-exportcert",
        "-alias",
        "Good",
        "-keystore",
        str(path),
        "-storepass:env",
        target.password_env,
        env=os.environ,
    )
    assert exported == certs[1]
    native(
        "-genkeypair",
        "-alias",
        "identity",
        "-keyalg",
        "EC",
        "-dname",
        "CN=Fixture",
        "-keystore",
        str(path),
        "-storepass:env",
        target.password_env,
        "-keypass:env",
        target.password_env,
        env=os.environ,
    )
    with pytest.raises(ValueError, match="key entries"):
        filter_bks(path.read_bytes(), incident, target)


@pytest.mark.parametrize("password", ["", "fïxture-🔒", "a" * 100])
def test_native_reads_python_written_password_variants(bks_fixture, monkeypatch, password):
    target, _, certs, incident = bks_fixture
    monkeypatch.setenv(target.password_env, password)
    raw = signed(entry("Bad", certs[0]) + entry("Good", certs[1]) + b"\0", password)
    _, output, _ = filter_bks(raw, incident, target)
    Path(target.path).write_bytes(output)
    assert (
        native(
            "-exportcert",
            "-alias",
            "Good",
            "-keystore",
            target.path,
            "-storepass:env",
            target.password_env,
            env=os.environ,
        )
        == certs[1]
    )
