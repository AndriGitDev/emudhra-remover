"""Independent wire fixtures exercise content that native Java can silently hide."""

import hashlib
import os
import shutil
import struct
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.adapters.java import filter_java
from emudhra_remover.adapters.jks import MAGIC, modified_utf8, read_certificates
from emudhra_remover.config import Target

PASSWORD = "fixture-password"
JAVA = os.environ.get("EMUDHRA_JAVA", shutil.which("java") or "")


def utf(text):
    encoded = bytearray()
    raw = text.encode("utf-16-be")
    for i in range(0, len(raw), 2):
        char = int.from_bytes(raw[i : i + 2], "big")
        if 1 <= char <= 127:
            encoded.append(char)
        elif char <= 2047:
            encoded.extend((0xC0 | (char >> 6), 0x80 | (char & 63)))
        else:
            encoded.extend((0xE0 | (char >> 12), 0x80 | ((char >> 6) & 63), 0x80 | (char & 63)))
    return struct.pack(">H", len(encoded)) + encoded


def signed(body, password=PASSWORD):
    return body + hashlib.sha1(password.encode("utf-16-be") + b"Mighty Aphrodite" + body).digest()


def collection(adapter, entries, version=2, password=PASSWORD):
    body = struct.pack(">III", MAGIC[adapter], version, len(entries))
    for alias, der in entries:
        body += struct.pack(">I", 2) + utf(alias) + struct.pack(">q", 1700000000123)
        if version == 2:
            body += utf("X.509")
        body += struct.pack(">I", len(der)) + der
    return signed(body, password)


@pytest.fixture
def certificates(fixture_bundle):
    return tuple(
        x509.load_pem_x509_certificate(raw).public_bytes(Encoding.DER) for raw in fixture_bundle[:2]
    )


def test_invalid_unicode_password_has_no_chained_secret_exception(target, monkeypatch):
    monkeypatch.setenv(target.password_env, "fixture-secret\udcff-value")
    with pytest.raises(ValueError, match="valid Unicode") as raised:
        filter_java(b"not-loaded", {"certificates": []}, target)
    assert raised.value.__cause__ is None
    assert raised.value.__suppress_context__ is True


@pytest.fixture(params=["java-jks", "java-jceks"])
def target(request, tmp_path, monkeypatch):
    monkeypatch.setenv("JKS_FIXTURE_PASSWORD", PASSWORD)
    if JAVA:
        monkeypatch.setenv("EMUDHRA_JAVA", JAVA)
    return Target(
        id="fixture",
        adapter=request.param,
        transport="local",
        path=str(tmp_path / "fixture.store"),
        password_env="JKS_FIXTURE_PASSWORD",
    )


@pytest.mark.parametrize("version", [1, 2])
def test_native_java_reads_versions_and_preserves_unicode_timestamp(
    target, certificates, fixture_bundle, version
):
    if not JAVA:
        pytest.skip("JDK unavailable")
    alias = "ca\x00\nü\U0001f512"
    original = collection(
        target.adapter, [("bad", certificates[0]), (alias, certificates[1])], version
    )
    matches, output, count = filter_java(original, fixture_bundle[2], target)
    assert count == 2 and matches[0]["alias"] == "bad"
    before = read_certificates(original, PASSWORD, target.adapter)
    assert read_certificates(output, PASSWORD, target.adapter) == {alias: before[alias]}
    assert filter_java(output, fixture_bundle[2], target) == ([], output, 1)


@pytest.mark.parametrize("aliases", [("a", "a"), ("a", "A")])
def test_duplicate_hidden_certificate_refused_before_java(
    target, certificates, monkeypatch, aliases
):
    raw = collection(target.adapter, list(zip(aliases, certificates, strict=True)))

    def unexpected(*args, **kwargs):
        pytest.fail("Ambiguous input reached native Java")

    monkeypatch.setattr("emudhra_remover.adapters.java.subprocess.run", unexpected)
    with pytest.raises(ValueError, match="duplicate|case-colliding"):
        filter_java(raw, {"certificates": []}, target)


@pytest.mark.parametrize("tag", [1, 3, 0, 0xFFFFFFFF])
def test_key_or_unknown_tag_rejected_before_deserialization(target, monkeypatch, tag):
    # No need to construct a serialized key: the tag itself must stop execution.
    body = struct.pack(">IIII", MAGIC[target.adapter], 2, 1, tag) + b"\xac\xed\x00\x05"

    def unexpected(*args, **kwargs):
        pytest.fail("Forbidden entry reached native Java")

    monkeypatch.setattr("emudhra_remover.adapters.java.subprocess.run", unexpected)
    with pytest.raises(ValueError, match="private or secret"):
        filter_java(signed(body), {"certificates": []}, target)


def test_trailing_hidden_content_and_bad_checksum(target, certificates):
    original = collection(target.adapter, [("a", certificates[0])])
    with pytest.raises(ValueError, match="Trailing or hidden"):
        read_certificates(signed(original[:-20] + b"hidden"), PASSWORD, target.adapter)
    with pytest.raises(ValueError, match="integrity"):
        read_certificates(original[:-1] + bytes([original[-1] ^ 1]), PASSWORD, target.adapter)
    with pytest.raises(ValueError, match="integrity"):
        read_certificates(original, "wrong-private-password", target.adapter)


def test_bounded_count_length_and_exact_magic(target, certificates):
    other = "java-jks" if target.adapter == "java-jceks" else "java-jceks"
    raw = collection(other, [("a", certificates[0])])
    with pytest.raises(ValueError, match="check format"):
        read_certificates(raw, PASSWORD, target.adapter)
    with pytest.raises(ValueError, match="too many"):
        read_certificates(
            signed(struct.pack(">III", MAGIC[target.adapter], 2, 0xFFFFFFFF)),
            PASSWORD,
            target.adapter,
        )
    truncated = collection(target.adapter, [("a", certificates[0])])[:-21]
    with pytest.raises(ValueError, match="Truncated"):
        read_certificates(signed(truncated), PASSWORD, target.adapter)


def test_concatenated_der_is_not_silently_truncated(target, certificates):
    raw = collection(target.adapter, [("a", b"".join(certificates))])
    with pytest.raises(ValueError):
        read_certificates(raw, PASSWORD, target.adapter)


@pytest.mark.parametrize(
    "data",
    [
        b"\x00",
        b"\xc1\x81",
        b"\xe0\x81\x81",
        b"\xc2",
        b"\xc2a",
        b"\xf0\x90\x80\x80",
        b"\xed\xa0\x80",
        b"\xed\xb0\x80",
    ],
)
def test_noncanonical_modified_utf8_refused(data):
    with pytest.raises(ValueError):
        modified_utf8(data)


@pytest.mark.parametrize("minimal_locale", [False, True])
def test_native_non_ascii_password_and_no_password_in_exception(
    target, certificates, fixture_bundle, monkeypatch, minimal_locale
):
    if not JAVA:
        pytest.skip("JDK unavailable")
    secret = "fïxture-\U0001f512-password"
    monkeypatch.setenv(target.password_env, secret)
    if minimal_locale:
        for key in ("LANG", "LC_ALL", "LC_CTYPE"):
            monkeypatch.delenv(key, raising=False)
    original = collection(
        target.adapter, [("bad", certificates[0]), ("good", certificates[1])], password=secret
    )
    matches, output, _ = filter_java(original, fixture_bundle[2], target)
    assert matches and list(read_certificates(output, secret, target.adapter)) == ["good"]
    with pytest.raises(ValueError) as error:
        filter_java(original[:-1], fixture_bundle[2], target)
    assert secret not in str(error.value)


def test_uppercase_alias_has_explicit_preflight_error(target, certificates, monkeypatch):
    raw = collection(target.adapter, [("Capitalized", certificates[0])])

    def unexpected(*args, **kwargs):
        pytest.fail("Unsupported alias reached native Java")

    monkeypatch.setattr("emudhra_remover.adapters.java.subprocess.run", unexpected)
    with pytest.raises(ValueError, match="Non-lowercase"):
        filter_java(raw, {"certificates": []}, target)


def test_native_java_hides_duplicate_alias_but_preflight_refuses_it(target, certificates):
    if not JAVA:
        pytest.skip("JDK unavailable")
    raw = collection(target.adapter, [("same", certificates[0]), ("same", certificates[1])])
    Path(target.path).write_bytes(raw)
    result = subprocess.run(
        [
            str(Path(JAVA).with_name("keytool")),
            "-exportcert",
            "-alias",
            "same",
            "-keystore",
            target.path,
            "-storetype",
            target.adapter.removeprefix("java-").upper(),
            "-storepass:env",
            target.password_env,
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    # The first certificate has disappeared from the native view despite a valid MAC.
    assert result.stdout == certificates[1]
    with pytest.raises(ValueError, match="duplicate"):
        filter_java(raw, {"certificates": []}, target)
