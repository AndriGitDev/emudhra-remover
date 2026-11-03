import base64
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from emudhra_remover.adapters.openssl import (
    ANY_PURPOSE,
    OBJECT,
    CertificateAux,
    decode_object,
    filter_openssl,
)


def native(*args, input=None):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL native utility unavailable")
    return subprocess.run(
        ["openssl", *args], input=input, capture_output=True, timeout=10, check=True
    ).stdout


def trusted(cert, *args):
    return native("x509", "-trustout", *args, input=cert)


def armored(raw, label=b"TRUSTED CERTIFICATE"):
    return (
        b"-----BEGIN "
        + label
        + b"-----\n"
        + base64.b64encode(raw)
        + b"\n-----END "
        + label
        + b"-----\n"
    )


def der(cert):
    return x509.load_pem_x509_certificate(cert).public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize("ordinary", [False, True])
async def test_native_trust_flags_workflow_and_exact_rollback(service, fixture_bundle, ordinary):
    app, path, _ = service
    bad, good, policy = fixture_bundle
    selected = bad if ordinary else trusted(bad, "-addtrust", "serverAuth", "-setalias", "incident")
    survivor = trusted(
        good, "-addtrust", "serverAuth", "-addreject", "emailProtection", "-setalias", "survivor"
    )
    original = b"# kept header\n" + selected + b"# survivor comment\n" + survivor
    path.write_bytes(original)
    app.inventory.targets[0].adapter = "openssl-trusted-bundle"
    plan = await app.plan("test")
    assert plan["matches"][0]["action"] == "set-anyExtendedKeyUsage-rejection"
    await app.apply(plan["plan_id"])
    after = path.read_bytes()
    assert b"# survivor comment\n" + survivor in after
    assert filter_openssl(after, policy) == ([], after, 2)
    bad_file, good_file = path.parent / "bad.crt", path.parent / "good.crt"
    bad_file.write_bytes(bad)
    good_file.write_bytes(good)
    for purpose in ("sslserver", "sslclient", "smimesign", "any"):
        result = subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CApath",
                "-no-CAstore",
                "-CAfile",
                str(path),
                "-purpose",
                purpose,
                str(bad_file),
            ],
            capture_output=True,
            timeout=10,
        )
        assert result.returncode != 0
        assert b"certificate rejected" in result.stderr
    native(
        "verify",
        "-no-CApath",
        "-no-CAstore",
        "-CAfile",
        str(path),
        "-purpose",
        "sslserver",
        str(good_file),
    )
    rejected_survivor = subprocess.run(
        [
            "openssl",
            "verify",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            str(path),
            "-purpose",
            "smimesign",
            str(good_file),
        ],
        capture_output=True,
        timeout=10,
    )
    assert rejected_survivor.returncode != 0
    assert b"certificate rejected" in rejected_survivor.stderr
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == original


def test_existing_universal_distrust_is_preserved(fixture_bundle):
    bad, good, policy = fixture_bundle
    original = trusted(bad, "-addreject", "anyExtendedKeyUsage") + good
    assert filter_openssl(original, policy) == ([], original, 2)


def test_aux_alias_keyid_and_other_fields_preserved(fixture_bundle):
    bad, good, policy = fixture_bundle
    aux = CertificateAux(
        {
            "trust": ["1.3.6.1.5.5.7.3.1"],
            "reject": ["1.3.6.1.5.5.7.3.4"],
            "alias": "Operator 名称",
            "keyid": b"\x00\xffidentifier",
            "other": [{"algorithm": "1.2.3.4"}],
        }
    )
    _, output, _ = filter_openssl(armored(der(bad) + aux.dump()) + good, policy)
    _, preserved_der, actual = decode_object(next(OBJECT.finditer(output)))
    assert preserved_der == der(bad)
    assert actual["trust"].native is None
    assert actual["reject"].native == ["1.3.6.1.5.5.7.3.4", ANY_PURPOSE]
    for field in ("alias", "keyid", "other"):
        assert actual[field].dump() == aux[field].dump()


@pytest.mark.parametrize(
    "suffix", [b"garbage", b"\x30\x03\x02\x01\x01", b"\x30\x00\x30\x00", b"\x30\x80\x00\x00"]
)
def test_malformed_or_trailing_aux_fails_closed(fixture_bundle, suffix):
    bad, good, policy = fixture_bundle
    with pytest.raises(ValueError, match="Malformed"):
        filter_openssl(good + armored(der(bad) + suffix), policy)


def test_aux_under_ordinary_label_is_rejected(fixture_bundle):
    bad, good, policy = fixture_bundle
    with pytest.raises(ValueError, match="Malformed"):
        filter_openssl(armored(der(bad) + b"\x30\x00", b"CERTIFICATE") + good, policy)


@pytest.mark.parametrize(
    "extra",
    [
        b"-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----",
        b"-----BEGIN CERTIFICATE-----\nbroken",
    ],
)
def test_other_objects_or_broken_delimiters_rejected(fixture_bundle, extra):
    with pytest.raises(ValueError, match="certificate-only"):
        filter_openssl(fixture_bundle[0] + extra, fixture_bundle[2])


async def test_external_trust_flag_edit_blocks_apply(service, fixture_bundle):
    app, path, _ = service
    bad, good, _ = fixture_bundle
    path.write_bytes(bad + trusted(good, "-addtrust", "serverAuth"))
    app.inventory.targets[0].adapter = "openssl-trusted-bundle"
    plan = await app.plan("test")
    changed = bad + trusted(good, "-addtrust", "emailProtection")
    path.write_bytes(changed)
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])
    assert path.read_bytes() == changed
    assert app.state.get(plan["plan_id"])["status"] == "apply-failed"


@pytest.mark.parametrize("selected_index", [0, 1])
@pytest.mark.parametrize("purpose", ["ocsphelper", "crlsign"])
def test_native_ocsp_crl_compatibility_purposes_are_documented_exceptions(
    certificate_chain, selected_index, purpose, tmp_path
):
    from cryptography.hazmat.primitives import hashes

    root, intermediate, leaf = certificate_chain
    fingerprint = (
        x509.load_pem_x509_certificate(certificate_chain[selected_index])
        .fingerprint(hashes.SHA256())
        .hex()
    )
    policy = {"certificates": [{"sha256": fingerprint}]}
    matches, after, _ = filter_openssl(root + intermediate, policy)
    assert len(matches) == 1
    bundle, server_chain, end_entity = [
        tmp_path / name for name in ("bundle.pem", "inter.pem", "leaf.pem")
    ]
    bundle.write_bytes(after)
    server_chain.write_bytes(intermediate)
    end_entity.write_bytes(leaf)
    output = native(
        "verify",
        "-no-CApath",
        "-no-CAstore",
        "-purpose",
        purpose,
        "-CAfile",
        str(bundle),
        "-untrusted",
        str(server_chain),
        str(end_entity),
    )
    assert b": OK" in output
