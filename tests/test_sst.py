import hashlib
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.adapters.sst import END, HEADER, filter_sst, read_sst
from emudhra_remover.config import Target


def block(identifier, value, encoding=1):
    return struct.pack("<III", identifier, encoding, len(value)) + value


@pytest.fixture
def groups(fixture_bundle):
    result = []
    for pem in fixture_bundle[:2]:
        der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
        # Deliberately non-sorted order: survivor properties must remain byte exact.
        group = block(13, "Description ü\0".encode("utf-16-le"))
        group += block(3, hashlib.sha1(der).digest())
        group += block(11, "Friendly\0".encode("utf-16-le"))
        group += block(107, hashlib.sha256(der).digest())
        group += block(4, hashlib.md5(der).digest())
        group += block(129, hashlib.sha1(der).digest() + hashlib.sha256(der).digest())
        result.append(group + block(32, der))
    return result


def test_exact_sst_group_removal_and_survivor_bytes(groups, fixture_bundle):
    original = HEADER + b"".join(groups) + END
    matches, output, count = filter_sst(original, fixture_bundle[2])
    assert count == 2 and len(matches) == 1
    assert output == HEADER + groups[1] + END
    assert filter_sst(output, fixture_bundle[2]) == ([], output, 1)


async def test_sst_file_apply_rollback_and_conflict(service, groups):
    app, path, _ = service
    app.inventory.targets[0].adapter = "windows-sst"
    app.inventory.targets[0].sst_trust_anchors = True
    original = HEADER + b"".join(groups) + END
    path.write_bytes(original)
    plan = await app.plan("test")
    await app.apply(plan["plan_id"])
    assert path.read_bytes() == HEADER + groups[1] + END
    await app.rollback(plan["plan_id"])
    assert path.read_bytes() == original
    plan = await app.plan("test")
    path.write_bytes(HEADER + groups[1] + groups[0] + END)
    with pytest.raises(ValueError, match="changed since planning"):
        await app.apply(plan["plan_id"])


async def test_sst_all_matching_plan_refused(service, groups):
    app, path, _ = service
    app.inventory.targets[0].adapter = "windows-sst"
    app.inventory.targets[0].sst_trust_anchors = True
    path.write_bytes(HEADER + groups[0] + END)
    assert len((await app.scan("test"))["matches"]) == 1
    with pytest.raises(ValueError, match="empty"):
        await app.plan("test")


@pytest.mark.parametrize("identifier", [1, 2, 5, 9, 19, 33, 34, 104, 117, 122, 128, 65535])
def test_identity_archive_policy_crl_ctl_and_unknown_properties_refused(groups, identifier):
    with pytest.raises(ValueError, match="unsupported"):
        read_sst(HEADER + block(identifier, b"fixture") + groups[0] + END)


@pytest.mark.parametrize(
    "malformation",
    [
        "header",
        "missing-end",
        "trailing",
        "orphan",
        "duplicate-cert",
        "duplicate-property",
        "encoding",
        "size",
        "der-trailing",
        "hash",
        "text",
        "surrogate",
    ],
)
def test_malformed_sst_fails_closed(groups, malformation, fixture_bundle):
    raw = HEADER + groups[0] + END
    if malformation == "header":
        raw = b"\1" + raw[1:]
    elif malformation == "missing-end":
        raw = raw[:-12]
    elif malformation == "trailing":
        raw += b"hidden"
    elif malformation == "orphan":
        raw = raw[:-12] + block(11, b"\0\0") + END
    elif malformation == "duplicate-cert":
        raw = HEADER + groups[0] * 2 + END
    elif malformation == "duplicate-property":
        raw = HEADER + block(11, b"\0\0") + groups[0] + END
    elif malformation == "encoding":
        raw = raw[:12] + struct.pack("<I", 0) + raw[16:]
    elif malformation == "size":
        raw = raw[:16] + struct.pack("<I", 0xFFFFFFFF) + raw[20:]
    else:
        der = x509.load_pem_x509_certificate(fixture_bundle[0]).public_bytes(Encoding.DER)
        prefix = b""
        if malformation == "der-trailing":
            der += b"junk"
        elif malformation == "hash":
            prefix = block(3, bytes(20))
        elif malformation == "text":
            prefix = block(11, "unterminated".encode("utf-16-le"))
        elif malformation == "surrogate":
            prefix = block(11, b"\0\xd8\0\0")
        raw = HEADER + prefix + block(32, der) + END
    with pytest.raises(ValueError):
        read_sst(raw)


def test_sst_positive_anchor_role_requires_operator_assertion(tmp_path):
    arguments = dict(
        id="sst", adapter="windows-sst", path=str(tmp_path / "roots.sst"), transport="local"
    )
    with pytest.raises(ValueError, match="sst_trust_anchors"):
        Target(**arguments)
    assert Target(**arguments, sst_trust_anchors=True).sst_trust_anchors
    with pytest.raises(ValueError, match="only supported"):
        Target(**{**arguments, "adapter": "pem-bundle"}, sst_trust_anchors=True)
