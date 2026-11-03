import base64
import copy
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.adapters.windows import filter_windows
from emudhra_remover.windows_policy import (
    decode,
    encode,
    fingerprint,
    is_intermediate,
    validate_transition,
)


def snapshot_for(bundle):
    source = {}
    for pem in bundle:
        der = x509.load_pem_x509_certificate(pem).public_bytes(Encoding.DER)
        # Opaque serialization is validated by native CryptoAPI tests on Windows.
        encoded = base64.b64encode(der).decode()
        source[fingerprint(der)] = {"der": encoded, "serialized": encoded, "plain": encoded}
    return {"source": source, "denied": {}}


def test_distrust_retains_sources_and_existing_denials(fixture_bundle):
    before = snapshot_for(fixture_bundle[:2])
    selected, survivor = list(before["source"])
    before["denied"][survivor] = before["source"][survivor]
    matches, after, count = filter_windows(encode(before), fixture_bundle[2])
    assert count == 2 and len(matches) == 1
    after = decode(after)
    assert after["source"] == before["source"]
    assert after["denied"] == before["source"]
    assert filter_windows(encode(after), fixture_bundle[2])[0] == []
    validate_transition(after, before)  # exact reversal is allowed
    assert selected in after["source"]


def test_partial_recovery_rejects_unknown_denials_and_property_edits(fixture_bundle):
    before = snapshot_for(fixture_bundle[:2])
    after = copy.deepcopy(before)
    after["denied"] = copy.deepcopy(after["source"])
    current = copy.deepcopy(before)
    selected = next(iter(after["denied"]))
    current["denied"][selected] = after["denied"][selected]
    assert is_intermediate(current, before, after)
    modified = copy.deepcopy(current)
    modified["denied"][selected]["serialized"] = "ZXh0ZXJuYWw="
    assert not is_intermediate(modified, before, after)
    modified = copy.deepcopy(current)
    modified["source"].pop(selected)
    assert not is_intermediate(modified, before, after)


def test_cannot_change_existing_denial_properties(fixture_bundle):
    before = snapshot_for(fixture_bundle[:2])
    key = next(iter(before["source"]))
    before["denied"][key] = dict(before["source"][key])
    after = copy.deepcopy(before)
    after["denied"][key]["serialized"] = "ZXh0ZXJuYWw="
    with pytest.raises(ValueError, match="Existing Windows distrust"):
        validate_transition(before, after)


def test_invalid_windows_snapshot_fingerprint_and_encoding(fixture_bundle):
    before = snapshot_for(fixture_bundle[:2])
    with pytest.raises(ValueError, match="canonical"):
        decode(json.dumps(before, indent=2).encode())
    key = next(iter(before["source"]))
    before["source"]["0" * 64] = before["source"].pop(key)
    with pytest.raises(ValueError, match="fingerprint mismatch"):
        decode(encode(before))
