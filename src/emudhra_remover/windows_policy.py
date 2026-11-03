"""Canonical Windows certificate snapshots and bounded, exact-entry recovery."""

import base64
import hashlib
import json

LIMIT = 16 * 1024 * 1024


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def unbase(value):
    return base64.b64decode(value, validate=True)


def fingerprint(value):
    return hashlib.sha256(value).hexdigest()


def decode(data):
    if len(data) > LIMIT:
        raise ValueError("Windows snapshot exceeds size limit")
    value = json.loads(data)
    if set(value) != {"identity", "source", "denied"}:
        raise ValueError("Invalid Windows snapshot fields")
    if not isinstance(value["identity"], str) or not 1 <= len(value["identity"]) <= 512:
        raise ValueError("Invalid Windows store identity")
    for group in (value["source"], value["denied"]):
        if not isinstance(group, dict) or len(group) > 4096:
            raise ValueError("Invalid Windows certificate collection")
        for key, record in group.items():
            if set(record) != {"der", "serialized", "plain"}:
                raise ValueError("Invalid Windows certificate record")
            der, serialized, plain = (
                unbase(record[name]) for name in ("der", "serialized", "plain")
            )
            if not der or not serialized or not plain or fingerprint(der) != key:
                raise ValueError("Windows certificate fingerprint mismatch")
    if encode(value) != data:
        raise ValueError("Windows snapshot must use canonical encoding")
    return value


def is_intermediate(current, before, after):
    """Only independently completed exact denial-entry additions/removals qualify."""
    if current["identity"] != before["identity"] or current["identity"] != after["identity"]:
        return False
    if current["source"] != before["source"] or current["source"] != after["source"]:
        return False
    keys = current["denied"].keys() | before["denied"].keys() | after["denied"].keys()
    return all(
        current["denied"].get(k) in (before["denied"].get(k), after["denied"].get(k)) for k in keys
    )


def validate_transition(before, after):
    if before["identity"] != after["identity"]:
        raise ValueError("Windows security principal or store identity changed")
    if before["source"] != after["source"]:
        raise ValueError("Windows source store cannot be changed")
    old, new = before["denied"], after["denied"]
    common = old.keys() & new.keys()
    if any(old[k] != new[k] for k in common):
        raise ValueError("Existing Windows distrust properties cannot be changed")
    added, removed = new.keys() - old.keys(), old.keys() - new.keys()
    if added and removed:
        raise ValueError("Mixed Windows denial additions/removals are unsupported")
    for key in added | removed:
        source = before["source"].get(key)
        record = (new if key in added else old)[key]
        if source is None or record != {**source, "serialized": source["plain"]}:
            raise ValueError("Windows transition must use an exact plain source certificate")
