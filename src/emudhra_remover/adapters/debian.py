"""Persistent package-certificate deselection; local anchors are audit-only."""

import base64
import json

from ..certificates import filter_bundle


def filter_debian(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    snapshot = json.loads(data)
    config = base64.b64decode(snapshot["config"], validate=True).decode("utf-8")
    matches, lines, count = [], [], 0
    for line in config.splitlines(keepends=True):
        name = line.rstrip("\r\n")
        if not name or name.startswith(("#", "!")):
            lines.append(line)
            continue
        raw = base64.b64decode(snapshot["sources"][name], validate=True)
        found, _, certificates = filter_bundle(raw, incident)
        if certificates != 1:
            raise ValueError("Debian requires one certificate per source file")
        matches.extend({**entry, "source": name, "removable": True} for entry in found)
        count += certificates
        lines.append("!" + line if found else line)
    for name, value in snapshot["local"].items():
        found, _, certificates = filter_bundle(base64.b64decode(value, validate=True), incident)
        if certificates != 1:
            raise ValueError("Debian requires one certificate per local anchor file")
        matches.extend(
            {
                **entry,
                "source": name,
                "removable": False,
                "reason": "Local anchors require separate administrator removal",
            }
            for entry in found
        )
        count += certificates
    snapshot["config"] = base64.b64encode("".join(lines).encode()).decode()
    return matches, json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode(), count
