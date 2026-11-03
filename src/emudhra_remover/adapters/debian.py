"""Persistent package-certificate deselection; local anchors are audit-only."""

import base64
import json

from ..certificates import filter_bundle


def filter_debian(data: bytes, incident: dict) -> tuple[list[dict], bytes, int]:
    snapshot = json.loads(data)
    config = base64.b64decode(snapshot["config"], validate=True).decode("utf-8")
    matches, lines, count = [], [], 0
    if any(char != "\n" and not " " <= char <= "~" for char in config):
        raise ValueError("Debian configuration must use ASCII text and LF line endings")
    for name in config.split("\n"):
        line = name + "\n"
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
    rewritten = "".join(lines)[:-1]
    snapshot["config"] = base64.b64encode(rewritten.encode()).decode()
    return matches, json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode(), count
