"""Offline importer for the pinned Microsoft announcement; review output before committing.

Usage: uv run python tools/import_incident.py /path/to/Announcements.md
No network feeds are executed or automatically trusted by the server.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

REVISION = "0fc6bfef5a36c073db756748e945b334bc87ba1f"
SOURCE_SHA256 = "da56e3945569350299f71bb7e780098c024038b7594095afb7d22a98685a65d6"
SOURCE = (
    f"https://github.com/TrustedRootProgram/Program-Requirements/blob/{REVISION}/Announcements.md"
)


def parse_source(data: bytes):
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise ValueError("Input is not the exact pinned announcement revision")
    text = data.decode()
    text = text.split("## Revoked intermediate CA certificates", 1)[1]
    text = text.split("# August 27, 2026", 1)[0]
    entries = []
    kind = "intermediate"
    for line in text.splitlines():
        if "## Certificates removed" in line:
            kind = "trust-anchor"
        columns = [c.strip().strip("`") for c in line.strip("| ").split("|")]
        hashes = [c for c in columns if re.fullmatch(r"[A-Fa-f0-9]{64}", c)]
        if hashes:
            entries.append({"name": columns[0], "sha256": hashes[0].lower(), "kind": kind})
    if (
        len(entries) != 23
        or len({e["sha256"] for e in entries}) != 23
        or sum(e["kind"] == "intermediate" for e in entries) != 16
        or sum(e["kind"] == "trust-anchor" for e in entries) != 7
    ):
        raise ValueError("Source structure changed: expected 16 intermediates and 7 trust anchors")
    return {
        "id": "microsoft-emudhra-2026-10-26",
        "reviewed_on": "2026-11-03",
        "source": SOURCE,
        "scope": "Known certificate fingerprints; not a general SPKI denylist or revocation engine",
        "certificates": entries,
    }


def main():
    output = parse_source(Path(sys.argv[1]).read_bytes())
    destination = Path(__file__).resolve().parents[1] / "src/emudhra_remover/incident.json"
    destination.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
