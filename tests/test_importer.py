import hashlib
import importlib.util
from pathlib import Path

import pytest


def importer():
    spec = importlib.util.spec_from_file_location(
        "incident_importer", Path(__file__).parents[1] / "tools/import_incident.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_source():
    lines = ["## Revoked intermediate CA certificates"]
    lines.extend(f"| intermediate | issuer | {number:064x} | revoked |" for number in range(16))
    lines.append("## Certificates removed from the Windows and Microsoft Edge trust lists")
    lines.extend(f"| root | {number:064x} | removed |" for number in range(16, 23))
    lines.append("# August 27, 2026")
    return "\n".join(lines).encode()


def test_importer_verifies_content_and_certificate_kinds(monkeypatch):
    module = importer()
    source = fixture_source()
    with pytest.raises(ValueError, match="exact pinned"):
        module.parse_source(source)
    monkeypatch.setattr(module, "SOURCE_SHA256", hashlib.sha256(source).hexdigest())
    result = module.parse_source(source)
    assert len(result["certificates"]) == 23
    assert sum(e["kind"] == "trust-anchor" for e in result["certificates"]) == 7
    changed = source.replace(b"## Certificates removed", b"## Different heading")
    monkeypatch.setattr(module, "SOURCE_SHA256", hashlib.sha256(changed).hexdigest())
    with pytest.raises(ValueError, match="structure changed"):
        module.parse_source(changed)
