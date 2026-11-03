"""Native research checks: these do not advertise a Fedora adapter."""

import importlib.util
import os
from pathlib import Path

import pytest


@pytest.mark.parametrize("same_source", [False, True])
def test_native_p11_source_precedence_probe(same_source):
    trust, module = os.environ.get("EMUDHRA_TEST_TRUST"), os.environ.get("EMUDHRA_TEST_P11_MODULE")
    if not trust or not module:
        pytest.skip("Set explicit native trust/module paths to run the isolated p11-kit probe")
    spec = importlib.util.spec_from_file_location(
        "p11_probe", Path(__file__).parents[1] / "tools/probe_p11.py"
    )
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)
    result = probe.probe(trust, module, same_source=same_source)
    assert result["deny_source"] == ("same-source" if same_source else "higher-priority-source")
    supported = [
        policy
        for policy in result["directory_policies"].values()
        if policy["tls_excludes_selected"]
    ]
    assert supported, "Neither native distrust directory is honored"
    assert all(p["tls_preserves_survivor"] for p in result["directory_policies"].values())
    for policy in supported:
        assert policy["openssl_rejects_selected"]["trust-policy"]["sslserver"]
    # Do not require --filter=certificates to retain rejection flags: the probe
    # intentionally records version/layout differences rather than hiding them.
