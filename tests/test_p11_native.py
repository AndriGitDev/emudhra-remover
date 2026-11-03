import os
import shutil
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from emudhra_remover.p11_formats import edk2_records, jks_records, pem_records
from emudhra_remover.p11_native import P11_EXPORTS, p11_generate, p11_output_tree


@pytest.fixture
def runtime():
    trust, module = os.environ.get("EMUDHRA_TEST_TRUST"), os.environ.get("EMUDHRA_TEST_P11_MODULE")
    if not trust or not module:
        pytest.skip("Explicit native p11-kit paths unavailable")
    return trust, module


@pytest.fixture
def source_paths(tmp_path, fixture_bundle):
    local, vendor = tmp_path / "local", tmp_path / "vendor"
    local.mkdir()
    (vendor / "anchors").mkdir(parents=True)
    for name, data in zip(("selected", "survivor"), fixture_bundle[:2], strict=True):
        (vendor / "anchors" / (name + ".pem")).write_bytes(data)
    return local, vendor


def cleanup_exports(path):
    # Native hash directories are read-only; allow temporary fixture cleanup.
    for current, _, _ in os.walk(path):
        Path(current).chmod(0o700)
    shutil.rmtree(path)


def test_complete_native_export_generation(runtime, source_paths, tmp_path, fixture_bundle):
    destination = tmp_path / "generated"
    try:
        p11_generate(*runtime, source_paths, destination)
        files, links = p11_output_tree(destination)
        assert {
            name for name, format, _, _ in P11_EXPORTS if format != "pem-directory-hash"
        } <= files.keys()
        expected = sorted(
            x509.load_pem_x509_certificate(data).public_bytes(Encoding.DER)
            for data in fixture_bundle[:2]
        )
        assert sorted(der for _, der in pem_records(files["pem/tls-ca-bundle.pem"])) == expected
        assert sorted(der for _, der in jks_records(files["java/cacerts"])) == expected
        assert sorted(der for _, der in edk2_records(files["edk2/cacerts.bin"])) == expected
        assert links["pem/directory-hash/ca-certificates.crt"] == "../tls-ca-bundle.pem"
        assert links["pem/directory-hash/ca-bundle.crt"] == "../tls-ca-bundle.pem"
        assert pem_records(files["audit/blocked.pem"]) == []
    finally:
        cleanup_exports(destination)


def test_blocklist_affects_native_tls_java_and_edk2(
    runtime, source_paths, tmp_path, fixture_bundle
):
    local, _ = source_paths
    (local / "blocklist").mkdir()
    (local / "blocklist" / "selected.pem").write_bytes(fixture_bundle[0])
    destination = tmp_path / "generated"
    try:
        p11_generate(*runtime, source_paths, destination)
        files, _ = p11_output_tree(destination)
        expected = [x509.load_pem_x509_certificate(fixture_bundle[1]).public_bytes(Encoding.DER)]
        for name in (
            "pem/tls-ca-bundle.pem",
            "pem/email-ca-bundle.pem",
            "pem/objsign-ca-bundle.pem",
        ):
            assert [der for _, der in pem_records(files[name])] == expected
        assert [der for _, der in jks_records(files["java/cacerts"])] == expected
        assert [der for _, der in edk2_records(files["edk2/cacerts.bin"])] == expected
        assert len(pem_records(files["audit/blocked.pem"])) == 1
    finally:
        cleanup_exports(destination)


def test_generation_never_overwrites_existing_directory(runtime, source_paths, tmp_path):
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "untouched"
    sentinel.write_bytes(b"existing data")
    with pytest.raises(FileExistsError):
        p11_generate(*runtime, source_paths, destination)
    assert sentinel.read_bytes() == b"existing data"


def test_export_reader_rejects_escaping_links(tmp_path):
    (tmp_path / "malicious.pem").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="Unsafe"):
        p11_output_tree(tmp_path)


def test_native_paths_reject_module_config_injection(runtime, source_paths, tmp_path):
    with pytest.raises(ValueError, match="special characters"):
        p11_generate(
            runtime[0], runtime[1] + "\nremote: |unexpected", source_paths, tmp_path / "output"
        )


def test_owned_top_level_policy_handles_anchor_collision(
    runtime, source_paths, tmp_path, fixture_bundle
):
    import subprocess

    _, vendor = source_paths
    policy = vendor / "emudhra-remover.p11-kit"
    policy.write_bytes(
        b"[p11-kit-object-v1]\nclass: certificate\ncertificate-type: x-509\n"
        b"trusted: false\nx-distrusted: true\n" + fixture_bundle[0]
    )
    original_sources = {p.name: p.read_bytes() for p in (vendor / "anchors").iterdir()}
    destination = tmp_path / "generated"
    try:
        p11_generate(*runtime, source_paths, destination)
        files, _ = p11_output_tree(destination)
        assert len(pem_records(files["pem/tls-ca-bundle.pem"])) == 1
        assert len(pem_records(files["audit/blocked.pem"])) == 1
        selected = subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CApath",
                "-no-CAstore",
                "-purpose",
                "sslserver",
                "-CAfile",
                str(destination / "openssl/ca-bundle.trust.crt"),
                str(vendor / "anchors/selected.pem"),
            ],
            capture_output=True,
            timeout=10,
        )
        assert selected.returncode != 0 and b"certificate rejected" in selected.stderr
        subprocess.run(
            [
                "openssl",
                "verify",
                "-no-CApath",
                "-no-CAstore",
                "-purpose",
                "sslserver",
                "-CAfile",
                str(destination / "openssl/ca-bundle.trust.crt"),
                str(vendor / "anchors/survivor.pem"),
            ],
            capture_output=True,
            timeout=10,
            check=True,
        )
        assert {p.name: p.read_bytes() for p in (vendor / "anchors").iterdir()} == original_sources
    finally:
        cleanup_exports(destination)
