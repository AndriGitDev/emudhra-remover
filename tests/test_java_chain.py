"""Native PKIX validation with explicit synthetic stores, never system roots."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
from conftest import certificate_chain
from cryptography import x509
from cryptography.hazmat.primitives import hashes

from emudhra_remover.config import Inventory, Target
from emudhra_remover.service import Service
from emudhra_remover.state import State

JAVA = os.environ.get("EMUDHRA_JAVA", shutil.which("java") or "")
JAR = os.environ.get("EMUDHRA_TEST_BC_JAR", "")
PASSWORD = "native-chain-fixture"

VERIFIER = """
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
public class VerifyTrust {
    public static void main(String[] args) throws Exception {
        Security.setProperty("keystore.type.compat", "false");
        KeyStore store;
        if (args[0].equals("BKS")) {
            Provider provider = (Provider) Class.forName(
                "org.bouncycastle.jce.provider.BouncyCastleProvider"
            ).getConstructor().newInstance();
            store = KeyStore.getInstance("BKS", provider);
        } else {
            store = KeyStore.getInstance(args[0]);
        }
        char[] password = new String(
            System.in.readAllBytes(), StandardCharsets.UTF_8
        ).toCharArray();
        try (InputStream input = Files.newInputStream(Path.of(args[1]))) {
            store.load(input, password);
        }
        Arrays.fill(password, '\\0');
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        CertPath path;
        try (InputStream input = Files.newInputStream(Path.of(args[2]))) {
            path = factory.generateCertPath(new ArrayList<>(factory.generateCertificates(input)));
        }
        PKIXParameters parameters = new PKIXParameters(store);
        parameters.setRevocationEnabled(false);
        try {
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
            System.out.println("VALID");
        } catch (CertPathValidatorException rejected) {
            System.out.println("REJECTED");
            System.exit(2);
        }
    }
}
"""


@pytest.fixture(scope="module")
def verifier(tmp_path_factory):
    if not JAVA or not Path(JAVA).with_name("javac").is_file():
        pytest.skip("JDK compiler unavailable")
    directory = tmp_path_factory.mktemp("native-java-chain")
    source = directory / "VerifyTrust.java"
    source.write_text(VERIFIER)
    subprocess.run(
        [str(Path(JAVA).with_name("javac")), "-d", str(directory), str(source)],
        capture_output=True,
        check=True,
        timeout=30,
    )
    return directory


@pytest.mark.parametrize("kind", ["JKS", "JCEKS", "PKCS12", "BKS"])
async def test_native_pkix_rejects_removed_root_and_preserves_other_chain(
    kind, verifier, tmp_path, monkeypatch
):
    if kind == "BKS" and not JAR:
        pytest.skip("Explicit Bouncy Castle provider unavailable")
    monkeypatch.setenv("CHAIN_FIXTURE_PASSWORD", PASSWORD)
    monkeypatch.setenv("EMUDHRA_JAVA", JAVA)
    chains = [certificate_chain.__wrapped__(), certificate_chain.__wrapped__()]
    store, paths = tmp_path / "trust.store", []
    provider = (
        [
            "-providerclass",
            "org.bouncycastle.jce.provider.BouncyCastleProvider",
            "-providerpath",
            JAR,
        ]
        if kind == "BKS"
        else []
    )
    for index, chain in enumerate(chains):
        anchor, path = tmp_path / f"root-{index}.pem", tmp_path / f"chain-{index}.pem"
        anchor.write_bytes(chain[0])
        path.write_bytes(chain[2] + chain[1])
        paths.append(path)
        subprocess.run(
            [
                str(Path(JAVA).with_name("keytool")),
                *provider,
                "-importcert",
                "-noprompt",
                "-alias",
                f"root-{index}",
                "-file",
                str(anchor),
                "-keystore",
                str(store),
                "-storetype",
                kind,
                "-storepass:env",
                "CHAIN_FIXTURE_PASSWORD",
            ],
            capture_output=True,
            check=True,
            timeout=30,
        )

    def validate(index, accepted):
        classpath = str(verifier) + (os.pathsep + JAR if kind == "BKS" else "")
        result = subprocess.run(
            [JAVA, "-cp", classpath, "VerifyTrust", kind, str(store), str(paths[index])],
            input=PASSWORD.encode(),
            capture_output=True,
            timeout=30,
            env={
                key: value for key, value in os.environ.items() if key in ("PATH", "HOME", "LANG")
            },
        )
        assert result.returncode == (0 if accepted else 2), result.stderr.decode(errors="replace")
        assert result.stdout.strip() == (b"VALID" if accepted else b"REJECTED")

    validate(0, True)
    validate(1, True)
    target = Target(
        id="chain-fixture",
        transport="local",
        adapter="bks" if kind == "BKS" else "java-" + kind.lower(),
        path=str(store),
        password_env="CHAIN_FIXTURE_PASSWORD",
    )
    state = State(tmp_path / "state")
    try:
        app = Service(Inventory(targets=[target]), state, write_enabled=True)
        fingerprint = (
            x509.load_pem_x509_certificate(chains[0][0]).fingerprint(hashes.SHA256()).hex()
        )
        app.incident = {"id": "native-chain-test", "certificates": [{"sha256": fingerprint}]}
        original = store.read_bytes()
        plan = await app.plan(target.id)
        await app.apply(plan["plan_id"])
        validate(0, False)
        validate(1, True)
        await app.rollback(plan["plan_id"])
        assert store.read_bytes() == original
        validate(0, True)
        validate(1, True)
    finally:
        state.close()
