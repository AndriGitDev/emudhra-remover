"""File adapters transform snapshots; transport owns atomic writes and recovery."""

from collections.abc import Callable
from dataclasses import dataclass

from ..certificates import filter_bundle
from ..config import Target
from .apple_profile import filter_apple_profile
from .debian import filter_debian
from .edk2 import filter_edk2
from .java import filter_java
from .nss import filter_nss
from .openssl import filter_openssl
from .p11 import filter_p11
from .pkcs7 import filter_pkcs7
from .windows import filter_windows


@dataclass(frozen=True)
class FileAdapter:
    id: str
    description: str
    coverage: str
    transform: Callable[..., tuple[list[dict], bytes, int]]
    needs_target: bool = False
    revision: int = 1
    removes_entries: bool = True


ADAPTERS = {
    "apple-profile": FileAdapter(
        "apple-profile",
        "Unsigned certificate-only Apple configuration-profile source file",
        "configured-profile-file-only-no-deployment-or-keychain-update",
        filter_apple_profile,
        revision=2,
    ),
    "windows-store": FileAdapter(
        "windows-store",
        "Windows Root/CA audit and exact-certificate additions to physical Disallowed",
        "configured-windows-logical-source-and-physical-disallowed-store",
        filter_windows,
        revision=2,
        removes_entries=False,
    ),
    "p11-kit": FileAdapter(
        "p11-kit",
        "Owned p11-kit distrust policy and consolidated Fedora-style native exports",
        "configured-p11-kit-sources-and-consolidated-exports",
        filter_p11,
        removes_entries=False,
    ),
    "edk2-cacerts": FileAdapter(
        "edk2-cacerts",
        "EDK2 HTTPS X509 certificate collection file (not firmware variables)",
        "configured-edk2-https-certificate-file-only",
        filter_edk2,
    ),
    "openssl-trusted-bundle": FileAdapter(
        "openssl-trusted-bundle",
        "OpenSSL PEM/X509_AUX bundle: explicit anyExtendedKeyUsage rejection",
        "configured-openssl-trusted-bundle-only",
        filter_openssl,
        removes_entries=False,
    ),
    "nss-sql": FileAdapter(
        "nss-sql",
        "Closed, empty-password NSS SQL database: explicit SSL/email/code distrust",
        "configured-nss-sql-certificates-only",
        filter_nss,
        revision=2,
        removes_entries=False,
    ),
    "java-jks": FileAdapter(
        "java-jks",
        "Java JKS trusted-certificate-only store",
        "configured-java-jks-store-only",
        filter_java,
        True,
        revision=2,
    ),
    "java-jceks": FileAdapter(
        "java-jceks",
        "Java JCEKS trusted-certificate-only store, with no key deserialization",
        "configured-java-jceks-store-only",
        filter_java,
        True,
    ),
    "java-pkcs12": FileAdapter(
        "java-pkcs12",
        "Java PKCS12 trusted-certificate-only store",
        "configured-java-pkcs12-store-only",
        filter_java,
        True,
    ),
    "debian": FileAdapter(
        "debian",
        "Debian/Ubuntu package CA deselection and regeneration",
        "debian-package-sources-and-generated-store",
        filter_debian,
    ),
    "pem-bundle": FileAdapter(
        "pem-bundle", "Ordinary PEM certificate bundle", "configured-pem-bundle-only", filter_bundle
    ),
    "pkcs7": FileAdapter(
        "pkcs7",
        "Unsigned certificates-only PKCS#7/P7B collection (DER or PEM)",
        "configured-pkcs7-collection-only",
        filter_pkcs7,
    ),
}


def get_adapter(name: str) -> FileAdapter:
    try:
        return ADAPTERS[name]
    except KeyError as error:
        raise ValueError(f"Unsupported adapter: {name}") from error


def capabilities() -> list[dict]:
    return [
        {
            "id": a.id,
            "description": a.description,
            "coverage": a.coverage,
            "operations": ["scan", "plan", "apply", "verify", "rollback"]
            + (["resume"] if a.id in ("nss-sql", "p11-kit", "windows-store") else []),
            "transports": ["ssh"] if a.id == "windows-store" else ["local", "ssh"],
            "target_platform": "windows" if a.id == "windows-store" else "linux",
            "validation": "native Windows custom-store fixtures; chain engine unvalidated"
            if a.id == "windows-store"
            else "temporary-file integration tests",
        }
        for a in ADAPTERS.values()
    ]


def transform_store(target: Target, data: bytes, incident: dict):
    adapter = get_adapter(target.adapter)
    if adapter.needs_target:
        return adapter.transform(data, incident, target)
    return adapter.transform(data, incident)
