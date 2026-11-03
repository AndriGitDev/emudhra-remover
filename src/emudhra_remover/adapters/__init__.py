"""File adapters transform snapshots; transport owns atomic writes and recovery."""

from collections.abc import Callable
from dataclasses import dataclass

from ..certificates import filter_bundle
from ..config import Target
from .debian import filter_debian
from .java import filter_java
from .nss import filter_nss
from .openssl import filter_openssl
from .pkcs7 import filter_pkcs7


@dataclass(frozen=True)
class FileAdapter:
    id: str
    description: str
    coverage: str
    transform: Callable[..., tuple[list[dict], bytes, int]]
    needs_target: bool = False
    revision: int = 1


ADAPTERS = {
    "openssl-trusted-bundle": FileAdapter(
        "openssl-trusted-bundle",
        "OpenSSL PEM/X509_AUX bundle: explicit anyExtendedKeyUsage rejection",
        "configured-openssl-trusted-bundle-only",
        filter_openssl,
    ),
    "nss-sql": FileAdapter(
        "nss-sql",
        "Closed, empty-password NSS SQL database: explicit SSL/email/code distrust",
        "configured-nss-sql-certificates-only",
        filter_nss,
        revision=2,
    ),
    "java-jks": FileAdapter(
        "java-jks",
        "Java JKS trusted-certificate-only store",
        "configured-java-jks-store-only",
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
            "operations": ["scan", "plan", "apply", "verify", "rollback"],
            "transports": ["local", "ssh"],
            "target_platform": "linux",
            "validation": "temporary-file integration tests",
        }
        for a in ADAPTERS.values()
    ]


def transform_store(target: Target, data: bytes, incident: dict):
    adapter = get_adapter(target.adapter)
    if adapter.needs_target:
        return adapter.transform(data, incident, target)
    return adapter.transform(data, incident)
