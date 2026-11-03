"""Operator-owned inventory. MCP callers cannot add hosts, paths or policy entries."""

import json
import re
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DebianPaths(BaseModel):
    model_config = ConfigDict(extra="forbid")
    certs_dir: str = "/usr/share/ca-certificates"
    local_certs_dir: str = "/usr/local/share/ca-certificates"
    output_dir: str = "/etc/ssl/certs"

    @model_validator(mode="after")
    def absolute_paths(self):
        for value in self.model_dump().values():
            if not re.fullmatch(r"/[A-Za-z0-9._/-]+", value) or value.endswith("/"):
                raise ValueError(
                    "Debian paths must be absolute without glob characters or trailing slash"
                )
        return self


class P11Paths(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_dirs: list[str] = Field(
        default_factory=lambda: ["/etc/pki/ca-trust/source", "/usr/share/pki/ca-trust-source"],
        min_length=1,
        max_length=4,
    )
    output_dir: str = "/etc/pki/ca-trust/extracted"
    trust_binary: str = "/usr/bin/trust"
    module_path: str = "/usr/lib64/pkcs11/p11-kit-trust.so"

    @model_validator(mode="after")
    def paths(self):
        values = [*self.source_dirs, self.output_dir, self.trust_binary, self.module_path]
        if any(not re.fullmatch(r"/[A-Za-z0-9._/-]+", p) or p.endswith("/") for p in values):
            raise ValueError("p11-kit paths must be absolute without special characters")
        trees = [*self.source_dirs, self.output_dir]
        if any(
            a == b or a.startswith(b + "/") or b.startswith(a + "/")
            for i, a in enumerate(trees)
            for b in trees[i + 1 :]
        ):
            raise ValueError("p11-kit source/output directories must not overlap")
        return self


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    transport: Literal["local", "ssh"] = "ssh"
    host: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$")
    user: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$")
    port: int = Field(default=22, ge=1, le=65535)
    adapter: Literal[
        "pem-bundle",
        "pkcs7",
        "debian",
        "java-jks",
        "java-pkcs12",
        "nss-sql",
        "openssl-trusted-bundle",
        "edk2-cacerts",
        "p11-kit",
        "windows-store",
    ] = "pem-bundle"
    path: str
    sudo: bool = False
    debian: DebianPaths | None = None
    p11: P11Paths | None = None
    nss_offline: bool = False
    password_env: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")

    @model_validator(mode="after")
    def validate_target(self):
        if self.adapter == "windows-store":
            if not re.fullmatch(r"cert://(?:CurrentUser|LocalMachine)/(?:Root|CA)", self.path):
                raise ValueError(
                    "Windows store path must be cert://CurrentUser|LocalMachine/Root|CA"
                )
            if self.transport != "ssh" or self.sudo:
                raise ValueError(
                    "Windows stores require SSH without sudo from the Linux controller"
                )
        elif not Path(self.path).is_absolute() or "\x00" in self.path:
            raise ValueError("Trust store path must be absolute")
        if self.transport == "ssh" and (not self.host or not self.user):
            raise ValueError("SSH targets require host and user")
        if self.transport == "local" and self.sudo:
            raise ValueError("Run the local server with appropriate permissions; sudo is SSH-only")
        if self.adapter == "nss-sql" and not self.nss_offline:
            raise ValueError(
                "NSS requires nss_offline=true after closing the consuming application"
            )
        if self.adapter != "nss-sql" and self.nss_offline:
            raise ValueError("nss_offline is only supported for NSS databases")
        if self.adapter.startswith("java-") and self.password_env is None:
            raise ValueError("Java stores require an operator password_env name")
        if not self.adapter.startswith("java-") and self.password_env is not None:
            raise ValueError("password_env is only supported for Java stores")
        if self.adapter == "debian" and self.debian is None:
            self.debian = DebianPaths()
        if self.adapter != "debian" and self.debian is not None:
            raise ValueError("Debian paths require the debian adapter")
        if self.adapter == "p11-kit":
            if self.p11 is None:
                self.p11 = P11Paths()
            if self.path != self.p11.source_dirs[0] + "/emudhra-remover.p11-kit":
                raise ValueError(
                    "p11-kit path must be the owned policy in the first source directory"
                )
        elif self.p11 is not None:
            raise ValueError("p11 paths require the p11-kit adapter")
        return self


class Inventory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    targets: list[Target] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def unique_ids(self):
        if len({t.id for t in self.targets}) != len(self.targets):
            raise ValueError("Duplicate target IDs")
        return self

    @classmethod
    def load(cls, path: Path):
        return cls.model_validate(json.loads(path.read_text()))

    def target(self, target_id: str) -> Target:
        for target in self.targets:
            if target.id == target_id:
                return target
        raise ValueError("Unknown target ID")
