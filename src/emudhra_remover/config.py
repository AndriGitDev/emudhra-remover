"""Operator-owned inventory. MCP callers cannot add hosts, paths or policy entries."""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    transport: Literal["local", "ssh"] = "ssh"
    host: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$")
    user: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}$")
    port: int = Field(default=22, ge=1, le=65535)
    adapter: Literal["pem-bundle"] = "pem-bundle"
    path: str
    sudo: bool = False

    @model_validator(mode="after")
    def validate_target(self):
        if not Path(self.path).is_absolute() or "\x00" in self.path:
            raise ValueError("Trust store path must be absolute")
        if self.transport == "ssh" and (not self.host or not self.user):
            raise ValueError("SSH targets require host and user")
        if self.transport == "local" and self.sudo:
            raise ValueError("Run the local server with appropriate permissions; sudo is SSH-only")
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
