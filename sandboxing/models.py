"""User choices, independent of SRT's evolving configuration format."""
from pathlib import Path
import re

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator

SRT_VERSION = "0.0.81"
# Bump whenever maintained permissions, launch semantics or worker code change.
PROFILE_REVISION = "kindred-srt-2"


class ConnectionProfile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    configuration_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    read_paths: list[str] = Field(default_factory=list, max_length=64)
    write_paths: list[str] = Field(default_factory=list, max_length=64)
    destinations: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("read_paths", "write_paths")
    @classmethod
    def paths(cls, values):
        if any(not Path(p).is_absolute() or any(c in p for c in "\x00\r\n*?[]{}") for p in values):
            raise ValueError("Use absolute, literal paths without wildcard characters.")
        return list(dict.fromkeys(values))

    @field_validator("destinations")
    @classmethod
    def hosts(cls, values):
        # Exact public hostnames only: no URLs, IP literals or wildcard grants.
        from ipaddress import ip_address
        for value in values:
            host, separator, port = value.partition(":")
            if len(host) > 253 or "." not in host or any(not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in host.split('.')) or (separator and (not port.isdigit() or not 1 <= int(port) <= 65535)):
                raise ValueError("Use an exact public hostname, optionally followed by :port.")
            try:
                ip_address(host)
            except ValueError:
                pass
            else:
                raise ValueError("Use public hostnames rather than IP addresses.")
            if host.lower().endswith((".localhost", ".local", ".internal")):
                raise ValueError("Local and internal destinations cannot be granted.")
        return list(dict.fromkeys(v.lower() for v in values))


class SandboxSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: StrictBool = False
    connections: dict[str, ConnectionProfile] = Field(default_factory=dict)
