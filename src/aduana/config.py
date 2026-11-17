"""Gateway configuration, loaded from YAML.

The shapes here are a contract: the proxy, the pipeline and the CLI all read
them. See ``aduana.example.yaml`` for a commented example.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aduana.pipeline.types import Severity

#: Separator between upstream name and tool name in the names agents see.
TOOL_NAMESPACE_SEP = "__"

_UPSTREAM_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,30}[a-z0-9])?$")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GatewayConfig(_Model):
    host: str = "127.0.0.1"
    port: int = 8700
    path: str = "/mcp"
    #: Exact ``Origin`` values allowed. A request with any other Origin gets 403.
    #: Requests without an Origin header (non-browser clients) are accepted.
    allowed_origins: tuple[str, ...] = ()
    max_body_bytes: int = 1_048_576
    upstream_timeout_s: float = 30.0
    #: Upper bound for the ``ttlMs`` we advertise on aggregated lists.
    max_list_ttl_ms: int = 60_000


class UpstreamConfig(_Model):
    #: Operator-chosen identifier; becomes the prefix of exposed tool names.
    name: str
    #: Streamable HTTP endpoint of the upstream MCP server.
    url: str
    #: Static headers sent to this upstream (its own credentials).
    #: The agent's ``Authorization`` header is never forwarded.
    headers: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _valid_name(cls, v: str) -> str:
        if not _UPSTREAM_NAME.match(v):
            raise ValueError(
                "upstream name must be 1-32 chars of [a-z0-9-], "
                "starting and ending with a letter or digit"
            )
        return v


class PolicyRule(_Model):
    """First matching rule wins. Patterns are shell-style globs (``fnmatch``)."""

    effect: Literal["allow", "deny"]
    subjects: tuple[str, ...] = ("*",)
    upstream: str = "*"
    tools: tuple[str, ...] = ("*",)
    #: Optional JSON Schema (2020-12) the call arguments must satisfy for an
    #: ``allow`` rule to apply. Arguments that fail it are denied.
    arguments: dict[str, Any] | None = None


class PolicyConfig(_Model):
    default: Literal["allow", "deny"] = "deny"
    rules: tuple[PolicyRule, ...] = ()


class PinningConfig(_Model):
    #: ``off``: no pinning. ``warn``: record drift, still expose the tool.
    #: ``enforce``: unknown or changed tool definitions are not exposed.
    mode: Literal["off", "warn", "enforce"] = "warn"
    lockfile: Path = Path("aduana.lock")


class DetectorConfig(_Model):
    enabled: bool = True
    #: Findings at or above this severity deny the message.
    deny_at: Severity = Severity.HIGH


class DetectorsConfig(_Model):
    rules: DetectorConfig = DetectorConfig()
    secrets: DetectorConfig = DetectorConfig()


class AuditConfig(_Model):
    #: JSONL file. ``None`` writes to stderr.
    path: Path | None = None


class Config(_Model):
    gateway: GatewayConfig = GatewayConfig()
    upstreams: tuple[UpstreamConfig, ...] = ()
    policy: PolicyConfig = PolicyConfig()
    pinning: PinningConfig = PinningConfig()
    detectors: DetectorsConfig = DetectorsConfig()
    audit: AuditConfig = AuditConfig()

    @model_validator(mode="after")
    def _unique_upstreams(self) -> Config:
        names = [u.name for u in self.upstreams]
        if len(names) != len(set(names)):
            raise ValueError("upstream names must be unique")
        return self


def load_config(path: str | Path) -> Config:
    """Read and validate a YAML config file."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top level must be a mapping")
    return Config.model_validate(raw)
