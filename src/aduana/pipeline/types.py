"""Contracts shared by the proxy and every security stage.

This module is the seam of the system. The transport/proxy side builds a
``CallContext`` and asks a ``Pipeline`` for a ``Decision``; policy, pinning and
detectors implement the stage protocols. Nothing here imports from the rest of
``aduana``, so both sides can depend on it without cycles.

Change these types deliberately: every stage and the proxy rely on them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

JsonObject = dict[str, Any]


class Action(StrEnum):
    """What the gateway does with a message."""

    ALLOW = "allow"
    #: Refuse. For ``tools/call`` the client receives a tool execution error.
    DENY = "deny"
    #: Forward a rewritten payload (``Decision.payload``) instead of the original.
    REDACT = "redact"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(StrEnum):
    """Threat classes. Mirrors docs/THREAT_MODEL.md; keep the two in sync."""

    POLICY = "policy"
    TOOL_POISONING = "tool_poisoning"
    RUG_PULL = "rug_pull"
    RESULT_INJECTION = "result_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"  # noqa: S105
    TOOL_SHADOWING = "tool_shadowing"
    PROTOCOL_ABUSE = "protocol_abuse"


@dataclass(frozen=True, slots=True)
class Identity:
    """Who is calling. ``anonymous`` until OAuth lands (M3).

    ``client_name`` is the self-reported ``clientInfo.name``. It is recorded for
    audit only and MUST NOT influence any decision.
    """

    subject: str = "anonymous"
    scopes: frozenset[str] = frozenset()
    client_name: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a stage noticed."""

    detector: str
    category: Category
    severity: Severity
    message: str
    #: Short excerpt of the offending text. Stages truncate it; never a full payload.
    evidence: str | None = None
    #: Where it was found, e.g. ``description`` or ``content[0].text``.
    location: str | None = None


@dataclass(slots=True)
class Decision:
    action: Action = Action.ALLOW
    findings: list[Finding] = field(default_factory=list)
    reason: str | None = None
    #: Replacement payload when ``action`` is ``REDACT``.
    payload: Any = None

    @classmethod
    def allow(cls) -> Decision:
        return cls()

    @classmethod
    def deny(cls, reason: str, findings: list[Finding] | None = None) -> Decision:
        return cls(action=Action.DENY, reason=reason, findings=findings or [])


@dataclass(slots=True)
class CallContext:
    """Everything a stage may know about one proxied request."""

    request_id: str | int
    #: JSON-RPC method, e.g. ``tools/call``.
    method: str
    identity: Identity
    #: Operator-chosen upstream name (from config), once routing has resolved it.
    upstream: str | None = None
    #: Tool name as the upstream knows it (without the ``<upstream>__`` prefix).
    tool: str | None = None
    arguments: JsonObject | None = None
    #: W3C ``traceparent`` value, if the client sent one.
    traceparent: str | None = None
    #: ``time.monotonic()`` at arrival, for latency accounting.
    started_at: float = 0.0


@runtime_checkable
class ToolStage(Protocol):
    """Judges a tool *definition* when an upstream catalog is (re)loaded."""

    name: str

    async def on_tool(self, upstream: str, tool: JsonObject) -> Decision | None: ...


@runtime_checkable
class RequestStage(Protocol):
    """Judges an outgoing ``tools/call`` before it reaches the upstream."""

    name: str

    async def on_request(self, ctx: CallContext) -> Decision | None: ...


@runtime_checkable
class ResponseStage(Protocol):
    """Judges a ``tools/call`` result before it reaches the agent."""

    name: str

    async def on_response(self, ctx: CallContext, result: JsonObject) -> Decision | None: ...


class Pipeline(Protocol):
    """What the proxy calls. Implemented by ``aduana.pipeline.engine``.

    Semantics every implementation must honour:

    * Stages run in the configured order.
    * The first ``DENY`` wins and stops the chain.
    * ``REDACT`` replaces the payload seen by later stages and by the caller.
    * Findings from every stage that ran are accumulated on the returned decision.
    * A stage that raises is a failure of the gateway, not a verdict: the engine
      fails **closed** (``DENY``) and records a ``PROTOCOL_ABUSE``/``CRITICAL`` finding
      naming the stage.
    """

    async def check_tool(self, upstream: str, tool: JsonObject) -> Decision: ...

    async def check_request(self, ctx: CallContext) -> Decision: ...

    async def check_response(self, ctx: CallContext, result: JsonObject) -> Decision: ...


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One line of the audit log."""

    #: ``tool_catalog`` | ``tool_call`` | ``tool_result`` | ``protocol_reject``
    kind: str
    #: Unix time, seconds.
    ts: float
    subject: str
    method: str
    action: Action
    upstream: str | None = None
    tool: str | None = None
    reason: str | None = None
    findings: tuple[Finding, ...] = ()
    latency_ms: float | None = None
    traceparent: str | None = None
    request_id: str | int | None = None


class AuditSink(Protocol):
    """Where audit events go. Must never raise into the request path."""

    def emit(self, event: AuditEvent) -> None: ...
