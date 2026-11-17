"""``_meta`` keys, validation of the per-request fields, and the ``_meta`` aduana emits.

In the 2026-07-28 revision version and capabilities travel on every request instead of in
a handshake, so this module replaces what used to be session state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import aduana
from aduana.protocol.errors import invalid_params

JsonObject = dict[str, Any]

META = "_meta"

PROTOCOL_VERSION_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_CAPABILITIES_KEY = "io.modelcontextprotocol/clientCapabilities"
CLIENT_INFO_KEY = "io.modelcontextprotocol/clientInfo"
LOG_LEVEL_KEY = "io.modelcontextprotocol/logLevel"
SUBSCRIPTION_ID_KEY = "io.modelcontextprotocol/subscriptionId"
SERVER_INFO_KEY = "io.modelcontextprotocol/serverInfo"
PROGRESS_TOKEN_KEY = "progressToken"  # noqa: S105 - a _meta key, not a secret
TRACEPARENT_KEY = "traceparent"
TRACESTATE_KEY = "tracestate"
BAGGAGE_KEY = "baggage"
TRACE_KEYS: tuple[str, ...] = (TRACEPARENT_KEY, TRACESTATE_KEY, BAGGAGE_KEY)

#: aduana's own vendor key for the decision attached to a blocked/redacted result.
DECISION_KEY = f"{aduana.META_PREFIX}decision"

#: Bound on self-reported strings we keep for audit (clientInfo.name).
_MAX_CLIENT_NAME = 128


def implementation_info() -> JsonObject:
    """aduana's ``Implementation`` object, used both as clientInfo and serverInfo."""
    return {"name": "aduana", "version": aduana.__version__}


@dataclass(frozen=True, slots=True)
class RequestMeta:
    protocol_version: str
    client_capabilities: JsonObject
    client_info: JsonObject | None = None
    traceparent: str | None = None
    tracestate: str | None = None
    baggage: str | None = None
    progress_token: str | int | None = None
    #: The full ``_meta`` object as received (untrusted; for future stages).
    raw: JsonObject = field(default_factory=dict)

    @property
    def client_name(self) -> str | None:
        """Self-reported; for audit only, never for decisions."""
        if self.client_info is None:
            return None
        name = self.client_info.get("name")
        return name[:_MAX_CLIENT_NAME] if isinstance(name, str) else None


def extract_request_meta(params: JsonObject) -> RequestMeta:
    """Read and validate ``params._meta``. Missing required fields → ``-32602``."""
    meta = params.get(META)
    if not isinstance(meta, dict):
        raise invalid_params("Missing params._meta")
    version = meta.get(PROTOCOL_VERSION_KEY)
    if not isinstance(version, str) or not version:
        raise invalid_params(f"Missing or invalid _meta field {PROTOCOL_VERSION_KEY}")
    caps = meta.get(CLIENT_CAPABILITIES_KEY)
    if not isinstance(caps, dict):
        raise invalid_params(f"Missing or invalid _meta field {CLIENT_CAPABILITIES_KEY}")
    info = meta.get(CLIENT_INFO_KEY)
    # clientInfo is optional and never used for decisions; a malformed one is ignored rather
    # than rejected.
    client_info = info if isinstance(info, dict) else None

    def _str(key: str) -> str | None:
        value = meta.get(key)
        return value if isinstance(value, str) else None

    token = meta.get(PROGRESS_TOKEN_KEY)
    progress_token = (
        token
        if isinstance(token, str) or (isinstance(token, int) and not isinstance(token, bool))
        else None
    )
    return RequestMeta(
        protocol_version=version,
        client_capabilities=caps,
        client_info=client_info,
        traceparent=_str(TRACEPARENT_KEY),
        tracestate=_str(TRACESTATE_KEY),
        baggage=_str(BAGGAGE_KEY),
        progress_token=progress_token,
        raw=meta,
    )


def build_upstream_meta(
    protocol_version: str,
    client_capabilities: JsonObject | None = None,
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> JsonObject:
    """The ``_meta`` aduana sends on a request it issues to an upstream.

    The agent's ``clientInfo`` is replaced with aduana's: the upstream talks to the gateway,
    and the agent's self-description is not the upstream's business. ``progressToken`` and
    ``logLevel`` are not forwarded at M0 (no notification passthrough yet).
    """
    meta: JsonObject = {
        PROTOCOL_VERSION_KEY: protocol_version,
        CLIENT_INFO_KEY: implementation_info(),
        CLIENT_CAPABILITIES_KEY: dict(client_capabilities or {}),
    }
    for key, value in (
        (TRACEPARENT_KEY, traceparent),
        (TRACESTATE_KEY, tracestate),
        (BAGGAGE_KEY, baggage),
    ):
        if value is not None:
            meta[key] = value
    return meta


def upstream_meta_for(request_meta: RequestMeta) -> JsonObject:
    """``build_upstream_meta`` from a validated client request."""
    return build_upstream_meta(
        request_meta.protocol_version,
        request_meta.client_capabilities,
        traceparent=request_meta.traceparent,
        tracestate=request_meta.tracestate,
        baggage=request_meta.baggage,
    )


def with_server_info(result: JsonObject) -> JsonObject:
    """Return ``result`` with aduana's serverInfo in its ``_meta``.

    Any key under aduana's own vendor prefix in an upstream-supplied ``_meta`` is dropped,
    so an upstream cannot forge a gateway decision. Other upstream keys pass through.
    """
    out = dict(result)
    existing = out.get(META)
    meta: JsonObject = (
        {k: v for k, v in existing.items() if not k.startswith(aduana.META_PREFIX)}
        if isinstance(existing, dict)
        else {}
    )
    meta[SERVER_INFO_KEY] = implementation_info()
    out[META] = meta
    return out
