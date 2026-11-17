"""JSON-RPC and MCP error codes (SPEC_NOTES §3) and the exception that carries them.

Only codes defined by JSON-RPC 2.0 or by the MCP 2026-07-28 specification live here.
The spec reserves ``-32020..-32099`` for itself and forbids emitting undefined codes in
that range, so adding a constant to this module is a protocol decision, not a convenience.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
HEADER_MISMATCH = -32020
MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
UNSUPPORTED_PROTOCOL_VERSION = -32022

#: HTTP status the Streamable HTTP transport pairs with each code.
HTTP_STATUS: dict[int, int] = {
    PARSE_ERROR: 400,
    INVALID_REQUEST: 400,
    METHOD_NOT_FOUND: 404,
    INVALID_PARAMS: 400,
    INTERNAL_ERROR: 500,
    HEADER_MISMATCH: 400,
    MISSING_REQUIRED_CLIENT_CAPABILITY: 400,
    UNSUPPORTED_PROTOCOL_VERSION: 400,
}

#: Codes a modern (2026-07-28) peer uses; seeing one in a 4xx body means "modern server".
MODERN_ERROR_CODES: frozenset[int] = frozenset(HTTP_STATUS)


def http_status_for(code: int) -> int:
    """HTTP status for an error code; unknown (application) codes map to 400."""
    return HTTP_STATUS.get(code, 400)


class McpError(Exception):
    """A protocol error that becomes a JSON-RPC ``error`` object on the wire.

    ``message`` is always written by aduana. Callers must never put upstream-authored text in
    it: it reaches the agent, and through the agent, the model.
    """

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data

    @property
    def http_status(self) -> int:
        return http_status_for(self.code)

    def to_error_object(self) -> dict[str, Any]:
        err: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            err["data"] = self.data
        return err

    def __repr__(self) -> str:
        return f"McpError({self.code}, {self.message!r})"


def parse_error(message: str = "Parse error") -> McpError:
    return McpError(PARSE_ERROR, message)


def invalid_request(message: str = "Invalid request") -> McpError:
    return McpError(INVALID_REQUEST, message)


def method_not_found(method: str | None = None) -> McpError:
    # The method name is client-supplied; echoing it back to the same client is harmless,
    # but keep it bounded.
    if method:
        return McpError(METHOD_NOT_FOUND, f"Method not found: {method[:128]}")
    return McpError(METHOD_NOT_FOUND, "Method not found")


def invalid_params(message: str = "Invalid params") -> McpError:
    return McpError(INVALID_PARAMS, message)


def internal_error(message: str = "Internal error") -> McpError:
    return McpError(INTERNAL_ERROR, message)


def header_mismatch(message: str) -> McpError:
    return McpError(HEADER_MISMATCH, f"Header mismatch: {message}")


def missing_required_client_capability(
    required_capabilities: dict[str, Any],
    message: str = "Missing required client capability",
) -> McpError:
    """``data.requiredCapabilities`` is a ``ClientCapabilities`` object (schema.ts)."""
    return McpError(
        MISSING_REQUIRED_CLIENT_CAPABILITY,
        message,
        {"requiredCapabilities": required_capabilities},
    )


def unsupported_protocol_version(
    requested: str,
    supported: Sequence[str],
    message: str | None = None,
) -> McpError:
    msg = message or (f"Unsupported protocol version; supported versions: {', '.join(supported)}")
    return McpError(
        UNSUPPORTED_PROTOCOL_VERSION,
        msg,
        {"supported": list(supported), "requested": requested},
    )
