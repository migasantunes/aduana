"""The MCP 2026-07-28 wire layer: pure functions, no I/O."""

from aduana.protocol.errors import (
    HEADER_MISMATCH,
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    PARSE_ERROR,
    UNSUPPORTED_PROTOCOL_VERSION,
    McpError,
)
from aduana.protocol.jsonrpc import (
    Message,
    Notification,
    Request,
    RequestId,
    Response,
    error_response,
    parse_message,
    result_response,
)
from aduana.protocol.meta import RequestMeta, extract_request_meta

__all__ = [
    "HEADER_MISMATCH",
    "INTERNAL_ERROR",
    "INVALID_PARAMS",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "MISSING_REQUIRED_CLIENT_CAPABILITY",
    "PARSE_ERROR",
    "UNSUPPORTED_PROTOCOL_VERSION",
    "McpError",
    "Message",
    "Notification",
    "Request",
    "RequestId",
    "RequestMeta",
    "Response",
    "error_response",
    "extract_request_meta",
    "parse_message",
    "result_response",
]
