"""Parsing and building single JSON-RPC 2.0 messages, with MCP's tighter rules.

MCP narrows JSON-RPC: ids are strings or integers and never ``null``, ``params`` is an
object, a POST body is one message (no batches), and clients never send responses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aduana.protocol.errors import McpError, invalid_request, parse_error

JsonObject = dict[str, Any]
RequestId = str | int

JSONRPC_VERSION = "2.0"

#: ``resultType`` values defined by the core protocol.
RESULT_COMPLETE = "complete"
RESULT_INPUT_REQUIRED = "input_required"
KNOWN_RESULT_TYPES: frozenset[str] = frozenset({RESULT_COMPLETE, RESULT_INPUT_REQUIRED})


@dataclass(frozen=True, slots=True)
class Request:
    id: RequestId
    method: str
    params: JsonObject = field(default_factory=dict)
    #: Whether ``params`` was present in the body (an absent ``params`` is not ``{}`` on the
    #: wire, but every MCP request needs ``params._meta`` anyway).
    has_params: bool = True


@dataclass(frozen=True, slots=True)
class Notification:
    method: str
    params: JsonObject = field(default_factory=dict)


Message = Request | Notification


@dataclass(frozen=True, slots=True)
class ErrorObject:
    code: int
    message: str
    data: Any = None


@dataclass(frozen=True, slots=True)
class Response:
    """A response received from a peer. Exactly one of ``result`` / ``error`` is set."""

    id: RequestId | None
    result: JsonObject | None = None
    error: ErrorObject | None = None


def is_request_id(value: object) -> bool:
    """``bool`` is a subclass of ``int`` in Python but not an integer id in JSON."""
    return isinstance(value, str) or (isinstance(value, int) and not isinstance(value, bool))


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant {name}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> JsonObject:
    # Duplicate keys are a smuggling vector: two parsers may keep different values.
    obj: JsonObject = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def loads_strict(raw: bytes | str) -> Any:
    """Parse JSON rejecting NaN/Infinity and duplicate object keys."""
    return json.loads(
        raw,
        parse_constant=_reject_constant,
        object_pairs_hook=_no_duplicate_keys,
    )


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )


def parse_json(raw: bytes | str) -> Any:
    """Decode a body; any failure is a JSON-RPC parse error."""
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        return loads_strict(raw)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise parse_error() from exc


def best_effort_id(obj: object) -> RequestId | None:
    """The id to put on an error response, if one can be read from a rejected message."""
    if isinstance(obj, dict):
        value = obj.get("id")
        if is_request_id(value):
            return value
    return None


def parse_message_obj(obj: object) -> Message:
    """Validate one decoded client message (request or notification)."""
    if isinstance(obj, list):
        raise invalid_request("Batch requests are not supported")
    if not isinstance(obj, dict):
        raise invalid_request("Message must be a JSON object")
    if obj.get("jsonrpc") != JSONRPC_VERSION:
        raise invalid_request('"jsonrpc" must be "2.0"')
    if "result" in obj or "error" in obj:
        raise invalid_request("Clients must not send responses")
    method = obj.get("method")
    if not isinstance(method, str) or not method:
        raise invalid_request('"method" must be a non-empty string')
    has_params = "params" in obj
    params = obj.get("params", {})
    if not isinstance(params, dict):
        raise invalid_request('"params" must be an object')
    if "id" not in obj:
        return Notification(method=method, params=params)
    msg_id = obj["id"]
    if not is_request_id(msg_id):
        raise invalid_request('"id" must be a string or an integer')
    return Request(id=msg_id, method=method, params=params, has_params=has_params)


def parse_message(raw: bytes | str) -> Message:
    return parse_message_obj(parse_json(raw))


def parse_response_obj(obj: object) -> Response:
    """Validate a response received from an upstream server.

    Raises ``ValueError`` (not ``McpError``): a bad upstream reply is the upstream's fault,
    and must not be turned into a protocol error carrying upstream text.
    """
    if not isinstance(obj, dict):
        raise ValueError("response is not a JSON object")
    if obj.get("jsonrpc") != JSONRPC_VERSION:
        raise ValueError('response "jsonrpc" is not "2.0"')
    raw_id = obj.get("id")
    if raw_id is not None and not is_request_id(raw_id):
        raise ValueError("response id has an invalid type")
    resp_id: RequestId | None = raw_id
    has_result = "result" in obj
    has_error = "error" in obj
    if has_result == has_error:
        raise ValueError("response must have exactly one of result and error")
    if has_result:
        result = obj["result"]
        if not isinstance(result, dict):
            raise ValueError("result is not an object")
        return Response(id=resp_id, result=result)
    err = obj["error"]
    if not isinstance(err, dict):
        raise ValueError("error is not an object")
    code = err.get("code")
    message = err.get("message")
    if not isinstance(code, int) or isinstance(code, bool):
        raise ValueError("error code is not an integer")
    if not isinstance(message, str):
        raise ValueError("error message is not a string")
    return Response(id=resp_id, error=ErrorObject(code=code, message=message, data=err.get("data")))


def is_response_shaped(obj: object) -> bool:
    return isinstance(obj, dict) and ("result" in obj or "error" in obj) and "method" not in obj


def request_obj(msg_id: RequestId, method: str, params: JsonObject | None = None) -> JsonObject:
    obj: JsonObject = {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "method": method}
    if params is not None:
        obj["params"] = params
    return obj


def result_response(msg_id: RequestId, result: JsonObject) -> JsonObject:
    return {"jsonrpc": JSONRPC_VERSION, "id": msg_id, "result": result}


def error_response(msg_id: RequestId | None, error: McpError) -> JsonObject:
    """An error response; ``id`` is omitted when it could not be read (spec allows this)."""
    obj: JsonObject = {"jsonrpc": JSONRPC_VERSION}
    if msg_id is not None:
        obj["id"] = msg_id
    obj["error"] = error.to_error_object()
    return obj


def result_type_of(result: JsonObject) -> str:
    """``resultType``, with absence treated as ``"complete"`` (older servers omit it).

    Raises ``ValueError`` for a present but non-string or unrecognised value: the spec says
    an unrecognised ``resultType`` is invalid.
    """
    rt = result.get("resultType", RESULT_COMPLETE)
    if not isinstance(rt, str) or rt not in KNOWN_RESULT_TYPES:
        raise ValueError("unrecognised resultType")
    return rt
