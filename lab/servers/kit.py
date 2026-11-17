"""Minimal MCP 2026-07-28 server kit for the attack lab (Streamable HTTP, POST only).

This is an independent implementation of the *server* side of the spec. It deliberately
shares no code with ``aduana``: running the gateway against these servers is the project's
interoperability check, so a misreading of the spec in one side should show up as a failure
instead of being copied into both.

Validation order for a POST to ``/mcp`` (the spec does not fix one; this is ours):

1. ``Origin`` present and not loopback: 403.
2. Body not JSON: 400 / -32700. Not a single JSON-RPC request or notification: 400 / -32600.
3. Notification (no ``id``): 202, empty body.
4. ``initialize`` (legacy handshake): 400 / -32022 naming the supported versions.
5. ``MCP-Protocol-Version`` / ``Mcp-Method`` missing or not matching the body: 400 / -32020.
6. Required ``_meta`` fields missing: 400 / -32602.
7. Version not supported: 400 / -32022 with ``data.supported`` and ``data.requested``.
8. Unknown method: 404 / -32601.
9. Per-method checks (``Mcp-Name``, params shape, tool dispatch).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

JsonObject = dict[str, Any]

PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_VERSIONS: tuple[str, ...] = (PROTOCOL_VERSION,)

META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"

# JSON-RPC / MCP error codes (SPEC_NOTES §3). Nothing else is ever emitted.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
HEADER_MISMATCH = -32020
UNSUPPORTED_PROTOCOL_VERSION = -32022

SENTINEL_PREFIX = "=?base64?"
SENTINEL_SUFFIX = "?="

#: Canary marker every synthetic payload in the lab carries. Seeing it outside the lab (in a
#: model's output, or in an argument that reached a server) is an attack's success signal.
CANARY_PREFIX = "CANARY-ADUANA-"

#: Methods whose ``Mcp-Name`` header is required (mirrors ``params.name`` or ``params.uri``).
_NAME_HEADER_METHODS = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}

_KNOWN_METHODS = frozenset({"server/discover", "tools/list", "tools/call"})

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


class ToolError(Exception):
    """Raised by a handler to return a tool execution error (``isError: true``)."""


@dataclass(slots=True)
class RecordedRequest:
    """One HTTP request as the server saw it, before any validation."""

    http_method: str
    path: str
    #: Header names lowercased; repeated headers joined with ``", "``.
    headers: dict[str, str]
    body: bytes
    #: Parsed body, or ``None`` when it was not valid JSON.
    json: Any


@dataclass(slots=True)
class KitState:
    """Per-app mutable state, exposed as ``app.state.mcp`` for tests and servers."""

    requests: list[RecordedRequest] = field(default_factory=list)
    tools_list_calls: int = 0
    tools_call_count: int = 0

    def rpc_requests(self, method: str | None = None) -> list[RecordedRequest]:
        """Recorded requests whose JSON body carries ``method`` (all, if ``method`` None)."""
        out: list[RecordedRequest] = []
        for r in self.requests:
            if (
                isinstance(r.json, dict)
                and "method" in r.json
                and (method is None or r.json.get("method") == method)
            ):
                out.append(r)
        return out


@dataclass(frozen=True, slots=True)
class ToolCall:
    """What a handler receives besides its parsed ``arguments``."""

    arguments: JsonObject
    meta: JsonObject
    headers: dict[str, str]
    state: KitState


#: A handler returns a partial result (at least ``content``); the kit fills in ``resultType``
#: and ``_meta``.
Handler = Callable[[ToolCall], Awaitable[JsonObject]]
#: A tool's definition dict, or a callable that produces it from state (so a server can change
#: a tool over time — used by the rug-pull server).
DefinitionSource = JsonObject | Callable[[KitState], JsonObject]


@dataclass(slots=True)
class Tool:
    """One tool: how to describe it and how to run it.

    ``definition`` is either a fixed dict or a callable of the app state, letting a server
    vary a tool's ``tools/list`` entry across calls. ``stream`` makes ``tools/call`` answer
    with SSE (one progress notification, then the final response) so the gateway's SSE path
    is exercised.
    """

    name: str
    definition: DefinitionSource
    handler: Handler
    stream: bool = False

    def describe(self, state: KitState) -> JsonObject:
        d = self.definition(state) if callable(self.definition) else self.definition
        # Always report the live name even if a callable forgot to.
        return {"name": self.name, **d}


class JsonRpcError(Exception):
    """A protocol-level failure, carried to the HTTP layer with its status."""

    def __init__(
        self,
        code: int,
        message: str,
        *,
        http_status: int,
        data: Any = None,
        request_id: str | int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status
        self.data = data
        self.request_id = request_id

    def to_response(self) -> JSONResponse:
        error: JsonObject = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        body: JsonObject = {"jsonrpc": "2.0", "id": self.request_id, "error": error}
        return JSONResponse(body, status_code=self.http_status)


def decode_sentinel(value: str) -> str:
    """Decode a base64-sentinel header value (``=?base64?...?=``); return others unchanged.

    Raises ``ValueError`` on a malformed sentinel so the caller can answer -32020.
    """
    if value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX):
        inner = value[len(SENTINEL_PREFIX) : -len(SENTINEL_SUFFIX)]
        try:
            return base64.b64decode(inner, validate=True).decode("utf-8")
        except (binascii.Error, ValueError) as exc:
            raise ValueError(f"invalid base64 sentinel: {value!r}") from exc
    return value


def _header_matches_body(header_value: str, body_value: Any) -> bool:
    """Compare a decoded header value with a body value (ints compared numerically)."""
    if isinstance(body_value, bool):
        return header_value == ("true" if body_value else "false")
    if isinstance(body_value, int):
        try:
            return int(header_value) == body_value
        except ValueError:
            return False
    if isinstance(body_value, float):
        try:
            return float(header_value) == body_value
        except ValueError:
            return False
    return header_value == str(body_value)


def _origin_ok(origin: str) -> bool:
    host = urlsplit_host(origin)
    return host in _LOOPBACK_HOSTS


def urlsplit_host(origin: str) -> str:
    # Local import keeps the module top clean; urlsplit is cheap.
    from urllib.parse import urlsplit

    return (urlsplit(origin).hostname or "").lower()


def make_server(
    name: str,
    version: str,
    tools: list[Tool],
    *,
    instructions: str | None = None,
) -> Starlette:
    """Build a Starlette app serving ``tools`` over MCP 2026-07-28 at POST ``/mcp``.

    The returned app records every request on ``app.state.mcp`` (a ``KitState``).
    """
    tools_by_name = {t.name: t for t in tools}
    server_info = {"name": name, "version": version}

    def result_meta() -> JsonObject:
        return {META_SERVER_INFO: dict(server_info)}

    async def discover(state: KitState, request_id: str | int) -> JsonObject:
        result: JsonObject = {
            "resultType": "complete",
            "supportedVersions": list(SUPPORTED_VERSIONS),
            "capabilities": {"tools": {}},
            "_meta": result_meta(),
            "ttlMs": 3_600_000,
            "cacheScope": "public",
        }
        if instructions is not None:
            result["instructions"] = instructions
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    async def tools_list(state: KitState, request_id: str | int) -> JsonObject:
        state.tools_list_calls += 1
        listed = [t.describe(state) for t in tools]
        # Deterministic order, prompt-cache friendly.
        listed.sort(key=lambda d: str(d.get("name", "")))
        result: JsonObject = {
            "resultType": "complete",
            "tools": listed,
            "ttlMs": 60_000,
            "cacheScope": "public",
            "_meta": result_meta(),
        }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    async def run_tool(tool: Tool, call: ToolCall, request_id: str | int) -> JsonObject:
        try:
            partial = await tool.handler(call)
            result = {"resultType": "complete", "_meta": result_meta(), **partial}
            result.setdefault("isError", False)
        except ToolError as exc:
            result = {
                "resultType": "complete",
                "isError": True,
                "content": [{"type": "text", "text": str(exc)}],
                "_meta": result_meta(),
            }
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def sse_stream(progress_token: Any, final: JsonObject) -> StreamingResponse:
        async def gen() -> AsyncIterator[bytes]:
            # One keep-alive comment, one progress notification, then the final response.
            yield b": aduana-lab stream open\n\n"
            if progress_token is not None:
                note = {
                    "jsonrpc": "2.0",
                    "method": "notifications/progress",
                    "params": {
                        "progressToken": progress_token,
                        "progress": 1,
                        "total": 1,
                        "message": "working",
                    },
                }
                yield _sse_event(note)
                await asyncio.sleep(0)
            yield _sse_event(final)

        return StreamingResponse(
            gen(),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
        )

    async def endpoint(request: Request) -> Response:
        state: KitState = request.app.state.mcp

        if request.method in ("GET", "DELETE"):
            # Legacy GET stream / DELETE session teardown: gone in this revision.
            return Response(status_code=405)
        if request.method != "POST":
            return Response(status_code=405)

        raw = await request.body()
        headers = {k.lower(): v for k, v in request.headers.items()}
        try:
            parsed: Any = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = None
        state.requests.append(
            RecordedRequest(
                http_method=request.method,
                path=request.url.path,
                headers=headers,
                body=raw,
                json=parsed,
            )
        )

        try:
            return await _handle_post(state, headers, raw, parsed)
        except JsonRpcError as exc:
            return exc.to_response()

    async def _handle_post(
        state: KitState, headers: dict[str, str], raw: bytes, parsed: Any
    ) -> Response:
        origin = headers.get("origin")
        if origin is not None and not _origin_ok(origin):
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": INVALID_REQUEST, "message": "bad origin"}},
                status_code=403,
            )

        if raw == b"":
            raise JsonRpcError(PARSE_ERROR, "empty body", http_status=400)
        if parsed is None:
            raise JsonRpcError(PARSE_ERROR, "body is not valid JSON", http_status=400)
        if not isinstance(parsed, dict) or parsed.get("jsonrpc") != "2.0":
            raise JsonRpcError(INVALID_REQUEST, "not a JSON-RPC 2.0 message", http_status=400)

        method = parsed.get("method")
        if not isinstance(method, str):
            raise JsonRpcError(INVALID_REQUEST, "missing method", http_status=400)

        request_id = parsed.get("id")
        if request_id is None:
            # Notification: clients never send responses, so no id means a notification.
            return Response(status_code=202)

        params = parsed.get("params")
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            # Legacy handshake: name supported versions so a legacy client has a diagnostic.
            raise JsonRpcError(
                UNSUPPORTED_PROTOCOL_VERSION,
                "this server implements MCP 2026-07-28 only (no initialize handshake); "
                f"supported versions: {', '.join(SUPPORTED_VERSIONS)}",
                http_status=400,
                data={"supported": list(SUPPORTED_VERSIONS)},
                request_id=request_id,
            )

        _validate_standard_headers(headers, method, params, request_id)
        meta = _validate_meta(params, request_id)
        _validate_version(headers, meta, request_id)

        if method not in _KNOWN_METHODS:
            raise JsonRpcError(
                METHOD_NOT_FOUND,
                f"unknown method: {method}",
                http_status=404,
                request_id=request_id,
            )

        if method == "server/discover":
            return JSONResponse(await discover(state, request_id))
        if method == "tools/list":
            return JSONResponse(await tools_list(state, request_id))

        # tools/call
        tool_name = params.get("name")
        if not isinstance(tool_name, str):
            raise JsonRpcError(
                INVALID_PARAMS,
                "tools/call requires a string name",
                http_status=400,
                request_id=request_id,
            )
        tool = tools_by_name.get(tool_name)
        if tool is None:
            raise JsonRpcError(
                INVALID_PARAMS,
                f"Unknown tool: {tool_name}",
                http_status=400,
                request_id=request_id,
            )
        arguments = params.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}
        state.tools_call_count += 1
        call = ToolCall(arguments=arguments, meta=meta, headers=headers, state=state)
        final = await run_tool(tool, call, request_id)
        if tool.stream:
            return sse_stream(meta.get("progressToken"), final)
        return JSONResponse(final)

    routes = [Route("/mcp", endpoint, methods=["GET", "POST", "DELETE"])]
    app = Starlette(routes=routes)
    app.state.mcp = KitState()
    return app


def _validate_standard_headers(
    headers: dict[str, str], method: str, params: JsonObject, request_id: str | int
) -> None:
    """Mirrored-header checks (SPEC_NOTES §4). Failures are -32020 / HTTP 400."""
    proto = headers.get("mcp-protocol-version")
    if proto is None:
        raise JsonRpcError(
            HEADER_MISMATCH,
            "missing MCP-Protocol-Version header",
            http_status=400,
            request_id=request_id,
        )

    mcp_method = headers.get("mcp-method")
    if mcp_method is None:
        raise JsonRpcError(
            HEADER_MISMATCH,
            "missing Mcp-Method header",
            http_status=400,
            request_id=request_id,
        )
    if mcp_method != method:
        raise JsonRpcError(
            HEADER_MISMATCH,
            "Mcp-Method header does not match body method",
            http_status=400,
            request_id=request_id,
        )

    source_field = _NAME_HEADER_METHODS.get(method)
    if source_field is not None:
        raw_name = headers.get("mcp-name")
        if raw_name is None:
            raise JsonRpcError(
                HEADER_MISMATCH,
                f"missing Mcp-Name header required for {method}",
                http_status=400,
                request_id=request_id,
            )
        try:
            decoded = decode_sentinel(raw_name)
        except ValueError as exc:
            raise JsonRpcError(
                HEADER_MISMATCH, str(exc), http_status=400, request_id=request_id
            ) from exc
        body_value = params.get(source_field)
        if body_value is None or not _header_matches_body(decoded, body_value):
            raise JsonRpcError(
                HEADER_MISMATCH,
                "Mcp-Name header does not match body value",
                http_status=400,
                request_id=request_id,
            )


def _validate_meta(params: JsonObject, request_id: str | int) -> JsonObject:
    """Required ``params._meta`` fields (SPEC_NOTES §2). Missing → -32602 / HTTP 400."""
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise JsonRpcError(
            INVALID_PARAMS, "missing params._meta", http_status=400, request_id=request_id
        )
    if META_PROTOCOL_VERSION not in meta:
        raise JsonRpcError(
            INVALID_PARAMS,
            f"missing _meta field {META_PROTOCOL_VERSION}",
            http_status=400,
            request_id=request_id,
        )
    if META_CLIENT_CAPABILITIES not in meta:
        raise JsonRpcError(
            INVALID_PARAMS,
            f"missing _meta field {META_CLIENT_CAPABILITIES}",
            http_status=400,
            request_id=request_id,
        )
    return meta


def _validate_version(headers: dict[str, str], meta: JsonObject, request_id: str | int) -> None:
    header_version = headers.get("mcp-protocol-version")
    body_version = meta.get(META_PROTOCOL_VERSION)
    if header_version != body_version:
        raise JsonRpcError(
            HEADER_MISMATCH,
            "MCP-Protocol-Version header does not match _meta protocol version",
            http_status=400,
            request_id=request_id,
        )
    if body_version not in SUPPORTED_VERSIONS:
        raise JsonRpcError(
            UNSUPPORTED_PROTOCOL_VERSION,
            f"unsupported protocol version: {body_version}",
            http_status=400,
            data={"supported": list(SUPPORTED_VERSIONS), "requested": body_version},
            request_id=request_id,
        )


def _sse_event(payload: JsonObject) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode()


def text_tool(
    name: str,
    description: str,
    text: str,
    *,
    input_schema: JsonObject | None = None,
    title: str | None = None,
    stream: bool = False,
) -> Tool:
    """Convenience: a tool whose definition is fixed and whose result is one text block."""
    definition: JsonObject = {
        "description": description,
        "inputSchema": input_schema or {"type": "object", "additionalProperties": False},
    }
    if title is not None:
        definition["title"] = title

    async def handler(_: ToolCall) -> JsonObject:
        return {"content": [{"type": "text", "text": text}]}

    return Tool(name=name, definition=definition, handler=handler, stream=stream)


#: Hosts the lab CLI will bind. Loopback is the default and the only one meant for a developer
#: machine. ``0.0.0.0`` is permitted *only* for the compose demo, where each server runs in a
#: container on an internal Docker network with no published port — equivalent isolation to
#: loopback on a host. No other host is accepted, so a lab server can never be exposed by a
#: stray ``--host`` value.
_ALLOWED_BIND_HOSTS = _LOOPBACK_HOSTS | {"0.0.0.0"}


def run_from_cli(app: Starlette, default_port: int) -> None:
    """``python -m lab.servers.<name> --port N`` runner. Loopback by default."""
    import uvicorn

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=default_port)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    if args.host not in _ALLOWED_BIND_HOSTS:
        raise SystemExit(
            "lab servers bind to loopback only (0.0.0.0 permitted only for the "
            "unpublished compose network)"
        )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
