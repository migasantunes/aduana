"""Test doubles: a small modern (2026-07-28) MCP server and a host-routing httpx transport.

Shared by tests/upstream and tests/gateway; imported as ``tests.gateway.fake_mcp_upstream``.
The fake server checks its mirrored headers independently of ``aduana.protocol`` (plain
string comparison), so a bug in our header code cannot hide behind itself.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

V = "2026-07-28"

CallHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]


@dataclass
class Received:
    headers: list[tuple[str, str]]
    body: dict[str, Any]

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return None

    def header_names(self) -> set[str]:
        return {k.lower() for k, _ in self.headers}


def tool(name: str, description: str = "A tool.", **props: Any) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": props or {"text": {"type": "string"}}},
    }


@dataclass
class FakeUpstream:
    tools: list[Any] = field(default_factory=list)
    page_size: int | None = None
    ttl_ms: int | None = 60_000
    #: "json" or "sse"
    reply: str = "json"
    omit_result_type: bool = False
    on_call: CallHandler | None = None
    received: list[Received] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.app = Starlette(routes=[Route("/mcp", self._handle, methods=["POST"])])

    @property
    def calls(self) -> list[Received]:
        return [r for r in self.received if r.body.get("method") == "tools/call"]

    @property
    def lists(self) -> list[Received]:
        return [r for r in self.received if r.body.get("method") == "tools/list"]

    async def _handle(self, request: Request) -> Response:
        body = json.loads(await request.body())
        rec = Received(headers=list(request.headers.items()), body=body)
        self.received.append(rec)
        method = body["method"]
        params = body.get("params", {})
        meta = params.get("_meta", {})
        if (
            rec.header("Mcp-Method") != method
            or rec.header("MCP-Protocol-Version")
            != meta.get("io.modelcontextprotocol/protocolVersion")
            or (method == "tools/call" and rec.header("Mcp-Name") != params.get("name"))
        ):
            return JSONResponse(
                {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32020, "message": "x"}},
                status_code=400,
            )
        if method == "tools/list":
            result = self._list(params)
        elif method == "tools/call":
            result = await self._call(params)
        else:
            return JSONResponse(
                {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601, "message": "nf"}},
                status_code=404,
            )
        if "__error__" in result:
            msg = {"jsonrpc": "2.0", "id": body["id"], "error": result["__error__"]}
        else:
            if not self.omit_result_type:
                result.setdefault("resultType", "complete")
            msg = {"jsonrpc": "2.0", "id": body["id"], "result": result}
        if self.reply == "sse":
            return self._sse(msg)
        return JSONResponse(msg)

    def _list(self, params: dict[str, Any]) -> dict[str, Any]:
        start = int(params.get("cursor") or 0)
        size = self.page_size or max(len(self.tools), 1)
        page = self.tools[start : start + size]
        result: dict[str, Any] = {"tools": page, "cacheScope": "public"}
        if self.ttl_ms is not None:
            result["ttlMs"] = self.ttl_ms
        if start + size < len(self.tools):
            result["nextCursor"] = str(start + size)
        return result

    async def _call(self, params: dict[str, Any]) -> dict[str, Any]:
        if self.on_call is None:
            return {
                "content": [{"type": "text", "text": json.dumps(params.get("arguments", {}))}],
                "_meta": {
                    "io.modelcontextprotocol/serverInfo": {"name": "fake", "version": "1"},
                    "io.github.migasantunes.aduana/decision": {"action": "allow"},
                },
            }
        out = self.on_call(params)
        if isinstance(out, Awaitable):
            out = await out
        return out

    @staticmethod
    def _sse(msg: dict[str, Any]) -> Response:
        progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"p": 1}}
        final = json.dumps(msg, indent=1)  # multi-line → several data: lines
        data_lines = "".join(f"data: {line}\r\n" for line in final.splitlines())
        text = f": keep-alive\r\n\r\ndata: {json.dumps(progress)}\r\n\r\n{data_lines}\r\n"
        return Response(text, media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})


class RoutingTransport(httpx.AsyncBaseTransport):
    """Routes by host to in-process ASGI apps; unknown hosts behave like a dead server."""

    def __init__(self, apps: dict[str, Any]) -> None:
        self._transports = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}

    def kill(self, host: str) -> None:
        self._transports.pop(host, None)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        transport = self._transports.get(request.url.host)
        if transport is None:
            raise httpx.ConnectError("connection refused", request=request)
        return await transport.handle_async_request(request)


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)

    def of(self, kind: str) -> list[Any]:
        return [e for e in self.events if e.kind == kind]
