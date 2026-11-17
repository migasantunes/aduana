"""Shared helpers for the lab tests: build correct MCP 2026-07-28 requests in-process."""

from __future__ import annotations

import base64
from typing import Any

import httpx
from starlette.applications import Starlette

PROTOCOL_VERSION = "2026-07-28"
META_PROTOCOL_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_CAPABILITIES = "io.modelcontextprotocol/clientCapabilities"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"

JsonObject = dict[str, Any]


def client_for(app: Starlette) -> httpx.AsyncClient:
    """An ASGI-transport client bound to a lab app, base URL on loopback."""
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1")


def base_meta(version: str = PROTOCOL_VERSION) -> JsonObject:
    return {
        META_PROTOCOL_VERSION: version,
        META_CLIENT_INFO: {"name": "lab-test-client", "version": "0.0.1"},
        META_CLIENT_CAPABILITIES: {},
    }


def rpc_body(
    method: str,
    *,
    request_id: str | int | None = 1,
    params: JsonObject | None = None,
    version: str = PROTOCOL_VERSION,
    with_meta: bool = True,
) -> JsonObject:
    body: JsonObject = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        body["id"] = request_id
    p = dict(params or {})
    if with_meta:
        p["_meta"] = {**base_meta(version), **p.get("_meta", {})}
    body["params"] = p
    return body


def encode_sentinel(value: str) -> str:
    inner = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{inner}?="


def headers_for(
    body: JsonObject,
    *,
    override: dict[str, str] | None = None,
    drop: set[str] | None = None,
) -> dict[str, str]:
    """Standard mirrored headers derived from ``body``; override/drop for negative tests."""
    method = body["method"]
    params = body.get("params", {})
    version = params.get("_meta", {}).get(META_PROTOCOL_VERSION, PROTOCOL_VERSION)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }
    if method in ("tools/call", "prompts/get"):
        name = params.get("name")
        if name is not None:
            headers["Mcp-Name"] = name
    elif method == "resources/read":
        uri = params.get("uri")
        if uri is not None:
            headers["Mcp-Name"] = uri
    if override:
        headers.update(override)
    if drop:
        for key in list(headers):
            if key.lower() in {d.lower() for d in drop}:
                del headers[key]
    return headers


async def call(
    app_client: httpx.AsyncClient,
    body: JsonObject,
    *,
    override: dict[str, str] | None = None,
    drop: set[str] | None = None,
) -> httpx.Response:
    headers = headers_for(body, override=override, drop=drop)
    return await app_client.post("/mcp", json=body, headers=headers)
