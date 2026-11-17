"""Transport-validation and dispatch tests for the lab server kit.

Driven in-process with httpx.ASGITransport against the benign notes server (a kit instance).
Each check asserts the exact HTTP status and JSON-RPC error code the spec mandates.
"""

from __future__ import annotations

import pytest
from lab.servers import benign_notes
from lab.servers.kit import decode_sentinel
from tests.lab.conftest import (
    call,
    client_for,
    encode_sentinel,
    headers_for,
    rpc_body,
)


@pytest.fixture
def app():
    # Fresh app per test so recorded requests and counters do not leak between tests.
    return benign_notes.make_app()


async def test_discover_ok(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("server/discover"))
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == ["2026-07-28"]
    assert result["_meta"]["io.modelcontextprotocol/serverInfo"]["name"] == "benign-notes"


async def test_tools_list_shape(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"))
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["resultType"] == "complete"
    assert result["ttlMs"] == 60_000
    assert result["cacheScope"] == "public"
    names = [t["name"] for t in result["tools"]]
    assert names == sorted(names)  # deterministic order
    assert set(names) == {"list_notes", "read_note", "add_note"}


async def test_tools_call_ok(app):
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "todo"}})
    async with client_for(app) as c:
        r = await call(c, body)
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["resultType"] == "complete"
    assert result["isError"] is False
    assert "milk" in result["content"][0]["text"]


async def test_handler_exception_is_tool_execution_error(app):
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "nope"}})
    async with client_for(app) as c:
        r = await call(c, body)
    assert r.status_code == 200  # tool execution errors are normal results
    result = r.json()["result"]
    assert result["isError"] is True
    assert result["resultType"] == "complete"


async def test_unknown_tool_is_minus_32602(app):
    body = rpc_body("tools/call", params={"name": "ghost", "arguments": {}})
    async with client_for(app) as c:
        r = await call(c, body, override={"Mcp-Name": "ghost"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32602


async def test_unknown_method_is_404_minus_32601(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("resources/list"))
    assert r.status_code == 404
    assert r.json()["error"]["code"] == -32601


async def test_get_and_delete_are_405(app):
    async with client_for(app) as c:
        rg = await c.get("/mcp")
        rd = await c.delete("/mcp")
    assert rg.status_code == 405
    assert rd.status_code == 405


async def test_notification_is_202(app):
    body = rpc_body("notifications/progress", request_id=None, with_meta=False)
    async with client_for(app) as c:
        r = await c.post(
            "/mcp",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Mcp-Method": "notifications/progress",
                "MCP-Protocol-Version": "2026-07-28",
            },
        )
    assert r.status_code == 202
    assert r.content == b""


async def test_bad_origin_is_403(app):
    async with client_for(app) as c:
        r = await call(
            c, rpc_body("tools/list"), override={"Origin": "https://evil.example.invalid"}
        )
    assert r.status_code == 403


async def test_loopback_origin_allowed(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"), override={"Origin": "http://127.0.0.1:9101"})
    assert r.status_code == 200


async def test_missing_protocol_version_header_is_minus_32020(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"), drop={"MCP-Protocol-Version"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_missing_mcp_method_header_is_minus_32020(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"), drop={"Mcp-Method"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_mcp_method_header_mismatch_is_minus_32020(app):
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"), override={"Mcp-Method": "tools/call"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_missing_mcp_name_on_tools_call_is_minus_32020(app):
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "todo"}})
    async with client_for(app) as c:
        r = await call(c, body, drop={"Mcp-Name"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_mcp_name_mismatch_is_minus_32020(app):
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "todo"}})
    async with client_for(app) as c:
        r = await call(c, body, override={"Mcp-Name": "add_note"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_mcp_name_base64_sentinel_accepted(app):
    # A name needing encoding still validates once decoded. read_note is plain ASCII, so we
    # encode it anyway to prove the sentinel path decodes before comparing.
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "todo"}})
    async with client_for(app) as c:
        r = await call(c, body, override={"Mcp-Name": encode_sentinel("read_note")})
    assert r.status_code == 200


async def test_malformed_sentinel_is_minus_32020(app):
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "todo"}})
    async with client_for(app) as c:
        r = await call(c, body, override={"Mcp-Name": "=?base64?not valid base64!?="})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_missing_meta_is_minus_32602(app):
    body = rpc_body("tools/list", with_meta=False)
    async with client_for(app) as c:
        r = await call(c, body)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32602


async def test_missing_client_capabilities_is_minus_32602(app):
    body = rpc_body("tools/list")
    del body["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]
    async with client_for(app) as c:
        r = await call(c, body)
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32602


async def test_header_version_body_version_mismatch_is_minus_32020(app):
    body = rpc_body("tools/list")
    async with client_for(app) as c:
        r = await call(c, body, override={"MCP-Protocol-Version": "2025-11-25"})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32020


async def test_unsupported_version_is_minus_32022_with_supported(app):
    body = rpc_body("tools/list", version="1900-01-01")
    async with client_for(app) as c:
        r = await call(c, body)  # header mirrors the body version, so they agree
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == -32022
    assert err["data"]["supported"] == ["2026-07-28"]
    assert err["data"]["requested"] == "1900-01-01"


async def test_initialize_is_rejected_naming_versions(app):
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    async with client_for(app) as c:
        r = await c.post(
            "/mcp",
            json=body,
            headers={
                "Content-Type": "application/json",
                "Mcp-Method": "initialize",
                "MCP-Protocol-Version": "2025-11-25",
            },
        )
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == -32022
    assert "2026-07-28" in err["message"]


async def test_parse_error_is_minus_32700(app):
    async with client_for(app) as c:
        r = await c.post(
            "/mcp",
            content=b"{not json",
            headers={
                "Content-Type": "application/json",
                "Mcp-Method": "tools/list",
                "MCP-Protocol-Version": "2026-07-28",
            },
        )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32700


async def test_requests_are_recorded(app):
    async with client_for(app) as c:
        await call(c, rpc_body("tools/list"))
    assert app.state.mcp.tools_list_calls == 1
    assert len(app.state.mcp.rpc_requests("tools/list")) == 1


def test_decode_sentinel_roundtrip():
    assert decode_sentinel(encode_sentinel("héllo")) == "héllo"
    assert decode_sentinel("plain") == "plain"


def test_headers_for_is_valid_by_construction():
    body = rpc_body("tools/call", params={"name": "read_note", "arguments": {"id": "x"}})
    h = headers_for(body)
    assert h["Mcp-Name"] == "read_note"
    assert h["Mcp-Method"] == "tools/call"
