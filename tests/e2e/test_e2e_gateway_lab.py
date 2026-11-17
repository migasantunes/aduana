"""The real gateway, with the real pipeline, in front of the attack-lab servers.

The lab is an independent implementation of the server side of MCP 2026-07-28
(it imports nothing from ``aduana``), so these tests are also an interop check
of the two readings of the spec. Each attack is run twice where it makes sense:
straight at the lab server to show it works, then through the gateway to show
it is stopped.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from lab.servers import (
    benign_notes,
    greedy_export,
    injecting_search,
    poisoned_weather,
    rugpull_calc,
)
from lab.servers.kit import CANARY_PREFIX

from aduana.cli import _pin
from aduana.config import Config
from aduana.gateway import create_app
from aduana.pipeline.engine import build_pipeline

VERSION = "2026-07-28"
DECISION = "io.github.migasantunes.aduana/decision"


class Routing(httpx.AsyncBaseTransport):
    def __init__(self, apps: dict[str, Any]) -> None:
        self._t = {host: httpx.ASGITransport(app=app) for host, app in apps.items()}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._t[request.url.host].handle_async_request(request)


class Audit:
    def __init__(self) -> None:
        self.events: list[Any] = []

    def emit(self, event: Any) -> None:
        self.events.append(event)


class Lab:
    def __init__(self, tmp_path: Path, pinning: str = "warn") -> None:
        self.apps = {
            "notes": benign_notes.make_app(),
            "weather": poisoned_weather.make_app(),
            "calc": rugpull_calc.make_app(switch_after=10**9),
            "search": injecting_search.make_app(),
            "export": greedy_export.make_app(),
        }
        self.config = Config.model_validate(
            {
                "upstreams": [{"name": n, "url": f"http://{n}.lab/mcp"} for n in self.apps],
                "policy": {
                    "default": "deny",
                    "rules": [
                        {"effect": "deny", "upstream": "notes", "tools": ["add_note"]},
                        {"effect": "allow", "upstream": "*", "tools": ["*"]},
                    ],
                },
                "pinning": {"mode": pinning, "lockfile": str(tmp_path / "aduana.lock")},
                # Catalogs are refetched on every list so the rug pull is observable.
                "gateway": {"max_list_ttl_ms": 0},
            }
        )
        self.upstream_http = httpx.AsyncClient(
            transport=Routing({f"{n}.lab": a for n, a in self.apps.items()})
        )
        self.audit = Audit()
        self._seq = 0

    def start(self) -> None:
        gateway = create_app(
            self.config,
            pipeline=build_pipeline(self.config),
            audit=self.audit,
            http_client=self.upstream_http,
        )
        self.agent = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gateway), base_url="http://gateway"
        )

    async def rpc(
        self, client: httpx.AsyncClient, url: str, method: str, **params: Any
    ) -> httpx.Response:
        self._seq += 1
        params["_meta"] = {
            "io.modelcontextprotocol/protocolVersion": VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "e2e", "version": "0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": VERSION,
            "Mcp-Method": method,
            "Authorization": "Bearer agent-token-must-not-leak",
        }
        if "name" in params:
            headers["Mcp-Name"] = params["name"]
        body = {"jsonrpc": "2.0", "id": self._seq, "method": method, "params": params}
        return await client.post(url, json=body, headers=headers)

    async def via_gateway(self, method: str, **params: Any) -> dict[str, Any]:
        r = await self.rpc(self.agent, "/mcp", method, **params)
        assert r.status_code == 200, r.text
        return r.json()["result"]  # type: ignore[no-any-return]

    async def direct(self, upstream: str, method: str, /, **params: Any) -> dict[str, Any]:
        r = await self.rpc(self.upstream_http, f"http://{upstream}.lab/mcp", method, **params)
        assert r.status_code == 200, r.text
        return r.json()["result"]  # type: ignore[no-any-return]

    async def exposed(self) -> set[str]:
        return {t["name"] for t in (await self.via_gateway("tools/list"))["tools"]}


@pytest.fixture
def lab(tmp_path: Path) -> Lab:
    lab = Lab(tmp_path)
    lab.start()
    return lab


async def test_discover_and_benign_call_work_through_the_gateway(lab: Lab) -> None:
    info = await lab.via_gateway("server/discover")
    assert VERSION in info["supportedVersions"]

    names = await lab.exposed()
    assert "notes__list_notes" in names

    result = await lab.via_gateway("tools/call", name="notes__list_notes", arguments={})
    assert result["resultType"] == "complete"
    assert not result.get("isError")


async def test_poisoned_definitions_never_reach_the_agent(lab: Lab) -> None:
    direct = (await lab.direct("weather", "tools/list"))["tools"]
    assert any("<IMPORTANT>" in t.get("description", "") for t in direct), "attack is live"

    listing = (await lab.via_gateway("tools/list"))["tools"]
    assert not [t for t in listing if t["name"].startswith("weather__")]
    assert "<IMPORTANT>" not in json.dumps(listing)
    assert CANARY_PREFIX not in json.dumps(listing, ensure_ascii=False)

    # A quarantined tool cannot be called by guessing its name either.
    r = await lab.rpc(lab.agent, "/mcp", "tools/call", name="weather__get_weather", arguments={})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == -32602


async def test_rug_pull_is_hidden_once_pinned(tmp_path: Path) -> None:
    lab = Lab(tmp_path, pinning="enforce")
    pinned, failed = await _pin(lab.config, lab.upstream_http)
    assert not failed and pinned["calc"] >= 1
    lab.start()

    assert "calc__add" in await lab.exposed()
    lab.apps["calc"].state.rugpull.trip()
    assert "calc__add" not in await lab.exposed()

    drift = [
        f
        for e in lab.audit.events
        if e.kind == "tool_catalog" and e.upstream == "calc"
        for f in e.findings
        if f.category == "rug_pull"
    ]
    assert drift, "drift must be audited"


async def test_injected_results_are_blocked(lab: Lab) -> None:
    direct = await lab.direct("search", "tools/call", name="search", arguments={"query": "text"})
    assert CANARY_PREFIX in json.dumps(direct), "attack is live"

    for query in ("text", "resource", "structured"):
        result = await lab.via_gateway(
            "tools/call", name="search__search", arguments={"query": query}
        )
        assert result["isError"] is True, query
        assert result["_meta"][DECISION]["action"] == "deny"
        assert CANARY_PREFIX not in json.dumps(result), query


async def test_sse_answers_from_an_upstream_are_inspected_too(lab: Lab) -> None:
    result = await lab.via_gateway(
        "tools/call", name="search__search_stream", arguments={"query": "text"}
    )
    assert result["resultType"] == "complete"
    assert CANARY_PREFIX not in json.dumps(result)


async def test_secret_in_arguments_never_reaches_the_upstream(lab: Lab) -> None:
    secret = (
        "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEow" + "IBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    )
    result = await lab.via_gateway("tools/call", name="export__export", arguments={"data": secret})
    assert result["isError"] is True
    assert "secret_exfiltration" in result["_meta"][DECISION]["categories"]
    assert lab.apps["export"].state.mcp.rpc_requests("tools/call") == []


async def test_policy_denial_never_reaches_the_upstream(lab: Lab) -> None:
    result = await lab.via_gateway(
        "tools/call", name="notes__add_note", arguments={"id": "n1", "text": "hello"}
    )
    assert result["isError"] is True
    assert result["_meta"][DECISION]["categories"] == ["policy"]
    assert lab.apps["notes"].state.mcp.rpc_requests("tools/call") == []


async def test_agent_credentials_and_identity_stay_at_the_gateway(lab: Lab) -> None:
    await lab.via_gateway("tools/call", name="notes__list_notes", arguments={})
    seen = lab.apps["notes"].state.mcp.rpc_requests()
    assert seen
    for request in seen:
        headers = {k.lower(): v for k, v in dict(request.headers).items()}
        assert "authorization" not in headers
        assert "agent-token-must-not-leak" not in json.dumps(request.json)
        client = request.json["params"]["_meta"]["io.modelcontextprotocol/clientInfo"]
        assert client["name"] == "aduana"
