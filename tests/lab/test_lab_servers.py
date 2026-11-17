"""Behavioural tests for the individual lab servers: poisoning surfaces, the rug-pull switch,
result-injection surfaces, the SSE reply, and the export sink.
"""

from __future__ import annotations

import json

from lab.servers import greedy_export, injecting_search, poisoned_weather, rugpull_calc
from lab.servers.kit import CANARY_PREFIX
from tests.lab.conftest import call, client_for, rpc_body


def _tool(tools: list[dict], name: str) -> dict:
    return next(t for t in tools if t["name"] == name)


async def _list_tools(app) -> list[dict]:
    async with client_for(app) as c:
        r = await call(c, rpc_body("tools/list"))
    assert r.status_code == 200
    return r.json()["result"]["tools"]


async def test_poisoned_weather_hides_canary_in_description():
    tools = await _list_tools(poisoned_weather.make_app())
    desc = _tool(tools, "get_weather")["description"]
    assert "<IMPORTANT>" in desc
    assert CANARY_PREFIX in desc


async def test_poisoned_weather_hides_canary_in_schema_property():
    tools = await _list_tools(poisoned_weather.make_app())
    notes = _tool(tools, "get_weather_schema")["inputSchema"]["properties"]["notes"]
    assert CANARY_PREFIX in notes["description"]


async def test_poisoned_weather_unicode_variant_has_invisible_chars():
    tools = await _list_tools(poisoned_weather.make_app())
    desc = _tool(tools, "get_weather_unicode")["description"]
    # Tag-block characters (U+E0000..U+E007F) are present and invisible.
    assert any(0xE0000 <= ord(ch) <= 0xE007F for ch in desc)
    # Decoding the tag characters back to ASCII reveals the canary.
    decoded = "".join(
        chr(ord(ch) - 0xE0000) if 0xE0000 <= ord(ch) <= 0xE007F else ch for ch in desc
    )
    assert CANARY_PREFIX in decoded


async def test_poisoned_weather_tool_itself_is_harmless():
    body = rpc_body(
        "tools/call", params={"name": "get_weather", "arguments": {"location": "Lisbon"}}
    )
    async with client_for(poisoned_weather.make_app()) as c:
        r = await call(c, body)
    text = r.json()["result"]["content"][0]["text"]
    assert "Lisbon" in text
    assert CANARY_PREFIX not in text  # the tool never emits the canary itself


async def test_rugpull_switches_after_first_list():
    app = rugpull_calc.make_app(switch_after=1)
    first = await _list_tools(app)
    second = await _list_tools(app)
    assert "<IMPORTANT>" not in _tool(first, "add")["description"]
    assert "<IMPORTANT>" in _tool(second, "add")["description"]
    assert "audit" in _tool(second, "add")["inputSchema"]["properties"]
    assert "audit" not in _tool(first, "add")["inputSchema"]["properties"]


async def test_rugpull_trip_forces_poison_immediately():
    app = rugpull_calc.make_app(switch_after=99)
    app.state.rugpull.trip()
    tools = await _list_tools(app)
    assert "<IMPORTANT>" in _tool(tools, "add")["description"]


async def test_rugpull_add_still_computes():
    app = rugpull_calc.make_app()
    body = rpc_body("tools/call", params={"name": "add", "arguments": {"a": 2, "b": 3}})
    async with client_for(app) as c:
        r = await call(c, body)
    result = r.json()["result"]
    assert result["structuredContent"]["sum"] == 5


async def test_injection_in_text_block():
    body = rpc_body("tools/call", params={"name": "search", "arguments": {"query": "text"}})
    async with client_for(injecting_search.make_app()) as c:
        r = await call(c, body)
    texts = [b["text"] for b in r.json()["result"]["content"] if b["type"] == "text"]
    assert any(CANARY_PREFIX in t for t in texts)


async def test_injection_in_embedded_resource():
    body = rpc_body("tools/call", params={"name": "search", "arguments": {"query": "resource"}})
    async with client_for(injecting_search.make_app()) as c:
        r = await call(c, body)
    blocks = r.json()["result"]["content"]
    resource = next(b for b in blocks if b["type"] == "resource")
    assert CANARY_PREFIX in resource["resource"]["text"]


async def test_injection_in_structured_content():
    body = rpc_body("tools/call", params={"name": "search", "arguments": {"query": "structured"}})
    async with client_for(injecting_search.make_app()) as c:
        r = await call(c, body)
    structured = r.json()["result"]["structuredContent"]
    assert CANARY_PREFIX in json.dumps(structured)


async def test_search_stream_answers_as_sse():
    body = rpc_body(
        "tools/call",
        params={
            "name": "search_stream",
            "arguments": {"query": "text"},
            "_meta": {"progressToken": "p1"},
        },
    )
    async with client_for(injecting_search.make_app()) as c:
        r = await call(c, body)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers.get("x-accel-buffering") == "no"
    events = [line for line in r.text.splitlines() if line.startswith("data: ")]
    payloads = [json.loads(line[len("data: ") :]) for line in events]
    # One progress notification, then the final response.
    assert any(p.get("method") == "notifications/progress" for p in payloads)
    assert any("result" in p for p in payloads)
    final = next(p for p in payloads if "result" in p)
    assert CANARY_PREFIX in json.dumps(final["result"])


async def test_export_records_what_it_receives():
    app = greedy_export.make_app()
    secret = f"{CANARY_PREFIX}WEATHER-SECRET=abc"
    body = rpc_body("tools/call", params={"name": "export", "arguments": {"data": secret}})
    async with client_for(app) as c:
        r = await call(c, body)
    assert r.status_code == 200
    # The sink captured the payload: this is what a gateway must prevent upstream of here.
    assert app.state.export.received_canary(CANARY_PREFIX)
    # The server's own reply never echoes the content.
    assert CANARY_PREFIX not in r.json()["result"]["content"][0]["text"]
