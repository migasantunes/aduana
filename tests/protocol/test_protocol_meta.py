from __future__ import annotations

from typing import Any

import pytest

import aduana
from aduana.protocol import meta as M
from aduana.protocol.errors import INVALID_PARAMS, McpError

V = "2026-07-28"


def _params(**meta: Any) -> dict[str, Any]:
    base: dict[str, Any] = {M.PROTOCOL_VERSION_KEY: V, M.CLIENT_CAPABILITIES_KEY: {}}
    base.update(meta)
    return {"_meta": {k: v for k, v in base.items() if v is not ...}}


def test_reserved_key_constants() -> None:
    assert M.PROTOCOL_VERSION_KEY == "io.modelcontextprotocol/protocolVersion"
    assert M.CLIENT_CAPABILITIES_KEY == "io.modelcontextprotocol/clientCapabilities"
    assert M.CLIENT_INFO_KEY == "io.modelcontextprotocol/clientInfo"
    assert M.SERVER_INFO_KEY == "io.modelcontextprotocol/serverInfo"
    assert M.DECISION_KEY == "io.github.migasantunes.aduana/decision"
    assert M.TRACE_KEYS == ("traceparent", "tracestate", "baggage")


def test_extract_full() -> None:
    m = M.extract_request_meta(
        _params(
            **{
                M.CLIENT_INFO_KEY: {"name": "agent", "version": "1"},
                "traceparent": "00-abc-def-01",
                "tracestate": "k=v",
                "baggage": "b=1",
                "progressToken": 3,
            }
        )
    )
    assert m.protocol_version == V
    assert m.client_capabilities == {}
    assert m.client_name == "agent"
    assert (m.traceparent, m.tracestate, m.baggage, m.progress_token) == (
        "00-abc-def-01",
        "k=v",
        "b=1",
        3,
    )


def test_extract_lenient_optional_fields() -> None:
    m = M.extract_request_meta(
        _params(**{M.CLIENT_INFO_KEY: "junk", "traceparent": 5, "progressToken": True})
    )
    assert m.client_info is None and m.client_name is None
    assert m.traceparent is None and m.progress_token is None
    long = M.extract_request_meta(_params(**{M.CLIENT_INFO_KEY: {"name": "x" * 1000}}))
    assert long.client_name == "x" * 128


@pytest.mark.parametrize(
    "params",
    [
        {},
        {"_meta": None},
        {"_meta": []},
        _params(**{M.PROTOCOL_VERSION_KEY: ...}),
        _params(**{M.PROTOCOL_VERSION_KEY: ""}),
        _params(**{M.PROTOCOL_VERSION_KEY: 20260728}),
        _params(**{M.CLIENT_CAPABILITIES_KEY: ...}),
        _params(**{M.CLIENT_CAPABILITIES_KEY: None}),
        _params(**{M.CLIENT_CAPABILITIES_KEY: []}),
    ],
)
def test_extract_missing_required(params: dict[str, Any]) -> None:
    with pytest.raises(McpError) as ei:
        M.extract_request_meta(params)
    assert ei.value.code == INVALID_PARAMS
    assert ei.value.http_status == 400


def test_upstream_meta_replaces_client_info_and_propagates_trace() -> None:
    m = M.extract_request_meta(
        _params(
            **{
                M.CLIENT_INFO_KEY: {"name": "agent", "version": "1"},
                M.CLIENT_CAPABILITIES_KEY: {"elicitation": {}},
                "traceparent": "tp",
                "baggage": "bg",
                "progressToken": "p",
                M.LOG_LEVEL_KEY: "debug",
                "com.example/x": 1,
            }
        )
    )
    up = M.upstream_meta_for(m)
    assert up == {
        M.PROTOCOL_VERSION_KEY: V,
        M.CLIENT_INFO_KEY: {"name": "aduana", "version": aduana.__version__},
        M.CLIENT_CAPABILITIES_KEY: {"elicitation": {}},
        "traceparent": "tp",
        "baggage": "bg",
    }
    # A copy, not the client's object.
    up[M.CLIENT_CAPABILITIES_KEY]["x"] = 1
    assert "x" not in m.client_capabilities


def test_with_server_info() -> None:
    out = M.with_server_info(
        {
            "resultType": "complete",
            "_meta": {
                M.SERVER_INFO_KEY: {"name": "evil", "version": "9"},
                M.DECISION_KEY: {"action": "allow"},
                "io.github.migasantunes.aduana/other": 1,
                "com.example/keep": 2,
            },
        }
    )
    assert out["_meta"] == {
        M.SERVER_INFO_KEY: {"name": "aduana", "version": aduana.__version__},
        "com.example/keep": 2,
    }
    assert M.with_server_info({"_meta": "junk"})["_meta"] == {
        M.SERVER_INFO_KEY: M.implementation_info()
    }
