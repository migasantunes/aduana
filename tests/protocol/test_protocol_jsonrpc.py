from __future__ import annotations

import json
from typing import Any

import pytest

from aduana.protocol import errors as E
from aduana.protocol.jsonrpc import (
    Notification,
    Request,
    best_effort_id,
    error_response,
    is_request_id,
    parse_message,
    parse_response_obj,
    result_response,
    result_type_of,
)


def test_parse_request() -> None:
    msg = parse_message(b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"a":1}}')
    assert msg == Request(id=1, method="tools/list", params={"a": 1})


def test_parse_request_string_id_and_no_params() -> None:
    msg = parse_message('{"jsonrpc":"2.0","id":"x","method":"m"}')
    assert isinstance(msg, Request)
    assert msg.id == "x" and msg.params == {} and not msg.has_params


def test_parse_notification() -> None:
    msg = parse_message(b'{"jsonrpc":"2.0","method":"notifications/x"}')
    assert msg == Notification(method="notifications/x")


@pytest.mark.parametrize(
    "raw",
    [b"not json", b'{"a":', b"\xff\xfe", b'{"jsonrpc":"2.0","id":1,"method":"m","x":NaN}'],
)
def test_parse_errors(raw: bytes) -> None:
    with pytest.raises(E.McpError) as ei:
        parse_message(raw)
    assert ei.value.code == E.PARSE_ERROR


def test_duplicate_keys_are_a_parse_error() -> None:
    raw = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","name":"b"}}'
    with pytest.raises(E.McpError) as ei:
        parse_message(raw)
    assert ei.value.code == E.PARSE_ERROR


@pytest.mark.parametrize(
    "obj",
    [
        [],
        [{"jsonrpc": "2.0", "id": 1, "method": "m"}],
        "str",
        {"id": 1, "method": "m"},
        {"jsonrpc": "1.0", "id": 1, "method": "m"},
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "id": 1, "method": ""},
        {"jsonrpc": "2.0", "id": 1, "method": 5},
        {"jsonrpc": "2.0", "id": None, "method": "m"},
        {"jsonrpc": "2.0", "id": True, "method": "m"},
        {"jsonrpc": "2.0", "id": 1.5, "method": "m"},
        {"jsonrpc": "2.0", "id": {}, "method": "m"},
        {"jsonrpc": "2.0", "id": 1, "method": "m", "params": [1, 2]},
        {"jsonrpc": "2.0", "id": 1, "result": {}},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": 1, "message": "x"}},
    ],
)
def test_invalid_requests(obj: Any) -> None:
    with pytest.raises(E.McpError) as ei:
        parse_message(json.dumps(obj))
    assert ei.value.code == E.INVALID_REQUEST
    assert ei.value.http_status == 400


def test_is_request_id() -> None:
    assert is_request_id(0) and is_request_id("") and is_request_id(-5)
    assert not is_request_id(True) and not is_request_id(None) and not is_request_id(1.0)


def test_best_effort_id() -> None:
    assert best_effort_id({"id": 7}) == 7
    assert best_effort_id({"id": False}) is None
    assert best_effort_id([1]) is None


def test_builders() -> None:
    assert result_response(1, {"resultType": "complete"}) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"resultType": "complete"},
    }
    assert error_response(None, E.parse_error()) == {
        "jsonrpc": "2.0",
        "error": {"code": -32700, "message": "Parse error"},
    }


def test_parse_response() -> None:
    r = parse_response_obj({"jsonrpc": "2.0", "id": 1, "result": {"x": 1}})
    assert r.result == {"x": 1} and r.error is None
    r = parse_response_obj(
        {"jsonrpc": "2.0", "id": "a", "error": {"code": -1, "message": "m", "data": 3}}
    )
    assert r.error is not None and r.error.code == -1 and r.error.data == 3
    for bad in (
        [],
        {"jsonrpc": "2.0", "id": 1},
        {"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}},
        {"jsonrpc": "2.0", "id": 1, "result": []},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": "x", "message": "m"}},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": True, "message": "m"}},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": 1}},
        {"jsonrpc": "2.0", "id": [1], "result": {}},
    ):
        with pytest.raises(ValueError):
            parse_response_obj(bad)


def test_result_type() -> None:
    assert result_type_of({}) == "complete"
    assert result_type_of({"resultType": "input_required"}) == "input_required"
    for bad in ("weird", 1, None):
        with pytest.raises(ValueError):
            result_type_of({"resultType": bad})


def test_error_codes_and_status() -> None:
    assert E.http_status_for(E.PARSE_ERROR) == 400
    assert E.http_status_for(E.INVALID_REQUEST) == 400
    assert E.http_status_for(E.METHOD_NOT_FOUND) == 404
    assert E.http_status_for(E.INVALID_PARAMS) == 400
    assert E.http_status_for(E.INTERNAL_ERROR) == 500
    assert E.http_status_for(E.HEADER_MISMATCH) == 400
    assert E.http_status_for(E.MISSING_REQUIRED_CLIENT_CAPABILITY) == 400
    assert E.http_status_for(E.UNSUPPORTED_PROTOCOL_VERSION) == 400
    # Never invent codes in the reserved range.
    for code in E.HTTP_STATUS:
        assert code in (-32700, -32600, -32601, -32602, -32603, -32020, -32021, -32022)


def test_error_data_shapes() -> None:
    err = E.unsupported_protocol_version("1900-01-01", ["2026-07-28"])
    assert err.to_error_object() == {
        "code": -32022,
        "message": err.message,
        "data": {"supported": ["2026-07-28"], "requested": "1900-01-01"},
    }
    assert "2026-07-28" in err.message
    err = E.missing_required_client_capability({"elicitation": {}})
    assert err.to_error_object()["data"] == {"requiredCapabilities": {"elicitation": {}}}
    assert err.code == -32021
    assert E.header_mismatch("x").code == -32020
    assert "data" not in E.invalid_params().to_error_object()
    assert E.method_not_found("a" * 500).message.endswith("a" * 128)
