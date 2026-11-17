from __future__ import annotations

import base64
from typing import Any

import pytest

from aduana.protocol.errors import HEADER_MISMATCH, INVALID_PARAMS, McpError
from aduana.protocol.headers import (
    HeaderAnnotation,
    HeaderValueError,
    HeaderView,
    InvalidToolHeaders,
    compute_request_headers,
    decode_header_value,
    encode_header_value,
    header_annotations,
    header_string,
    needs_encoding,
    validate_param_headers,
    validate_standard_headers,
    value_at_path,
)

V = "2026-07-28"

# --------------------------------------------------------------------------- sentinel


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        # The examples table from the spec, verbatim.
        ("us-west1", "us-west1"),
        ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
        (" padded ", "=?base64?IHBhZGRlZCA=?="),
        ("line1\nline2", "=?base64?bGluZTEKbGluZTI=?="),
        ("=?base64?literal?=", "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?="),
    ],
)
def test_spec_encoding_examples(value: str, encoded: str) -> None:
    assert encode_header_value(value) == encoded
    assert decode_header_value(encoded) == value


@pytest.mark.parametrize(
    "value",
    [
        "inner space ok",
        "tab\tinside",
        "!#$%&'*+-.^_`|~",
        "",
        "=?BASE64?upper?=",  # markers are case-sensitive: not a sentinel
        "=?base64?no-suffix",
        "suffix-only?=",
    ],
)
def test_plain_values_pass_through(value: str) -> None:
    assert not needs_encoding(value)
    assert encode_header_value(value) == value
    assert decode_header_value(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "\ttab-leading",
        "trailing-tab\t",
        " leading",
        "trailing ",
        "nul\x00byte",
        "del\x7f",
        "cr\rhere",
        "café",
        "emoji 🙂",
        "=?base64??=",
        "=?base64?=",  # prefix and suffix overlap; still looks like the sentinel
    ],
)
def test_values_that_need_encoding_round_trip(value: str) -> None:
    assert needs_encoding(value)
    enc = encode_header_value(value)
    assert enc.startswith("=?base64?") and enc.endswith("?=")
    assert all(0x21 <= ord(c) <= 0x7E for c in enc)
    assert decode_header_value(enc) == value


@pytest.mark.parametrize(
    "raw",
    [
        "=?base64?!!!notbase64?=",
        "=?base64?abc?=",  # bad padding
        "=?base64?" + base64.b64encode(b"\xff\xfe").decode() + "?=",  # not UTF-8
        "=?base64?=",  # too short to hold a payload
        "bad\x00char",
        "line\nbreak",
        "latin1-\xe9",  # obs-text as Starlette would decode it
    ],
)
def test_decode_rejects_malformed(raw: str) -> None:
    with pytest.raises(HeaderValueError):
        decode_header_value(raw)


def test_header_string_conversion() -> None:
    assert header_string("x") == "x"
    assert header_string(42) == "42"
    assert header_string(-7) == "-7"
    assert header_string(True) == "true"
    assert header_string(False) == "false"
    assert header_string(3.0) == "3"
    assert header_string(None) is None
    for bad in (1.5, {"a": 1}, [1]):
        with pytest.raises(ValueError):
            header_string(bad)


# --------------------------------------------------------------------------- x-mcp-header


def _schema(**props: Any) -> dict[str, Any]:
    return {"type": "object", "properties": props}


def test_annotations_flat_and_nested() -> None:
    schema = _schema(
        region={"type": "string", "x-mcp-header": "Region"},
        query={"type": "string"},
        opts=_schema(
            limit={"type": "integer", "x-mcp-header": "Limit"},
            deep=_schema(flag={"type": "boolean", "x-mcp-header": "Flag"}),
        ),
    )
    anns = header_annotations(schema)
    assert anns == (
        HeaderAnnotation("Region", ("region",), "string"),
        HeaderAnnotation("Limit", ("opts", "limit"), "integer"),
        HeaderAnnotation("Flag", ("opts", "deep", "flag"), "boolean"),
    )
    assert anns[0].header_name == "Mcp-Param-Region"


def test_annotations_none_and_nullable() -> None:
    assert header_annotations(None) == ()
    assert header_annotations(_schema(a={"type": "string"})) == ()
    anns = header_annotations(_schema(a={"type": ["string", "null"], "x-mcp-header": "A"}))
    assert anns[0].type == "string"


def test_property_literally_named_x_mcp_header_is_not_an_annotation() -> None:
    schema = _schema(**{"x-mcp-header": {"type": "object"}})
    assert header_annotations(schema) == ()


def test_annotation_in_data_keywords_is_ignored() -> None:
    schema = _schema(a={"type": "string", "default": {"x-mcp-header": "Nope"}})
    assert header_annotations(schema) == ()


@pytest.mark.parametrize(
    "schema",
    [
        _schema(a={"type": "string", "x-mcp-header": ""}),
        _schema(a={"type": "string", "x-mcp-header": "Has Space"}),
        _schema(a={"type": "string", "x-mcp-header": "Bad\r\nInjected: 1"}),
        _schema(a={"type": "string", "x-mcp-header": "Colon:"}),
        _schema(a={"type": "string", "x-mcp-header": 5}),
        _schema(
            a={"type": "string", "x-mcp-header": "Dup"},
            b={"type": "string", "x-mcp-header": "dUP"},
        ),
        _schema(a={"type": "number", "x-mcp-header": "N"}),
        _schema(a={"type": "object", "x-mcp-header": "O"}),
        _schema(a={"type": "array", "x-mcp-header": "Arr"}),
        _schema(a={"x-mcp-header": "Untyped"}),
        _schema(a={"type": ["string", "integer"], "x-mcp-header": "Mixed"}),
        _schema(a={"type": "null", "x-mcp-header": "Null"}),
        # Not statically reachable:
        _schema(a={"type": "array", "items": {"type": "string", "x-mcp-header": "Item"}}),
        _schema(a={"anyOf": [{"type": "string", "x-mcp-header": "Any"}]}),
        {"type": "object", "oneOf": [_schema(a={"type": "string", "x-mcp-header": "One"})]},
        {"type": "object", "allOf": [_schema(a={"type": "string", "x-mcp-header": "All"})]},
        {"type": "object", "not": _schema(a={"type": "string", "x-mcp-header": "Not"})},
        {"if": _schema(a={"type": "string", "x-mcp-header": "If"}), "then": {}},
        {"$defs": {"d": {"type": "string", "x-mcp-header": "Def"}}, "properties": {}},
        {"type": "object", "x-mcp-header": "Root"},
        _schema(a={"$ref": "#/$defs/x", "x-mcp-header": "Ref", "type": "object"}),
        _schema(m={"type": "object", "additionalProperties": {"x-mcp-header": "AP"}}),
        {"patternProperties": {"^a": {"type": "string", "x-mcp-header": "PP"}}},
    ],
)
def test_invalid_annotations_rejected(schema: dict[str, Any]) -> None:
    with pytest.raises(InvalidToolHeaders):
        header_annotations(schema)


def test_input_schema_not_object() -> None:
    with pytest.raises(InvalidToolHeaders):
        header_annotations(["not", "an", "object"])


def test_value_at_path() -> None:
    args = {"a": {"b": {"c": 1}}, "n": None}
    assert value_at_path(args, ("a", "b", "c")) == 1
    assert value_at_path(args, ("a", "x")) is None
    assert value_at_path(args, ("n",)) is None
    assert value_at_path({"a": 5}, ("a", "b")) is None
    assert value_at_path(None, ("a",)) is None


# --------------------------------------------------------------------------- outbound


def test_compute_headers_tools_call() -> None:
    anns = header_annotations(
        _schema(
            region={"type": "string", "x-mcp-header": "Region"},
            n={"type": "integer", "x-mcp-header": "N"},
            ok={"type": "boolean", "x-mcp-header": "Ok"},
            missing={"type": "string", "x-mcp-header": "Missing"},
            nulled={"type": "string", "x-mcp-header": "Nulled"},
        )
    )
    params = {
        "name": "café",
        "arguments": {"region": " eu ", "n": 42, "ok": False, "nulled": None},
    }
    h = compute_request_headers("tools/call", params, protocol_version=V, annotations=anns)
    assert h == {
        "MCP-Protocol-Version": V,
        "Mcp-Method": "tools/call",
        "Mcp-Name": encode_header_value("café"),
        "Mcp-Param-Region": encode_header_value(" eu "),
        "Mcp-Param-N": "42",
        "Mcp-Param-Ok": "false",
    }


def test_compute_headers_other_methods() -> None:
    assert compute_request_headers("tools/list", {}, protocol_version=V) == {
        "MCP-Protocol-Version": V,
        "Mcp-Method": "tools/list",
    }
    h = compute_request_headers("resources/read", {"uri": "file:///x y"}, protocol_version=V)
    assert h["Mcp-Name"] == "file:///x y"
    with pytest.raises(ValueError):
        compute_request_headers("tools/call", {}, protocol_version=V)


# --------------------------------------------------------------------------- inbound


def _std(**extra: str) -> list[tuple[str, str]]:
    base = {"mcp-protocol-version": V, "mcp-method": "tools/call", "mcp-name": "echo"}
    base.update(extra)
    return [(k, v) for k, v in base.items() if v != "<absent>"]


def _expect_mismatch(fn: Any) -> McpError:
    with pytest.raises(McpError) as ei:
        fn()
    assert ei.value.code == HEADER_MISMATCH
    assert ei.value.http_status == 400
    return ei.value


def test_standard_headers_ok_case_insensitive_names() -> None:
    pairs = [("MCP-PROTOCOL-VERSION", V), ("mcp-METHOD", "tools/call"), ("MCP-name", "echo")]
    validate_standard_headers(HeaderView(pairs), "tools/call", {"name": "echo"}, V)


def test_standard_headers_mapping_input() -> None:
    validate_standard_headers(
        HeaderView({"Mcp-Method": "tools/list", "MCP-Protocol-Version": V}), "tools/list", {}, V
    )


@pytest.mark.parametrize(
    "pairs",
    [
        _std(**{"mcp-protocol-version": "<absent>"}),
        _std(**{"mcp-protocol-version": "2025-11-25"}),
        _std(**{"mcp-method": "<absent>"}),
        _std(**{"mcp-method": "tools/list"}),
        _std(**{"mcp-method": "Tools/Call"}),  # values are case-sensitive
        _std(**{"mcp-name": "<absent>"}),
        _std(**{"mcp-name": "other"}),
        _std(**{"mcp-name": "ECHO"}),
        _std(**{"mcp-name": "=?base64?!!?="}),
        _std(**{"mcp-name": "ec\x00ho"}),
        _std(**{"mcp-name": encode_header_value("other")}),
        [*_std(), ("Mcp-Name", "echo")],  # duplicated
        [*_std(), ("mcp-method", "tools/call")],
    ],
)
def test_standard_headers_rejections(pairs: list[tuple[str, str]]) -> None:
    _expect_mismatch(
        lambda: validate_standard_headers(HeaderView(pairs), "tools/call", {"name": "echo"}, V)
    )


def test_mcp_name_sentinel_is_decoded_before_compare() -> None:
    validate_standard_headers(
        HeaderView(_std(**{"mcp-name": encode_header_value("echo")})),
        "tools/call",
        {"name": "echo"},
        V,
    )
    name = "naïve tool"
    validate_standard_headers(
        HeaderView(_std(**{"mcp-name": encode_header_value(name)})),
        "tools/call",
        {"name": name},
        V,
    )


def test_literal_sentinel_name_must_be_double_encoded() -> None:
    name = "=?base64?ZWNobw==?="  # a tool literally named like a sentinel for "echo"
    # Sent raw, it decodes to "echo" and does not match the body.
    _expect_mismatch(
        lambda: validate_standard_headers(
            HeaderView(_std(**{"mcp-name": name})), "tools/call", {"name": name}, V
        )
    )
    validate_standard_headers(
        HeaderView(_std(**{"mcp-name": encode_header_value(name)})),
        "tools/call",
        {"name": name},
        V,
    )


def test_mcp_name_body_not_string_is_invalid_params() -> None:
    with pytest.raises(McpError) as ei:
        validate_standard_headers(HeaderView(_std()), "tools/call", {"name": 5}, V)
    assert ei.value.code == INVALID_PARAMS


def test_resources_read_uses_uri() -> None:
    pairs = [("mcp-protocol-version", V), ("mcp-method", "resources/read"), ("mcp-name", "a:b")]
    validate_standard_headers(HeaderView(pairs), "resources/read", {"uri": "a:b"}, V)


def test_name_header_not_required_for_list() -> None:
    validate_standard_headers(
        HeaderView([("mcp-protocol-version", V), ("mcp-method", "tools/list")]),
        "tools/list",
        {},
        V,
    )


_ANNS = header_annotations(
    _schema(
        region={"type": "string", "x-mcp-header": "Region"},
        n={"type": "integer", "x-mcp-header": "N"},
        flag={"type": "boolean", "x-mcp-header": "Flag"},
        nested=_schema(k={"type": "string", "x-mcp-header": "K"}),
    )
)


def test_param_headers_ok() -> None:
    args = {"region": "us-west1", "n": 42, "flag": True, "nested": {"k": "ü"}}
    pairs = [
        ("mcp-param-region", "us-west1"),
        ("MCP-PARAM-N", "42"),
        ("Mcp-Param-Flag", "true"),
        ("mcp-param-k", encode_header_value("ü")),
        ("mcp-param-unknown", "ignored"),
    ]
    validate_param_headers(HeaderView(pairs), args, _ANNS)


@pytest.mark.parametrize("header", ["42", "42.0", "4.2e1", "42.000"])
def test_param_integer_compared_numerically(header: str) -> None:
    validate_param_headers(HeaderView([("mcp-param-n", header)]), {"n": 42}, _ANNS)


def test_param_integer_float_body() -> None:
    validate_param_headers(HeaderView([("mcp-param-n", "42")]), {"n": 42.0}, _ANNS)


@pytest.mark.parametrize("header", ["43", "042", "+42", "42 ", "0x2a", "NaN", "forty-two", ""])
def test_param_integer_mismatch(header: str) -> None:
    _expect_mismatch(
        lambda: validate_param_headers(HeaderView([("mcp-param-n", header)]), {"n": 42}, _ANNS)
    )


def test_param_string_is_not_numeric() -> None:
    # A string body value is compared as a string even if it looks like a number.
    _expect_mismatch(
        lambda: validate_param_headers(
            HeaderView([("mcp-param-region", "42.0")]), {"region": "42"}, _ANNS
        )
    )


@pytest.mark.parametrize(
    ("pairs", "args"),
    [
        ([], {"region": "x"}),  # value in body, header missing
        ([("mcp-param-region", "y")], {"region": "x"}),  # mismatch
        ([("mcp-param-region", "x")], {}),  # header without body value
        ([("mcp-param-region", "x")], {"region": None}),  # header for null value
        ([("mcp-param-region", "x"), ("mcp-param-region", "x")], {"region": "x"}),  # dup
        ([("mcp-param-region", "x\x01")], {"region": "x\x01"}),  # raw control char
        ([("mcp-param-flag", "True")], {"flag": True}),  # booleans are lowercase
        ([("mcp-param-flag", "1")], {"flag": True}),
        ([("mcp-param-region", "{}")], {"region": {}}),  # unmirrorable body value
        ([("mcp-param-k", "a")], {"nested": {"k": "b"}}),
    ],
)
def test_param_header_rejections(pairs: list[tuple[str, str]], args: dict[str, Any]) -> None:
    _expect_mismatch(lambda: validate_param_headers(HeaderView(pairs), args, _ANNS))


def test_param_absent_and_null_need_no_header() -> None:
    validate_param_headers(HeaderView([]), {"region": None}, _ANNS)
    validate_param_headers(HeaderView([]), {}, _ANNS)
    validate_param_headers(HeaderView([]), None, _ANNS)


def test_round_trip_compute_then_validate() -> None:
    args = {"region": "=?base64?x?=", "n": -3, "flag": False, "nested": {"k": " sp "}}
    params = {"name": "t", "arguments": args}
    h = compute_request_headers("tools/call", params, protocol_version=V, annotations=_ANNS)
    view = HeaderView(h)
    validate_standard_headers(view, "tools/call", params, V)
    validate_param_headers(view, args, _ANNS)
