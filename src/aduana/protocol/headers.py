"""Mirrored request headers (Streamable HTTP, 2026-07-28) and the base64 sentinel.

The transport copies selected body fields into headers so intermediaries can route without
parsing JSON. That only stays safe if every party that reads the body also checks that the
headers agree with it: otherwise a load balancer routes on one value while the server
executes another. This module computes the headers for requests aduana sends and validates
the ones it receives.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any

from aduana.protocol.errors import header_mismatch, invalid_params

JsonObject = dict[str, Any]

PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
METHOD_HEADER = "Mcp-Method"
NAME_HEADER = "Mcp-Name"
PARAM_HEADER_PREFIX = "Mcp-Param-"

#: Methods that require ``Mcp-Name`` and the params field it mirrors.
NAME_SOURCE_FIELD: dict[str, str] = {
    "tools/call": "name",
    "resources/read": "uri",
    "prompts/get": "name",
}

X_MCP_HEADER = "x-mcp-header"

SENTINEL_PREFIX = "=?base64?"
SENTINEL_SUFFIX = "?="

# RFC 9110 tchar.
_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# JSON number grammar, for numeric header comparison.
_JSON_NUMBER = re.compile(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$")

_ALLOWED_TYPES = frozenset({"string", "integer", "boolean"})

# Schema keywords whose values are data, not subschemas.
_DATA_KEYWORDS = frozenset({"const", "default", "enum", "examples", "required"})
# Keywords whose value maps names to subschemas (the keys are names, not keywords).
_NAMED_SCHEMA_MAPS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)


class HeaderValueError(ValueError):
    """A header value that is not valid on the wire (bad characters, bad sentinel)."""


class InvalidToolHeaders(ValueError):
    """A tool definition whose ``x-mcp-header`` annotations violate the spec constraints.

    The message is gateway-authored and may name a JSON path; it never contains values from
    the tool definition other than property names.
    """


# --------------------------------------------------------------------------- sentinel


def _is_plain_char(ch: str) -> bool:
    o = ord(ch)
    return 0x21 <= o <= 0x7E or ch in (" ", "\t")


def looks_like_sentinel(value: str) -> bool:
    return value.startswith(SENTINEL_PREFIX) and value.endswith(SENTINEL_SUFFIX)


def needs_encoding(value: str) -> bool:
    """True when ``value`` cannot travel as a plain header value."""
    if not all(_is_plain_char(ch) for ch in value):
        return True
    if value and (value[0] in " \t" or value[-1] in " \t"):
        return True
    return looks_like_sentinel(value)


def encode_header_value(value: str) -> str:
    if not needs_encoding(value):
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"{SENTINEL_PREFIX}{encoded}{SENTINEL_SUFFIX}"


def decode_header_value(raw: str) -> str:
    """Decode a received ``Mcp-Name`` / ``Mcp-Param-*`` value.

    Raises ``HeaderValueError`` for characters outside the RFC 9110 field-value set or for a
    malformed sentinel. Markers are case-sensitive, so ``=?BASE64?...?=`` is a plain value.
    """
    if not all(_is_plain_char(ch) for ch in raw):
        raise HeaderValueError("header value contains invalid characters")
    if not looks_like_sentinel(raw):
        return raw
    if len(raw) < len(SENTINEL_PREFIX) + len(SENTINEL_SUFFIX):
        raise HeaderValueError("malformed base64 sentinel")
    payload = raw[len(SENTINEL_PREFIX) : len(raw) - len(SENTINEL_SUFFIX)]
    try:
        data = base64.b64decode(payload, validate=True)
        return data.decode("utf-8")
    except (binascii.Error, ValueError) as exc:
        raise HeaderValueError("malformed base64 sentinel") from exc


# --------------------------------------------------------------------------- values


def header_string(value: Any) -> str | None:
    """Type conversion from the spec: string as-is, integer in decimal, boolean lowercase.

    ``None`` means "no header" (value absent or JSON ``null``). Raises ``ValueError`` for a
    value that cannot be mirrored (object, array, non-integral number).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer():
            return str(int(value))
        raise ValueError("non-integral number cannot be mirrored")
    if isinstance(value, str):
        return value
    raise ValueError("value of this type cannot be mirrored")


def _header_matches_body(decoded: str, body_value: Any) -> bool:
    """Compare a decoded header with the body value; numbers compare numerically."""
    if isinstance(body_value, bool):
        return decoded == ("true" if body_value else "false")
    if isinstance(body_value, int | float):
        if not _JSON_NUMBER.match(decoded):
            return False
        try:
            return Decimal(decoded) == Decimal(body_value)
        except InvalidOperation:
            return False
    if isinstance(body_value, str):
        return decoded == body_value
    return False


# --------------------------------------------------------------------------- x-mcp-header


@dataclass(frozen=True, slots=True)
class HeaderAnnotation:
    """One ``x-mcp-header`` annotation: header ``Mcp-Param-{name}`` mirrors ``path``."""

    name: str
    #: Chain of ``properties`` keys from the schema root to the annotated property.
    path: tuple[str, ...]
    type: str

    @property
    def header_name(self) -> str:
        return f"{PARAM_HEADER_PREFIX}{self.name}"


def _all_annotated_nodes(schema: Any, out: list[int], depth: int = 0) -> None:
    """Collect ``id()`` of every schema node carrying ``x-mcp-header`` anywhere."""
    if depth > 64:
        raise InvalidToolHeaders("inputSchema is nested too deeply")
    if isinstance(schema, list):
        for item in schema:
            _all_annotated_nodes(item, out, depth + 1)
        return
    if not isinstance(schema, dict):
        return
    if X_MCP_HEADER in schema:
        out.append(id(schema))
    for key, value in schema.items():
        if key in _DATA_KEYWORDS or key == X_MCP_HEADER:
            continue
        if key in _NAMED_SCHEMA_MAPS and isinstance(value, dict):
            for sub in value.values():
                _all_annotated_nodes(sub, out, depth + 1)
        else:
            _all_annotated_nodes(value, out, depth + 1)


def _annotation_type(node: JsonObject, where: str) -> str:
    t = node.get("type")
    if isinstance(t, str):
        types = [t]
    elif isinstance(t, list) and all(isinstance(x, str) for x in t):
        types = [x for x in t if x != "null"]
    else:
        raise InvalidToolHeaders(f"{where}: annotated property must declare a primitive type")
    if len(types) != 1 or types[0] not in _ALLOWED_TYPES:
        raise InvalidToolHeaders(
            f"{where}: x-mcp-header only applies to string, integer or boolean properties"
        )
    return types[0]


def header_annotations(input_schema: Any) -> tuple[HeaderAnnotation, ...]:
    """Validate and return the ``x-mcp-header`` annotations of a tool's ``inputSchema``.

    Raises ``InvalidToolHeaders`` when any constraint from the spec is violated; the caller
    must then drop the tool from the catalog.
    """
    if input_schema is None:
        return ()
    if not isinstance(input_schema, dict):
        raise InvalidToolHeaders("inputSchema is not an object")

    reachable: list[tuple[JsonObject, tuple[str, ...]]] = []

    def walk(node: JsonObject, path: tuple[str, ...], depth: int) -> None:
        if depth > 64:
            raise InvalidToolHeaders("inputSchema is nested too deeply")
        props = node.get("properties")
        if not isinstance(props, dict):
            return
        for prop_name, sub in props.items():
            if not isinstance(sub, dict):
                continue
            sub_path = (*path, prop_name)
            if X_MCP_HEADER in sub:
                reachable.append((sub, sub_path))
            walk(sub, sub_path, depth + 1)

    walk(input_schema, (), 0)

    every: list[int] = []
    _all_annotated_nodes(input_schema, every)
    reachable_ids = {id(node) for node, _ in reachable}
    if any(node_id not in reachable_ids for node_id in every):
        raise InvalidToolHeaders(
            "x-mcp-header is only allowed on properties reachable through 'properties' alone"
        )

    seen: set[str] = set()
    result: list[HeaderAnnotation] = []
    for node, path in reachable:
        where = "/".join(path)
        name = node[X_MCP_HEADER]
        if not isinstance(name, str) or not name:
            raise InvalidToolHeaders(f"{where}: x-mcp-header must be a non-empty string")
        if not _TOKEN.match(name):
            raise InvalidToolHeaders(f"{where}: x-mcp-header is not a valid HTTP token")
        folded = name.lower()
        if folded in seen:
            raise InvalidToolHeaders(f"{where}: x-mcp-header is not unique (case-insensitive)")
        seen.add(folded)
        result.append(HeaderAnnotation(name=name, path=path, type=_annotation_type(node, where)))
    return tuple(result)


def tool_header_annotations(tool: JsonObject) -> tuple[HeaderAnnotation, ...]:
    return header_annotations(tool.get("inputSchema"))


def value_at_path(arguments: Any, path: tuple[str, ...]) -> Any:
    """Instance value at a chain of property names; ``None`` when absent."""
    current = arguments
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


# --------------------------------------------------------------------------- outbound


def compute_request_headers(
    method: str,
    params: JsonObject,
    *,
    protocol_version: str,
    annotations: Iterable[HeaderAnnotation] = (),
) -> dict[str, str]:
    """All mirrored headers for a request aduana sends.

    Raises ``ValueError`` when a mirrored value cannot be represented (e.g. an object where
    the schema says string).
    """
    headers = {PROTOCOL_VERSION_HEADER: protocol_version, METHOD_HEADER: method}
    source = NAME_SOURCE_FIELD.get(method)
    if source is not None:
        name = params.get(source)
        if not isinstance(name, str):
            raise ValueError(f"params.{source} must be a string for {method}")
        headers[NAME_HEADER] = encode_header_value(name)
    if method == "tools/call":
        arguments = params.get("arguments")
        for ann in annotations:
            text = header_string(value_at_path(arguments, ann.path))
            if text is not None:
                headers[ann.header_name] = encode_header_value(text)
    return headers


# --------------------------------------------------------------------------- inbound


class HeaderView:
    """Case-insensitive, duplicate-aware view of received headers."""

    def __init__(self, pairs: Iterable[tuple[str, str]] | Mapping[str, str]) -> None:
        items = pairs.items() if isinstance(pairs, Mapping) else pairs
        self._values: dict[str, list[str]] = {}
        for key, value in items:
            self._values.setdefault(key.lower(), []).append(value)

    def get_single(self, name: str) -> str | None:
        """The value of ``name``; a repeated mirrored header is itself a mismatch."""
        values = self._values.get(name.lower())
        if not values:
            return None
        if len(values) > 1:
            raise header_mismatch(f"{name} header appears more than once")
        return values[0]

    def has(self, name: str) -> bool:
        return name.lower() in self._values


def validate_standard_headers(
    headers: HeaderView,
    method: str,
    params: JsonObject,
    protocol_version: str,
) -> None:
    """``MCP-Protocol-Version``, ``Mcp-Method`` and ``Mcp-Name`` against the body.

    Raises ``McpError`` ``-32020`` on any missing, malformed or mismatched header, and
    ``-32602`` if the body field that ``Mcp-Name`` mirrors is not a string.
    """
    version = headers.get_single(PROTOCOL_VERSION_HEADER)
    if version is None:
        raise header_mismatch(f"{PROTOCOL_VERSION_HEADER} header is required")
    if version != protocol_version:
        raise header_mismatch(f"{PROTOCOL_VERSION_HEADER} header does not match the body")

    got_method = headers.get_single(METHOD_HEADER)
    if got_method is None:
        raise header_mismatch(f"{METHOD_HEADER} header is required")
    if got_method != method:
        raise header_mismatch(f"{METHOD_HEADER} header does not match the body")

    source = NAME_SOURCE_FIELD.get(method)
    if source is None:
        return
    body_name = params.get(source)
    if not isinstance(body_name, str):
        raise invalid_params(f"params.{source} must be a string")
    raw = headers.get_single(NAME_HEADER)
    if raw is None:
        raise header_mismatch(f"{NAME_HEADER} header is required for {method}")
    try:
        decoded = decode_header_value(raw)
    except HeaderValueError as exc:
        raise header_mismatch(f"{NAME_HEADER} header is malformed") from exc
    if decoded != body_name:
        raise header_mismatch(f"{NAME_HEADER} header does not match the body")


def validate_param_headers(
    headers: HeaderView,
    arguments: Any,
    annotations: Iterable[HeaderAnnotation],
) -> None:
    """``Mcp-Param-*`` headers for the annotated parameters of the target tool.

    A value present in the body requires its header. A header sent for a parameter that is
    absent or ``null`` in the body is also rejected: a router may have acted on it.
    Unannotated ``Mcp-Param-*`` headers are ignored (aduana does not forward client headers).
    """
    for ann in annotations:
        body_value = value_at_path(arguments, ann.path)
        raw = headers.get_single(ann.header_name)
        if body_value is None:
            if raw is not None:
                raise header_mismatch(f"{ann.header_name} header has no value in the body")
            continue
        try:
            header_string(body_value)
        except ValueError as exc:
            raise header_mismatch(f"{ann.header_name} body value cannot be mirrored") from exc
        if raw is None:
            raise header_mismatch(f"{ann.header_name} header is required")
        try:
            decoded = decode_header_value(raw)
        except HeaderValueError as exc:
            raise header_mismatch(f"{ann.header_name} header is malformed") from exc
        if not _header_matches_body(decoded, body_value):
            raise header_mismatch(f"{ann.header_name} header does not match the body")


__all__ = [
    "METHOD_HEADER",
    "NAME_HEADER",
    "NAME_SOURCE_FIELD",
    "PARAM_HEADER_PREFIX",
    "PROTOCOL_VERSION_HEADER",
    "SENTINEL_PREFIX",
    "SENTINEL_SUFFIX",
    "X_MCP_HEADER",
    "HeaderAnnotation",
    "HeaderValueError",
    "HeaderView",
    "InvalidToolHeaders",
    "compute_request_headers",
    "decode_header_value",
    "encode_header_value",
    "header_annotations",
    "header_string",
    "looks_like_sentinel",
    "needs_encoding",
    "tool_header_annotations",
    "validate_param_headers",
    "validate_standard_headers",
    "value_at_path",
]
