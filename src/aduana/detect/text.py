"""Extract every model-visible string, and normalise text for detectors.

Detectors only work on what they are shown, so extraction errs on the side of
too much: in a tool definition every string inside ``inputSchema`` and
``outputSchema`` is extracted (not only ``description``/``title``/``enum``/
``default``/``examples``/``const``), because clients typically serialise the
whole schema into the prompt and an attacker can put prose in ``pattern``,
``format`` or an unknown ``x-`` keyword just as well. Property names and
unknown keyword names are extracted too.

Everything here walks hostile input, so it is bounded: nesting depth, number
of strings and total characters. Hitting a bound sets ``Extraction.truncated``;
the caller decides what that means (the rule detector reports it).

Normalisation exists to defeat cheap obfuscation: zero-width characters inside
words, bidi controls, fullwidth or other compatibility forms (NFKC folds them),
and Unicode tag characters (U+E0000 block), which render as nothing but
spell ASCII. Tag text is decoded and returned separately so detectors can scan
the hidden message itself. The presence of any of these is reported, since in
a tool description it is a signal on its own.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from aduana.pipeline.types import JsonObject


@dataclass(frozen=True, slots=True)
class Limits:
    max_depth: int = 32
    max_strings: int = 10_000
    max_chars: int = 512_000


DEFAULT_LIMITS = Limits()


@dataclass(slots=True)
class Extraction:
    items: list[tuple[str, str]] = field(default_factory=list)
    #: A bound was hit; some input was not extracted.
    truncated: bool = False

    def __iter__(self) -> Iterator[tuple[str, str]]:
        return iter(self.items)


class _Collector:
    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.out = Extraction()
        self._chars = 0

    @property
    def full(self) -> bool:
        return (
            len(self.out.items) >= self.limits.max_strings or self._chars >= self.limits.max_chars
        )

    def add(self, location: str, text: str) -> None:
        if not text:
            return
        if self.full:
            self.out.truncated = True
            return
        room = self.limits.max_chars - self._chars
        if len(text) > room:
            text = text[:room]
            self.out.truncated = True
        self._chars += len(text)
        self.out.items.append((location, text))

    def too_deep(self, depth: int) -> bool:
        if depth > self.limits.max_depth:
            self.out.truncated = True
            return True
        return False


_PLAIN_KEY = re.compile(r"^[A-Za-z0-9_$-]{1,64}$")


def _seg(key: str) -> str:
    """A location segment for ``key``. Keys are attacker-chosen: keep them short."""
    if _PLAIN_KEY.match(key):
        return "." + key
    return "[" + escape_control(json.dumps(key[:64], ensure_ascii=False)) + "]"


def _walk_value(value: Any, path: str, c: _Collector, depth: int, *, keys: bool) -> None:
    """Every string leaf (and, if ``keys``, every object key) of a JSON value."""
    if c.full:
        c.out.truncated = True
        return
    if c.too_deep(depth):
        return
    if isinstance(value, str):
        c.add(path, value)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                continue
            sub = path + _seg(k)
            if keys:
                c.add(sub + "#key", k)
            _walk_value(v, sub, c, depth + 1, keys=keys)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _walk_value(v, f"{path}[{i}]", c, depth + 1, keys=keys)


# Keywords whose value maps names to subschemas.
_NAMED_SUBSCHEMAS = frozenset(
    {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"}
)
# Keywords whose value is one subschema.
_SUBSCHEMA = frozenset(
    {
        "items",
        "additionalItems",
        "additionalProperties",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "not",
        "if",
        "then",
        "else",
        "contentSchema",
    }
)
# Keywords whose value is a list of subschemas.
_SUBSCHEMA_LIST = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
# Other standard 2020-12 keywords. Anything else is an unknown keyword, whose
# *name* is extracted as text as well.
_KNOWN = (
    _NAMED_SUBSCHEMAS
    | _SUBSCHEMA
    | _SUBSCHEMA_LIST
    | frozenset(
        {
            "$schema",
            "$id",
            "$ref",
            "$anchor",
            "$dynamicRef",
            "$dynamicAnchor",
            "$vocabulary",
            "$comment",
            "type",
            "enum",
            "const",
            "default",
            "examples",
            "title",
            "description",
            "format",
            "pattern",
            "required",
            "dependentRequired",
            "minimum",
            "maximum",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
            "minLength",
            "maxLength",
            "minItems",
            "maxItems",
            "uniqueItems",
            "minContains",
            "maxContains",
            "minProperties",
            "maxProperties",
            "contentEncoding",
            "contentMediaType",
            "readOnly",
            "writeOnly",
            "deprecated",
        }
    )
)


def _walk_schema(schema: Any, path: str, c: _Collector, depth: int) -> None:
    if c.full:
        c.out.truncated = True
        return
    if c.too_deep(depth):
        return
    if not isinstance(schema, dict):
        # A boolean schema has no text; anything else is malformed but may
        # still be shown to the model, so extract its strings.
        _walk_value(schema, path, c, depth, keys=True)
        return
    for key, value in schema.items():
        if not isinstance(key, str):
            continue
        sub = path + _seg(key)
        if key in _NAMED_SUBSCHEMAS and isinstance(value, dict):
            for name, subschema in value.items():
                if not isinstance(name, str):
                    continue
                named = sub + _seg(name)
                c.add(named, name)
                _walk_schema(subschema, named, c, depth + 1)
        elif key in _SUBSCHEMA:
            _walk_schema(value, sub, c, depth + 1)
        elif key in _SUBSCHEMA_LIST and isinstance(value, list):
            for i, subschema in enumerate(value):
                _walk_schema(subschema, f"{sub}[{i}]", c, depth + 1)
        else:
            if key not in _KNOWN:
                c.add(sub + "#key", key)
            _walk_value(value, sub, c, depth + 1, keys=key not in _KNOWN)


def extract_tool_text(tool: JsonObject, limits: Limits = DEFAULT_LIMITS) -> Extraction:
    """Model-visible strings of a tool definition. ``icons`` and ``_meta`` are skipped."""
    c = _Collector(limits)
    for key in ("name", "title", "description"):
        value = tool.get(key)
        if isinstance(value, str):
            c.add(key, value)
    for key in ("inputSchema", "outputSchema"):
        if key in tool:
            _walk_schema(tool[key], key, c, 1)
    if isinstance(tool.get("annotations"), dict):
        _walk_value(tool["annotations"], "annotations", c, 1, keys=False)
    return c.out


def extract_result_text(result: JsonObject, limits: Limits = DEFAULT_LIMITS) -> Extraction:
    """Attacker-controllable strings of a ``tools/call`` result.

    Binary payloads (``image``/``audio`` data, ``resource.blob``) are not text
    the model reads as prose and are skipped.
    """
    c = _Collector(limits)
    content = result.get("content")
    if isinstance(content, list):
        for i, block in enumerate(content):
            if c.full:
                c.out.truncated = True
                break
            if not isinstance(block, dict):
                continue
            base = f"content[{i}]"
            kind = block.get("type")
            if kind == "text":
                if isinstance(block.get("text"), str):
                    c.add(base + ".text", block["text"])
            elif kind == "resource":
                res = block.get("resource")
                if isinstance(res, dict):
                    for key in ("text", "uri"):
                        if isinstance(res.get(key), str):
                            c.add(f"{base}.resource.{key}", res[key])
            elif kind == "resource_link":
                for key in ("name", "title", "description", "uri"):
                    if isinstance(block.get(key), str):
                        c.add(f"{base}.{key}", block[key])
    if "structuredContent" in result:
        _walk_value(result["structuredContent"], "structuredContent", c, 1, keys=True)
    return c.out


def iter_string_leaves(
    value: Any, path: str, limits: Limits = DEFAULT_LIMITS, *, keys: bool = False
) -> Extraction:
    """Bounded string leaves of any JSON value (used for call arguments)."""
    c = _Collector(limits)
    _walk_value(value, path, c, 1, keys=keys)
    return c.out


# --- normalisation --------------------------------------------------------

_ZERO_WIDTH = frozenset(
    [
        *(0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, 0x3164, 0xFEFF, 0xFFA0),
        *range(0x200B, 0x200F + 1),  # ZWSP, ZWNJ, ZWJ, LRM, RLM
        *range(0x2060, 0x2064 + 1),  # word joiner, invisible operators
    ]
)
_BIDI = frozenset(list(range(0x202A, 0x202E + 1)) + list(range(0x2066, 0x2069 + 1)))
_TAG_FIRST, _TAG_LAST = 0xE0000, 0xE007F
_VS_SUPPLEMENT = range(0xE0100, 0xE01EF + 1)

_WHITESPACE = re.compile(r"\s+")
# ANSI escape sequences (CSI and OSC), which terminals render as nothing.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]{0,256}(?:\x07|\x1b\\)?")
_LAYOUT_CONTROLS = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D})


def _hidden_class(cp: int) -> str | None:
    if _TAG_FIRST <= cp <= _TAG_LAST:
        return "tag"
    if cp in _BIDI:
        return "bidi"
    if cp in _ZERO_WIDTH:
        return "zero_width"
    if cp in _VS_SUPPLEMENT:
        return "variation_selector"
    if (cp < 0x20 and cp not in _LAYOUT_CONTROLS) or 0x7F <= cp <= 0x9F:
        return "control"
    return None


@dataclass(frozen=True, slots=True)
class Normalized:
    text: str
    #: Count of hidden characters per class: ``tag``, ``bidi``, ``zero_width``,
    #: ``variation_selector``, ``control`` (C0/C1 controls and ANSI escapes).
    hidden: dict[str, int]
    #: ASCII spelled by Unicode tag characters, if any.
    tag_payload: str = ""

    @property
    def has_hidden(self) -> bool:
        return bool(self.hidden)


def normalize(text: str) -> Normalized:
    """Strip ANSI escapes and hidden characters, NFKC, collapse whitespace."""
    hidden: dict[str, int] = {}
    kept: list[str] = []
    tags: list[str] = []
    text, ansi = _ANSI.subn("", text)
    if ansi:
        hidden["control"] = ansi
    for ch in text:
        cp = ord(ch)
        cls = _hidden_class(cp)
        if cls is None:
            kept.append(ch)
            continue
        hidden[cls] = hidden.get(cls, 0) + 1
        if cls == "tag" and 0xE0020 <= cp <= 0xE007E:
            tags.append(chr(cp - _TAG_FIRST))
    folded = unicodedata.normalize("NFKC", "".join(kept))
    # NFKC can in principle reintroduce nothing hidden from the sets above, but
    # strip again cheaply in case a compatibility mapping produced one.
    folded = "".join(ch for ch in folded if _hidden_class(ord(ch)) is None)
    collapsed = _WHITESPACE.sub(" ", folded).strip()
    return Normalized(collapsed, hidden, "".join(tags))


def is_hidden_char(ch: str) -> bool:
    return _hidden_class(ord(ch)) is not None


def escape_control(text: str) -> str:
    """Make ``text`` safe to show in a log: escape anything non-printable or hidden."""
    out: list[str] = []
    for ch in text:
        if ch.isprintable() and not is_hidden_char(ch):
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}")
    return "".join(out)


def excerpt(text: str, start: int, end: int, limit: int = 120) -> str:
    """Up to ``limit`` characters around ``text[start:end]``, control chars escaped."""
    # Escape the three parts separately so escaping (which lengthens text)
    # never pushes the match itself out of the excerpt.
    mid = escape_control(text[start:end])
    if len(mid) >= limit - 2:
        return mid[: limit - 1] + "…"
    room = limit - len(mid) - 2  # two ellipses at most
    pre = escape_control(text[max(0, start - room) : start])
    post = escape_control(text[end : end + room])
    pre = pre[-(room // 2) :] if room // 2 else ""
    post = post[: room - len(pre)]
    lead = "…" if start - len(pre) > 0 else ""
    tail = "…" if end + len(post) < len(text) else ""
    return lead + pre + mid + post + tail
