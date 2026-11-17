"""Canonical hashing of tool definitions.

What is hashed: the fields that change what the model reads or what the tool
accepts and returns: ``name``, ``title``, ``description``, ``inputSchema``,
``outputSchema``, ``annotations``. ``annotations`` is included because hints
like ``readOnlyHint`` steer clients' approval UX; flipping one is a rug pull.

What is not: ``icons`` (presentation; icon URLs are commonly cache-busted, which
would cause drift noise) and ``_meta`` (protocol plumbing, free to change).
Unknown extra fields are also ignored, which means a future spec field that is
model-visible must be added here explicitly.

Canonical form: JSON with sorted keys, ``(",", ":")`` separators, UTF-8 bytes,
``ensure_ascii=False`` (so the bytes are the text, not escapes of it), and no
NaN/Infinity (they are not JSON; ``ValueError`` is raised and the stage fails
closed). An absent field and ``null`` hash the same: both mean "not provided".
Numbers hash as Python serialises them, so ``1`` and ``1.0`` differ; an upstream
re-sending the same JSON text always gets the same hash, which is what pinning
needs. Hashes are written ``sha256:<hex>`` so the algorithm can change later.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from aduana.pipeline.types import JsonObject

HASHED_FIELDS: tuple[str, ...] = (
    "name",
    "title",
    "description",
    "inputSchema",
    "outputSchema",
    "annotations",
)

PREFIX = "sha256:"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return PREFIX + hashlib.sha256(canonical_json(value)).hexdigest()


def security_view(tool: JsonObject) -> JsonObject:
    """The hashed projection of ``tool``, absent fields filled with ``None``."""
    return {field: tool.get(field) for field in HASHED_FIELDS}


def tool_hash(tool: JsonObject) -> str:
    return _digest(security_view(tool))


def field_hashes(tool: JsonObject) -> dict[str, str]:
    """One hash per hashed field, so drift can name what changed."""
    return {field: _digest(value) for field, value in security_view(tool).items()}


def changed_fields(old: dict[str, str], new: dict[str, str]) -> list[str]:
    """Fields whose hash differs, in ``HASHED_FIELDS`` order.

    A field missing from ``old`` (e.g. an older lockfile) counts as changed.
    """
    return [f for f in HASHED_FIELDS if old.get(f) != new.get(f)]
