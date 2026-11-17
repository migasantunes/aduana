"""The pin lockfile and the pinning tool stage.

The lockfile is meant to be committed and reviewed like a package lock: JSON,
two-space indented, keys sorted, one tool per block, so a changed description
shows up as a one-line diff of its field hash::

    {"version": 1, "upstreams": {"<upstream>": {"<tool>": {"hash": "...", "fields": {...}}}}}

Writes are atomic (temp file in the same directory, then ``os.replace``) so a
crash mid-write never leaves a truncated lockfile that would unpin everything.
A missing lockfile loads as empty: in ``enforce`` mode that means nothing is
exposed until the operator runs ``aduana pin``, which is the safe reading.
A *malformed* lockfile raises: silently treating it as empty would hide the
problem behind a wall of "unpinned" findings.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from aduana.pinning.hashing import HASHED_FIELDS, changed_fields, field_hashes, tool_hash
from aduana.pipeline.types import Action, Category, Decision, Finding, JsonObject, Severity

LOCKFILE_VERSION = 1
DETECTOR = "pinning"

REASON_UNPINNED = "tool definition is not pinned"
REASON_CHANGED = "tool definition changed since it was pinned"


class LockfileError(ValueError):
    """The lockfile exists but is not a valid version-1 lockfile."""


@dataclass(frozen=True, slots=True)
class PinnedTool:
    hash: str
    fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def of(cls, tool: JsonObject) -> PinnedTool:
        return cls(hash=tool_hash(tool), fields=field_hashes(tool))

    def to_json(self) -> JsonObject:
        return {"hash": self.hash, "fields": dict(sorted(self.fields.items()))}


def _parse(raw: Any, path: Path) -> dict[str, dict[str, PinnedTool]]:
    if not isinstance(raw, dict) or raw.get("version") != LOCKFILE_VERSION:
        raise LockfileError(f"{path}: not a version {LOCKFILE_VERSION} aduana lockfile")
    upstreams = raw.get("upstreams", {})
    if not isinstance(upstreams, dict):
        raise LockfileError(f"{path}: 'upstreams' must be an object")
    pins: dict[str, dict[str, PinnedTool]] = {}
    for upstream, tools in upstreams.items():
        if not isinstance(tools, dict):
            raise LockfileError(f"{path}: upstream {upstream!r} must map tool names to pins")
        entry: dict[str, PinnedTool] = {}
        for name, pin in tools.items():
            if not (
                isinstance(pin, dict)
                and isinstance(pin.get("hash"), str)
                and isinstance(pin.get("fields", {}), dict)
                and all(isinstance(v, str) for v in pin.get("fields", {}).values())
            ):
                raise LockfileError(f"{path}: malformed pin for {upstream!r}/{name!r}")
            entry[name] = PinnedTool(hash=pin["hash"], fields=dict(pin.get("fields", {})))
        pins[upstream] = entry
    return pins


class PinStore:
    """In-memory view of the lockfile. Safe to share between threads."""

    def __init__(self, path: Path, pins: dict[str, dict[str, PinnedTool]] | None = None) -> None:
        self.path = Path(path)
        self._pins: dict[str, dict[str, PinnedTool]] = pins or {}
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path: str | Path) -> PinStore:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except FileNotFoundError:
            return cls(p)
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LockfileError(f"{p}: invalid JSON") from exc
        return cls(p, _parse(raw, p))

    def get(self, upstream: str, tool: str) -> PinnedTool | None:
        with self._lock:
            return self._pins.get(upstream, {}).get(tool)

    def upstreams(self) -> dict[str, dict[str, PinnedTool]]:
        with self._lock:
            return {u: dict(t) for u, t in self._pins.items()}

    def pin(self, upstream: str, tools: Iterable[JsonObject]) -> dict[str, PinnedTool]:
        """Record the current definitions of ``upstream``'s tools.

        Replaces the upstream's whole entry: a tool the upstream no longer
        lists is unpinned, so if it reappears later it is "unknown", not
        silently trusted. Does not write; call ``save``.
        """
        entry: dict[str, PinnedTool] = {}
        for tool in tools:
            name = tool.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("every tool to pin needs a non-empty string 'name'")
            entry[name] = PinnedTool.of(tool)
        with self._lock:
            self._pins[upstream] = entry
        return dict(entry)

    def to_json(self) -> JsonObject:
        with self._lock:
            return {
                "version": LOCKFILE_VERSION,
                "upstreams": {
                    u: {name: pin.to_json() for name, pin in sorted(tools.items())}
                    for u, tools in sorted(self._pins.items())
                },
            }

    def save(self) -> None:
        text = json.dumps(self.to_json(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        directory = self.path.parent
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", suffix=".tmp", dir=directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp)
            raise


def pin(lockfile: str | Path, upstream: str, tools: Iterable[JsonObject]) -> PinStore:
    """Load ``lockfile``, pin ``upstream``'s ``tools``, write it back atomically."""
    store = PinStore.load(lockfile)
    store.pin(upstream, tools)
    store.save()
    return store


class PinningStage:
    """``ToolStage`` comparing each definition with its pin.

    ``enforce``: unknown or changed tools are denied (quarantined from the
    catalog). ``warn``: same findings, tool still exposed. Finding messages name
    the changed *fields* (our own vocabulary), never upstream text.
    """

    name = "pinning"

    def __init__(self, store: PinStore, mode: Literal["warn", "enforce"] = "warn") -> None:
        if mode not in ("warn", "enforce"):
            raise ValueError(f"unsupported pinning mode {mode!r}")
        self.store = store
        self.mode = mode

    async def on_tool(self, upstream: str, tool: JsonObject) -> Decision | None:
        return self.check(upstream, tool)

    def check(self, upstream: str, tool: JsonObject) -> Decision | None:
        name = tool.get("name")
        pinned = self.store.get(upstream, name) if isinstance(name, str) else None

        if pinned is None:
            finding = Finding(
                detector=DETECTOR,
                category=Category.RUG_PULL,
                severity=Severity.MEDIUM,
                message="tool is not in the lockfile",
                location="tool",
            )
            return self._verdict(REASON_UNPINNED, finding)

        current = tool_hash(tool)
        if current == pinned.hash:
            return None

        changed = changed_fields(pinned.fields, field_hashes(tool)) or list(HASHED_FIELDS)
        finding = Finding(
            detector=DETECTOR,
            category=Category.RUG_PULL,
            severity=Severity.HIGH,
            message="tool definition changed since pinned: " + ", ".join(changed),
            evidence=", ".join(changed),
            location=",".join(changed),
        )
        return self._verdict(REASON_CHANGED, finding)

    def _verdict(self, reason: str, finding: Finding) -> Decision:
        if self.mode == "enforce":
            return Decision.deny(reason, [finding])
        return Decision(action=Action.ALLOW, findings=[finding])
