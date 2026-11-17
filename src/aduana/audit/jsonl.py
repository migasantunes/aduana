"""JSON Lines audit sink.

One object per line so the log can be tailed, grepped and loaded with
``pandas.read_json(lines=True)``. Output is ASCII-only JSON
(``ensure_ascii=True``): upstream text inside evidence may contain bidi
controls or terminal escapes, and escaping them keeps a ``tail -f`` of the log
from being a display-spoofing surface.

``emit`` never raises: the audit log failing must not take the request path
down with it (``AuditSink`` contract). Failures are counted in ``errors`` so a
health check can surface them.
"""

from __future__ import annotations

import json
import sys
import threading
from dataclasses import fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from aduana.pipeline.types import AuditEvent, AuditSink

if TYPE_CHECKING:
    from aduana.config import Config

#: Defensive cap on evidence in the log, in case a stage forgot to truncate.
MAX_EVIDENCE_CHARS = 240


def _jsonable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: _jsonable(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, (list, tuple, frozenset, set)):
        items = sorted(value) if isinstance(value, (set, frozenset)) else value
        return [_jsonable(v) for v in items]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        return None
    return value


def event_to_dict(event: AuditEvent) -> dict[str, Any]:
    data: dict[str, Any] = _jsonable(event)
    for finding in data.get("findings", []):
        ev = finding.get("evidence")
        if isinstance(ev, str) and len(ev) > MAX_EVIDENCE_CHARS:
            finding["evidence"] = ev[: MAX_EVIDENCE_CHARS - 1] + "…"
    return data


def event_to_line(event: AuditEvent) -> str:
    return json.dumps(event_to_dict(event), ensure_ascii=True, separators=(",", ":"), default=str)


class JsonlAuditSink:
    """Append audit events to ``path``, or to stderr when ``path`` is ``None``."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path is not None else None
        self.errors = 0
        self._lock = threading.Lock()
        self._fh: IO[str] | None = None
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8", buffering=1)

    def _stream(self) -> IO[str]:
        # stderr is looked up per write so redirection (and pytest capture) works.
        return self._fh if self._fh is not None else sys.stderr

    def emit(self, event: AuditEvent) -> None:
        try:
            line = event_to_line(event) + "\n"
            with self._lock:
                stream = self._stream()
                stream.write(line)
                stream.flush()
        except Exception:
            # Never into the request path. The lock is released by ``with``.
            self.errors += 1

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                try:
                    self._fh.close()
                finally:
                    self._fh = None

    def __enter__(self) -> JsonlAuditSink:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def build_audit_sink(config: Config) -> AuditSink:
    return JsonlAuditSink(config.audit.path)
