"""Aggregated, namespaced, vetted tool catalog over all upstreams.

Quarantine happens here, at catalog time: a tool that fails a tool stage never reaches the
model, so its description cannot steer the model, and since routing only resolves names in
this catalog it cannot be called by name either.
"""

from __future__ import annotations

import asyncio
import contextlib
import copy
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import aduana
from aduana.config import TOOL_NAMESPACE_SEP
from aduana.pipeline.types import (
    Action,
    AuditEvent,
    AuditSink,
    Category,
    Decision,
    Finding,
    JsonObject,
    Pipeline,
    Severity,
)
from aduana.protocol.headers import HeaderAnnotation, InvalidToolHeaders, tool_header_annotations
from aduana.protocol.meta import META, build_upstream_meta
from aduana.upstream.client import UpstreamClient, UpstreamError, UpstreamProtocolError

TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,128}$")
MAX_TOOL_NAME = 128
DEFAULT_MAX_PAGES = 100

#: ``subject`` recorded on audit events the gateway raises on its own behalf.
GATEWAY_SUBJECT = "gateway"


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    """One exposed tool and everything needed to route a call to it."""

    exposed_name: str
    upstream: str
    #: The tool's name as the upstream knows it.
    tool_name: str
    #: The upstream's definition, untouched. Used for outbound header mirroring.
    original: JsonObject
    #: What agents see: renamed, and replaced by a tool stage's payload on REDACT.
    exposed: JsonObject
    upstream_headers: tuple[HeaderAnnotation, ...] = ()
    exposed_headers: tuple[HeaderAnnotation, ...] = ()


@dataclass(frozen=True, slots=True)
class CatalogListing:
    tools: tuple[CatalogEntry, ...]
    #: Advertised ``ttlMs``: time until the earliest per-upstream cache expires.
    ttl_ms: int
    #: Upstreams left out of this listing because they failed.
    failed: tuple[str, ...] = ()

    def tool_definitions(self) -> list[JsonObject]:
        return [copy.deepcopy(e.exposed) for e in self.tools]


@dataclass(slots=True)
class _Cached:
    entries: dict[str, CatalogEntry]
    expires_at: float


@dataclass(slots=True)
class _UpstreamState:
    client: UpstreamClient
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    cached: _Cached | None = None


def split_exposed_name(exposed_name: str) -> tuple[str, str] | None:
    """``<upstream>__<tool>`` → (upstream, tool). Upstream names cannot contain ``__``."""
    upstream, sep, tool = exposed_name.partition(TOOL_NAMESPACE_SEP)
    if not sep or not upstream or not tool:
        return None
    return upstream, tool


class Catalog:
    def __init__(
        self,
        clients: Iterable[UpstreamClient],
        pipeline: Pipeline,
        audit: AuditSink,
        *,
        max_ttl_ms: int,
        protocol_version: str = aduana.SUPPORTED_PROTOCOL_VERSIONS[0],
        max_pages: int = DEFAULT_MAX_PAGES,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._upstreams: dict[str, _UpstreamState] = {c.name: _UpstreamState(c) for c in clients}
        self._pipeline = pipeline
        self._audit = audit
        self._max_ttl_ms = max_ttl_ms
        self._protocol_version = protocol_version
        self._max_pages = max_pages
        self._clock = clock
        self._wall = wall_clock

    @property
    def upstream_names(self) -> tuple[str, ...]:
        return tuple(self._upstreams)

    def invalidate(self, upstream: str | None = None) -> None:
        for name, state in self._upstreams.items():
            if upstream is None or name == upstream:
                state.cached = None

    async def list_tools(self) -> CatalogListing:
        names = list(self._upstreams)
        results = await asyncio.gather(*(self._load(n) for n in names), return_exceptions=True)
        entries: list[CatalogEntry] = []
        failed: list[str] = []
        expiries: list[float] = []
        for name, res in zip(names, results, strict=True):
            if isinstance(res, BaseException):
                if not isinstance(res, Exception):
                    raise res
                failed.append(name)
                continue
            cached = res
            entries.extend(cached.entries.values())
            expiries.append(cached.expires_at)
        entries.sort(key=lambda e: e.exposed_name)
        now = self._clock()
        if expiries:
            ttl_ms = max(0, int((min(expiries) - now) * 1000))
        elif not names:
            ttl_ms = self._max_ttl_ms
        else:
            ttl_ms = 0
        return CatalogListing(tools=tuple(entries), ttl_ms=ttl_ms, failed=tuple(failed))

    async def resolve(self, exposed_name: str) -> CatalogEntry | None:
        """The entry for an exposed name, or ``None`` if it is not in the exposed catalog.

        Raises ``UpstreamError`` if the owning upstream's catalog cannot be loaded.
        """
        split = split_exposed_name(exposed_name)
        if split is None:
            return None
        upstream, tool = split
        if upstream not in self._upstreams:
            return None
        cached = await self._load(upstream)
        return cached.entries.get(tool)

    # ------------------------------------------------------------------ loading

    async def _load(self, upstream: str) -> _Cached:
        state = self._upstreams[upstream]
        async with state.lock:
            if state.cached is not None and self._clock() < state.cached.expires_at:
                return state.cached
            state.cached = None
            try:
                tools, ttl_ms = await self.fetch_all(state.client)
            except UpstreamError as exc:
                self._emit_catalog(upstream, None, Action.DENY, f"upstream unavailable: {exc}")
                raise
            entries = await self._vet(upstream, tools)
            state.cached = _Cached(entries=entries, expires_at=self._clock() + ttl_ms / 1000)
            return state.cached

    async def fetch_all(self, client: UpstreamClient) -> tuple[list[Any], int]:
        tools: list[Any] = []
        ttl_ms = self._max_ttl_ms
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(self._max_pages):
            params: JsonObject = {META: build_upstream_meta(self._protocol_version, {})}
            if cursor is not None:
                params["cursor"] = cursor
            result = await client.request("tools/list", params)
            page = result.get("tools")
            if not isinstance(page, list):
                raise UpstreamProtocolError(client.name, "tools/list result has no tools array")
            tools.extend(page)
            page_ttl = result.get("ttlMs")
            if isinstance(page_ttl, int) and not isinstance(page_ttl, bool) and page_ttl >= 0:
                ttl_ms = min(ttl_ms, page_ttl)
            nxt = result.get("nextCursor")
            if nxt is None:
                return tools, ttl_ms
            if not isinstance(nxt, str) or nxt in seen_cursors:
                raise UpstreamProtocolError(client.name, "tools/list pagination is invalid")
            seen_cursors.add(nxt)
            cursor = nxt
        raise UpstreamProtocolError(client.name, "tools/list has too many pages")

    async def _vet(self, upstream: str, tools: list[Any]) -> dict[str, CatalogEntry]:
        counts = Counter(
            t["name"] for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)
        )
        duplicates = {n for n, c in counts.items() if c > 1}
        entries: dict[str, CatalogEntry] = {}
        for tool in tools:
            entry = await self._vet_one(upstream, tool, duplicates)
            if entry is not None:
                entries[entry.tool_name] = entry
        return entries

    async def _vet_one(self, upstream: str, tool: Any, duplicates: set[str]) -> CatalogEntry | None:
        if not isinstance(tool, dict):
            self._quarantine(upstream, None, "tool definition is not an object", "definition")
            return None
        name = tool.get("name")
        if not isinstance(name, str) or not TOOL_NAME_RE.match(name):
            self._quarantine(upstream, None, "tool name is invalid", "name")
            return None
        if name in duplicates:
            self._quarantine(upstream, name, "tool name is not unique on its upstream", "name")
            return None
        exposed_name = f"{upstream}{TOOL_NAMESPACE_SEP}{name}"
        if len(exposed_name) > MAX_TOOL_NAME:
            self._quarantine(upstream, name, "namespaced tool name exceeds 128 characters", "name")
            return None
        if not isinstance(tool.get("inputSchema"), dict):
            self._quarantine(
                upstream, name, "inputSchema is missing or not an object", "inputSchema"
            )
            return None
        try:
            upstream_headers = tool_header_annotations(tool)
        except InvalidToolHeaders as exc:
            self._quarantine(upstream, name, f"invalid x-mcp-header: {exc}", "inputSchema")
            return None

        try:
            decision = await self._pipeline.check_tool(upstream, copy.deepcopy(tool))
        except Exception:
            decision = Decision.deny(
                "tool stage failed",
                [
                    Finding(
                        detector="pipeline",
                        category=Category.PROTOCOL_ABUSE,
                        severity=Severity.CRITICAL,
                        message="check_tool raised; failing closed",
                    )
                ],
            )

        source: Any = tool
        if decision.action == Action.DENY:
            self._emit_catalog(upstream, name, Action.DENY, decision.reason, decision.findings)
            return None
        if decision.action == Action.REDACT:
            source = decision.payload
            if not isinstance(source, dict) or not isinstance(source.get("inputSchema"), dict):
                self._emit_catalog(
                    upstream,
                    name,
                    Action.DENY,
                    "tool stage returned an unusable redaction",
                    decision.findings,
                )
                return None

        exposed = copy.deepcopy(source)
        exposed["name"] = exposed_name
        try:
            exposed_headers = tool_header_annotations(exposed)
        except InvalidToolHeaders as exc:
            self._quarantine(upstream, name, f"invalid x-mcp-header after redaction: {exc}", "")
            return None

        if decision.action == Action.REDACT or decision.findings:
            self._emit_catalog(upstream, name, decision.action, decision.reason, decision.findings)

        return CatalogEntry(
            exposed_name=exposed_name,
            upstream=upstream,
            tool_name=name,
            original=copy.deepcopy(tool),
            exposed=exposed,
            upstream_headers=upstream_headers,
            exposed_headers=exposed_headers,
        )

    # ------------------------------------------------------------------ audit

    def _quarantine(self, upstream: str, tool: str | None, reason: str, location: str) -> None:
        finding = Finding(
            detector="catalog",
            category=Category.PROTOCOL_ABUSE,
            severity=Severity.MEDIUM,
            message=reason,
            location=location or None,
        )
        self._emit_catalog(upstream, tool, Action.DENY, reason, [finding])

    def _emit_catalog(
        self,
        upstream: str,
        tool: str | None,
        action: Action,
        reason: str | None,
        findings: Iterable[Finding] = (),
    ) -> None:
        event = AuditEvent(
            kind="tool_catalog",
            ts=self._wall(),
            subject=GATEWAY_SUBJECT,
            method="tools/list",
            action=action,
            upstream=upstream,
            tool=tool,
            reason=reason,
            findings=tuple(findings),
        )
        # An audit sink must never break the request path.
        with contextlib.suppress(Exception):
            self._audit.emit(event)
