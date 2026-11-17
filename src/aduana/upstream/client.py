"""Modern (2026-07-28) Streamable HTTP client for one upstream MCP server.

aduana is an MCP *client* towards each upstream. Each request is a fresh POST built by the
gateway: nothing from the downstream HTTP request (headers, id, ``_meta``) is reused, which
is what keeps the agent's ``Authorization`` header and any smuggled header away from the
upstream.
"""

from __future__ import annotations

import asyncio
import codecs
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any

import httpx

import aduana
from aduana.config import UpstreamConfig
from aduana.protocol.errors import MODERN_ERROR_CODES
from aduana.protocol.headers import HeaderAnnotation, compute_request_headers
from aduana.protocol.jsonrpc import (
    RESULT_COMPLETE,
    JsonObject,
    RequestId,
    dumps,
    is_response_shaped,
    loads_strict,
    parse_response_obj,
    request_obj,
    result_type_of,
)
from aduana.protocol.meta import META, PROTOCOL_VERSION_KEY

NotificationHandler = Callable[[JsonObject], Awaitable[None]]

DEFAULT_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_ACCEPT = "application/json, text/event-stream"


# --------------------------------------------------------------------------- errors


class UpstreamError(Exception):
    """Base class. ``str(exc)`` is gateway-authored and never contains upstream text."""

    def __init__(self, upstream: str, message: str) -> None:
        super().__init__(message)
        self.upstream = upstream


class UpstreamUnavailable(UpstreamError):
    """Could not reach the upstream, or it did not answer in time."""


class UpstreamHttpError(UpstreamError):
    """The upstream answered with an HTTP error status and no JSON-RPC error body."""

    def __init__(self, upstream: str, status: int) -> None:
        super().__init__(upstream, f"upstream answered HTTP {status}")
        self.status = status


class UpstreamProtocolError(UpstreamError):
    """The upstream's reply is not a valid JSON-RPC response to our request."""


class UpstreamRpcError(UpstreamError):
    """The upstream returned a JSON-RPC error.

    ``upstream_message`` and ``data`` are upstream-authored: untrusted, for audit only.
    """

    def __init__(
        self,
        upstream: str,
        code: int,
        upstream_message: str,
        data: Any = None,
        http_status: int = 200,
    ) -> None:
        super().__init__(upstream, f"upstream returned JSON-RPC error {code}")
        self.code = code
        self.upstream_message = upstream_message
        self.data = data
        self.http_status = http_status

    @property
    def is_modern(self) -> bool:
        """A code defined by the spec: the server speaks modern MCP (era detection, M1)."""
        return self.code in MODERN_ERROR_CODES


# --------------------------------------------------------------------------- SSE


@dataclass(frozen=True, slots=True)
class SseEvent:
    data: str
    event: str = "message"
    id: str | None = None


class SseParser:
    """Incremental ``text/event-stream`` parser (WHATWG HTML §9.2).

    Fed decoded text in arbitrary chunks; yields complete events. Lines starting with ``:``
    are comments (keep-alives). ``retry`` and ``id`` are parsed but unused: this revision has
    no resumability.
    """

    def __init__(self) -> None:
        self._buf = ""
        self._data: list[str] = []
        self._event = ""
        self._id: str | None = None
        self._started = False
        self._pending_cr = False

    def feed(self, text: str) -> list[SseEvent]:
        if not self._started and text:
            self._started = True
            if text.startswith("﻿"):
                text = text[1:]
        if self._pending_cr and text.startswith("\n"):
            text = text[1:]
        self._pending_cr = False
        self._buf += text
        events: list[SseEvent] = []
        while True:
            idx = _line_end(self._buf)
            if idx is None:
                break
            line = self._buf[:idx]
            if self._buf[idx] == "\r":
                if idx + 1 < len(self._buf):
                    skip = 2 if self._buf[idx + 1] == "\n" else 1
                else:
                    # A lone CR at the end of a chunk may be the first half of CRLF.
                    skip = 1
                    self._pending_cr = True
            else:
                skip = 1
            self._buf = self._buf[idx + skip :]
            ev = self._line(line)
            if ev is not None:
                events.append(ev)
        return events

    def close(self) -> list[SseEvent]:
        """End of stream. A trailing event without its blank line is dispatched (lenient)."""
        events: list[SseEvent] = []
        if self._buf:
            ev = self._line(self._buf)
            self._buf = ""
            if ev is not None:
                events.append(ev)
        ev = self._dispatch()
        if ev is not None:
            events.append(ev)
        return events

    def _line(self, line: str) -> SseEvent | None:
        if line == "":
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._event = value
        elif name == "id" and "\x00" not in value:
            self._id = value
        return None

    def _dispatch(self) -> SseEvent | None:
        if not self._data:
            self._event = ""
            return None
        ev = SseEvent(data="\n".join(self._data), event=self._event or "message", id=self._id)
        self._data = []
        self._event = ""
        return ev


def _line_end(buf: str) -> int | None:
    for i, ch in enumerate(buf):
        if ch in "\r\n":
            return i
    return None


def parse_sse(chunks: Iterable[str]) -> list[SseEvent]:
    """Convenience: parse a whole stream given as text chunks."""
    parser = SseParser()
    events: list[SseEvent] = []
    for chunk in chunks:
        events.extend(parser.feed(chunk))
    events.extend(parser.close())
    return events


# --------------------------------------------------------------------------- client


def _media_type(content_type: str | None) -> str:
    if not content_type:
        return ""
    return content_type.split(";", 1)[0].strip().lower()


def _new_id() -> str:
    return f"aduana-{uuid.uuid4().hex}"


class UpstreamClient:
    """Sends one JSON-RPC request at a time to an upstream and returns the final result."""

    def __init__(
        self,
        config: UpstreamConfig,
        http: httpx.AsyncClient,
        *,
        timeout_s: float = 30.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        id_factory: Callable[[], RequestId] = _new_id,
    ) -> None:
        self.config = config
        self._http = http
        self._timeout_s = timeout_s
        self._max_bytes = max_response_bytes
        self._id_factory = id_factory

    @property
    def name(self) -> str:
        return self.config.name

    def build_headers(
        self,
        method: str,
        params: JsonObject,
        annotations: Iterable[HeaderAnnotation] = (),
    ) -> dict[str, str]:
        meta = params.get(META)
        version = meta.get(PROTOCOL_VERSION_KEY) if isinstance(meta, dict) else None
        if not isinstance(version, str):
            raise ValueError("params._meta must carry the protocol version")
        # Operator-configured headers first; protocol headers win on conflict.
        headers: dict[str, str] = dict(self.config.headers)
        headers["Accept"] = _ACCEPT
        headers["Content-Type"] = "application/json"
        headers["User-Agent"] = f"aduana/{aduana.__version__}"
        headers.update(
            compute_request_headers(
                method, params, protocol_version=version, annotations=annotations
            )
        )
        return headers

    async def request(
        self,
        method: str,
        params: JsonObject,
        *,
        annotations: Iterable[HeaderAnnotation] = (),
        on_notification: NotificationHandler | None = None,
    ) -> JsonObject:
        """Send ``method`` with ``params`` (which must include ``_meta``); return the result.

        The result always carries ``resultType`` (absent upstream → ``"complete"``).
        ``annotations`` are the target tool's ``x-mcp-header`` annotations, from the
        upstream's own definition of the tool.
        """
        msg_id = self._id_factory()
        try:
            headers = self.build_headers(method, params, annotations)
        except ValueError as exc:
            raise UpstreamProtocolError(
                self.name, "request cannot be mirrored into headers"
            ) from exc
        body = dumps(request_obj(msg_id, method, params))
        try:
            async with asyncio.timeout(self._timeout_s):
                return await self._send(msg_id, body, headers, on_notification)
        except TimeoutError as exc:
            raise UpstreamUnavailable(self.name, "upstream timed out") from exc
        except httpx.HTTPError as exc:
            raise UpstreamUnavailable(self.name, "upstream unreachable") from exc

    async def _send(
        self,
        msg_id: RequestId,
        body: bytes,
        headers: dict[str, str],
        on_notification: NotificationHandler | None,
    ) -> JsonObject:
        async with self._http.stream(
            "POST",
            self.config.url,
            content=body,
            headers=headers,
            timeout=self._timeout_s,
        ) as resp:
            media = _media_type(resp.headers.get("content-type"))
            if not 200 <= resp.status_code < 300:
                raw = await self._read_capped(resp)
                self._raise_http_error(resp.status_code, media, raw, msg_id)
            if media == "application/json":
                raw = await self._read_capped(resp)
                return self._final(self._decode(raw), msg_id, 200)
            if media == "text/event-stream":
                return await self._read_sse(resp, msg_id, on_notification)
            raise UpstreamProtocolError(self.name, "upstream reply has an unexpected content type")

    async def _read_capped(self, resp: httpx.Response) -> bytes:
        chunks: list[bytes] = []
        total = 0
        async for chunk in resp.aiter_bytes():
            total += len(chunk)
            if total > self._max_bytes:
                raise UpstreamProtocolError(self.name, "upstream reply is too large")
            chunks.append(chunk)
        return b"".join(chunks)

    def _decode(self, raw: bytes) -> Any:
        try:
            return loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise UpstreamProtocolError(self.name, "upstream reply is not valid JSON") from exc

    def _raise_http_error(self, status: int, media: str, raw: bytes, msg_id: RequestId) -> None:
        if media == "application/json" and raw:
            try:
                obj = loads_strict(raw.decode("utf-8"))
                resp = parse_response_obj(obj)
            except (UnicodeDecodeError, ValueError, RecursionError):
                resp = None
            if resp is not None and resp.error is not None and resp.id in (None, msg_id):
                raise UpstreamRpcError(
                    self.name,
                    resp.error.code,
                    resp.error.message,
                    resp.error.data,
                    http_status=status,
                )
        raise UpstreamHttpError(self.name, status)

    def _final(self, obj: Any, msg_id: RequestId, http_status: int) -> JsonObject:
        try:
            resp = parse_response_obj(obj)
        except ValueError as exc:
            raise UpstreamProtocolError(self.name, "upstream reply is not JSON-RPC") from exc
        if resp.error is not None:
            # An error with no id is allowed when the server could not read ours.
            if resp.id not in (None, msg_id):
                raise UpstreamProtocolError(self.name, "upstream reply has the wrong id")
            raise UpstreamRpcError(
                self.name,
                resp.error.code,
                resp.error.message,
                resp.error.data,
                http_status=http_status,
            )
        if resp.id != msg_id:
            raise UpstreamProtocolError(self.name, "upstream reply has the wrong id")
        result = resp.result
        if result is None:  # pragma: no cover - parse_response_obj guarantees one is set
            raise UpstreamProtocolError(self.name, "upstream reply has no result")
        try:
            result_type_of(result)
        except ValueError as exc:
            raise UpstreamProtocolError(
                self.name, "upstream result has an invalid resultType"
            ) from exc
        if "resultType" not in result:
            result = {**result, "resultType": RESULT_COMPLETE}
        return result

    async def _read_sse(
        self,
        resp: httpx.Response,
        msg_id: RequestId,
        on_notification: NotificationHandler | None,
    ) -> JsonObject:
        parser = SseParser()
        decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
        total = 0

        async def handle(events: list[SseEvent]) -> JsonObject | None:
            for ev in events:
                if ev.event != "message":
                    continue
                obj = self._decode(ev.data.encode("utf-8"))
                if is_response_shaped(obj):
                    resp_id = obj.get("id") if isinstance(obj, dict) else None
                    if resp_id == msg_id or (resp_id is None and "error" in obj):
                        return self._final(obj, msg_id, 200)
                    # A response for some other request on a request-scoped stream: ignore.
                    continue
                if isinstance(obj, dict) and "method" in obj and "id" not in obj:
                    if on_notification is not None:
                        await on_notification(obj)
                    continue
                # Servers MUST NOT send requests on this stream; ignore anything else.
            return None

        try:
            async for chunk in resp.aiter_bytes():
                total += len(chunk)
                if total > self._max_bytes:
                    raise UpstreamProtocolError(self.name, "upstream stream is too large")
                final = await handle(parser.feed(decoder.decode(chunk)))
                if final is not None:
                    return final
            final = await handle(parser.feed(decoder.decode(b"", final=True)) + parser.close())
        except UnicodeDecodeError as exc:
            raise UpstreamProtocolError(self.name, "upstream stream is not valid UTF-8") from exc
        if final is not None:
            return final
        raise UpstreamProtocolError(self.name, "upstream stream ended without a response")
