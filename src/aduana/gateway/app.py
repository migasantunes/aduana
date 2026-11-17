"""The downstream endpoint: transport validation, dispatch, and decisions on the wire.

Order of checks follows ARCHITECTURE.md "Request lifecycle". Every request is judged alone:
the 2026-07-28 revision has no sessions, so there is no per-connection state to consult.
"""

from __future__ import annotations

import contextlib
import copy
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.requests import Request as HttpRequest
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

import aduana
from aduana.config import Config
from aduana.gateway.defaults import AllowAllPipeline, NullAuditSink
from aduana.gateway.denials import (
    UPSTREAM_INVALID,
    UPSTREAM_UNAVAILABLE,
    decision_meta,
    denial_result,
    upstream_failure_result,
    upstream_rpc_error_result,
)
from aduana.pipeline.types import (
    Action,
    AuditEvent,
    AuditSink,
    CallContext,
    Category,
    Decision,
    Finding,
    Identity,
    JsonObject,
    Pipeline,
    Severity,
)
from aduana.protocol.errors import (
    McpError,
    internal_error,
    invalid_params,
    invalid_request,
    method_not_found,
    unsupported_protocol_version,
)
from aduana.protocol.headers import HeaderView, validate_param_headers, validate_standard_headers
from aduana.protocol.jsonrpc import (
    RESULT_COMPLETE,
    Notification,
    Request,
    RequestId,
    best_effort_id,
    dumps,
    error_response,
    parse_json,
    parse_message_obj,
    result_response,
)
from aduana.protocol.meta import (
    DECISION_KEY,
    META,
    RequestMeta,
    extract_request_meta,
    upstream_meta_for,
    with_server_info,
)
from aduana.upstream.catalog import Catalog
from aduana.upstream.client import (
    UpstreamClient,
    UpstreamError,
    UpstreamProtocolError,
    UpstreamRpcError,
)

ANONYMOUS = "anonymous"
_ALL_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
_MAX_ECHO = 128


class _BodyTooLarge(Exception):
    pass


def _json(obj: JsonObject, status: int = 200) -> Response:
    return Response(content=dumps(obj), status_code=status, media_type="application/json")


def _fail_closed(stage: str) -> Decision:
    return Decision.deny(
        f"{stage} raised",
        [
            Finding(
                detector="pipeline",
                category=Category.PROTOCOL_ABUSE,
                severity=Severity.CRITICAL,
                message=f"{stage} raised; failing closed",
            )
        ],
    )


async def _guarded(stage: str, call: Callable[[], Awaitable[Decision]]) -> Decision:
    """Run a pipeline call; an exception is a gateway failure and denies (fail closed)."""
    try:
        decision = await call()
    except Exception:
        return _fail_closed(stage)
    if not isinstance(decision, Decision):
        return _fail_closed(stage)
    return decision


class Gateway:
    """Request handling. ``create_app`` wraps it in Starlette."""

    def __init__(
        self,
        config: Config,
        pipeline: Pipeline,
        audit: AuditSink,
        http_client: httpx.AsyncClient,
    ) -> None:
        self.config = config
        self.pipeline = pipeline
        self.audit = audit
        self.http = http_client
        timeout = config.gateway.upstream_timeout_s
        self.clients: dict[str, UpstreamClient] = {
            u.name: UpstreamClient(u, http_client, timeout_s=timeout) for u in config.upstreams
        }
        self.catalog = Catalog(
            self.clients.values(),
            pipeline,
            audit,
            max_ttl_ms=config.gateway.max_list_ttl_ms,
        )

    # ------------------------------------------------------------------ helpers

    def _emit(self, event: AuditEvent) -> None:
        # An audit sink must never break the request path.
        with contextlib.suppress(Exception):
            self.audit.emit(event)

    def _reject(
        self,
        err: McpError,
        msg_id: RequestId | None,
        *,
        method: str,
        started: float,
        traceparent: str | None = None,
        subject: str = ANONYMOUS,
        status: int | None = None,
    ) -> Response:
        self._emit(
            AuditEvent(
                kind="protocol_reject",
                ts=time.time(),
                subject=subject,
                method=method,
                action=Action.DENY,
                reason=f"{err.code}: {err.message}",
                latency_ms=(time.monotonic() - started) * 1000,
                traceparent=traceparent,
                request_id=msg_id,
            )
        )
        return _json(error_response(msg_id, err), status or err.http_status)

    async def _read_body(self, request: HttpRequest) -> bytes:
        limit = self.config.gateway.max_body_bytes
        declared = request.headers.get("content-length")
        if declared is not None:
            with contextlib.suppress(ValueError):
                if int(declared) > limit:
                    raise _BodyTooLarge
        chunks: list[bytes] = []
        total = 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > limit:
                raise _BodyTooLarge
            chunks.append(chunk)
        return b"".join(chunks)

    def _origin_allowed(self, request: HttpRequest) -> bool:
        origins = request.headers.getlist("origin")
        if not origins:
            return True
        if len(origins) > 1:
            return False
        return origins[0] in self.config.gateway.allowed_origins

    # ------------------------------------------------------------------ endpoint

    async def handle(self, request: HttpRequest) -> Response:
        started = time.monotonic()
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        if not self._origin_allowed(request):
            return self._reject(
                invalid_request("Origin not allowed"), None, method="", started=started, status=403
            )
        try:
            body = await self._read_body(request)
        except _BodyTooLarge:
            return self._reject(
                invalid_request("Request body too large"),
                None,
                method="",
                started=started,
                status=413,
            )

        msg_id: RequestId | None = None
        method = ""
        meta: RequestMeta | None = None
        try:
            obj = parse_json(body)
            msg_id = best_effort_id(obj)
            if isinstance(obj, dict) and isinstance(obj.get("method"), str):
                method = obj["method"][:_MAX_ECHO]
            msg = parse_message_obj(obj)
            if isinstance(msg, Notification):
                # No client-to-server notification is defined for this transport; accept
                # and drop. Nothing is forwarded, so there is nothing to validate.
                return Response(status_code=202)
            if msg.method == "initialize":
                raise self._initialize_error(msg)
            meta = extract_request_meta(msg.params)
            if meta.protocol_version not in aduana.SUPPORTED_PROTOCOL_VERSIONS:
                raise unsupported_protocol_version(
                    meta.protocol_version, aduana.SUPPORTED_PROTOCOL_VERSIONS
                )
            headers = HeaderView(request.headers.items())
            validate_standard_headers(headers, msg.method, msg.params, meta.protocol_version)
            return await self._dispatch(msg, meta, headers, started)
        except McpError as err:
            return self._reject(
                err,
                msg_id,
                method=method,
                started=started,
                traceparent=meta.traceparent if meta else None,
            )
        except Exception:
            return self._reject(
                internal_error(),
                msg_id,
                method=method,
                started=started,
                traceparent=meta.traceparent if meta else None,
            )

    @staticmethod
    def _initialize_error(msg: Request) -> McpError:
        supported = aduana.SUPPORTED_PROTOCOL_VERSIONS
        requested = msg.params.get("protocolVersion")
        return unsupported_protocol_version(
            requested if isinstance(requested, str) else "",
            supported,
            message=(
                "The initialize handshake is not supported: aduana speaks only stateless MCP. "
                f"Supported protocol versions: {', '.join(supported)}"
            ),
        )

    async def _dispatch(
        self, msg: Request, meta: RequestMeta, headers: HeaderView, started: float
    ) -> Response:
        if msg.method == "server/discover":
            return _json(result_response(msg.id, self._discover_result()))
        if msg.method == "tools/list":
            return _json(result_response(msg.id, await self._tools_list(msg)))
        if msg.method == "tools/call":
            return await self._tools_call(msg, meta, headers, started)
        raise method_not_found(msg.method)

    # ------------------------------------------------------------------ methods

    def _discover_result(self) -> JsonObject:
        # Upstream ``instructions`` are third-party, model-facing text; not forwarded at M0.
        return with_server_info(
            {
                "resultType": RESULT_COMPLETE,
                "supportedVersions": list(aduana.SUPPORTED_PROTOCOL_VERSIONS),
                "capabilities": {"tools": {}},
                "ttlMs": self.config.gateway.max_list_ttl_ms,
                "cacheScope": "public",
            }
        )

    async def _tools_list(self, msg: Request) -> JsonObject:
        if msg.params.get("cursor") is not None:
            # The aggregated list is a single page; we never issue cursors.
            raise invalid_params("Invalid cursor")
        listing = await self.catalog.list_tools()
        return with_server_info(
            {
                "resultType": RESULT_COMPLETE,
                "tools": listing.tool_definitions(),
                "ttlMs": listing.ttl_ms,
                "cacheScope": "private",
            }
        )

    async def _tools_call(
        self, msg: Request, meta: RequestMeta, headers: HeaderView, started: float
    ) -> Response:
        params = msg.params
        name = params["name"]  # validated as a string with Mcp-Name
        arguments: Any = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise invalid_params("params.arguments must be an object")
        identity = Identity(subject=ANONYMOUS, client_name=meta.client_name)

        def audit(
            kind: str,
            action: Action,
            *,
            upstream: str | None,
            tool: str | None,
            reason: str | None = None,
            findings: tuple[Finding, ...] = (),
        ) -> None:
            self._emit(
                AuditEvent(
                    kind=kind,
                    ts=time.time(),
                    subject=identity.subject,
                    method=msg.method,
                    action=action,
                    upstream=upstream,
                    tool=tool,
                    reason=reason,
                    findings=findings,
                    latency_ms=(time.monotonic() - started) * 1000,
                    traceparent=meta.traceparent,
                    request_id=msg.id,
                )
            )

        try:
            entry = await self.catalog.resolve(name)
        except UpstreamError:
            audit("tool_call", Action.DENY, upstream=None, tool=None, reason="catalog unavailable")
            return _json(result_response(msg.id, upstream_failure_result(UPSTREAM_UNAVAILABLE)))
        if entry is None:
            raise invalid_params(f"Unknown tool: {name[:_MAX_ECHO]}")

        validate_param_headers(headers, arguments, entry.exposed_headers)

        ctx = CallContext(
            request_id=msg.id,
            method=msg.method,
            identity=identity,
            upstream=entry.upstream,
            tool=entry.tool_name,
            arguments=copy.deepcopy(arguments),
            traceparent=meta.traceparent,
            started_at=started,
        )
        decision = await _guarded("check_request", lambda: self.pipeline.check_request(ctx))
        if decision.action == Action.REDACT and not isinstance(decision.payload, dict):
            decision = _fail_closed("check_request redaction")
        audit(
            "tool_call",
            decision.action,
            upstream=entry.upstream,
            tool=entry.tool_name,
            reason=decision.reason,
            findings=tuple(decision.findings),
        )
        if decision.action == Action.DENY:
            return _json(result_response(msg.id, denial_result("request", decision)))
        if decision.action == Action.REDACT:
            arguments = decision.payload
            ctx.arguments = copy.deepcopy(arguments)

        upstream_params: JsonObject = {
            "name": entry.tool_name,
            "arguments": arguments,
            META: upstream_meta_for(meta),
        }
        # MRTR retry fields are opaque to the gateway at M0 and round-trip unchanged.
        for key in ("inputResponses", "requestState"):
            if key in params:
                upstream_params[key] = params[key]

        client = self.clients[entry.upstream]
        try:
            result = await client.request(
                "tools/call", upstream_params, annotations=entry.upstream_headers
            )
        except UpstreamRpcError as exc:
            audit(
                "tool_result",
                Action.DENY,
                upstream=entry.upstream,
                tool=entry.tool_name,
                reason=f"upstream JSON-RPC error {exc.code}",
            )
            return _json(result_response(msg.id, upstream_rpc_error_result(exc.code)))
        except UpstreamProtocolError:
            audit(
                "tool_result",
                Action.DENY,
                upstream=entry.upstream,
                tool=entry.tool_name,
                reason="upstream reply invalid",
            )
            return _json(result_response(msg.id, upstream_failure_result(UPSTREAM_INVALID)))
        except UpstreamError:
            audit(
                "tool_result",
                Action.DENY,
                upstream=entry.upstream,
                tool=entry.tool_name,
                reason="upstream unavailable",
            )
            return _json(result_response(msg.id, upstream_failure_result(UPSTREAM_UNAVAILABLE)))

        if result.get("resultType") != RESULT_COMPLETE:
            # input_required (MRTR) passes through untouched at M0; see open question 1.
            audit("tool_result", Action.ALLOW, upstream=entry.upstream, tool=entry.tool_name)
            return _json(result_response(msg.id, with_server_info(result)))

        snapshot = copy.deepcopy(result)
        rdecision = await _guarded(
            "check_response", lambda: self.pipeline.check_response(ctx, snapshot)
        )
        if rdecision.action == Action.REDACT and not isinstance(rdecision.payload, dict):
            rdecision = _fail_closed("check_response redaction")
        audit(
            "tool_result",
            rdecision.action,
            upstream=entry.upstream,
            tool=entry.tool_name,
            reason=rdecision.reason,
            findings=tuple(rdecision.findings),
        )
        if rdecision.action == Action.DENY:
            return _json(result_response(msg.id, denial_result("response", rdecision)))
        out = result
        if rdecision.action == Action.REDACT:
            out = dict(rdecision.payload)
            out.setdefault("resultType", RESULT_COMPLETE)
        out = with_server_info(out)
        if rdecision.action == Action.REDACT:
            out[META][DECISION_KEY] = decision_meta(Action.REDACT, rdecision.findings)
        return _json(result_response(msg.id, out))


async def _healthz(_: HttpRequest) -> Response:
    return JSONResponse({"status": "ok"})


def create_app(
    config: Config,
    *,
    pipeline: Pipeline | None = None,
    audit: AuditSink | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> Starlette:
    """Build the gateway ASGI app.

    If ``http_client`` is not given, the app owns one and closes it on lifespan shutdown.
    The ``Gateway`` instance is available as ``app.state.gateway``.
    """
    owned = http_client is None
    client = http_client if http_client is not None else httpx.AsyncClient(follow_redirects=False)
    gateway = Gateway(
        config,
        pipeline if pipeline is not None else AllowAllPipeline(),
        audit if audit is not None else NullAuditSink(),
        client,
    )

    @contextlib.asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if owned:
                await client.aclose()

    app = Starlette(
        routes=[
            Route("/healthz", _healthz, methods=["GET"]),
            # Every verb reaches ``handle`` so non-POST gets the transport's 405 with Allow;
            # Starlette answers 405 itself for any verb not listed.
            Route(config.gateway.path, gateway.handle, methods=list(_ALL_METHODS)),
        ],
        lifespan=lifespan,
    )
    app.state.gateway = gateway
    return app
