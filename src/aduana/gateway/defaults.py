"""No-op implementations of the pipeline contracts.

Used when the gateway is wired without security stages (tests, ``--no-pipeline`` style
runs). They are explicit objects rather than ``None`` checks so the request path has a single
shape.
"""

from __future__ import annotations

from aduana.pipeline.types import AuditEvent, CallContext, Decision, JsonObject


class AllowAllPipeline:
    """Allows every tool, request and response. Not a security control."""

    async def check_tool(self, upstream: str, tool: JsonObject) -> Decision:
        return Decision.allow()

    async def check_request(self, ctx: CallContext) -> Decision:
        return Decision.allow()

    async def check_response(self, ctx: CallContext, result: JsonObject) -> Decision:
        return Decision.allow()


class NullAuditSink:
    """Discards audit events."""

    def emit(self, event: AuditEvent) -> None:
        return None
