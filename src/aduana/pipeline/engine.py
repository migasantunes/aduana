"""The stage runner behind ``Pipeline``.

The engine owns the semantics the proxy relies on (see ``Pipeline`` in
``types.py``) so that no individual stage has to: ordering, first-deny-wins,
payload chaining for ``REDACT``, finding accumulation and failing closed.

Failing closed is the important part. A stage that raises, returns something
that is not a ``Decision``, or returns a ``REDACT`` without a usable payload is
a broken gateway, and a broken gateway must not let the message through. The
exception text is never put into ``reason``: it may contain upstream-controlled
data, and ``reason`` ends up in front of the model.

``build_pipeline`` imports the stage packages lazily. That keeps this module
importable from ``aduana.pipeline`` without import cycles (every stage package
imports ``aduana.pipeline.types``), and keeps the module-level dependency of
``pipeline`` on ``types`` only, as ARCHITECTURE.md says.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Awaitable, Callable, Sequence
from typing import TYPE_CHECKING, Any

from aduana.pipeline.types import (
    Action,
    CallContext,
    Category,
    Decision,
    Finding,
    JsonObject,
    RequestStage,
    ResponseStage,
    Severity,
    ToolStage,
)

if TYPE_CHECKING:
    from aduana.config import Config
    from aduana.pinning.store import PinStore

log = logging.getLogger(__name__)

#: Detector name used on findings the engine itself produces.
ENGINE_DETECTOR = "pipeline"


def _failure(stage_name: str, what: str) -> Decision:
    finding = Finding(
        detector=stage_name,
        category=Category.PROTOCOL_ABUSE,
        severity=Severity.CRITICAL,
        message=f"security stage failed ({what}); failing closed",
    )
    # Stage names are chosen by us, never by an upstream, so they are safe here.
    return Decision.deny(f"internal error in security stage {stage_name!r}", [finding])


async def _run[P](
    stages: Sequence[Any],
    payload: P,
    call: Callable[[Any, P], Awaitable[Decision | None]],
    accept: Callable[[object], bool],
) -> Decision:
    """Run ``stages`` in order over ``payload``.

    ``accept`` says whether a ``REDACT`` payload has the right shape for this
    kind of check; a malformed one is treated like a stage failure.
    """
    findings: list[Finding] = []
    current: P = payload
    redacted = False
    reason: str | None = None

    for stage in stages:
        name = str(getattr(stage, "name", type(stage).__name__))
        try:
            result = await call(stage, current)
        except Exception as exc:
            # Only the type name is logged: the message may carry upstream text.
            log.warning("security stage %s raised %s; failing closed", name, type(exc).__name__)
            failed = _failure(name, type(exc).__name__)
            failed.findings[:0] = findings
            return failed

        if result is None:
            continue
        if not isinstance(result, Decision):
            failed = _failure(name, "invalid decision")
            failed.findings[:0] = findings
            return failed

        findings.extend(result.findings)

        if result.action is Action.DENY:
            return Decision(
                action=Action.DENY,
                findings=findings,
                reason=result.reason or f"blocked by security stage {name!r}",
            )
        if result.action is Action.REDACT:
            if not accept(result.payload):
                failed = _failure(name, "invalid redaction payload")
                failed.findings[:0] = findings
                return failed
            current = result.payload
            redacted = True
            reason = result.reason or reason

    if redacted:
        return Decision(action=Action.REDACT, findings=findings, reason=reason, payload=current)
    return Decision(action=Action.ALLOW, findings=findings)


def _is_object(value: object) -> bool:
    return isinstance(value, dict)


def _is_arguments(value: object) -> bool:
    return value is None or isinstance(value, dict)


class StagePipeline:
    """Ordered stages for each of the three checkpoints.

    For ``check_request`` a ``REDACT`` payload is the replacement *arguments*
    object (or ``None``); later stages see a copy of the context carrying it and
    the caller receives it in ``Decision.payload``. For ``check_tool`` it is the
    replacement tool definition and for ``check_response`` the replacement result.
    """

    def __init__(
        self,
        tool_stages: Sequence[ToolStage] = (),
        request_stages: Sequence[RequestStage] = (),
        response_stages: Sequence[ResponseStage] = (),
    ) -> None:
        self.tool_stages: tuple[ToolStage, ...] = tuple(tool_stages)
        self.request_stages: tuple[RequestStage, ...] = tuple(request_stages)
        self.response_stages: tuple[ResponseStage, ...] = tuple(response_stages)

    async def check_tool(self, upstream: str, tool: JsonObject) -> Decision:
        async def call(stage: ToolStage, payload: JsonObject) -> Decision | None:
            return await stage.on_tool(upstream, payload)

        return await _run(self.tool_stages, tool, call, _is_object)

    async def check_request(self, ctx: CallContext) -> Decision:
        async def call(stage: RequestStage, payload: JsonObject | None) -> Decision | None:
            view = ctx if payload is ctx.arguments else dataclasses.replace(ctx, arguments=payload)
            return await stage.on_request(view)

        return await _run(self.request_stages, ctx.arguments, call, _is_arguments)

    async def check_response(self, ctx: CallContext, result: JsonObject) -> Decision:
        async def call(stage: ResponseStage, payload: JsonObject) -> Decision | None:
            return await stage.on_response(ctx, payload)

        return await _run(self.response_stages, result, call, _is_object)


def build_pipeline(config: Config, *, pin_store: PinStore | None = None) -> StagePipeline:
    """Assemble the stages the config enables, in the documented order.

    Tool stages: pinning, rule detector. Request stages: policy, secret scanner.
    Response stages: rule detector. ``pin_store`` lets a caller share an already
    loaded lockfile; by default it is loaded from ``config.pinning.lockfile``.
    """
    from aduana.detect.rules import RuleDetector
    from aduana.detect.secrets import SecretScanner
    from aduana.pinning.store import PinningStage, PinStore
    from aduana.policy.engine import PolicyStage

    tool_stages: list[ToolStage] = []
    request_stages: list[RequestStage] = [PolicyStage(config.policy)]
    response_stages: list[ResponseStage] = []

    if config.pinning.mode != "off":
        store = pin_store if pin_store is not None else PinStore.load(config.pinning.lockfile)
        tool_stages.append(PinningStage(store, mode=config.pinning.mode))

    if config.detectors.rules.enabled:
        rules = RuleDetector(deny_at=config.detectors.rules.deny_at)
        tool_stages.append(rules)
        response_stages.append(rules)

    if config.detectors.secrets.enabled:
        request_stages.append(SecretScanner(deny_at=config.detectors.secrets.deny_at))

    return StagePipeline(tool_stages, request_stages, response_stages)
