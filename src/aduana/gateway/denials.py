"""Wire shape of blocked and failed ``tools/call`` results.

Every sentence the model can read here is a fixed, gateway-authored template. Neither
``Decision.reason`` nor finding messages are used: a detector's reason may quote the
offending upstream text, and a denial that repeats an injection delivers it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from aduana.pipeline.types import Action, Category, Decision, Finding, JsonObject
from aduana.protocol.jsonrpc import RESULT_COMPLETE
from aduana.protocol.meta import DECISION_KEY, META, SERVER_INFO_KEY, implementation_info

Stage = Literal["request", "response"]

BLOCK_PREFIX = "Blocked by aduana: "

_CATEGORY_REASON: dict[Category, str] = {
    Category.POLICY: "this call is not permitted by the gateway policy.",
    Category.SECRET_EXFILTRATION: "the arguments appear to contain a secret or credential.",
    Category.RESULT_INJECTION: (
        "the tool result contained content that looks like instructions to the model."
    ),
    Category.TOOL_POISONING: "the tool definition failed a security check.",
    Category.RUG_PULL: "the tool definition changed since it was approved.",
    Category.TOOL_SHADOWING: "the tool definition failed a security check.",
    Category.PROTOCOL_ABUSE: "the gateway could not verify this message.",
}

_DEFAULT_REASON: dict[str, str] = {
    "request": "this call was blocked by a gateway security check.",
    "response": "the tool result was withheld by a gateway security check.",
}

UPSTREAM_UNAVAILABLE = "aduana: the upstream server for this tool is unavailable."
UPSTREAM_INVALID = "aduana: the upstream server returned an invalid response."


def categories_of(findings: Iterable[Finding]) -> list[str]:
    """Distinct categories in first-seen order."""
    out: list[str] = []
    for f in findings:
        if f.category.value not in out:
            out.append(f.category.value)
    return out


def reason_text(stage: Stage, decision: Decision) -> str:
    for f in decision.findings:
        if f.category in _CATEGORY_REASON:
            return _CATEGORY_REASON[f.category]
    return _DEFAULT_REASON[stage]


def decision_meta(action: Action, findings: Iterable[Finding]) -> JsonObject:
    return {"action": action.value, "categories": categories_of(findings)}


def _base_meta() -> JsonObject:
    return {SERVER_INFO_KEY: implementation_info()}


def denial_result(stage: Stage, decision: Decision) -> JsonObject:
    """A tool execution error for a DENY decision."""
    meta = _base_meta()
    meta[DECISION_KEY] = decision_meta(Action.DENY, decision.findings)
    return {
        "resultType": RESULT_COMPLETE,
        "isError": True,
        "content": [{"type": "text", "text": BLOCK_PREFIX + reason_text(stage, decision)}],
        META: meta,
    }


def upstream_failure_result(text: str) -> JsonObject:
    """A tool execution error for an upstream that failed; ``text`` is a module template."""
    return {
        "resultType": RESULT_COMPLETE,
        "isError": True,
        "content": [{"type": "text", "text": text}],
        META: _base_meta(),
    }


def upstream_rpc_error_result(code: int) -> JsonObject:
    """The upstream's JSON-RPC error code is an integer and safe to show; its message is not."""
    return upstream_failure_result(
        f"aduana: the upstream server rejected the call (JSON-RPC error {int(code)})."
    )
