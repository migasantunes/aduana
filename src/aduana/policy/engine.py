"""Who may call which tool with which arguments.

Rules come from the operator's config, which is trusted; arguments come from
the agent, which may be steered by an attacker, so they are treated as
untrusted input: validation errors are never echoed (the denial reason is a
fixed template), and a validator that blows up on hostile input denies.

Matching: the first rule whose ``subjects``, ``upstream`` and ``tools`` globs
all match wins (``fnmatchcase``, so ``Files`` and ``files`` differ, like MCP
tool names). An ``allow`` rule with an ``arguments`` schema that the arguments
fail is a denial; evaluation does not fall through to later rules, because a
schema on an allow rule is a constraint, not a selector.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from jsonschema import Draft202012Validator

from aduana.config import PolicyConfig, PolicyRule
from aduana.pipeline.types import CallContext, Category, Decision, Finding, Identity, Severity

DETECTOR = "policy"

REASON_NO_ROUTE = "request was not routed to a tool"
REASON_RULE = "policy does not allow this tool for this caller"
REASON_DEFAULT = "no policy rule allows this tool for this caller"
REASON_ARGUMENTS = "tool arguments are not allowed by policy"


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    index: int
    rule: PolicyRule
    validator: Draft202012Validator | None

    def matches(self, subject: str, upstream: str, tool: str) -> bool:
        r = self.rule
        return (
            any(fnmatchcase(subject, p) for p in r.subjects)
            and fnmatchcase(upstream, r.upstream)
            and any(fnmatchcase(tool, p) for p in r.tools)
        )


def _compile(index: int, rule: PolicyRule) -> _CompiledRule:
    validator: Draft202012Validator | None = None
    if rule.arguments is not None:
        # Raises SchemaError at startup for a broken operator schema: better than
        # discovering it on the first call. No format checker, no remote $ref
        # retrieval (the ``referencing`` registry does not fetch by default).
        Draft202012Validator.check_schema(rule.arguments)
        validator = Draft202012Validator(rule.arguments)
    return _CompiledRule(index, rule, validator)


class PolicyStage:
    """``RequestStage`` enforcing ``PolicyConfig``. Validators are compiled once."""

    name = "policy"

    def __init__(self, config: PolicyConfig) -> None:
        self.default = config.default
        self._rules = tuple(_compile(i, r) for i, r in enumerate(config.rules))

    def _first_match(self, subject: str, upstream: str, tool: str) -> _CompiledRule | None:
        for compiled in self._rules:
            if compiled.matches(subject, upstream, tool):
                return compiled
        return None

    def is_tool_visible(self, identity: Identity, upstream: str, tool: str) -> bool:
        """Could ``identity`` ever be allowed to call this tool?

        Argument constraints are ignored: an allow rule with a schema still
        makes the tool visible, since some arguments may satisfy it.
        """
        match = self._first_match(identity.subject, upstream, tool)
        effect = match.rule.effect if match is not None else self.default
        return effect == "allow"

    def evaluate(
        self, identity: Identity, upstream: str | None, tool: str | None, arguments: Any
    ) -> Decision:
        if upstream is None or tool is None:
            return self._deny(REASON_NO_ROUTE, "request has no resolved upstream/tool", None)

        match = self._first_match(identity.subject, upstream, tool)
        if match is None:
            if self.default == "allow":
                return Decision.allow()
            return self._deny(REASON_DEFAULT, "no rule matched; default is deny", None)

        where = f"policy.rules[{match.index}]"
        if match.rule.effect == "deny":
            return self._deny(REASON_RULE, "matched a deny rule", where)

        if match.validator is not None:
            args = {} if arguments is None else arguments
            try:
                valid = match.validator.is_valid(args)
            except Exception:
                # Hostile arguments (e.g. pathological nesting) must not crash
                # into an allow; treat any validator failure as invalid.
                valid = False
            if not valid:
                return self._deny(REASON_ARGUMENTS, "arguments failed the rule's schema", where)
        return Decision.allow()

    async def on_request(self, ctx: CallContext) -> Decision | None:
        return self.evaluate(ctx.identity, ctx.upstream, ctx.tool, ctx.arguments)

    @staticmethod
    def _deny(reason: str, message: str, location: str | None) -> Decision:
        finding = Finding(
            detector=DETECTOR,
            category=Category.POLICY,
            severity=Severity.MEDIUM,
            message=message,
            location=location,
        )
        return Decision.deny(reason, [finding])
