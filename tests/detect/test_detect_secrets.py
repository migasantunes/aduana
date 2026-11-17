"""Secret scanner tests.

Every fake credential is assembled at runtime from fragments so that this file
contains no token-shaped literal for repository secret scanners to trip on.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from aduana.detect.secrets import REASON, SecretScanner, mask, shannon_entropy
from aduana.pipeline.types import Action, CallContext, Category, Identity, Severity

ALNUM = "Q7mZ2xK9pL4vR8nT3wY6bH1cJ5dF0gS"  # deterministic pseudo-random filler


def filler(n: int, alphabet: str = ALNUM) -> str:
    return (alphabet * (n // len(alphabet) + 1))[:n]


def upper_filler(n: int) -> str:
    return filler(n, "Q7MZ2XK9PL4VR8NT3WY6BH1CJ5DF0GS")


FAKE: dict[str, str] = {
    "pem_private_key": "-----BEGIN " + "RSA PRIVATE" + " KEY-----\n" + filler(64) + "\n-----END",
    "openssh_private_key": "-----BEGIN " + "OPENSSH PRIVATE" + " KEY-----\nb3Blbn",
    "aws_access_key_id": "AK" + "IA" + upper_filler(16),
    "github_token": "gh" + "p_" + filler(36),
    "github_pat": "github" + "_pat_" + filler(40),
    "slack_token": "xo" + "xb-" + "1234567890-" + filler(24),
    "slack_webhook": "https://hooks.slack.com/services/"
    + "T0"
    + "AAAA/"
    + "B0"
    + "BBBB/"
    + filler(24),
    "google_api_key": "AI" + "za" + filler(35),
    "stripe_key": "sk" + "_live_" + filler(24),
    "sk_api_key": "sk" + "-proj-" + filler(40),
    "jwt": "ey" + "J" + filler(20) + ".ey" + "J" + filler(30) + "." + filler(30),
}

EXPECTED_RULE = {
    "pem_private_key": "pem_private_key",
    "openssh_private_key": "pem_private_key",
    "aws_access_key_id": "aws_access_key_id",
    "github_token": "github_token",
    "github_pat": "github_token",
    "slack_token": "slack_token",
    "slack_webhook": "slack_token",
    "google_api_key": "google_api_key",
    "stripe_key": "stripe_key",
    "sk_api_key": "sk_api_key",
    "jwt": "jwt",
}


def ctx(arguments: Any) -> CallContext:
    return CallContext(
        request_id=1,
        method="tools/call",
        identity=Identity(),
        upstream="u",
        tool="t",
        arguments=arguments,
    )


def ids(findings: list[Any]) -> set[str]:
    return {f.detector.removeprefix("secrets:") for f in findings}


@pytest.mark.parametrize("kind", sorted(FAKE))
async def test_format_rules_deny_and_mask(kind: str) -> None:
    secret = FAKE[kind]
    d = await SecretScanner().on_request(ctx({"note": f"here you go: {secret} thanks"}))
    assert d is not None and d.action is Action.DENY and d.reason == REASON
    assert EXPECTED_RULE[kind] in ids(d.findings)
    for f in d.findings:
        assert f.category is Category.SECRET_EXFILTRATION
        assert f.location == "arguments.note"
        assert f.evidence is not None and "…(" in f.evidence
    blob = repr(d)
    # Neither the secret nor any long chunk of it may appear anywhere.
    assert secret not in blob
    assert secret[4:20] not in blob


def test_pem_is_critical() -> None:
    (f,) = SecretScanner().scan({"k": FAKE["pem_private_key"]})
    assert f.severity is Severity.CRITICAL


def test_mask_format() -> None:
    assert mask("abcdefghij") == "abcd…(10 chars)"
    assert mask("\x1bxyz123") == "\\u001bxyz…(7 chars)"


async def test_nested_arguments_and_lists() -> None:
    secret = FAKE["github_token"]
    d = await SecretScanner().on_request(ctx({"a": {"b": [1, "x", {"c": secret}]}}))
    assert d is not None and d.action is Action.DENY
    assert d.findings[0].location == "arguments.a.b[2].c"


async def test_zero_width_inside_token_still_caught() -> None:
    secret = FAKE["aws_access_key_id"]
    hidden = secret[:6] + "​" + secret[6:]
    d = await SecretScanner().on_request(ctx({"x": hidden}))
    assert d is not None and d.action is Action.DENY


# --- entropy heuristic ---------------------------------------------------------

OPAQUE = "Zx81" + "qPv0" + "Lm2Tk9Rb4Wy7Nc3Hd6Fj5Gs1Ae8"


def test_entropy_of_opaque_value() -> None:
    assert shannon_entropy(OPAQUE) > 4.0
    assert shannon_entropy("aaaa") == 0.0


async def test_assignment_in_free_text_is_high() -> None:
    d = await SecretScanner().on_request(ctx({"body": "config: client_secret=" + OPAQUE}))
    assert d is not None and d.action is Action.DENY
    assert ids(d.findings) == {"high_entropy_assignment"}
    assert OPAQUE not in repr(d)


async def test_bearer_context_is_high() -> None:
    d = await SecretScanner().on_request(ctx({"h": "Authorization: Bearer " + OPAQUE}))
    assert d is not None and d.action is Action.DENY


async def test_named_argument_is_medium_and_allowed_by_default() -> None:
    d = await SecretScanner().on_request(ctx({"api_key": OPAQUE}))
    assert d is not None and d.action is Action.ALLOW
    (f,) = d.findings
    assert f.severity is Severity.MEDIUM and f.detector == "secrets:high_entropy_named_argument"
    assert OPAQUE not in repr(d)


async def test_named_argument_denied_with_lower_threshold() -> None:
    d = await SecretScanner(deny_at=Severity.MEDIUM).on_request(ctx({"auth": {"token": OPAQUE}}))
    assert d is not None and d.action is Action.DENY


@pytest.mark.parametrize(
    "arguments",
    [
        {"path": "/srv/data/reports/2026/q3/summary-final.pdf"},
        {"id": "3f2b8c1e-9a4d-4e7b-8c2f-1a2b3c4d5e6f"},  # UUID, no context
        {"sha": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"text": "The quick brown fox jumps over the lazy dog. " * 20},
        {"image": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"},
        {"author": OPAQUE},  # 'author' is not 'auth'
        {"password": "hunter2"},  # short: below the entropy length floor
        {"skill": "sk-learn is a library"},
        {},
    ],
)
async def test_benign_arguments_not_flagged(arguments: dict[str, Any]) -> None:
    assert await SecretScanner().on_request(ctx(arguments)) is None


async def test_none_arguments() -> None:
    assert await SecretScanner().on_request(ctx(None)) is None


async def test_bounded_scan_reports_truncation() -> None:
    scanner = SecretScanner()
    findings = scanner.scan(["x"] * 20_000)
    assert any(f.detector == "secrets:limits.truncated" for f in findings)


def test_findings_capped() -> None:
    args = {f"k{i}": FAKE["github_token"] for i in range(200)}
    assert len(SecretScanner().scan(args)) <= 65


async def test_secret_never_reaches_audit_line() -> None:
    from aduana.audit.jsonl import event_to_line
    from aduana.pipeline.types import AuditEvent

    for secret in FAKE.values():
        d = await SecretScanner().on_request(ctx({"x": secret}))
        assert d is not None
        line = event_to_line(
            AuditEvent(
                kind="tool_call",
                ts=0.0,
                subject="s",
                method="tools/call",
                action=d.action,
                reason=d.reason,
                findings=tuple(d.findings),
            )
        )
        assert secret not in line and secret[4:16] not in line
        assert json.loads(line)["findings"]
