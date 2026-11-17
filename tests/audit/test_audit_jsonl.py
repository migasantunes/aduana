from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from aduana.audit.jsonl import MAX_EVIDENCE_CHARS, JsonlAuditSink, build_audit_sink
from aduana.config import AuditConfig, Config
from aduana.pipeline.types import Action, AuditEvent, AuditSink, Category, Finding, Severity


def event(**kw: object) -> AuditEvent:
    base: dict[str, object] = {
        "kind": "tool_call",
        "ts": 1_700_000_000.5,
        "subject": "alice",
        "method": "tools/call",
        "action": Action.DENY,
        "upstream": "files",
        "tool": "read",
        "reason": "blocked",
        "findings": (
            Finding(
                detector="rules:x",
                category=Category.RESULT_INJECTION,
                severity=Severity.HIGH,
                message="m",
                evidence="ev",
                location="content[0].text",
            ),
        ),
        "latency_ms": 1.25,
        "traceparent": "00-abc-def-01",
        "request_id": 7,
    }
    base.update(kw)
    return AuditEvent(**base)  # type: ignore[arg-type]


def test_protocol() -> None:
    sink: AuditSink = JsonlAuditSink()
    assert sink is not None


def test_writes_one_json_object_per_line(tmp_path: Path) -> None:
    path = tmp_path / "logs" / "nested" / "audit.jsonl"
    with JsonlAuditSink(path) as sink:
        sink.emit(event())
        sink.emit(event(action=Action.ALLOW, findings=()))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["action"] == "deny"
    assert first["kind"] == "tool_call"
    assert first["request_id"] == 7
    assert first["findings"] == [
        {
            "detector": "rules:x",
            "category": "result_injection",
            "severity": "high",
            "message": "m",
            "evidence": "ev",
            "location": "content[0].text",
        }
    ]
    assert json.loads(lines[1])["findings"] == []


def test_appends_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    for _ in range(2):
        with JsonlAuditSink(path) as sink:
            sink.emit(event())
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_line_is_flushed_immediately(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    sink.emit(event())
    assert path.read_text(encoding="utf-8").count("\n") == 1
    sink.close()


def test_stderr_when_no_path(capsys: pytest.CaptureFixture[str]) -> None:
    JsonlAuditSink(None).emit(event())
    err = capsys.readouterr().err
    assert json.loads(err)["subject"] == "alice"


def test_newlines_and_controls_cannot_forge_lines(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    with JsonlAuditSink(path) as sink:
        sink.emit(event(reason='x\n{"forged": true}‮\x1b[2J'))
    text = path.read_text(encoding="utf-8")
    assert text.count("\n") == 1
    assert text.isascii()
    assert json.loads(text)["reason"].startswith("x\n")


def test_evidence_capped(tmp_path: Path) -> None:
    long = Finding(
        detector="d",
        category=Category.POLICY,
        severity=Severity.LOW,
        message="m",
        evidence="e" * 10_000,
    )
    path = tmp_path / "a.jsonl"
    with JsonlAuditSink(path) as sink:
        sink.emit(event(findings=(long,)))
    ev = json.loads(path.read_text(encoding="utf-8"))["findings"][0]["evidence"]
    assert len(ev) <= MAX_EVIDENCE_CHARS


def test_non_finite_numbers_become_null(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    with JsonlAuditSink(path) as sink:
        sink.emit(event(latency_ms=float("nan")))
    assert json.loads(path.read_text(encoding="utf-8"))["latency_ms"] is None


def test_emit_never_raises_and_counts_errors(tmp_path: Path) -> None:
    sink = JsonlAuditSink(tmp_path / "a.jsonl")
    sink.close()
    sink._fh = open(tmp_path / "b.jsonl", "w")  # noqa: SIM115
    sink._fh.close()  # writes to a closed file raise ValueError
    sink.emit(event())
    sink.emit(event())
    assert sink.errors == 2


def test_emit_survives_unserialisable_and_broken_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    class Broken:
        def write(self, s: str) -> int:
            raise OSError("pipe closed")

        def flush(self) -> None:
            raise OSError("pipe closed")

    import sys

    monkeypatch.setattr(sys, "stderr", Broken())
    sink = JsonlAuditSink(None)
    sink.emit(event())
    sink.emit(event(request_id=object()))  # default=str copes; stream still broken
    assert sink.errors == 2


def test_thread_safety(tmp_path: Path) -> None:
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)

    def worker(n: int) -> None:
        for i in range(200):
            sink.emit(event(request_id=n * 1000 + i, reason="r" * 500))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    sink.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1600
    ids = {json.loads(line)["request_id"] for line in lines}
    assert len(ids) == 1600
    assert sink.errors == 0


def test_build_audit_sink(tmp_path: Path) -> None:
    sink = build_audit_sink(Config(audit=AuditConfig(path=tmp_path / "x" / "a.jsonl")))
    assert isinstance(sink, JsonlAuditSink)
    sink.emit(event())
    sink.close()
    assert (tmp_path / "x" / "a.jsonl").exists()
    assert isinstance(build_audit_sink(Config()), JsonlAuditSink)
