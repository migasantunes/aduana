"""Validate every scenario YAML: it parses, references an existing server and a valid Category,
and carries the fields the schema in lab/scenarios/README.md documents.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest
import yaml

from aduana.pipeline.types import Category

SCENARIOS_DIR = Path(__file__).resolve().parents[2] / "lab" / "scenarios"
SCENARIO_FILES = sorted(SCENARIOS_DIR.glob("*.yaml"))

_REQUIRED_FIELDS = {
    "id",
    "category",
    "server",
    "description",
    "attacker_goal",
    "steps",
    "success_signal",
    "expected_gateway_action",
}
_VALID_CATEGORIES = {c.value for c in Category}


def test_scenarios_exist():
    assert SCENARIO_FILES, "no scenario YAML files found"


@pytest.mark.parametrize("path", SCENARIO_FILES, ids=lambda p: p.name)
def test_scenario_is_valid(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{path.name}: top level must be a mapping"

    missing = _REQUIRED_FIELDS - data.keys()
    assert not missing, f"{path.name}: missing fields {missing}"

    # id matches the file name.
    assert data["id"] == path.stem, f"{path.name}: id must equal the file stem"

    # category is a real Category value.
    assert data["category"] in _VALID_CATEGORIES, (
        f"{path.name}: unknown category {data['category']!r}"
    )

    # server module exists under lab.servers and exposes make_app.
    module = importlib.import_module(f"lab.servers.{data['server']}")
    assert hasattr(module, "make_app"), f"{path.name}: server has no make_app"

    # steps are well-formed.
    assert isinstance(data["steps"], list) and data["steps"], f"{path.name}: steps empty"
    for step in data["steps"]:
        assert step.get("action") in {"list_tools", "call_tool", "discover"}, (
            f"{path.name}: bad step action {step.get('action')!r}"
        )
        if step["action"] == "call_tool":
            assert "tool" in step, f"{path.name}: call_tool step needs a tool"


def test_every_category_with_a_server_is_covered():
    """Each attack category that the lab has a server for appears in at least one scenario."""
    covered = {yaml.safe_load(p.read_text(encoding="utf-8"))["category"] for p in SCENARIO_FILES}
    expected = {
        "tool_poisoning",
        "rug_pull",
        "result_injection",
        "secret_exfiltration",
        "policy",
        "protocol_abuse",
    }
    assert expected <= covered, f"categories missing scenarios: {expected - covered}"
