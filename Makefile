# Developer shortcuts. All real config lives in pyproject.toml; these just wrap uv.
.PHONY: install test lab-test lint fmt fmt-check typecheck check serve lab-up compose-up compose-down

install:
	uv sync

test:
	uv run pytest -q

lab-test:
	uv run pytest -q tests/lab

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

fmt-check:
	uv run ruff format --check .

typecheck:
	uv run mypy

# The gate every commit must pass.
check: lint fmt-check typecheck test

serve:
	uv run aduana serve --config aduana.example.yaml

# Start all five lab servers locally on 127.0.0.1:9101-9105 (backgrounded).
lab-up:
	uv run python -m lab.servers.benign_notes --port 9101 &
	uv run python -m lab.servers.poisoned_weather --port 9102 &
	uv run python -m lab.servers.rugpull_calc --port 9103 &
	uv run python -m lab.servers.injecting_search --port 9104 &
	uv run python -m lab.servers.greedy_export --port 9105 &
	@echo "lab servers started on 9101-9105 (kill with: pkill -f lab.servers)"

compose-up:
	docker compose up --build

compose-down:
	docker compose down
