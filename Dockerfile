# Multi-stage, uv-based build for the aduana gateway.
#
# The gateway's host/port come from the CLI (another engineer's work): the entrypoint runs
# `aduana serve`; --host/--port flags can be appended by compose or `docker run`.

# ---- builder: resolve and install dependencies into a venv -------------------------------
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0

WORKDIR /app

# Install dependencies first (cached unless the lockfile or project metadata changes).
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

# Then install the project itself.
COPY src ./src
COPY README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# ---- runtime: slim Python, non-root, just the venv and the source ------------------------
FROM python:3.12-slim-bookworm AS runtime

# curl is used by the healthcheck below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 aduana

WORKDIR /app

COPY --from=builder --chown=aduana:aduana /app/.venv /app/.venv
COPY --from=builder --chown=aduana:aduana /app/src /app/src
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

USER aduana

EXPOSE 8700

# The gateway serves a liveness endpoint at /healthz (bound to 0.0.0.0 inside the container).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8700/healthz || exit 1

# Config is mounted at /etc/aduana/aduana.yaml. Host/port flags are provided by the CLI.
ENTRYPOINT ["aduana", "serve", "--config", "/etc/aduana/aduana.yaml", "--host", "0.0.0.0"]

# ---- lab: the attack-lab servers, for the compose demo -----------------------------------
# A small target on top of the runtime image: adds the lab package (deliberately malicious and
# benign MCP servers, starlette-only). compose.yaml builds its lab services from this target.
# Lab servers bind loopback only, so they run on an internal network and are never published.
FROM runtime AS lab

USER root
COPY --chown=aduana:aduana lab /app/lab
ENV PYTHONPATH=/app
USER aduana

# Overridden per service in compose (each runs a different module on its own port).
ENTRYPOINT ["python", "-m"]
CMD ["lab.servers.benign_notes", "--port", "9101", "--host", "0.0.0.0"]
