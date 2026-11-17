# aduana

A security gateway for the Model Context Protocol: it proxies MCP traffic between agents and
MCP servers and blocks poisoned tools, changed tool definitions, injected results and leaked
secrets. Portfolio project; correctness against the spec and measured results matter more than
feature count.

## Read first

- `docs/PLAN.md`: milestones and what is done. Update it when you finish a task.
- `docs/ARCHITECTURE.md`: components, request lifecycle, decisions, open questions.
- `docs/SPEC_NOTES.md`: the MCP 2026-07-28 rules this code relies on.
- `docs/THREAT_MODEL.md`: threats and the lab scenario that exercises each.

## Commands

```bash
uv sync                      # install (add --extra interop / auth / otel / lab as needed)
uv run pytest -q             # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy                  # strict, src/aduana only
uv run aduana serve --config aduana.example.yaml
```

All four checks must pass before a commit.

## How to work in this repo

- The lead model plans and reviews; implementation is delegated to Opus sub-agents. Give each
  sub-agent a set of files no other sub-agent touches, the relevant section of the plan, and
  the contracts it must honour. Review and run the checks yourself before accepting the work.
- MCP changed fundamentally in the 2026-07-28 revision (no sessions, no `initialize`). Do not
  write protocol code from memory. Check `docs/SPEC_NOTES.md`, and when it is silent, fetch the
  spec page (append `.md` to the URL) and then add what you learned to SPEC_NOTES.
- The same applies to the official `mcp` Python SDK: inspect the installed package before
  using it.

## Rules of the codebase

- `src/aduana/pipeline/types.py` and `src/aduana/config.py` are contracts. Changing them is a
  design change: update ARCHITECTURE.md in the same commit.
- `gateway/` and `upstream/` never import `policy/`, `pinning/`, `detect/` or `audit/`.
- `lab/` is never imported by `src/aduana`. Lab servers are intentionally malicious; they bind
  to loopback only and must not gain real capabilities (no real file or network access).
- Fail closed: an exception in a security stage denies the message.
- Never forward the client's `Authorization` header to an upstream.
- Text written by an upstream is untrusted everywhere, including in log lines, denial messages
  and error strings. Never interpolate it into anything the model will read.
- Audit evidence is truncated to a short excerpt; secrets found by the scanner are masked.
- Error codes: only the ones in SPEC_NOTES §3. Never invent a code in `-32768..-32000`.
- Every security control gets a test that fails without it.
- No claims in the README without a reproducible command behind them.

## Style

Python 3.12+, full type hints, mypy strict, ruff. Small pure functions in `protocol/`.
Async I/O only at the edges. Docstrings say why, not what. No new dependency without a reason
written in the commit message.
