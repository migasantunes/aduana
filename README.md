# aduana

A security gateway (reverse proxy) for the Model Context Protocol. Agents connect to aduana as
if it were a single MCP server; aduana connects to the real servers ("upstreams") as an MCP
client and inspects everything that crosses: it blocks poisoned tool definitions, changed
definitions, injected results, and leaked secrets.

Portfolio project. Correctness against the spec and measured results matter more than feature
count — so this README makes no effectiveness claim that is not backed by a reproducible
command, and the benchmark is explicitly **not run yet** (see [Status](#status) and
[Results](#results)).

Targets **MCP revision 2026-07-28** — the stateless revision: no `initialize` handshake, no
sessions, every request carries its own protocol version and capabilities.

## The problem

MCP lets an agent use tools exposed by third-party servers. Those servers, and the content they
return, are not trustworthy, and the agent reads both tool *definitions* and tool *results* as
context it may act on. That is an injection surface. aduana puts an inspection point between the
agent and the servers.

| Threat | Where it enters | Control | Lab scenario |
| --- | --- | --- | --- |
| Tool poisoning — hidden instructions in a description or schema | `tools/list` | detectors over every model-visible string; quarantine at catalog time | `weather-*-poisoning` |
| Rug pull — a definition changes after approval | `tools/list` | hash pinning against a lockfile | `calc-rug-pull` |
| Result injection — instructions inside tool output | `tools/call` result | detectors over text, embedded resources, links, `structuredContent` | `search-*-injection` |
| Secret exfiltration — agent tricked into sending a secret | `tools/call` arguments | secret scanner on the request side | `export-secret-exfiltration` |
| Excess privilege — forbidden tool or arguments | `tools/call` | default-deny policy with argument schemas | `export-policy-denied` |
| Header/body smuggling, malformed traffic | HTTP transport | mirrored-header validation, Origin allow-list | `header-body-smuggling` |

Full analysis, limits and residual risks: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Architecture

```
                 ┌──────────────── aduana ────────────────┐
  agent / client │  gateway/      pipeline/     upstream/  │  MCP servers
  ───────────────▶  POST /mcp  ─▶ policy, pins ─▶ client  ─▶  files, search, ...
    2026-07-28   │  validation    detectors      registry  │
  ◀───────────────  response   ◀─ (fail closed) ◀─ catalog ◀─
                 │               audit/ (JSONL)             │
                 └─────────────────────────────────────────┘
```

The protocol being stateless makes the proxy simple: every request is validated, judged and
forwarded with no memory of earlier requests. The gateway holds only two pieces of derived
state — the cached upstream catalogs and the pin lockfile. Components and the request lifecycle
are documented in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); the protocol rules the code
relies on are in [`docs/SPEC_NOTES.md`](docs/SPEC_NOTES.md).

## Quickstart

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync                                       # install
```

Run a lab server (a deliberately malicious or benign MCP server used for testing — see
[`lab/README.md`](lab/README.md)):

```bash
uv run python -m lab.servers.benign_notes --port 9101
```

Run the gateway in front of the lab servers:

```bash
uv run aduana serve --config aduana.example.yaml
```

A correct MCP 2026-07-28 `tools/list` request needs the mirrored headers and the required
`_meta` fields. Against the gateway on its default endpoint:

```bash
curl -sS http://127.0.0.1:8700/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/list' \
  -d '{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
          "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientInfo": { "name": "curl", "version": "0" },
            "io.modelcontextprotocol/clientCapabilities": {}
          }
        }
      }'
```

A `tools/call` additionally requires an `Mcp-Name` header equal to the body's `params.name`
(base64-sentinel-encoded if it is not plain ASCII). Omitting or mismatching a mirrored header is
rejected with HTTP 400 / JSON-RPC `-32020` — that check is one of the gateway's controls, not a
formality.

## Configuration

[`aduana.example.yaml`](aduana.example.yaml) is a commented example that drives the whole lab
demo (upstreams on ports 9101–9105, a default-deny policy). It is validated strictly
(`extra="forbid"`); verify it loads with:

```bash
uv run python -c "from aduana.config import load_config; print(load_config('aduana.example.yaml'))"
```

## Development

```bash
uv run pytest -q                              # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy                                   # strict, src/aduana only
```

The attack lab has its own suite:

```bash
uv run pytest -q tests/lab
```

A `Makefile` wraps these (`make check`, `make test`, `make lab-up`), and `compose.yaml` runs the
gateway plus the lab servers on an internal network with only the gateway published on
loopback.

## Status

Milestones mirror [`docs/PLAN.md`](docs/PLAN.md).

- [x] **M0 — scaffold and walking skeleton.** Contracts (`pipeline/types.py`, `config.py`), the
  2026-07-28 wire layer, the gateway endpoint, the upstream client, the pipeline engine with
  rule-based detectors and JSONL audit, and the attack lab v0 (server kit, one benign and four
  malicious servers, scenario files, packaging and CI).
- [ ] **M1 — protocol completeness.** Streaming passthrough, MRTR, resources/prompts,
  subscriptions, pagination, stdio and legacy upstreams, interop tests against the official SDK.
- [ ] **M2 — policy and pinning, complete.** `aduana pin` review flow, drift reports, argument
  constraints, tool-shadowing check, schema hygiene.
- [ ] **M3 — OAuth 2.1.** Resource-server + client roles, per-identity catalogs.
- [ ] **M4 — attack lab and benchmark.** ≥ 12 attack servers, a benign suite, the agent
  harness, and the headline numbers. **This is where results come from.**
- [ ] **M5 — learned detectors.** A fine-tuned classifier and an LLM-judge, measured against the
  rule baseline.
- [ ] **M6 — observability, packaging, write-up.**

## Results

**Not run yet.** The benchmark that produces attack-success, false-positive, task-completion and
latency numbers is milestone M4, and the agent harness it needs is not built. There are no
measured results to report, and this repository contains no invented ones. The measurement
method and the empty result tables are in [`docs/BENCHMARK.md`](docs/BENCHMARK.md).

## License

MIT — see [`LICENSE`](LICENSE).
