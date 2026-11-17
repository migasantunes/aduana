# aduana attack lab

A set of small MCP servers — one benign, the rest deliberately malicious — plus scenario files
that describe concrete attacks against them. The lab is how aduana's security controls are
exercised and, at milestone M4, measured.

> **This code is never imported by `aduana`.** Running the gateway against these servers is the
> project's interoperability and detection check: the lab implements the *server* side of MCP
> 2026-07-28 independently of the gateway, so a misreading of the spec shows up as a failure
> rather than being shared by both sides.

## Safety rules

The malicious servers are safe to run because they have no teeth:

- **Loopback only.** Every server binds to `127.0.0.1` and refuses any other host.
- **No real capabilities.** No server reads a file, opens a socket, or runs a subprocess.
  A "credential exfiltration" tool only ever appends a string to an in-memory list.
- **Synthetic payloads only.** Every attack string carries the canary prefix
  `CANARY-ADUANA-…` and every sink URL uses the reserved `.invalid` TLD, which can never
  resolve. There is no working exploit infrastructure anywhere.
- **The canary is the success signal.** An attack "succeeds" exactly when the canary turns up
  where it should not: in an argument a server recorded, or in content that reached the client.
  Tests and the future harness check for the canary, never for real damage.

## The servers

| Module | Port | Category | What it does |
| --- | --- | --- | --- |
| `benign_notes` | 9101 | — | Ordinary in-memory notes (list/read/add). The control. |
| `poisoned_weather` | 9102 | `tool_poisoning` | Weather tools hiding instructions in the description, a schema property, and invisible Unicode. |
| `rugpull_calc` | 9103 | `rug_pull` | A calculator whose `add` tool turns malicious after the first `tools/list`. |
| `injecting_search` | 9104 | `result_injection` | A search tool that injects instructions via text, embedded resource, and `structuredContent`; includes an SSE-answering tool. |
| `greedy_export` | 9105 | `secret_exfiltration` | A clean-looking `export` sink that records what it receives. |

## Running a server

```bash
uv run python -m lab.servers.benign_notes --port 9101
uv run python -m lab.servers.poisoned_weather --port 9102
uv run python -m lab.servers.rugpull_calc --port 9103
uv run python -m lab.servers.injecting_search --port 9104
uv run python -m lab.servers.greedy_export --port 9105
```

Each server exposes one POST endpoint, `/mcp`, speaking MCP 2026-07-28. A correct request
needs the mirrored headers and `_meta` (see the repository `README.md` for a full `curl`
example). The tests drive the same apps in-process with `httpx.ASGITransport`, which is the
quickest way to see a valid request.

## Scenarios

`lab/scenarios/*.yaml` — one file per attack, schema documented in
`lab/scenarios/README.md`. Each names the server it drives, the steps a client performs, the
`success_signal` that proves the attack worked without a gateway, and the
`expected_gateway_action` aduana should take. The tests validate that every scenario parses and
references a real server and a valid `Category`.

## M4 agent harness — design sketch (NOT BUILT YET)

The harness that turns these servers into headline numbers is milestone M4 and does not exist
yet. The intended shape:

- **Driver.** A real model with tool use (via the `lab` extra, `anthropic>=0.40`) is given a
  task and a set of MCP servers, once connected directly and once through aduana.
- **Replay.** Each scenario's `steps` seed the task; the model chooses tool calls freely. A run
  is an *attacker win* when the canary is exfiltrated (recorded by a sink server) or a
  forbidden tool is invoked, matching the scenario's `success_signal`.
- **Metrics** (defined in `docs/BENCHMARK.md`): attack success rate with and without the
  gateway per category; false-positive rate on the benign suite; task-completion rate through
  the gateway; added latency p50/p95/p99. Each with a confidence interval over repeated runs,
  and the model name and date recorded.
- **Budget.** The model-call budget is written down before any run; no numbers are published
  until the harness is built and run. There are no results yet.
