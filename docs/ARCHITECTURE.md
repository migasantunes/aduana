# Architecture

aduana is a reverse proxy for the Model Context Protocol. Agents connect to it as if it were
one MCP server; it connects to the real servers ("upstreams") as an MCP client. Everything that
crosses is inspected.

```
                    ┌──────────────────────── aduana ────────────────────────┐
 agent / MCP client │  gateway/          pipeline/              upstream/     │  MCP servers
 ───────────────────▶  POST /mcp   ──▶  request stages   ──▶   client  ──────▶  files
   2026-07-28       │  validation        policy, secrets                      │  search
 ◀───────────────────  response    ◀──  response stages  ◀──   registry ◀─────  ...
                    │                    injection detectors                  │
                    │  catalog  ◀──────  tool stages (pinning, poisoning)     │
                    │                         │                               │
                    │                     audit/ (JSONL, later OTel)          │
                    └─────────────────────────────────────────────────────────┘
```

## Why the 2026-07-28 revision makes this design simple

The protocol is stateless: no handshake, no session ID, every request carries its own version
and capabilities. A request can therefore be validated, judged and forwarded with no memory of
earlier requests. The gateway holds exactly two pieces of state, both derived and rebuildable:
the cached upstream catalogs and the pin lockfile. Any number of gateway replicas can sit
behind a load balancer.

## Components

| Package | Responsibility | Depends on |
| --- | --- | --- |
| `aduana.protocol` | JSON-RPC models, `_meta` keys, error codes, header mirroring and the base64 sentinel. Pure functions, no I/O. | nothing |
| `aduana.gateway` | The Starlette app: downstream endpoint, transport validation, method dispatch, turning decisions into wire responses. | protocol, upstream, pipeline.types |
| `aduana.upstream` | Modern Streamable HTTP client (JSON and SSE responses), upstream registry, aggregated catalog and tool-name routing. | protocol |
| `aduana.pipeline` | `types.py` is the contract. `engine.py` runs stages in order and merges their decisions. | types only |
| `aduana.policy` | Who may call which tool with which arguments. | pipeline.types, config |
| `aduana.pinning` | Canonical hashing of tool definitions and the lockfile. | pipeline.types, config |
| `aduana.detect` | Detectors for poisoned descriptions, injected results, leaked secrets. | pipeline.types |
| `aduana.audit` | Audit sinks. | pipeline.types |
| `aduana.config` | YAML → validated config objects. | pipeline.types |
| `aduana.cli` | `aduana serve`, `aduana pin`. Wires everything together. | all |
| `lab/` | Attack lab: deliberately malicious and benign MCP servers, scenarios, harness. Not shipped in the wheel and never imported by `aduana`. | starlette only |

Rule: `gateway` and `upstream` never import `policy`, `pinning`, `detect` or `audit`. They see
only `Pipeline` and `AuditSink` from `pipeline/types.py`. This keeps the proxy testable with a
fake pipeline and keeps every security stage testable with no HTTP.

## Request lifecycle: `tools/call`

1. **Transport validation** (`gateway`). POST only. Origin check. Body size cap. Parse one
   JSON-RPC message. Required `_meta` fields present. `MCP-Protocol-Version`, `Mcp-Method`,
   `Mcp-Name` present and equal to the body (after sentinel decoding). Failures are answered
   here with the spec's status and error code and logged as `protocol_reject`.
2. **Routing** (`upstream.catalog`). Split the exposed name `<upstream>__<tool>` on the first
   `__`. Unknown upstream or a tool not in the exposed catalog → JSON-RPC `-32602` "Unknown
   tool". A tool that pinning or a detector quarantined is not in the exposed catalog, so it
   cannot be called even by name.
3. **Request stages** (`pipeline.check_request`). Policy first (cheap, decisive), then secret
   scanning of the arguments.
4. **Forward** (`upstream.client`). The gateway builds a *new* request: its own `id`, its own
   `_meta` (version, its own `clientInfo`, the client's declared capabilities, `traceparent`
   propagated), the upstream's tool name, fresh mirrored headers including `Mcp-Param-*`
   computed from the upstream tool's `inputSchema`. The agent's `Authorization` header is never
   forwarded; upstream credentials come from config.
5. **Response stages** (`pipeline.check_response`). Only for `resultType: "complete"`.
   An `input_required` result is passed through untouched at M0 (see open questions).
6. **Reply**. The client's original `id` is restored. `serverInfo` in `_meta` is aduana's.

### How a denial looks on the wire

A blocked `tools/call` is returned as a **tool execution error**, not a JSON-RPC error:

```json
{
  "resultType": "complete",
  "isError": true,
  "content": [{ "type": "text", "text": "Blocked by aduana: <reason>" }],
  "_meta": { "io.github.migasantunes.aduana/decision": { "action": "deny", "categories": ["policy"] } }
}
```

Reason: the spec reserves JSON-RPC errors for things the model cannot fix, and says clients
should hand tool execution errors to the model. A model that sees "blocked" can tell the user
or choose another tool; a model that sees a transport error tends to retry. The `reason` text
is written by the gateway from a fixed set of templates. It never echoes upstream-controlled
text, otherwise the denial message itself would carry the injection.

## Catalog lifecycle: `tools/list`

1. For each upstream, fetch all pages of `tools/list` (cached until its `ttlMs`, capped by
   `gateway.max_list_ttl_ms`).
2. Each tool definition goes through the **tool stages**: `x-mcp-header` constraint check
   (the spec requires clients to drop invalid tools), pinning, poisoning detection.
   Denied tools are quarantined: left out of the exposed catalog and audited.
3. Surviving tools are renamed `<upstream>__<tool>`, sorted by exposed name (deterministic
   order), and returned with `ttlMs` = the minimum over upstreams and `cacheScope: "private"`
   (the list depends on the caller's identity once policy filtering applies).
4. Policy filters the list per identity: a tool the caller could never invoke is not shown.

One upstream being down removes its tools from the list and is audited; it does not fail the
whole list.

## Threat → control map

Details and test cases live in `docs/THREAT_MODEL.md`.

| Threat | Where it enters | Control | Stage |
| --- | --- | --- | --- |
| Tool poisoning (hidden instructions in a description or schema) | `tools/list` | detectors over every model-visible string of the definition | tool |
| Rug pull (definition changes after approval) | `tools/list` | hash pinning against the lockfile | tool |
| Tool shadowing (one server's description steers use of another's tool) | `tools/list` | cross-upstream reference check; namespacing | tool |
| Result injection (instructions inside tool output) | `tools/call` result | detectors over text, embedded resources, links, `structuredContent` strings | response |
| Secret exfiltration (agent tricked into sending secrets as arguments) | `tools/call` arguments | secret scanner | request |
| Excess privilege | `tools/call` | policy rules, argument schemas | request |
| Header/body smuggling | HTTP | mirrored-header validation | transport |
| DNS rebinding | HTTP | Origin allow-list, loopback bind | transport |
| Confused deputy / token passthrough | HTTP auth | audience-bound tokens, separate upstream credentials | transport (M3) |

## Decisions and their reasons

- **Python, own wire layer.** The target reader is hiring for ML engineering, the detectors are
  ML, and the stateless revision makes the wire layer a few hundred lines. The official `mcp`
  SDK is used only as an interop counterpart in tests (M1), which also makes those tests a
  check of our reading of the spec by an independent implementation.
- **Starlette + httpx, no framework above them.** A proxy needs raw control over status codes,
  headers and streaming.
- **Fail closed.** A stage that raises denies the message. A gateway that lets traffic through
  when its checks break is worse than none.
- **Operator-chosen upstream names for namespacing.** `serverInfo.name` is self-reported and
  the spec says not to rely on it. A malicious server could otherwise name itself after a
  trusted one.
- **Quarantine at catalog time, not call time.** If the model never sees a poisoned
  description, it cannot be steered by it. Call-time checks would be too late.
- **Denials are tool errors.** See above.
- **Audit evidence is truncated.** The audit log must not become a second copy of every
  payload, nor a place where secrets found by the scanner are written in full.

## Open questions (decide in the milestone noted)

1. **MRTR through a gateway (M1).** An upstream may answer `input_required` with an
   elicitation request, whose `message` is third-party text shown to the user: an injection
   and phishing surface. Should response stages scan `inputRequests`? Should URL-mode
   elicitation be allowed at all by default? `requestState` must round-trip opaque.
2. **Sampling requests via MRTR (M1).** Deprecated feature, but an upstream asking the agent's
   model to complete a prompt is the most direct injection there is. Default proposal: deny.
3. **Streaming results (M1).** Response stages need the whole result. Buffer the final
   response, forward progress notifications live.
4. **Per-identity catalogs and caching (M3).** `cacheScope` and cache keys once OAuth lands.
5. **Latency budget (M4/M5).** Which detectors may run inline. The classifier must be measured
   before it is allowed on the request path.
