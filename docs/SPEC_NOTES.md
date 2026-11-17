# MCP 2026-07-28: notes for implementers of aduana

Distilled from the official specification on 2026-11-16. The spec is the source of truth:
<https://modelcontextprotocol.io/specification/2026-07-28>. When this file and the spec
disagree, the spec wins; fix this file. Do not implement protocol behaviour from memory of
older MCP revisions: this revision removed sessions and the handshake.

## 1. What changed versus 2025-11-25 (and why it matters for a gateway)

| Change | Consequence for aduana |
| --- | --- |
| No `initialize` / `notifications/initialized` handshake | Nothing to track per connection. Every request is judged alone. |
| No `Mcp-Session-Id`, no GET stream, no DELETE | Downstream endpoint is POST only. GET/DELETE get `405`. Ignore `Mcp-Session-Id` and `Last-Event-ID`. |
| Version + capabilities travel in `params._meta` on every request | We validate them on every request and re-issue our own towards upstreams. |
| `server/discover` is mandatory for servers | We answer it ourselves and call it on upstreams. |
| Server-to-client requests are gone; replaced by MRTR (`resultType: "input_required"`) | A proxied result can be an input request. Must be passed through, not treated as final content. |
| `subscriptions/listen` replaces GET stream and `resources/subscribe` | One long-lived POST response stream. M1. |
| List results carry `ttlMs` and `cacheScope` | We must emit both on aggregated lists. |
| `ping`, `logging/setLevel`, `notifications/roots/list_changed` removed | Do not implement. |
| Roots, Sampling, Logging deprecated | Pass through if an upstream uses them; do not build features on them. |
| SSE resumability removed | A broken stream loses the request. No event IDs. |
| Error codes `-32020..-32099` reserved for the spec | Never invent codes in `-32768..-32000`. |

## 2. Messages

JSON-RPC 2.0. Request `id` is a string or integer, never `null`.

Every **result** MUST contain `resultType`:
- `"complete"`: final.
- `"input_required"`: MRTR interim result with `inputRequests` and optional `requestState`.
- A missing `resultType` from an older server MUST be treated as `"complete"`.
- An unrecognised value is invalid.

### Per-request `_meta` (inside `params._meta`)

| Key | Required | Notes |
| --- | --- | --- |
| `io.modelcontextprotocol/protocolVersion` | yes | e.g. `"2026-07-28"` |
| `io.modelcontextprotocol/clientCapabilities` | yes | object, may be `{}` |
| `io.modelcontextprotocol/clientInfo` | no (SHOULD) | `{name, version}`; self-reported, never use for security decisions |
| `io.modelcontextprotocol/logLevel` | no | deprecated logging feature |
| `progressToken` | no | opts into progress notifications |
| `traceparent`, `tracestate`, `baggage` | no | W3C trace context; propagate to upstreams |

A request missing a required field is malformed: JSON-RPC `-32602`, HTTP `400`.

### Per-response `_meta`

Servers SHOULD put `io.modelcontextprotocol/serverInfo` (`{name, version}`) in every result's
`_meta`. Self-reported; never trust it for security decisions or disambiguation.

### Vendor `_meta` keys

Prefix is reverse-DNS + `/`. Any prefix whose second label is `mcp` or `modelcontextprotocol`
is reserved. aduana uses `io.github.migasantunes.aduana/` (for example
`io.github.migasantunes.aduana/decision`).

## 3. Error codes

| Code | Name | HTTP |
| --- | --- | --- |
| `-32700` | Parse error | 400 |
| `-32600` | Invalid request | 400 |
| `-32601` | Method not found | 404 |
| `-32602` | Invalid params (also: unknown tool, resource not found, missing `_meta` field) | 400 where stated |
| `-32603` | Internal error | 500 |
| `-32020` | `HeaderMismatch` | 400 |
| `-32021` | `MissingRequiredClientCapability` (`data.requiredCapabilities`) | 400 |
| `-32022` | `UnsupportedProtocolVersion` (`data.supported: [...]`, `data.requested`) | 400 |

`-32002` and `-32042` belong to older revisions: accept from legacy upstreams, never emit.
Application-defined codes go outside `-32768..-32000`.

Two kinds of tool failure:
- **Protocol error** (JSON-RPC `error`): unknown tool, malformed request, server fault.
- **Tool execution error** (a normal result with `isError: true`): feedback the model can act on.

## 4. Streamable HTTP transport

One endpoint, POST only (aduana: `/mcp`).

Client request headers:
- `Accept: application/json, text/event-stream` (both, always)
- `Content-Type: application/json`
- `MCP-Protocol-Version: <version>`; MUST equal `_meta["io.modelcontextprotocol/protocolVersion"]`
- `Mcp-Method: <method>`; MUST equal body `method`; required on all requests
- `Mcp-Name: <params.name or params.uri>`; required for `tools/call`, `resources/read`, `prompts/get`
- `Mcp-Param-{Name}: <value>` for every tool parameter annotated with `x-mcp-header` in the
  tool's `inputSchema` (clients MUST support this)

Header **names** compare case-insensitively; **values** are case-sensitive.

### Base64 sentinel

A value that is not plain visible ASCII (0x21-0x7E plus inner spaces/tabs), has leading or
trailing whitespace, or itself looks like the sentinel, is sent as
`=?base64?<base64 of UTF-8>?=` (markers lowercase, case-sensitive). Applies to `Mcp-Name` and
`Mcp-Param-*`. Servers decode before comparing with the body.

### Server validation (this is security-relevant: it is what stops header/body smuggling)

Reject with HTTP `400` + JSON-RPC `-32020` when:
- a required standard header is missing,
- a header value differs from the body value (after sentinel decoding; integers compared
  numerically),
- a header value contains invalid characters.

Other rules:
- Unsupported version: `400` + `-32022` listing `supported`.
- Unknown method: `404` + `-32601`.
- `Origin` present and not allowed: `403` (DNS-rebinding defence). Bind to `127.0.0.1` by default.
- Body is one JSON-RPC request or notification. Clients never send responses.
- Notification accepted: `202`, empty body.
- Request: answer with `application/json` (one object) **or** `text/event-stream` (notifications
  related to that request, then the final response, then close). Clients must handle both.
- SSE streams SHOULD set `X-Accel-Buffering: no`. Lines starting with `:` are keep-alive comments.
- Closing the response stream cancels the request. No `notifications/cancelled` over HTTP.
- Unknown `Mcp-Param-*` headers: intermediaries MUST forward them.
- Intermediaries enforcing policy on mirrored headers SHOULD reject requests whose
  `MCP-Protocol-Version` is absent or older than the revision that mandates header/body validation.

### Legacy traffic hitting a modern-only server

- GET or DELETE on the endpoint: `405`.
- `Mcp-Session-Id` / `Last-Event-ID`: ignore; never mint or echo a session ID.
- `initialize`: reject, and name the supported versions in the error message (legacy clients
  cannot fall forward, this text is their only diagnostic).

### Client talking to an unknown-era server (upstream side of aduana, M1)

Try a modern request first. On `400`, read the body: a recognised modern JSON-RPC error means
"modern server, fix the request"; anything else means legacy, fall back to `initialize`.
Cache the era per origin.

## 5. `server/discover`

Request: no params beyond `_meta`. Result:

```json
{
  "resultType": "complete",
  "supportedVersions": ["2026-07-28"],
  "capabilities": { "tools": {} },
  "_meta": { "io.modelcontextprotocol/serverInfo": { "name": "aduana", "version": "0.0.1" } },
  "instructions": "optional text for the model",
  "ttlMs": 3600000,
  "cacheScope": "public"
}
```

`instructions` from an upstream is model-facing text written by a third party: it is an
injection surface and goes through the detectors like a tool description.

## 6. Tools

`tools/list` params: optional `cursor`. Result: `tools`, optional `nextCursor`, required
`ttlMs`, `cacheScope` (`"public"` | `"private"`), `resultType`.

- The list MUST NOT vary per connection. It MAY vary by the authorization presented.
- Order SHOULD be deterministic (prompt-cache friendly). aduana sorts by exposed name.

Tool: `name`, optional `title`, `description`, `inputSchema` (JSON Schema object, default
dialect 2020-12), optional `outputSchema`, `annotations`, `icons`, `_meta`.

- Names: 1-128 chars, `[A-Za-z0-9_.-]`, case-sensitive, unique per server only.
- Aggregating proxies SHOULD disambiguate by prefixing with a server identifier, and MUST NOT
  rely on `serverInfo.name` for that. aduana uses the operator-chosen upstream name from its
  own config: `<upstream>__<tool>`.
- `annotations` are untrusted unless the server is trusted.
- Never auto-dereference a network `$ref`. Bound schema depth / subschema count.

`tools/call` params: `name`, `arguments`, plus on an MRTR retry `inputResponses` and
`requestState`. Result: `content` (blocks of type `text`, `image`, `audio`, `resource_link`,
`resource`), optional `structuredContent` (any JSON value), optional `isError`.

Every one of those content types can carry attacker-controlled text: `text`, the `text` of an
embedded `resource`, `description`/`name` of a `resource_link`, and string leaves of
`structuredContent`.

## 7. Authorization (M3)

The gateway is an OAuth 2.1 **resource server** towards agents and an OAuth **client** towards
protected upstreams. These are two separate trust relationships.

- Serve Protected Resource Metadata (RFC 9728) at `/.well-known/oauth-protected-resource`.
- No or bad token: `401` with
  `WWW-Authenticate: Bearer resource_metadata="<PRM URL>", scope="<needed scopes>"`.
- Insufficient scope: `403` with `error="insufficient_scope"`, `scope=...`, `resource_metadata=...`.
  Emit all scopes needed for the operation in one challenge.
- Validate that the token audience is this gateway (RFC 8707 resource indicators).
- **Token passthrough is forbidden.** Never forward the agent's token upstream. Upstreams get
  credentials issued for them, held by the gateway.
- Tokens only in the `Authorization: Bearer` header, never in the query string.
- As a client: record the expected issuer before redirecting; validate `iss` in the
  authorization response (RFC 9207) before redeeming the code; key stored credentials by issuer.
- STDIO upstreams do not use this: credentials come from the environment.

## 8. Where the spec is silent and what aduana does

These are our choices, not spec text. Revisit them if the spec later decides otherwise.

| Situation | aduana's behaviour | Why |
| --- | --- | --- |
| `initialize` from a legacy client | `400` + `-32022`, `data.supported` listed, versions named in the message | The spec leaves the code open. `-32022` is a recognised modern error, so a dual-era client knows not to fall back. |
| Notification POST | `202` right after parsing, no `_meta` or header checks | The revision defines no client notifications over HTTP and no header rules for them. Nothing is forwarded. |
| `Mcp-Param-*` header the tool's schema does not annotate | Not forwarded upstream | The spec says intermediaries forward unknown ones. aduana is not a pass-through: it terminates the request and issues a new one, so it acts as server and client. Recorded as a deliberate deviation. |
| `Mcp-Param-*` header for a parameter absent or `null` in the body | `400` + `-32020` | The spec says a server "must not expect" it. A router may already have acted on the header, so we fail closed. |
| Numeric comparison of `Mcp-Param-*` | Numeric only when the body value is a JSON number | A string that looks like a number stays a string. |
| JSON body with duplicate keys, NaN or Infinity | `-32700` | Two parsers can disagree on duplicate keys: a smuggling vector. |
| `tools/list` with a cursor | `-32602` | The aggregated list is one page at M0. |
| Upstream result `_meta` keys under aduana's prefix | Stripped | An upstream must not be able to forge a gateway decision. |

Also learned from the spec while building M0:

- `data.requiredCapabilities` of `-32021` is a `ClientCapabilities` object.
- `x-mcp-header`: integer values must be within the JavaScript safe-integer range; type
  `number` is not allowed; the annotated property must be reachable through `properties` keys
  only.

## 9. Pages to read before each milestone

- MRTR: `/specification/2026-07-28/basic/patterns/mrtr`
- Subscriptions: `/specification/2026-07-28/basic/patterns/subscriptions`
- Cancellation, progress: `/specification/2026-07-28/basic/patterns/`
- Caching, pagination: `/specification/2026-07-28/server/utilities/`
- stdio transport: `/specification/2026-07-28/basic/transports/stdio`
- Authorization sub-pages: `/specification/2026-07-28/basic/authorization/`
- Security best practices: `/docs/2026-07-28/tutorials/security/security_best_practices`
- Schema (source of truth): `schema/2026-07-28/schema.ts` in the specification repo
- Appending `.md` to any spec URL returns plain markdown.
