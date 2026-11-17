# Work plan

Each milestone ends in something that runs and a number or artefact that can go on the README.
Work top to bottom. Tick boxes as you go and keep this file honest: it is the project's memory
between Claude Code sessions.

Working setup: the lead model (Fable 5.2) plans a milestone and reviews the result; Opus
sub-agents implement the tasks, one sub-agent per group of files that does not overlap with
another's. See `CLAUDE.md`.

## M0: scaffold and walking skeleton (done in the planning session)

- [x] Architecture, spec notes, threat model, this plan
- [x] Contracts: `pipeline/types.py`, `config.py`
- [x] Wire layer for 2026-07-28: JSON-RPC, `_meta`, mirrored headers, base64 sentinel
- [x] Gateway endpoint: transport validation, `server/discover`, `tools/list`, `tools/call`
- [x] Upstream client (JSON and SSE responses), registry, namespaced catalog
- [x] Pipeline engine, policy, pinning, rule-based detectors, JSONL audit
- [x] Attack lab v0: kit, one benign and three malicious servers, scenario files
- [x] Dockerfile, compose, CI, tests

What M0 does **not** do, on purpose: no auth, no streaming passthrough of progress, no
resources/prompts, no subscriptions, no legacy or stdio upstreams, no LLM in the loop.

State at hand-over (2026-11-17): 592 tests pass, ruff and mypy strict are clean, and
`tests/e2e/` runs the real gateway and pipeline against the lab servers (an independent
implementation of the server side of the spec). The gateway, `aduana pin` and the five lab
servers were also exercised over real sockets with curl.

Known gaps left by M0, each assigned to a milestone below:

- **The Docker image and compose file have never been built.** No Docker daemon was available
  in the planning session. Build them first thing and fix what breaks (M6, but check now).
- `tools/list` is not filtered per identity: a tool that policy would deny is still listed,
  and only the call is refused. `PolicyStage.is_tool_visible` exists; the `Pipeline` contract
  has no hook for it yet (M2).
- Upstream `instructions` from `server/discover` are neither fetched nor scanned (M1).
- `aduana pin` records definitions without showing them or running the detectors over them.
  It is a trust-on-first-use step, not yet a review step (M2).
- The rule detector takes about 0.3 to 1.0 s on a worst-case 512 KB hostile string. Cap the
  inspected size or add a cheap pre-filter before measuring latency (M4).
- The rule detector flags text that merely quotes an injection phrase. Expected for a baseline;
  the benign suite in M4 must include such text so the false-positive rate is honest.
- No lab server for tool shadowing (M2/M4).

## M1: protocol completeness

Goal: any modern MCP client can use any MCP server through aduana without noticing it.

- [ ] Read the MRTR, subscriptions, cancellation, progress, caching, pagination and stdio pages
      (URLs in `docs/SPEC_NOTES.md` §9) and extend SPEC_NOTES with what you learn
- [ ] Interop tests against the official SDK (`uv sync --extra interop`): an SDK client through
      the gateway to an SDK server. Inspect the installed package for its current API; it
      changed a lot in 2.x, do not write it from memory
- [ ] Streaming: forward `notifications/progress` live, buffer and inspect the final result
- [ ] Cancellation: client disconnect cancels the upstream request
- [ ] MRTR: pass `input_required` results through, round-trip `requestState` opaque, decide and
      implement ARCHITECTURE open questions 1 and 2
- [ ] Fetch upstream `server/discover`; scan `instructions` before exposing any of it
- [ ] `resources/*` and `prompts/*`: aggregation with URI/name namespacing, detectors over
      prompt text and resource text
- [ ] `subscriptions/listen`: one downstream stream fanned in from the upstreams, with
      `io.modelcontextprotocol/subscriptionId` tagging; a list-changed event invalidates the
      catalog cache and re-runs the tool stages
- [ ] Pagination on the aggregated list (opaque cursor)
- [ ] `Mcp-Param-*`: validate downstream, recompute upstream from the upstream schema
- [ ] Upstream eras: dual-era client (modern first, `initialize` fallback, era cached per origin)
- [ ] stdio upstreams (most real-world servers are still stdio): subprocess management,
      `server/discover` probe
- [ ] Extensions: pass the `extensions` capability maps through; refuse what we cannot inspect
- [ ] Run the official conformance suite if one exists for this revision; record the result

Exit: interop suite green; Claude Code configured with only aduana can use two real servers.

## M2: policy and pinning, complete

- [ ] `aduana pin`: review flow that shows a diff of tool definitions and writes the lockfile
- [ ] Drift report: which field changed (description, schema, annotations) with a unified diff
- [ ] Per-identity `tools/list` filtering: add a hook to the `Pipeline` contract, use
      `PolicyStage.is_tool_visible`
- [ ] Policy: argument constraints (path prefixes, read-only SQL by parsing, host allow-lists),
      rate limits per subject and tool, dry-run mode that logs what would be denied
- [ ] Tool shadowing check across upstreams
- [ ] Schema hygiene: bounded depth and subschema count, no network `$ref`
- [ ] Policy tests written as a table of (identity, call) → expected decision

Exit: every row of the threat table that M2 covers has a failing-then-passing lab scenario.

## M3: OAuth 2.1

- [ ] Read all authorization sub-pages and the security best practices page first
- [ ] Protected Resource Metadata endpoint; `401`/`403` challenges with `resource_metadata`
      and `scope`
- [ ] JWT validation: signature via JWKS (cached, rotated), `iss`, `exp`, audience bound to the
      gateway's canonical URI
- [ ] Scopes → policy subjects and rules; per-identity catalogs; `cacheScope` review
- [ ] Upstream credentials: per-upstream client-credentials or stored tokens keyed by issuer;
      test that the agent's token never appears in any upstream request
- [ ] Compose profile with Keycloak for a full local demo
- [ ] Lab scenarios: token passthrough attempt, audience confusion, mix-up

Exit: documented demo where two identities see different tool lists and a replayed token for
another audience is refused.

## M4: attack lab and benchmark

This is the milestone that produces the project's headline numbers.

- [ ] Grow the lab to ≥ 12 attack servers across all categories in `docs/THREAT_MODEL.md`,
      with ≥ 3 variants each (plain, obfuscated, split across fields)
- [ ] Benign suite: ≥ 10 ordinary servers and ≥ 200 ordinary tasks, to measure false positives.
      Include benign text that *looks* suspicious (security docs, prompt-engineering articles)
- [ ] Agent harness: a real model with tool use, connected directly or through aduana; a
      scenario succeeds for the attacker when a canary is exfiltrated or a forbidden tool runs
- [ ] Metrics, each with a confidence interval over repeated runs:
      attack success rate without and with the gateway, per category;
      false-positive rate on the benign suite; task completion rate through the gateway;
      added latency p50/p95/p99 and throughput under load (use a load generator, not the agent)
- [ ] `docs/BENCHMARK.md` filled with the method and results; a results table in the README
- [ ] Report the misses: which attacks got through and why

Exit: one command reproduces the table. Budget for model calls is written down before running.

## M5: learned detectors

- [ ] Dataset: public prompt-injection corpora (check licences) plus lab-generated examples;
      split by attack *family* so the test set has unseen families
- [ ] Baseline: the rule detector from M0, measured
- [ ] Fine-tune a small encoder classifier; export to ONNX; measure CPU latency
- [ ] LLM-judge detector with a fixed prompt, measured for accuracy, latency and cost
- [ ] Comparison table: precision, recall, F1, p50/p99 latency, cost per 1k calls
- [ ] Decide the production cascade (e.g. rules → classifier → judge only on uncertainty) and
      justify it with the numbers
- [ ] Adversarial check: paraphrase and encoding attacks against each detector

Exit: the comparison table and the cascade decision in the README, model card for the classifier.

## M6: observability, packaging, write-up

- [ ] OpenTelemetry spans following the MCP semantic conventions; propagate `traceparent`
- [ ] Metrics endpoint: decisions by action and category, latency histograms
- [ ] Published container image, non-root, with healthcheck; compose demo with two upstreams
- [ ] Guide: putting aduana in front of Claude Code's MCP servers
- [ ] README rewritten around results; architecture diagram; a short demo recording
- [ ] Blog-style write-up: what the stateless revision changes for MCP security

## Risks

| Risk | Mitigation |
| --- | --- |
| The spec or SDK moves again | SPEC_NOTES names the revision; interop tests pin the SDK version |
| Benchmark numbers depend on the model used | Report model and date; run at least two models |
| Detection never reaches 100% | Say so; report misses; position as defence in depth |
| Crowded category (many MCP gateways exist) | Differentiate on measurement and on the 2026-07-28 revision, not on feature count |
| Scope creep in M1 | stdio and legacy upstreams can slip to after M4 if time is short; M4 needs only modern HTTP |
