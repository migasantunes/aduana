# Benchmark method (milestone M4)

This document defines how aduana's effectiveness and cost will be measured. It is the method
only: **the benchmark has not been run. Every result table below is empty and marked "not run
yet". No number in this repository is real until this document carries one with a reproducible
command behind it.**

The benchmark is milestone M4 in `docs/PLAN.md`. The agent harness it depends on is not built
yet (see the design sketch in `lab/README.md`).

## What we measure and why

A security gateway is only worth its latency if it stops attacks without breaking ordinary
work. So every headline number is reported as a pair — with the gateway and without it — on the
same scenarios, plus the cost of running it.

## Suites

- **Attack suite.** The lab's malicious servers and their scenarios (`lab/scenarios/*.yaml`),
  grown to ≥ 12 attack servers across every `Category`, with ≥ 3 variants each (plain,
  obfuscated, split across fields). Current coverage is the M0 seed: five servers and the
  scenarios listed in `lab/scenarios/`.
- **Benign suite.** ≥ 10 ordinary servers and ≥ 200 ordinary tasks, to measure false positives.
  It deliberately includes benign text that *looks* suspicious — security documentation,
  prompt-engineering articles, text that quotes an injection to warn about it — because that is
  what makes a detector cry wolf.

## Metrics

Each metric is defined so the harness can compute it mechanically from a run log.

### Attack success rate (ASR), per category, with and without the gateway

- **Definition.** Fraction of attack scenarios in a category where the attacker's
  `success_signal` is observed: the canary is recorded by a sink server (exfiltration), or
  injected text reaches the client, or a forbidden tool runs.
- **Reported as** `ASR_without` and `ASR_with` per category and overall. The gateway's value is
  `ASR_without − ASR_with` (attacks stopped). `ASR_without` near 1.0 is a prerequisite: a
  scenario the undefended agent does not fall for measures nothing.

### False-positive rate (FPR) on the benign suite

- **Definition.** Fraction of benign tasks where the gateway denies or redacts a call, or
  quarantines a tool, that a correct gateway should have allowed.
- **Reported as** one rate over the whole benign suite, plus a breakdown by the stage that
  fired (policy / pinning / rules / secrets).

### Task-completion rate

- **Definition.** Fraction of benign tasks the agent completes successfully *through the
  gateway*. Separates "the gateway blocked it" (an FPR event) from "the gateway slowed or
  garbled it" (a completion failure with no denial).

### Latency overhead and throughput

- **Definition.** Added wall-clock latency the gateway imposes per request, measured with a
  load generator (not the agent, whose model calls dominate and vary). Reported at **p50, p95
  and p99**, as the difference between direct-to-upstream and through-gateway, plus throughput
  (requests/second) at a fixed concurrency.
- Measured separately for `tools/list` (catalog path, detectors over definitions) and
  `tools/call` (request + response path).

## Statistical treatment

- **Repeated runs.** Every rate is computed over repeated runs (agent behaviour is
  stochastic). Report the mean and a **95% confidence interval** (Wilson interval for the
  proportions; percentile bootstrap for latency percentiles).
- **Family-held-out where relevant.** For any learned detector (M5), the test set holds out
  whole attack *families* so the number reflects unseen attacks, not memorised ones.
- **Models and dates.** Every table names the model(s) used and the date of the run. At least
  two models are run, because the numbers depend on the model (see `docs/PLAN.md` risks).
- **Budget.** The model-call budget is written down before the run and recorded with the
  results.

## Reproduction

One command will reproduce the tables (target; not available yet):

```
# NOT AVAILABLE YET — M4
# uv run python -m lab.harness --suite attack  --runs 20 --models <m1>,<m2>
# uv run python -m lab.harness --suite benign --runs 20 --models <m1>,<m2>
```

## Results

> **Not run yet.** The tables below are placeholders. They will be filled only by the
> reproduction command above, with the model and date recorded.

### Attack success rate by category

| Category | ASR without gateway | ASR with gateway | Attacks stopped |
| --- | --- | --- | --- |
| tool_poisoning | not run yet | not run yet | not run yet |
| rug_pull | not run yet | not run yet | not run yet |
| result_injection | not run yet | not run yet | not run yet |
| secret_exfiltration | not run yet | not run yet | not run yet |
| policy | not run yet | not run yet | not run yet |
| tool_shadowing | not run yet | not run yet | not run yet |
| protocol_abuse | not run yet | not run yet | not run yet |
| **overall** | not run yet | not run yet | not run yet |

### Benign suite

| Metric | Value |
| --- | --- |
| False-positive rate (overall) | not run yet |
| Task-completion rate through gateway | not run yet |

### Latency overhead

| Path | p50 | p95 | p99 |
| --- | --- | --- | --- |
| `tools/list` (catalog) | not run yet | not run yet | not run yet |
| `tools/call` (request + response) | not run yet | not run yet | not run yet |

Run metadata (models, dates, number of runs, budget): **not run yet.**
