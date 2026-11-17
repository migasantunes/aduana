# Attack scenarios

One YAML file per attack. Each file describes a concrete attempt against the lab servers and
what a correct gateway should do about it. The files are data: the tests in `tests/lab/` parse
every one, and the M4 agent harness (not built yet; see `lab/README.md`) will replay the
`steps` against a model with and without aduana in front.

## Schema

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Unique scenario id, kebab-case. Matches the file name. |
| `category` | string | One of the values of `aduana.pipeline.types.Category`: `policy`, `tool_poisoning`, `rug_pull`, `result_injection`, `secret_exfiltration`, `tool_shadowing`, `protocol_abuse`. |
| `server` | string | The lab server module the scenario drives, e.g. `poisoned_weather`. Must exist under `lab/servers/`. |
| `description` | string | What the attack is, in one or two sentences. |
| `attacker_goal` | string | What the attacker wants to happen. |
| `steps` | list | Ordered actions a client performs. Each step has `action` (`list_tools`, `call_tool`, or `discover`) and action-specific fields (`tool`, `arguments`, `note`). |
| `success_signal` | string | The observable fact that proves the attack worked without a gateway (e.g. canary present in arguments the server received, injected text reaching the client). |
| `expected_gateway_action` | string | What aduana should do: `deny`, `redact`, or `quarantine` (leave the tool out of the exposed catalog), plus the category it should attribute. |

## Conventions

- Every payload is synthetic and carries the canary `CANARY-ADUANA-…`. Sink URLs use the
  reserved `.invalid` TLD and never resolve.
- `success_signal` is phrased so the harness can check it mechanically: it names either the
  canary reaching a server's recorded arguments, or injected text reaching the client.
- A scenario's `category` is the category aduana should attribute when it blocks the attack,
  and matches the `Category` enum so the detector and the scenario stay in sync.
