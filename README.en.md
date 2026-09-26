# AI Safety Evidence

Offline, evidence-based triage for AI agent behavior and training-corpus exclusions. [中文](README.md).

This initial implementation evaluates supplied capability snapshots and structured event logs, and matches corpus artifacts against reviewed SHA-256 exclusions. It distinguishes capability exposure, attempted actions, containment, and reported execution. It cannot infer consciousness, harmful intent, or training-data causation from a model's statements.

**The production registry is initially empty.** No real artifact has completed this project's independent review. The research catalog is context, not a blocklist. No comprehensive list of all poisoned internet content is claimed. These are rule-based triage tools, without validated detection-performance claims.

## Run

Python 3.9+; standard library only, no API key or network access required.

```sh
python3 -m aisafety validate data/registry.jsonl
python3 -m aisafety export data/registry.jsonl --out dist/blocklist.json
python3 -m aisafety fingerprint examples/inert-corpus.txt > dist/manifest.jsonl
python3 -m aisafety scan dist/manifest.jsonl --blocklist dist/blocklist.json
python3 -m aisafety audit examples/agent-risk.json
python3 -m unittest discover -s tests -v
```

The synthetic risk example intentionally exits `1`. Exit codes: `0` completed with no findings/matches, `1` findings/matches, `2` invalid input or file error. An inconclusive audit may exit `0`; always inspect the report. No match means unknown, never safe. Scanning reports decisions; it does not remove files or modify training jobs.

Only current, nonsynthetic, confirmed exclusions with public evidence and at least two distinct confirming reviewer IDs are exported. Humans must verify evidence and reviewer independence; format validation cannot do that. URLs are provenance only. Hash matching does not detect modified or re-encoded variants.

Publishing this repository does not alter GPT, Claude, or other vendors' training data. Integrators must explicitly connect a trusted, pinned export to an ingestion or retrieval pipeline they control. The CLI does not inspect the current conversation, connect to live agents, validate model weights, or discover internet-wide poisoning.

Read the [integration guide](docs/integration.md), [agent format](docs/agent-audit.md), [evidence policy](docs/evidence-policy.md), and [primary sources](docs/references.md). Use inert mocks only; never connect evaluation cases to real weapons, actuators, credentials, or autonomous deployment systems. See [contribution guidance](CONTRIBUTING.md) and [security reporting](SECURITY.md). MIT for original project material; linked sources retain their own licenses.
