# vulnfixer / nexus-autofix

Automated remediation of Nexus IQ dependency vulnerabilities via an AI coding agent, with
deterministic build/test/rescan verification. See
[docs/superpowers/specs/2026-07-28-nexus-autofix-design.md](docs/superpowers/specs/2026-07-28-nexus-autofix-design.md)
for the full design and
[docs/superpowers/plans/2026-07-28-nexus-autofix.md](docs/superpowers/plans/2026-07-28-nexus-autofix.md)
for the build plan.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest tests/unit -v          # fast, fully offline, 204 tests
.venv/bin/pytest tests -v -m slow       # includes a real Gradle build via the fixture repo
```

`nexusfix --help` (via `.venv/bin/nexusfix`) shows the `run` and `gc` subcommands.

## What's real vs. unverified

Everything except two integration points is implemented and tested offline against fakes and
mocks: the orchestrator loop, repo/toolchain detection, diff classification, build/test
verification, the state store, and publish logic all have real, exercised implementations —
including two end-to-end tests that run the full orchestrator against a real Gradle project with
real `git`/`./gradlew` subprocess calls (`tests/test_orchestrator_e2e.py`).

The two pieces that are written to spec but **not verified against a live service**, because none
was available while building this:

- **`nexus_autofix/iq/client.py`** — the Nexus IQ HTTP client. Endpoint sequence follows the
  design doc's section 7 exactly, but field names in the JSON responses are best-effort guesses.
- **`nexus_autofix/agent/copilot_cli.py`** — the Copilot CLI adapter. The exact non-interactive
  invocation flags are unconfirmed.

Fill in real credentials in a gitignored `.env` (see `nexus_autofix/config.py` for the
`NEXUSFIX_*` variables) and real toolchain paths in `config.yml`, then report back anything that
doesn't match — wrong endpoint field names, wrong CLI flags — for a follow-up fix.
