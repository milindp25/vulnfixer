# vulnfixer / nexus-autofix

Automated remediation of Nexus IQ dependency vulnerabilities via an AI coding agent, with
deterministic build/test/rescan verification. See
[docs/superpowers/specs/2026-07-28-nexus-autofix-design.md](docs/superpowers/specs/2026-07-28-nexus-autofix-design.md)
for the full design and
[docs/superpowers/plans/2026-07-28-nexus-autofix.md](docs/superpowers/plans/2026-07-28-nexus-autofix.md)
for the build plan.

## Prerequisites

- Python 3.11+ (this repo was built and tested on 3.13)
- git
- For the "slow" test suite only: Java 17+ on `PATH` (used to run a real Gradle build against a
  test fixture). Gradle itself is not required — the fixture ships its own wrapper.

## Setup

```bash
git clone <this-repo> && cd vulnfixer
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

This installs the package in editable mode and gives you the `nexusfix` CLI at `.venv/bin/nexusfix`.

## Running the tests

```bash
.venv/bin/pytest tests/unit -v          # fast, fully offline, 204 tests, no external deps
.venv/bin/pytest tests -v -m slow       # + 2 tests that run a real Gradle build (~5-10s)
.venv/bin/pytest tests -v               # everything
```

The "slow" tests copy the fixture at `tests/fixtures/demo_gradle_repo/` into a temp directory,
`git init` it fresh, and run the real `Orchestrator` against it with real `git`/`./gradlew`
subprocess calls — only the Nexus IQ client and the coding agent are faked. First run downloads
Gradle 8.10 into `~/.gradle` via the wrapper; subsequent runs are fast.

## Running the CLI

```bash
.venv/bin/nexusfix --help
.venv/bin/nexusfix run --app-id <app-id> --branch <branch-name> [--gate none|pre-pr|pre-push] [--dry-run] [--mock-agent]
.venv/bin/nexusfix gc [--older-than-days 7]
```

**Current state of `nexusfix run`:** it loads `config.yml` and your `.env`, validates that
`--app-id` maps to a configured repo, and prints its resolved settings. It does **not yet**
mirror a real repo or call a live Nexus IQ instance end-to-end — that wiring is one of the two
unverified integration points (see below), deliberately left out of this build since there's no
live Nexus IQ tenant or installed Copilot CLI to test it against here. The `Orchestrator` class
itself (`nexus_autofix/orchestrator.py`) is fully built, tested, and ready to be wired up — see
`tests/test_orchestrator_e2e.py` for a complete example of constructing and running one.

`nexusfix gc` **is** fully wired — it talks to the real GitHub REST API to sweep stale
`autofix/nexus/*` branches with no open PR, once `NEXUSFIX_GITHUB_TOKEN` and `config.yml`'s
`repos` map are filled in.

## Configuration

Two separate sources, by design: secrets go in a gitignored `.env` file (never committed);
non-secret project decisions go in `config.yml` (checked into this repo).

### `.env` — secrets

Copy the template and fill in real values:

```bash
cp .env.example .env
```

| Variable | Required for | Meaning |
|---|---|---|
| `NEXUSFIX_IQ_URL` | any real IQ call | Base URL of your Nexus IQ instance, e.g. `https://iq.corp.example.com`. No trailing slash needed. |
| `NEXUSFIX_IQ_USERNAME` | any real IQ call | Nexus IQ user token ID (or username). |
| `NEXUSFIX_IQ_PASSWORD` | any real IQ call | Nexus IQ user token secret (or password). |
| `NEXUSFIX_GITHUB_TOKEN` | `nexusfix gc`, opening PRs | A GitHub (or GHES) personal access token / app token with repo and pull-request scope. |
| `NEXUSFIX_GITHUB_API_URL` | GitHub Enterprise Server only | API base URL, e.g. `https://ghes.corp.example.com/api/v3`. Defaults to `https://api.github.com`. |
| `NEXUSFIX_WORKSPACE_ROOT` | optional | Where mirror clones and per-run worktrees live. Defaults to `~/nfx`. |
| `NEXUSFIX_AGENT_BACKEND` | optional | `mock` or `copilot` — which agent implementation to wire up when this gets connected to the orchestrator. |

None of these raise an error if left unset — `load_secrets()` deliberately defaults everything to
an empty string so `--dry-run`/`--mock-agent` usage and the test suite work without any real
credentials present. Real validation happens at the point of use (e.g. `HTTPIQClient` will fail
loudly the moment you actually call it with an empty URL).

### `config.yml` — project config, checked in

The repo ships with placeholder values you need to replace before running anything for real:

```yaml
subprocess_timeout_seconds: 1800   # max seconds for a single build/test subprocess
max_attempts: 2                    # how many times the agent retries a failing fix
poll_timeout_seconds: 900          # max seconds to wait for a Nexus IQ scan to finish
default_stage_id: build            # Nexus IQ policy stage to evaluate against
default_gate: pre-pr               # none | pre-pr | pre-push — see design doc section 8

toolchains:
  java:
    "21": /usr/bin                 # <- REPLACE: real JDK home per major version you support
  node:
    "24": /usr/local/bin           # <- REPLACE: real Node install dir per major version

repos: {}                          # <- REPLACE: app-id -> git URL, e.g.:
  # payments-core: https://github.com/your-org/payments-core.git
```

What you need to change:

1. **`toolchains.java` / `toolchains.node`** — the placeholder paths (`/usr/bin`,
   `/usr/local/bin`) won't resolve to a real JDK/Node install on most machines.
   `nexus_autofix/verify/toolchain.py` checks the path actually exists and contains a real
   `bin/java` (for Java) before letting a run proceed — a wrong path fails loudly *before* the
   agent runs, by design, rather than surfacing as a confusing build error later. Find your real
   JDK path (e.g. `/usr/libexec/java_home -v 21` on macOS, or `echo $JAVA_HOME`) and use that.
   Add one entry per major version your target repos declare in `.trident/build.yaml`.
2. **`repos`** — map each Nexus IQ application's public ID to its git clone URL. This is what
   lets `--app-id` on the CLI and `nexusfix gc` resolve which repo to act on.
3. The five top-level numeric/string settings have sane defaults and usually don't need changing.

## What's real vs. unverified

Everything except two integration points is implemented and tested offline against fakes and
mocks: the orchestrator loop, repo/toolchain detection, diff classification, build/test
verification, the state store, and publish logic all have real, exercised implementations —
including two end-to-end tests that run the full orchestrator against a real Gradle project with
real `git`/`./gradlew` subprocess calls (`tests/test_orchestrator_e2e.py`).

The two pieces that are written to spec but **not verified against a live service**, because none
was available while building this:

- **`nexus_autofix/iq/client.py`** (`HTTPIQClient`) — the Nexus IQ HTTP client. Endpoint sequence
  follows the design doc's section 7 exactly, but field names in the JSON responses are
  best-effort guesses.
- **`nexus_autofix/agent/copilot_cli.py`** (`CopilotCLIAgent`) — the Copilot CLI adapter. The
  exact non-interactive invocation flags are unconfirmed.

Once you've filled in `.env` and `config.yml` above and pointed this at a real Nexus IQ tenant and
an installed Copilot CLI, report back anything that doesn't match — wrong endpoint field names,
wrong CLI flags — for a follow-up fix.
