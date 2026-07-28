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

`nexusfix run` performs the full pipeline against your live Nexus IQ instance and your real
repository, once `.env` and `config.yml` are filled in:

1. Resolves the application in Nexus IQ and starts a source-control evaluation of `--branch`.
2. Clones/updates a local mirror of the repo (from `config.repos[<app-id>]`) under
   `NEXUSFIX_WORKSPACE_ROOT`, and resolves the branch to a commit SHA.
3. Fetches the policy report, then per-component remediation, to determine exact target versions.
4. Creates a git worktree on a fresh `autofix/nexus/<run-id>` branch.
5. Invokes the GitHub Copilot CLI agent with the assembled prompt (findings + ecosystem playbook).
6. Classifies the resulting diff, then runs the real build and test commands, retrying on failure.
7. Commits, pushes the branch, triggers a fresh IQ scan, and compares it against the baseline.
8. Applies the gate (`pre-pr` by default), then opens a PR.

Useful flags while you're getting it working:

- `--dry-run` — does every real step (IQ scan, mirror, worktree, agent, build, test, diff
  classification) but never commits, pushes, or opens a PR. Best first run against a real app.
- `--mock-agent` — substitutes a no-op agent so you can verify IQ discovery, mirroring, worktree
  creation, and toolchain resolution all work before involving the Copilot CLI at all.
- `--gate pre-push` — stops after build/test, before anything is pushed.

`nexusfix gc` sweeps stale `autofix/nexus/*` branches with no open PR via the GitHub REST API.

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

### Everything you must supply — checklist

Nothing else is required; if a run fails for any *other* missing input, that's a bug worth
reporting.

| # | Input | Where | Notes |
|---|---|---|---|
| 1 | Nexus IQ base URL | `.env` → `NEXUSFIX_IQ_URL` | e.g. `https://iq.corp.example.com` |
| 2 | IQ user token ID | `.env` → `NEXUSFIX_IQ_USERNAME` | IQ user tokens are an ID/secret pair |
| 3 | IQ user token secret | `.env` → `NEXUSFIX_IQ_PASSWORD` | |
| 4 | GitHub/GHES token | `.env` → `NEXUSFIX_GITHUB_TOKEN` | needs repo + PR scope. Not required with `--dry-run` |
| 5 | GHES API URL | `.env` → `NEXUSFIX_GITHUB_API_URL` | **only** if not github.com |
| 6 | app-id → repo URL | `config.yml` → `repos:` | the app-id must be the IQ **public** application ID |
| 7 | Real JDK/Node paths | `config.yml` → `toolchains:` | one entry per major version your repos declare |
| 8 | `--app-id` and `--branch` | CLI args | branch is the one to scan and to target the PR at |

Two things that must line up outside this tool, or a run will fail in ways it can't fix for you:

- **The IQ application must already exist** with the public ID you pass as `--app-id`, and the
  git credentials on the machine must be able to clone the URL in `repos:` (use a credential
  helper or `gh auth setup-git` — never put a token in the clone URL, it gets stored in plaintext).
- **The target repo needs a `.trident/build.yaml`** declaring its ecosystem and toolchain
  version. Without it the run escalates rather than guessing. Its declared Java/Node major
  version must have a matching entry in `config.yml`'s `toolchains:` map.

### Logging

Every run writes two streams:

- **Console** — INFO: each IQ call, poll attempts with status, findings and their target
  versions, build/test progress, and the final outcome. `-v/--verbose` adds full bodies here too.
- **File** — always DEBUG, at `<workspace_root>/runs/<run-id>/nexusfix.log`: every IQ request URL,
  request body, response status, timing, and **full response body**. On any HTTP error the
  response body is logged at ERROR (IQ puts the real reason there).

Credentials are never logged — they're passed via the HTTP auth mechanism, and request headers
are deliberately never written to the log.

That DEBUG log is the fastest way to resolve the unverified-field-names caveat below: if
something parses as empty when the IQ UI clearly shows findings, the real JSON shape is sitting
in that file.

## What's real vs. unverified

The whole pipeline is wired end to end and runs for real. What has *not* been exercised is the
two places where this code talks to an external service, because no live Nexus IQ tenant or
installed Copilot CLI was available on the machine it was built on. Expect to iterate on these
two on first live run:

- **`nexus_autofix/iq/client.py`** (`HTTPIQClient`) — the Nexus IQ HTTP client. Endpoint sequence
  follows the design doc's section 7 exactly, but field names in the JSON responses are
  best-effort guesses. Polling is written defensively: an HTTP 200 with a pending status keeps
  polling, a terminal failure status fails immediately with IQ's own error message rather than
  burning the full timeout, and several plausible spellings of the status field and its values
  are matched case-insensitively. If your instance uses different names, the DEBUG log shows the
  real response and the fix is a one-line change to `_STATUS_FIELDS` / the status value sets.
- **`nexus_autofix/agent/copilot_cli.py`** (`CopilotCLIAgent`) — the Copilot CLI adapter. The
  exact non-interactive invocation flags are unconfirmed.

Suggested order for the first live run, so a failure tells you exactly which layer broke:

```bash
# 1. IQ connectivity + mirroring + worktree only — no agent, no mutations.
nexusfix run --app-id <your-app> --branch main --dry-run --mock-agent

# 2. Add the real Copilot agent and a real build, still no push/PR.
nexusfix run --app-id <your-app> --branch main --dry-run

# 3. Full run, stopping for your approval before the PR is opened.
nexusfix run --app-id <your-app> --branch main --gate pre-pr
```

Step 1 exercises `HTTPIQClient` (the first unverified piece); step 2 adds `CopilotCLIAgent` (the
second). Add `-v` to any of them to see full request/response bodies on the console.

If something breaks, send the run's log file (`<workspace_root>/runs/<run-id>/nexusfix.log`) —
it contains the actual URLs, status codes, and response bodies, which is enough to correct the
field mappings or CLI flags without guessing.
