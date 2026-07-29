# vulnfixer / nexus-autofix

Automated remediation of Nexus IQ dependency vulnerabilities via an AI coding agent, with
deterministic build/test/rescan verification. See
[docs/superpowers/specs/2026-07-28-nexus-autofix-design.md](docs/superpowers/specs/2026-07-28-nexus-autofix-design.md)
for the full design and
[docs/superpowers/plans/2026-07-28-nexus-autofix.md](docs/superpowers/plans/2026-07-28-nexus-autofix.md)
for the build plan.

## Prerequisites

- Python 3.11+ (this repo was built and tested on 3.13)
- git, already authenticated for the repos you'll point it at
- For the "slow" test suite only: Java 17+ on `PATH` (used to run a real Gradle build against a
  test fixture). Gradle itself is not required — the fixture ships its own wrapper.

Runs on **macOS, Linux and Windows**. Windows specifics are handled: the Gradle/Maven wrappers
resolve to `gradlew.bat` / `mvnw.cmd` by full path, `npm`/`yarn`/`pnpm`/`copilot` are resolved
through `PATHEXT` (they're `.cmd` shims, which `subprocess` can't find by bare name), JDK/Node
probing looks for `java.exe` / `node.exe`, and `PATH` is joined with the platform separator.
Keep the workspace root short (the `~/nfx` default is fine) to stay clear of the 260-character
path limit, or enable long paths with `git config --global core.longpaths true`.

### How it reaches GitHub

Two different mechanisms, which matters for credentials:

| Operation | Mechanism | Auth |
|---|---|---|
| clone, fetch, worktree, commit, push | the **`git` CLI** | whatever git already uses — Git Credential Manager on Windows, keychain/helper on macOS. Nothing extra to configure |
| opening the PR, `nexusfix gc` | **GitHub REST API** | `NEXUSFIX_GITHUB_TOKEN` |

So if `git clone <your-repo>` works in your terminal, the repo half works here too. The token is
only needed for the PR (and `gc`) — which is why `--dry-run` doesn't require one.

#### Generating the token

Settings → Developer settings → Personal access tokens → **Tokens (classic)** → Generate new
token (classic). Tick **`repo`** — that single scope covers every call this tool makes (create a
PR; and for `gc`: list branches, list open PRs, delete a ref). Nothing else is needed. For a
public-only repo, `public_repo` is sufficient.

- **Org with SAML SSO:** after creating the token, click **Configure SSO** next to it and
  authorize your organisation. Without that, API calls fail with a **404** (not a 403), which
  reads as "repo doesn't exist" and is easy to misdiagnose.
- **If your org disallows classic tokens**, use a fine-grained token scoped to the repo with
  **Contents: Read and write** and **Pull requests: Read and write**.

## Setup

**macOS / Linux:**

```bash
git clone <this-repo> && cd vulnfixer
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

**Windows (PowerShell):**

```powershell
git clone <this-repo>; cd vulnfixer
py -m venv .venv
.venv\Scripts\pip install -e ".[dev]"
```

Note that creating a venv does **not** activate it, and Windows puts executables in
`.venv\Scripts\`, not `.venv/bin/`. Calling the venv's `pip` by path as above sidesteps
activation entirely. If you'd rather activate it (so plain `pip`, `pytest` and `nexusfix` work),
run `.venv\Scripts\Activate.ps1` first — your prompt gains a `(.venv)` prefix. Should PowerShell
refuse with *"running scripts is disabled on this system"*, either stick with the by-path form or
allow it for that session with
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`. In `cmd.exe` the activation script
is `.venv\Scripts\activate.bat`; in Git Bash, `source .venv/Scripts/activate`.

This installs the package in editable mode and gives you the `nexusfix` CLI — at
`.venv/bin/nexusfix` on macOS/Linux, `.venv\Scripts\nexusfix.exe` on Windows.

## Running the tests

```bash
.venv/bin/pytest tests/unit -v          # fast, fully offline, no external deps
.venv/bin/pytest tests -v -m slow       # + 2 tests that run a real Gradle build (~5-10s)
.venv/bin/pytest tests -v               # everything
```

On Windows, swap the prefix: `.venv\Scripts\pytest tests\unit -v` (or just `pytest tests/unit -v`
once activated).

The "slow" tests copy the fixture at `tests/fixtures/demo_gradle_repo/` into a temp directory,
`git init` it fresh, and run the real `Orchestrator` against it with real `git`/`./gradlew`
subprocess calls — only the Nexus IQ client and the coding agent are faked. First run downloads
Gradle 8.10 into `~/.gradle` via the wrapper; subsequent runs are fast.

## Running the CLI

```bash
.venv/bin/nexusfix --help
.venv/bin/nexusfix run --app-id <app-id> --branch <branch-name> [--gate none|pre-pr|pre-push] [--dry-run] [--mock-agent] [--interactive-agent]
.venv/bin/nexusfix gc [--older-than-days 7]
```

There are three ways to run the agent step. They differ **only** in who edits the files.
Nexus IQ discovery, remediation targets, diff classification, build, test, rescan and PR are
the same code in all three:

| Mode | Who drives | Use when |
|---|---|---|
| `nexusfix run` | nexusfix, calling the Copilot CLI | Unattended agent runs are permitted in your org |
| `nexusfix run --interactive-agent` | nexusfix, pausing for you | The Copilot CLI is blocked from unattended tool use |
| `discover` / `check` / `publish` | a coding agent, reading [RUNBOOK.md](RUNBOOK.md) | You want to drive it from VS Code Copilot Chat |

See [Agent-orchestrated mode](#agent-orchestrated-mode-discover--check--publish) for the third.

(Windows: `.venv\Scripts\nexusfix ...`, or just `nexusfix ...` with the venv activated. The rest
of this README writes it as plain `nexusfix` for brevity.)

Run it from the directory holding your `config.yml` and `.env` — both are read from the current
working directory.

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
- `--interactive-agent` — does everything above except step 5, then prints the prepared
  worktree path and waits. You run Copilot there yourself (CLI or VS Code Chat), or edit by
  hand, then press Enter and steps 6-8 continue. Use this when your organisation's Copilot
  policy answers *"Access denied by policy settings"*: that block applies to unattended tool
  use (`--allow-all-tools`), not to a human approving each action. Only `git status` decides
  what changed, so it makes no difference what did the editing.

`nexusfix gc` sweeps stale `autofix/nexus/*` branches with no open PR via the GitHub REST API.

## Agent-orchestrated mode (`discover` / `check` / `publish`)

The inverse arrangement: a coding agent drives and calls nexusfix as a tool, rather than
nexusfix driving and calling the agent. Built for organisations where the Copilot CLI cannot
run unattended at all, leaving an interactive agent as the only thing able to edit files.

**The agent never talks to Nexus IQ.** Every IQ call stays in `nexus_autofix/iq/client.py` —
the same client, endpoints and parsing that `nexusfix run` uses. The agent runs these commands
and reads their JSON.

### Step by step

**1. You run discover.** This is the only step that talks to Nexus IQ.

```bash
nexusfix discover
```

It prints, among other fields:

```json
{
  "run_id": "a1b2c3d4-...",
  "open_this_in_your_editor": "C:\\Users\\you\\nfx\\runs\\a1b2c3d4-...",
  "runbook": "C:\\Users\\you\\nfx\\runs\\a1b2c3d4-...\\RUNBOOK.md",
  "worktree": "C:\\Users\\you\\nfx\\runs\\a1b2c3d4-...\\wt",
  "findings": [
    { "component": "brace-expansion", "current_version": "5.0.7",
      "target_version": "5.0.8", "remediation_type": "next-no-violations",
      "threat_level": 9, "is_direct": false,
      "pulled_in_by": ["pkg:npm/some-parent@1.2.3"], "actionable": true }
  ]
}
```

**Check `target_version` before going further.** It must be genuinely newer than
`current_version`. If it is not, stop — the log holds IQ's raw response for that component.

**2. Open the run directory** — not this repo:

```bash
code C:\Users\you\nfx\runs\<run-id>
```

You get `RUNBOOK.md`, `run.json`, `nexusfix.log` and `wt/` (the checkout to edit). The
runbook is copied here by `discover`, so the agent has the instructions and the code in one
place. It sits beside `wt/` rather than inside it, because `git status` reports untracked
files and a runbook inside the checkout would be committed onto the fix branch.

**3. In Copilot Chat (agent mode), say:**

> Read RUNBOOK.md and follow it. The run_id is `<paste it>`.

That is the whole interaction. The runbook tells the agent to read the findings, edit `wt/`,
then run `check` and `publish` itself.

**4. Or drive the remaining steps yourself** — the agent only has to do the editing:

```bash
nexusfix check --run-id <run-id>      # classify the diff, then build and test
```

```bash
nexusfix publish --run-id <run-id>    # commit, push, rescan to confirm, open a PR
```

[RUNBOOK.md](RUNBOOK.md) holds the full steps, the JSON shapes and the prohibitions.

### Notes

The worktree is a **git worktree**, not a clone. One mirror per application lives at
`$NEXUSFIX_WORKSPACE_ROOT/mirrors/<app-id>`, and each run adds a worktree off it already
switched to `autofix/nexus/<run-id>`. The agent never clones, branches or configures
anything.

The runbook tells the agent not to commit, because `publish` does that. If it commits
anyway — agents do — nothing breaks: `check` and `publish` diff from the commit the
worktree was created at, not from `HEAD`, so the changes are still seen and still
classified. Committing cannot be used to slip a suspicious diff past the classifier.

Verification is deliberately **not** delegated, because the agent asking to publish is the same
one that made the changes:

- `check` classifies the diff and refuses a `SUSPICIOUS` one **before building anything**. The
  ordering is the safeguard, not an optimisation: a diff that disables tests builds and passes
  trivially, so classifying afterwards would bless exactly what the classifier exists to catch.
- `publish` refuses without a passing verdict that `check` itself wrote, and re-reads the diff —
  if the worktree changed since `check`, what would be pushed is not what was verified, and it
  stops.
- The IQ rescan still has to confirm the findings cleared. If it does not, the pushed branch is
  deleted rather than left inviting a merge.
- Findings carry `is_direct` and `pulled_in_by`, so a transitive finding does not get "fixed" by
  adding a direct dependency to force a version.

`run.json` and `verdict.json` are written beside the log in
`$NEXUSFIX_WORKSPACE_ROOT/runs/<run-id>/`; that is how state survives between the three
invocations.

This mode lives on the `copilot-orchestrator` branch and is unproven against a real agent.

## Configuration

Two separate sources, by design: secrets go in a gitignored `.env` file (never committed);
non-secret project decisions go in `config.yml` (checked into this repo).

### `.env` — secrets

Copy the template and fill in real values:

```bash
cp .env.example .env          # Windows: Copy-Item .env.example .env
```

Only two filenames are read, and only from the directory you run `nexusfix` in:
**`.env.local`** first, then **`.env`**. Values are merged per-variable, so `.env.local` is for
machine-specific overrides without touching `.env`. Anything already exported in your shell wins
over both. Parent directories are deliberately *not* searched — otherwise a stray `.env` above
the repo could silently supply credentials. Both files are gitignored.

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
| 4 | GitHub token | `.env` → `NEXUSFIX_GITHUB_TOKEN` | needs repo + PR scope. Not required with `--dry-run` |
| 5 | app-id → repo URL | `config.yml` → `repos:` | the app-id must be the IQ **public** application ID |
| 6 | app-id and branch | `.env` → `NEXUSFIX_APP_ID` / `NEXUSFIX_BRANCH`, **or** `--app-id` / `--branch` | put them in `.env` and you can just run `nexusfix run`; a CLI flag overrides |

Optional, only if the defaults don't fit:

| Input | Where | When you need it |
|---|---|---|
| GHES API URL | `.env` → `NEXUSFIX_GITHUB_API_URL` | only if you're **not** on github.com |
| JDK / Node paths | `config.yml` → `toolchains:` | only if one machine juggles several JDK/Node versions across repos. Left empty, it uses `JAVA_HOME` (or `java` on `PATH`) and `node` on `PATH` |
| Workspace root | `.env` → `NEXUSFIX_WORKSPACE_ROOT` | defaults to `~/nfx` |

**Toolchains are optional on purpose.** With `toolchains:` empty, a run uses whatever JDK/Node is
already active on your machine. It still reads the version the repo declares in
`.trident/build.yaml`, compares it against what it found, and **warns** on a mismatch rather than
failing — you might knowingly be on a newer JDK, which usually works, but if the build then fails
to compile, that warning in the log is the first thing to check. A run only fails outright when no
JDK/Node can be found at all.

**The branch you give is used everywhere**, consistently: it's resolved to a commit SHA on the
remote (`origin/<branch>`), that exact SHA is what Nexus IQ scans and what the worktree is created
at, and it's the base branch the PR targets. A branch that doesn't exist fails immediately with
the list of branches that do.

Two things that must line up outside this tool, or a run will fail in ways it can't fix for you:

- **The IQ application must already exist** with the public ID you pass as `--app-id`, and the
  git credentials on the machine must be able to clone the URL in `repos:` (use a credential
  helper or `gh auth setup-git` — never put a token in the clone URL, it gets stored in plaintext).
- **The target repo needs a `.trident/build.yaml`** declaring its ecosystem and toolchain
  version. Without it the run escalates rather than guessing.

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
  follows the design doc's section 7. Polling is written defensively: an HTTP 200 with a pending
  status keeps polling, a terminal failure fails immediately with IQ's own error message rather
  than burning the full timeout, and several plausible spellings of the status field are matched
  case-insensitively.

  These parts are now **confirmed against a live instance** and should not be "corrected" back
  to what the design doc says:

  | Behaviour | What the doc implied | What the instance does |
  |---|---|---|
  | `sourceControlEvaluation` body | include `commitHash` | only `stageId` + `branchName`; `commitHash` is rejected |
  | `statusUrl` | absolute or rooted | returned with **no** leading slash — must be normalised |
  | report id | last path segment of `reportDataUrl` | the URL ends `/raw`, so the id is the segment **after** `reports` |
  | `/policy` response | a bare array | an object with a `components` array |
  | remediation version | `data.componentIdentifier…version` | `data.`**`component`**`.componentIdentifier.coordinates.version` |

  Still unconfirmed: `parentRemediation` and `goldenVersion`. Neither appeared in any live
  response seen so far, so if a transitive finding reports empty parent-bump advice, check
  those field names first.

- **`nexus_autofix/agent/copilot_cli.py`** (`CopilotCLIAgent`) — the Copilot CLI adapter. The
  non-interactive invocation flags are still unconfirmed. It now fails loudly rather than
  returning "no changes": a missing binary, a non-zero exit or a timeout each raise with the
  command and the CLI's own output attached. On an organisation that blocks unattended tool use
  this reports *"Access denied by policy settings"* — see `--interactive-agent` above.

Suggested order for the first live run, so a failure tells you exactly which layer broke:

With `NEXUSFIX_APP_ID` and `NEXUSFIX_BRANCH` in `.env`, you can drop the flags entirely:

```bash
# 1. IQ connectivity + mirroring + worktree only — no agent, no mutations.
nexusfix run --dry-run --mock-agent

# 2. Add the real Copilot agent and a real build, still no push/PR.
nexusfix run --dry-run

# 3. Full run, stopping for your approval before the PR is opened.
nexusfix run --gate pre-pr
```

If step 2 fails with *"Access denied by policy settings"*, your organisation blocks unattended
Copilot tool use. Use `nexusfix run --interactive-agent` instead, or the
[agent-orchestrated mode](#agent-orchestrated-mode-discover--check--publish).

(Or pass `--app-id <app> --branch <branch>` explicitly on any of them to override `.env`.)

Step 1 exercises `HTTPIQClient` (the first unverified piece); step 2 adds `CopilotCLIAgent` (the
second). Add `-v` to any of them to see full request/response bodies on the console.

If something breaks, send the run's log file (`<workspace_root>/runs/<run-id>/nexusfix.log`) —
it contains the actual URLs, status codes, and response bodies, which is enough to correct the
field mappings or CLI flags without guessing.
