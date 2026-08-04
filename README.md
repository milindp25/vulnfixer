# nexus-autofix

Fixes Nexus IQ dependency vulnerabilities. It asks IQ which components are vulnerable and
what version clears each one, a coding agent makes the change, then it **proves** the fix:
the diff is refused if it does anything a dependency bump shouldn't, the real build and
tests run, and a fresh IQ scan confirms the findings actually cleared.

The agent chooses nothing. Target versions come from Nexus IQ, and nothing the agent says
about what it did is believed — changed files are read from `git status`.

---

## Setup

Python 3.11+ and `git` already authenticated for the repos you'll point it at.

### macOS / Linux

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
py -m venv .venv
```

```powershell
.venv\Scripts\pip install -e ".[dev]"
```

### Then, on both

Copy `.env.example` to `.env` and fill it in:

```bash
NEXUSFIX_IQ_URL=https://iq.corp.example.com
NEXUSFIX_IQ_USERNAME=<IQ user token ID>
NEXUSFIX_IQ_PASSWORD=<IQ user token secret>
NEXUSFIX_APP_ID=<the app you usually work on>     # optional, saves --app-id
NEXUSFIX_BRANCH=main                              # optional, saves --branch
NEXUSFIX_WORKSPACE_ROOT=<path>                    # optional; default ~/nfx, see below
```

**Windows paths in `.env`: don't put them in double quotes.** Unquoted is fine, but inside
double quotes the escape sequences are processed, so `"C:\Users\you\nfx"` reads back with
the `\n` turned into a newline. Verified, not guessed:

```bash
NEXUSFIX_WORKSPACE_ROOT=C:\Users\you\nfx     # fine
NEXUSFIX_WORKSPACE_ROOT=C:/Users/you/nfx     # also fine, and immune to the above
NEXUSFIX_WORKSPACE_ROOT="C:\Users\you\nfx"   # BROKEN — \n becomes a newline
```

And `config.yml`, mapping each IQ **public application ID** to its repo:

```yaml
min_threat_level: 8      # only fix threat level 8+ (IQ's Severe/Critical)

repos:
  boardingwizard-static: https://github.com/your-org/boardingwizard-static.git
```

Run every command from the directory holding `config.yml` and `.env` — both are read from
the current directory.

Two things must be true outside this tool: `git clone <your repo URL>` works in your
terminal (cloning and pushing use the git CLI and its existing credentials), and the repo
has a **`.trident/build.yaml`** declaring its ecosystem and toolchain. Without it a run
stops rather than guessing how to build.

---

## Using it

`nexusfix` isn't on your `PATH` unless the virtualenv is activated. Everywhere below it
means:

| | Activate the venv first | Or call it directly |
|---|---|---|
| **macOS / Linux** | `source .venv/bin/activate` | `.venv/bin/nexusfix` |
| **Windows** | `.venv\Scripts\activate` | `.venv\Scripts\nexusfix.exe` |

Run every command from the directory holding `config.yml` and `.env`. Not from the run
directory, and not from `wt/`.

**1. Discover.** The only step that talks to Nexus IQ.

macOS / Linux:

```bash
.venv/bin/nexusfix discover
```

Windows:

```powershell
.venv\Scripts\nexusfix.exe discover
```

It scans the branch, works out each vulnerable component's target version, clones the repo
into a run directory, and writes `run.json`. Nothing is modified. It prints the `run_id` —
you need it for every command after this.

**2. Open the run directory** — not this repo:

macOS / Linux:

```bash
code ~/nfx/runs/<run-id>
```

Windows:

```powershell
code $env:USERPROFILE\nfx\runs\<run-id>
```

It holds `RUNBOOK.md`, `run.json`, `nexusfix.log`, and `wt/` — the checkout to edit.
(`discover` prints the full path, so you can copy it from there instead.)

**3. In Copilot Chat, agent mode:**

> Read RUNBOOK.md and follow it. The run_id is `<paste it>`.

The agent reads `run.json` for the exact version changes and edits `wt/`. It never talks to
Nexus IQ. `run.json` records `nexusfix_executable` — the exact path this run was started
with — so the agent doesn't have to work out the platform difference itself.

**4. Verify and publish** — either the agent runs these, or you do, from your config
directory (not from `wt/`):

macOS / Linux:

```bash
.venv/bin/nexusfix check --run-id <run-id>
```

```bash
.venv/bin/nexusfix publish --run-id <run-id>
```

Windows:

```powershell
.venv\Scripts\nexusfix.exe check --run-id <run-id>
```

```powershell
.venv\Scripts\nexusfix.exe publish --run-id <run-id>
```

`check` classifies the diff, then builds, then tests. `publish` commits, pushes, and
rescans in IQ to confirm the findings cleared — then prints a compare URL for you to open
the PR from. Step 4's `publish` is the first thing that touches the remote; stop before it
and nothing has left your machine.

### Commands

| Command | What it does | Remote? |
|---|---|---|
| `discover` | Scans in IQ, resolves target versions, prepares the checkout, writes `run.json`. | No |
| `check` | Refuses a diff that disables tests, waives a policy, hand-edits a lockfile or downgrades — **before** building. Then runs the real build and tests, and records the verdict. On Gradle it also finds and runs contract/integration test tasks the repo defines outside `test`. | No |
| `publish` | Commits, pushes, rescans in IQ. Refuses without a passing `check`. Deletes the pushed branch if the rescan shows the findings are still there. | Yes |
| `remediate <component>` | Asks IQ what version of one component clears the policy. For a component that never reached the report — typically a quarantined transitive dependency. | No |
| `gc` | Deletes stale `autofix/nexus/*` branches with no open PR. | Yes |

There's also `nexusfix run`, which does everything in one command by calling the Copilot
CLI directly. It needs unattended agent runs to be permitted in your org.

**Why `check` before `publish`:** `publish` won't run without a verdict `check` itself
wrote, and re-reads the diff — if the worktree changed since, what would be pushed isn't
what was verified, and it stops. The party asking to publish is the same one that made the
changes, so its own assurance is worth nothing.

**Contract and integration tests.** A Gradle repo often registers these as their own
tasks — `contractTestConsumer`, `contractTestProvider`, `integrationTest`, `pactVerify` —
wired into neither `test` nor `check`. Nothing would run them, so a bump that breaks a
consumer contract would reach a clean verdict. `check` lists the repo's tasks, picks out
the ones that are tests, and runs them after the unit tests; they appear in the verdict as
`extra_test_tasks`. The `*Classes` tasks that merely *compile* them are excluded — running
one proves nothing and passes.

See what a repo has with `./gradlew tasks --all` (`--group verification` and
`check --dry-run` both miss an ungrouped task). Turn it off where those tests need a broker
or a provider that isn't reachable from your machine:

```yaml
repos:
  java-svc:
    url: https://github.com/org/java-svc.git
    run_extra_tests: false
```

**Which branches:** the branch you pass to `discover` is resolved to a commit SHA, that
exact SHA is what IQ scans and what the checkout is made at, and it's the branch the PR
targets. The fix goes on `autofix/nexus/<run-id>`.

---

## Scanning: source control or the IQ CLI

By default IQ reads what's **committed**. That's complete for npm — `package-lock.json`
enumerates the whole pinned tree — but not for Maven or Gradle, where the manifest names
**direct dependencies only** and the transitive closure isn't in the repo at all. A Java
repo will report on direct dependencies and silently say nothing about the rest.

Set a jar URL in `.env` and it scans the **built** application with the Nexus IQ CLI
instead, fingerprinting what actually landed on the classpath:

```bash
NEXUSFIX_IQ_CLI_URL=https://.../nexus-iq-cli.jar
NEXUSFIX_IQ_CLI_SHA256=<the sha256 it logs on first download>
```

The jar is fetched once into `<workspace_root>/tools/` and reused. Pin the checksum: the
jar runs with your IQ credentials on its command line.

What gets scanned is derived from the ecosystem, and you normally shouldn't set it by hand:

| Ecosystem | Built first | Scanned |
|---|---|---|
| Gradle | yes | `build/`, else the whole checkout |
| Maven | yes | `target/`, else the whole checkout |
| npm / yarn / pnpm | **no** | the lockfile + `package.json` |

Java has no components until a build produces jars to fingerprint. Node is the opposite —
the lockfile already pins the resolved tree, so there's nothing to build for.

Every run logs what it saw:

```
IQ scanned 312 component(s): 47 direct, 265 transitive, 0 unmarked
```

`0 transitive` means only direct dependencies are covered, and the run says so loudly.

**Per-repo settings** go on the repo, since a Java service and a Node app need different
ones:

```yaml
repos:
  java-svc: https://github.com/org/java-svc.git

  node-app:
    url: https://github.com/org/node-app.git
    stage_id: stage-release        # if this repo's pipeline scans at a different stage
    scan_target: [yarn.lock, package.json]   # only for an unusual layout
    prescan_command: yarn pack     # only if the target is built rather than committed
```

`stage_id` matters more than it looks — the stage selects which policies apply, so the same
code scanned at the wrong stage reports a different set of violations.

`NEXUSFIX_SCAN_METHOD=source-control` forces the API scan back on, which is how to get
findings when a build is broken.

---

## When something fails

`<workspace_root>/runs/<run-id>/nexusfix.log` is the file worth sending — that's
`~/nfx/runs/<run-id>/nexusfix.log` on macOS, `%USERPROFILE%\nfx\runs\<run-id>\nexusfix.log`
on Windows unless you set `NEXUSFIX_WORKSPACE_ROOT`. It has what the
console doesn't: full IQ request/response bodies, the **complete** build and test output
(not the tail), and the stack trace of any crash. Safe to share — credentials are never
logged. `-v` on any command also puts the detail on the console.

If the build fails on a **403 / quarantined** artifact, that's the repository manager
refusing to serve a dependency. `RUNBOOK.md` has the procedure. Never work around it — no
extra repository, no `--offline`, no excluding the dependency. `check` refuses that diff.

---

## Notes

**`wt/` is a clone, not a `git worktree`.** In a worktree `.git` is a *file*, and build
tooling that reads it directly breaks — Gradle's `gradle-git-properties` fails with
`RepositoryNotFoundException`. Don't "optimise" it back.

**Toolchains are optional.** Left unset, a run uses whatever JDK/Node is active and warns
on a mismatch with `.trident/build.yaml` rather than failing. Pin paths under `toolchains:`
in `config.yml` only if one machine juggles several versions.

**These IQ behaviours are confirmed against a live instance** and shouldn't be "corrected"
back to what the docs say:

| Behaviour | The doc implied | The instance does |
|---|---|---|
| `sourceControlEvaluation` body | include `commitHash` | rejects it; only `stageId` + `branchName` |
| `statusUrl` | rooted | returned with **no** leading slash |
| report id | last segment of `reportDataUrl` | the URL ends `/raw`; the id is the segment **after** `reports` |
| `/policy` response | a bare array | an object with a `components` array |
| remediation version | `data.componentIdentifier…version` | `data.`**`component`**`.componentIdentifier.coordinates.version` |

`parentRemediation` and `goldenVersion` remain **unverified** — neither has appeared in a
live response.

---

## Tests

macOS / Linux:

```bash
.venv/bin/python -m pytest -q
```

Windows:

```powershell
.venv\Scripts\python -m pytest -q
```
