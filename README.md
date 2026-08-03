# nexus-autofix

Fixes Nexus IQ dependency vulnerabilities. It asks Nexus IQ which components are vulnerable
and what version clears each one, has a coding agent make the change, then **proves** the fix:
the diff is checked for anything a dependency bump should not do, the real build and tests run,
and a fresh IQ scan confirms the findings actually cleared before a PR is opened.

The agent chooses nothing. Target versions come from Nexus IQ, and nothing is believed about
what the agent did — changed files are read from `git status`, never from the agent's own
report.

---

## Setup

Requires Python 3.11+ and `git` already authenticated for the repos you'll point it at. Runs on
macOS, Linux and Windows.

```bash
python -m venv .venv
```

```bash
.venv/bin/pip install -e ".[dev]"
```

(Windows: `py -m venv .venv`, then `.venv\Scripts\pip install -e ".[dev]"`. Commands below are
written as plain `nexusfix`; on Windows that's `.venv\Scripts\nexusfix.exe`.)

Copy `.env.example` to `.env` and fill it in:

| Variable | Required | What |
|---|---|---|
| `NEXUSFIX_IQ_URL` | yes | e.g. `https://iq.corp.example.com` |
| `NEXUSFIX_IQ_USERNAME` | yes | IQ user token **ID** |
| `NEXUSFIX_IQ_PASSWORD` | yes | IQ user token **secret** |
| `NEXUSFIX_GITHUB_TOKEN` | for PRs | classic token with the `repo` scope |
| `NEXUSFIX_APP_ID` | optional | saves passing `--app-id` every time |
| `NEXUSFIX_BRANCH` | optional | saves passing `--branch` |
| `NEXUSFIX_WORKSPACE_ROOT` | optional | defaults to `~/nfx` |
| `NEXUSFIX_GITHUB_API_URL` | optional | only if you're not on github.com |

Then map your IQ application to its repo in `config.yml`:

```yaml
min_threat_level: 8      # only fix threat level 8+ (IQ's Severe/Critical)

repos:
  boardingwizard-static: https://github.com/your-org/boardingwizard-static.git
```

The key must be the IQ **public** application ID.

Run every command from the directory holding `config.yml` and `.env` — they're read from the
current directory.

### Two things that must be true outside this tool

- The IQ application already exists under that public ID, and `git clone <your repo URL>` works
  in your terminal. Cloning, pushing and committing use the **`git` CLI** and whatever
  credentials it already has; the GitHub token is only for opening the PR.
- The target repo has a **`.trident/build.yaml`** declaring its ecosystem and toolchain version.
  Without it a run stops rather than guessing how to build.

---

## Commands

| Command | What it does | Touches the remote? |
|---|---|---|
| `discover` | Scans the branch in Nexus IQ, works out each vulnerable component's target version, prepares a checkout to edit, writes `run.json`, and prints the findings plus what to do next. | No |
| `check` | 1. Classifies the diff and **refuses** it if it does anything a dependency fix must not — disabled tests, an IQ waiver, a hand-edited lockfile, `--legacy-peer-deps`, a downgrade. 2. Runs the real **build**. 3. Runs the real **tests**. Records the verdict. | No |
| `publish` | **Commits**, **pushes** the fix branch, then runs a **fresh IQ scan** to confirm the findings cleared. Prints a GitHub compare URL to open the PR from. Refuses without a passing `check`. Deletes the pushed branch if the rescan shows the findings are still there. | Yes |
| `run` | All of the above in one command, invoking a coding agent for the editing step. | Yes (unless `--dry-run`) |
| `remediate` | Asks Nexus IQ what version of one component clears the policy. For components that never reached the policy report — typically a transitive dependency whose artifact is quarantined, so the scan could not resolve it either. | No |
| `usage` | For a finding IQ can't fix: where the component is declared and referenced, and whether IQ can clear it by bumping a **parent** instead. Reports evidence; changes nothing. | No |
| `gc` | Deletes stale `autofix/nexus/*` branches with no open PR. | Yes |

**`check` verifies, `publish` ships.** `check` is more than the tests: the diff classification
runs *first*, before anything is built, because a diff that disables tests would build and pass
trivially — so checking after the build would bless exactly what the check exists to catch.

**Nothing runs by itself.** Somebody has to invoke each command — either you, or the coding
agent following [RUNBOOK.md](RUNBOOK.md). Nothing is pushed and no PR is opened until `publish`
is run.

**Who makes the git commit:** `publish` does. You don't `git commit` in the worktree, and the
agent is told not to. `publish` commits only after the diff check, the build and the tests have
passed, so nothing half-verified reaches the branch. (If something did commit early, nothing
breaks — `check` and `publish` diff from the commit the worktree was created at, not from
`HEAD`.)

**Why `check` before `publish`:** `publish` refuses to run without a passing verdict that
`check` itself wrote. The point is that the party asking to publish is the same one that made
the changes, so its own assurance is worth nothing — the verdict has to come from a real build
and a real diff classification, not from anyone's say-so.

**The PR is not opened automatically.** `publish` commits, pushes and rescans, then prints a
GitHub compare URL for you to open the PR from. That step is the only one needing
`NEXUSFIX_GITHUB_TOKEN` — pushing uses git's own credentials — so keeping it opt-in means a
token problem can't fail a run whose real work is already done. Pass `--open-pr` to have it
call the API instead.

**Which branches:** the branch you pass to `discover` (or `NEXUSFIX_BRANCH`) is used for
everything, consistently. It's resolved to a commit SHA on the remote, that exact SHA is what
Nexus IQ scans and what the worktree is created at, and it's the branch the PR **targets**. The
fix goes on a fresh `autofix/nexus/<run-id>` branch, so the PR is:

```
autofix/nexus/<run-id>  ->  <the branch you passed>
```

Both are recorded in `run.json` as `fix_branch` and `base_branch`. A branch that doesn't exist
fails immediately, listing the ones that do.

### Seeing transitive dependencies (Maven / Gradle)

By default the scan is `sourceControlEvaluation` — IQ reads what's **committed**. For npm
that's the whole story, because `package-lock.json` enumerates the full pinned tree. For
Maven and Gradle it isn't: a `pom.xml` or `build.gradle` names **direct dependencies only**,
and the transitive closure exists nowhere in the repo. So a Java repo reports findings on
direct dependencies and silently says nothing about the rest.

Point it at the Nexus IQ CLI jar and it scans the **built** application instead —
fingerprinting the artifacts actually on the classpath, so the whole tree is visible.

The least you have to set is a download URL, in `.env`:

```bash
NEXUSFIX_IQ_CLI_URL=https://.../nexus-iq-cli.jar
```

The jar is fetched once into `<workspace_root>/tools/` and reused; there's no path to keep
in step across machines. The first download logs the jar's sha256 — pin it, because this
jar is executed with your IQ credentials on its command line and a URL that quietly starts
serving something else isn't a failure anyone would notice:

```bash
NEXUSFIX_IQ_CLI_SHA256=<the sha256 it logged>
```

| Setting | `.env` | `config.yml` | What |
|---|---|---|---|
| jar URL | `NEXUSFIX_IQ_CLI_URL` | `iq_cli_download_url` | fetched if the jar isn't there |
| jar checksum | `NEXUSFIX_IQ_CLI_SHA256` | `iq_cli_sha256` | verified on download |
| existing jar | `NEXUSFIX_IQ_CLI_JAR` | `iq_cli_jar` | use one you already have |
| force a method | `NEXUSFIX_SCAN_METHOD` | `scan_method` | `iq-cli` or `source-control` |
| scan target(s) | `NEXUSFIX_IQ_CLI_SCAN_TARGET` | `iq_cli_scan_target` | comma-separated / YAML list; defaults per ecosystem |

Environment wins over `config.yml` — the latter is committed and shared, while a jar's
location is per-machine.

**Scan targets and the IQ stage belong per repo, not per machine.** A Java service and a
Node app need different ones, so a single global value is wrong for one of them by
construction. Put them on the repo:

```yaml
repos:
  java-svc: https://github.com/org/java-svc.git      # ecosystem default: build then scan build/

  node-app:
    url: https://github.com/org/node-app.git
    scan_target: [yarn.lock, package.json]           # optional; this IS the yarn default
    stage_id: stage-release                          # if this repo's pipeline scans there
    prescan_command: yarn pack                       # only if the target is a build artifact
```

Most repos need nothing beyond the URL. Reach for `scan_target` only when the layout is
unusual — a monorepo, or a packed tarball like `package-tar/package/package.json` — and
for `prescan_command` only when the target is produced by a build rather than committed. Configuring a jar or a URL is what turns the CLI scan on;
`scan_method` overrides that either way, which is how you fall back to the source-control
scan when a build is broken and you still want findings.

It runs the same invocation your pipeline does:

```
java -jar <jar> -i <app> -r <result.json> -s <iq-url> -a <user:pass> -t <stage> <target>
```

**Which build folder?** The run's own clone — `<workspace_root>/runs/<run-id>/wt`.
`discover` clones the repo there, builds *there*, and scans *there*. Your local working
copy and the directory you run `nexusfix` from are never built or scanned.

**What gets scanned depends on the ecosystem**, and you normally shouldn't set it by hand:

| Ecosystem | Built first? | Scanned |
|---|---|---|
| Gradle | yes | `build/`, or the whole checkout if there's no `build/` |
| Maven | yes | `target/`, or the whole checkout |
| yarn | **no** | `yarn.lock` + `package.json` |
| npm | **no** | `package-lock.json` (or `npm-shrinkwrap.json`) + `package.json` |
| pnpm | **no** | `pnpm-lock.yaml` + `package.json` |

Java has no components until a build makes jars to fingerprint. Node is the opposite: the
lockfile already pins the whole resolved tree, so there is nothing an install would add and
no build directory to look in. A single configured path can't be right for both — pointing
a Node repo at `build/` finds nothing and reports an application with no dependencies.

Three consequences worth knowing:

- **`discover` now builds the repo**, because there are no artifacts to scan otherwise. It
  takes as long as a build, and a repo that can't build can't be discovered at all.
- **`publish` rescans with the same scanner.** Mixing them is refused outright — a deep
  baseline compared against a shallow rescan makes every transitive finding *look* cleared,
  and `publish` would certify a fix that was never verified.
- **A quarantined artifact still blocks it.** If the repository manager 403s a dependency,
  the build fails and there's nothing to fingerprint. Deeper scan, same wall.

Every run logs which scanner ran and what it saw:

```
IQ scanned 312 component(s): 47 direct, 265 transitive, 0 unmarked
```

If transitive is `0`, only direct dependencies are covered — the run warns, loudly.

### The usual sequence

| Step | Who does it | What happens |
|---|---|---|
| 1 | you | `nexusfix discover` — nothing is modified |
| 2 | you or the agent | edit the manifest in `wt/`, leave it uncommitted |
| 3 | you or the agent | `nexusfix check --run-id …` — diff check, build, tests |
| 4 | you | read `git diff` in `wt/` — this is your review point |
| 5 | you or the agent | `nexusfix publish --run-id …` — commit, push, rescan |
| 6 | you | open the PR from the compare URL it prints |

Step 5 is the first thing that touches the remote. Stop after step 3 and nothing has left your
machine.

Add `-v` to any command for full IQ request/response bodies on the console. They're always in
`<workspace_root>/runs/<run-id>/nexusfix.log` regardless. Credentials are never logged.

### When something fails, send the log

`<workspace_root>/runs/<run-id>/nexusfix.log` is written at DEBUG on every command, and it is
the one file worth handing over. It has what the console does not:

- every IQ request and the **full response body** — the fastest way to settle "IQ says X but
  the tool did Y"
- the **complete build and test output**, not the 200-line tail the console shows — this is
  where a `403 quarantined` or a resolution failure actually appears
- the **stack trace** of any unexpected crash. The console deliberately shows a one-line
  `TypeError: …` instead of a wall of frames, so without the file the frames are gone.

The whole file is safe to share: credentials go via `auth=` and an `Authorization` header, and
request headers are never logged.

---

## How it works

```
IQ scan → target versions → worktree → agent edits → diff check → build → test → push → rescan → PR
└──────────── discover ────────────┘                 └──── check ────┘   └──── publish ────┘
```

Three ways to run the agent step. They differ **only** in who edits the files — everything else
is the same code:

| Mode | Who drives | Use when |
|---|---|---|
| `nexusfix run` | nexusfix, calling the Copilot CLI | Unattended agent runs are allowed in your org |
| `nexusfix run --interactive-agent` | nexusfix, pausing for you | The Copilot CLI is blocked from unattended tool use |
| `discover` / `check` / `publish` | a coding agent following [RUNBOOK.md](RUNBOOK.md) | You want to drive it from VS Code Copilot Chat |

`run` also takes `--gate none|pre-pr|pre-push` (default `pre-pr`, which stops for your approval
before the PR), `--dry-run` (every real step, no remote mutation) and `--mock-agent` (a no-op
agent, to test everything around it).

### Driving it from VS Code Copilot Chat

**1.** Run discover — the only step that talks to Nexus IQ:

```bash
nexusfix discover
```

It prints the findings and the next steps, including the run directory. Check each
`target_version` is genuinely newer than `current_version`.

**2.** Open the run directory — not this repo:

```bash
code ~/nfx/runs/<run-id>
```

It holds `RUNBOOK.md`, `run.json`, `nexusfix.log`, and `wt/` — the checkout to edit.

**3.** In Copilot Chat, agent mode:

> Read RUNBOOK.md and follow it. The run_id is `<paste it>`.

The agent reads `run.json` for the exact version changes, edits `wt/`, then runs `check` and
`publish`. Or do those two yourself — from your config directory, not from `wt/`.

The agent never talks to Nexus IQ. Every IQ call stays in `nexus_autofix/iq/client.py`.

### Why the checks aren't left to the agent

The agent asking to publish is the same one that made the changes, so its own assurance is
worth nothing:

- A `SUSPICIOUS` diff is refused **before** anything is built, and re-running won't change that.
- `publish` requires a verdict `check` itself wrote, and re-reads the diff — if the worktree
  changed since, what would be pushed isn't what was verified, and it stops.
- The IQ rescan has to confirm the findings cleared, or the pushed branch is deleted.
- Findings carry `is_direct` and `pulled_in_by`, so a transitive finding isn't "fixed" by adding
  a direct dependency to force a version.

---

## Toolchains

Optional. Left empty, a run uses whatever JDK/Node is active, compares it against what the repo
declares in `.trident/build.yaml`, and **warns** on a mismatch rather than failing. Only pin
paths when one machine juggles several versions across repos:

```yaml
toolchains:
  java:
    "17": /Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
  node: {}
```

---

## Tests

```bash
.venv/bin/python -m pytest -q
```

The slow subset runs a real Gradle build against a fixture and needs Java 17+ on `PATH`; the
fixture ships its own wrapper.

---

## Known caveats

**The Copilot CLI invocation is unverified.** The non-interactive flags came from the design
doc, not from a real install. It fails loudly rather than reporting "no changes" — a missing
binary, a non-zero exit or a timeout each raise with the command and the CLI's own output. On an
org that blocks unattended tool use it reports *"Access denied by policy settings"*; use
`--interactive-agent` or the agent-orchestrated mode.

**`wt/` is a clone, not a `git worktree`.** It used to be a worktree — cheaper and faster,
but in one `.git` is a *file* holding `gitdir: <path>`, and the directory it points at has no
`objects/`, only a `commondir` pointing back to the shared repo. Build tooling that opens
`.git` expecting a directory breaks: Gradle's `gradle-git-properties` fails its
`generateGitProperties` task with `org.eclipse.jgit.errors.RepositoryNotFoundException`, and
Maven's `buildnumber-maven-plugin` and some IDE integrations fail similarly. Those look like
the dependency bump broke the build. Cloning from the local mirror hardlinks the object
store, so it stays cheap, and `origin` is re-pointed at the real remote so `publish` pushes
where it should. Don't "optimise" it back.

**Two IQ fields are still unverified:** `parentRemediation` and `goldenVersion`. Neither has
appeared in a live response. If a transitive finding shows empty parent-bump advice, check those
field names against the log first.

**These five IQ behaviours are confirmed against a live instance** and should not be "corrected"
back to what the design doc says:

| Behaviour | The doc implied | The instance does |
|---|---|---|
| `sourceControlEvaluation` body | include `commitHash` | rejects it; only `stageId` + `branchName` |
| `statusUrl` | rooted | returned with **no** leading slash |
| report id | last segment of `reportDataUrl` | the URL ends `/raw`; the id is the segment **after** `reports` |
| `/policy` response | a bare array | an object with a `components` array |
| remediation version | `data.componentIdentifier…version` | `data.`**`component`**`.componentIdentifier.coordinates.version` |

If a response parses as empty while the IQ UI clearly shows findings, the run log has the real
JSON — that's the fastest way to settle it.

Design notes: [docs/superpowers/specs/2026-07-28-nexus-autofix-design.md](docs/superpowers/specs/2026-07-28-nexus-autofix-design.md).
