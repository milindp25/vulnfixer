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

And `config.yml`, listing the applications this tool may work on:

```yaml
min_threat_level: 8      # only fix threat level 8+ (IQ's Severe/Critical)

repos:
  boardingwizard-static: https://github.com/your-org/boardingwizard-static.git
```

The **key is the name you use everywhere else** — `--app-id`, `NEXUSFIX_APP_ID`, the mirror
directory, per-repo settings. Call it whatever you call the repo.

Nexus IQ is the one consumer needing its own identifier, and it is often a different
string. Say so, and nothing else changes:

```yaml
repos:
  payments-core:
    url: https://github.com/your-org/payments-core.git
    iq_app_id: card-payments-core     # what Nexus IQ calls this application
```

Then `--app-id payments-core` works while IQ is asked about `card-payments-core`.
`iq_app_id` defaults to the key, so a config where the two already match needs no change.

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
| `appsec-discover` | Everything `discover` does, **plus** the libraries the AppSec SCA worksheet names for this repo. See below. | No |
| `resolve` | Records which version to use where IQ and the AppSec sheet disagree. | No |
| `approve` | Releases a finding held back for review — a major version jump, usually. | No |
| `gc` | Deletes stale `autofix/nexus/*` branches with no open PR. | Yes |

There's also `nexusfix run`, which does everything in one command by calling the Copilot
CLI directly. It needs unattended agent runs to be permitted in your org.

**Why `check` before `publish`:** `publish` won't run without a verdict `check` itself
wrote, and re-reads the diff — if the worktree changed since, what would be pushed isn't
what was verified, and it stops. The party asking to publish is the same one that made the
changes, so its own assurance is worth nothing.

**Contract tests.** A Gradle repo often registers these as their own tasks —
`contractTestConsumer`, `contractTestProvider`, `pactVerify` — wired into neither `test`
nor `check`, so nothing runs them. A dependency bump can change a serialised payload and
break a consumer contract without a single unit test noticing. Turn them on per repo:

```yaml
repos:
  java-api:
    url: https://github.com/org/java-api.git
    run_contract_tests: true                      # discovers the Gradle tasks

  react-app:
    url: https://github.com/org/react-app.git
    run_contract_tests: true
    contract_test_command: yarn test:contract     # npm has no discoverable task name
```

`check` then runs them after the unit tests and reports `contract_test_tasks` /
`contract_tests_ok` in the verdict, separately from `test_ok`.

**Only contract tests** — not `integrationTest`, `e2eTest`, `componentTest` or
`smokeTest`. Contract tests are self-contained, so they run here as they do in CI; the
others need the surrounding systems up and would fail for reasons that have nothing to do
with the dependency change. The `*Classes` tasks are excluded too — those *compile* the
contract tests, so running one proves nothing and passes.

Off by default. See what a repo has with `./gradlew tasks --all` (`--group verification`
and `check --dry-run` both miss an ungrouped task).

**Which branches:** the branch you pass to `discover` is resolved to a commit SHA, that
exact SHA is what IQ scans and what the checkout is made at, and it's the branch the PR
targets. The fix goes on `autofix/nexus/<run-id>`.

---

## Major version jumps

A major bump — `nanoid 3.3.7 -> 5.0.9` — is **not** attempted automatically. It can change
an API and break whatever depends on the package in ways a passing build does not rule out,
so it arrives as `"actionable": false` with `"needs_approval": true`, and it stays out of
`target_purls` so `publish` doesn't expect it to clear.

That's the default, not the end of it. The agent is expected to *investigate* these rather
than just report them: whether the repo actually uses the affected surface, what the
changelog says between the two versions, what `pulled_in_by` names as depending on it. It
gives you a recommendation, and you decide:

```bash
.venv/bin/nexusfix approve --run-id <run-id> --component nanoid --version 5.0.9
```

`--version` has to match what Nexus IQ recommended. It confirms *which* change you're
approving; it never chooses one. The agent can't run `approve` — an agent approving its own
analysis would mean nothing, which is the same reason `publish` needs a verdict `check`
wrote.

Say nothing and nothing happens. That's the point of the default.

---

## AppSec findings

Nexus IQ is not the only source of dependency problems. AppSec tracks libraries that are
**quarantined or about to be flagged** in a Tableau report — findings IQ has not raised as
policy violations yet, and which no IQ scan can therefore surface. `discover` cannot see
them: IQ's policy endpoint returns only components carrying a violation, and one that *is*
flagged below `min_threat_level` is filtered out before the agent sees it.

There is no API between Tableau and this tool, so the data arrives as an exported workbook.
Download it, then:

```bash
.venv/bin/nexusfix appsec-discover --sheet ./SCA_Worksheet_data.xlsx
```

This is `discover` **plus** the AppSec rows — one run, one worktree, one build, one PR.
Deliberately not a separate run: both sets of changes touch the same manifest, so two runs
would mean two branches editing the same lines.

Everything after it is unchanged. `check` and `publish` work as they always have, and
`RUNBOOK.md` needs no new instructions for the ordinary case — an AppSec finding is just a
finding in `run.json` with `"source": ["appsec"]`.

**Which columns are read.** `GITHUB_ORG` and `GITHUB_REPO_NAME` (matched against your
`repos:` clone URLs), `LIBRARY_FILENAME`, `VULN_TOPFIX_RESOLUTION`, and optionally
`LIBRARY_TYPE`, `VULN_NAME`, `DIRECT_DEPENDENCY` and `CVSS3 Score`. Everything is looked up
**by header name**, so the column order can change freely; only a rename needs
`appsec.columns` in `config.yml`.

`LIBRARY_NAME` is read for display only. It holds a human label — "Bouncy Castle Provider" —
which matches neither a groupId nor an artifactId, so all identity comes from
`LIBRARY_FILENAME`: `bcprov-jdk15on-1.49.jar` is artifact `bcprov-jdk15on` at `1.49`. A
filename with no version in it (`jtidy-r938.jar`) is reported as unreadable rather than
guessed at.

**Rows repeat per CVE** — one library commonly fills eight rows — and are folded into a
single finding carrying every CVE.

### What it will not do on its own

`VULN_TOPFIX_RESOLUTION` is a *list of candidates*, not an answer, and most entries name a
**different artifact** than the one installed. Four outcomes:

| Outcome | Meaning |
|---|---|
| `RESOLVED` | One usable target. Handed to the agent like any other finding. |
| `CONFLICT` | IQ and the sheet both offer a real upgrade and they differ. **`check` refuses until you settle it.** |
| `SWAP_ONLY` | Every suggestion is a different artifact — `bcprov-jdk15on` → `bc-fips` is a migration, not a bump. Reported, never applied. |
| `AMBIGUOUS_GROUP` | The same artifact name under several group ids. `com.fasterxml.jackson.core:jackson-core` and `tools.jackson.core:jackson-core` are different packages, and the filename does not say which is installed. |

For a `CONFLICT`, `check` stops and prints the exact command:

```bash
.venv/bin/nexusfix resolve --run-id <run-id> --component org.bouncycastle:bcprov-jdk15on --version 1.64
```

`resolve` accepts **only one of the two versions already proposed**. A third is refused.
That constraint is the point: the agent can read changelogs and recommend, but it cannot
launder a version of its own choosing through this command and have it arrive looking like
your decision. If both candidates are wrong, fix the sheet or escalate.

Nothing IQ says about an AppSec library is taken on trust either — a candidate that is not
newer than what is installed is discarded, from either source.

**The rescan proves less here, and the run says so.** `publish` confirms a fix by the
finding disappearing from the IQ report. A library that was never a violation cannot
disappear from a list it was never on, so for those the IQ rescan is not evidence. The
build, the tests and the diff classification still are.

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

## TLS behind a corporate proxy

If Python fails with `SSLCertVerificationError` where a browser on the same machine is
fine, the proxy is presenting its own root CA. Best fix is `pip install truststore`, which
makes Python use the OS trust store with nothing to configure.

Otherwise, instead of `curl`-ing the CA down by hand on every machine, put the URL in
`.env`:

```bash
NEXUSFIX_CA_BUNDLE_URL=https://pki.corp.example.com/corporate-root-ca.pem
NEXUSFIX_CA_BUNDLE_SHA256=<the sha256 the first run logs>
```

It is fetched once into `<workspace_root>/tools/corporate-ca.pem` and reused; later runs
make no network call for it. That path is outside any git working tree, so it cannot be
committed.

**Set the checksum.** That first download *cannot verify the certificate it is fetching* —
there is no CA to verify with yet, which is the entire problem being solved — so the
checksum is the only thing establishing that what arrived is your organisation's CA rather
than one substituted in transit. Every "verified" connection afterwards trusts whatever
that file contains. Without a checksum it still works and warns loudly, printing the sha256
to paste back.

A download that returns a proxy sign-in page instead of a certificate is refused rather
than saved, since that failure otherwise surfaces much later as an unintelligible SSL error.

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
