# Runbook: fix Nexus IQ dependency vulnerabilities

You are fixing dependency vulnerabilities in a repository. Follow these steps in order.
Do not skip steps and do not invent your own. Every command prints JSON on stdout.

`nexusfix` below is shorthand. Use the exact path in `nexusfix_executable` from `run.json` —
the bare name only resolves with the virtualenv activated, and on Windows the executable is
`.venv\Scripts\nexusfix.exe`.

**Start by saying whether you can run terminal commands**, so the user knows which of you is
driving:

> "I can run commands, so I'll run `check` and `publish` myself." — agent mode
>
> "I can edit files but not run commands, so I'll give you each command to run." — edit mode

**If you cannot run them** — Copilot edit mode, or any setup where tool use is unavailable —
you can still do every part of this that matters. Make the file changes as described, then
**print the exact commands for the user to run** and stop, rather than skipping the step or
claiming it is done. Nothing is weakened by this: the changed files are read from
`git status`, never from your account of them, so `check` and `publish` behave identically
whether you ran them or the user did.

Never report a step as done when you could not run it. If you are unsure whether a command
executed, say so — a step wrongly reported as passed is worse than one openly skipped.

---

## Step 1 — Find out what needs fixing

**If you were given a `run_id`**, the work has already been done. Read `run.json` in this
same directory and use what is in it. Do **not** run `discover` again — that would start a
second Nexus IQ scan and create a second worktree.

**Only if you were not given a `run_id`**, run:

```
nexusfix discover
```

Either way you end up with the same information. `discover` talks to Nexus IQ, scans the
branch, works out which components need upgrading and to which versions, prepares a git
worktree, and writes all of it to `run.json`.

Do not read `nexusfix.log` for this. It is a human-readable trace with no stable format —
`run.json` is the machine-readable source of truth.

The fields:

```json
{
  "run_id": "...",
  "run_dir": "...",
  "worktree": "<-- the ONLY directory you may edit",
  "fix_branch": "autofix/nexus/...",
  "ecosystem": "npm",
  "build_command": "npm ci",
  "test_command": "npm test",
  "findings": [
    {
      "component": "brace-expansion",
      "current_version": "5.0.7",
      "target_version": "5.0.8",
      "remediation_type": "next-no-violations",
      "threat_level": 9,
      "is_direct": false,
      "pulled_in_by": ["pkg:npm/some-parent@1.2.3"],
      "actionable": true
    }
  ]
}
```

**Read `findings` carefully. It is the only list you act on.**

Each entry states the change to make outright — you do not work out, look up or choose any
version yourself. The example above means exactly:

> upgrade `brace-expansion` from `5.0.7` to `5.0.8`

Ignore `target_purls` if you see it in `run.json`. It is internal bookkeeping for the
post-fix rescan, and the versions in it are the CURRENT ones — acting on it would leave
everything as it is.

- Only work on entries with `"actionable": true`. An entry with `"actionable": false`
  has a `reason_not_actionable` — report it to the user and leave it alone, unless it also
  has `"needs_approval": true`, which is covered below.

### Findings that need approval

`"needs_approval": true` means Nexus IQ **did** name a target version, but this tool held
it back — almost always a major version jump, where `nanoid 3.3.7 -> 5.0.9` can change an
API and break whatever depends on it in ways a passing build does not rule out.

These are the one place you are asked to **investigate rather than just report.** Do the
work, then recommend:

1. **Does this repo actually use the affected surface?** Search the worktree for how the
   package is imported and called. A major that drops a Node version, or renames an export
   nothing here touches, is a very different risk from one that changes a function you call
   in twenty places.
2. **What does the upgrade actually change?** The changelog or release notes between the
   two versions, if you can reach them. Say plainly when you cannot.
3. **What else depends on it?** `pulled_in_by` names the parents. Forcing a major under a
   parent that expects the old one is how a green build breaks at runtime.
4. **Give the user a recommendation and your reasoning**, including what you could not
   check. Then tell them the command:

   ```
   nexusfix approve --run-id <run-id> --component <component> --version <target_version>
   ```

**You cannot run `approve` yourself, and you must not ask the user to paste it back for you
to run.** The decision is the entire point — an agent approving its own analysis is worth
nothing. Once they run it, the finding becomes actionable and you fix it like any other.

If they say no, or say nothing, leave it alone. That is the default and it is the safe one.
Do not fix it anyway on the grounds that you looked into it and it seemed fine.
- `target_version` is decided by Nexus IQ. **Use it exactly.** Do not pick a different
  version because it looks newer, safer or tidier.
- `is_direct: false` with a non-empty `pulled_in_by` means the manifest probably does not
  name this component at all. It is pulled in by the listed parent(s). See below — this
  needs a different edit from a direct dependency, and getting it wrong is the most common
  mistake made here.

### Fixing a transitive dependency

The component is not in your manifest. Something else depends on it. There are three
correct moves, in this order:

**1. If a parent is named, bump the parent.** That is the real fix — it moves the whole
subtree the way its author intended.

**2. Otherwise, on npm / yarn / pnpm, pin it with an override.** This is the sanctioned
mechanism for forcing a transitive version, and the version still comes from Nexus IQ:

```jsonc
// npm 8.3+ — package.json
"overrides": { "nanoid": "3.3.8" }

// yarn and pnpm — package.json
"resolutions": { "nanoid": "3.3.8" }
```

Use whichever your repo already uses; if neither is present, `overrides` for npm and
`resolutions` for yarn/pnpm. Then regenerate the lockfile.

**3. On Gradle and Maven, do not force it.** There is no safe equivalent —
`resolutionStrategy.force` is refused by `check`, deliberately. Report it and stop.

**Never add the component to `dependencies` or `devDependencies`.** That does not pin a
transitive version — it makes the package a direct dependency of your application, which
is a different change with different consequences, and it can leave the vulnerable copy
still resolved deeper in the tree. An override constrains what everything else resolves
to; a new dependency entry just adds one more thing that depends on it. If you are tempted
to add a dependency entry, that is the signal you want an override instead.

This applies only to findings already marked `"actionable": true`. A major version jump is
never one of them — it is escalated for a human precisely because forcing, say, `nanoid` 5
under a `postcss` that expects 3 breaks things a build may not catch.

### AppSec findings

A finding with `"source"` containing `"appsec"` came from the AppSec SCA worksheet rather
than from a Nexus IQ policy violation — a library that is quarantined or about to be
flagged. If `"actionable": true`, treat it exactly like any other entry: `target_version`
is decided, use it as written.

If it is not actionable, `appsec_decision` says why, and each case needs something
different from you:

**`CONFLICT`** — Nexus IQ and the AppSec sheet recommend different versions, in
`iq_version` and `sheet_version`. `candidate_versions` holds both.

Do **not** edit the manifest for this component, and do not pick one yourself. Instead:

1. Compare **only those two versions**. Look at what the repo actually uses — the manifest,
   how the library is called, whether the bump crosses a major version. You may explain
   what each choice would mean.
2. Present both to the user with a recommendation and your reasoning.
3. Ask them to decide. The command is:

   ```
   nexusfix resolve --run-id <run-id> --component <component> --version <one of the two>
   ```

Do not propose a third version. `resolve` refuses anything that is not one of the two, so
suggesting one wastes the user's time. If both look wrong, say so and stop — the sheet
needs fixing, or it needs escalating.

You cannot run `resolve` on the user's behalf and then carry on as though they had chosen.
The whole reason the decision goes through that command is that it is theirs to make.

`nexusfix check` will refuse to run while any `CONFLICT` is outstanding, so there is
nothing to gain by proceeding to step 4 first.

**`SWAP_ONLY`** — every fix the sheet proposes names a *different artifact*
(`org.bouncycastle:bcprov-jdk15on` → `org.bouncycastle:bc-fips`). That is a migration, not
a dependency bump: it changes which package the code depends on, and often its API. Report
it to the user with the `swap_candidates` list and leave it alone. Do not attempt it.

**`AMBIGUOUS_GROUP`** — the sheet proposes the same artifact name under more than one group
id (`com.fasterxml.jackson.core:jackson-core` and `tools.jackson.core:jackson-core` are
different packages), and nothing states which one is installed. Report it and leave it
alone.

## Step 2 — Show the user what you are about to do

**Before you edit a single file**, list every change you intend to make:

```
Planned changes (3):
  org.bouncycastle:bcprov-jdk15on   1.49  -> 1.64   [appsec, 6 CVEs]
  xalan:xalan                       2.7.2 -> 2.7.3  [threat 9]
  org.apache.neethi:neethi          3.2.2 -> 3.2.3  [appsec]

Not being fixed (2):
  bcprov-jdk18on   the sheet only proposes a different artifact (bc-fips) — a migration
  jackson-core     the sheet names two group ids; nothing says which is installed
```

Every actionable finding, with its from- and to-version, and every one you are skipping with
the reason. Do not summarise it as "3 dependency updates" — the versions are the part worth
checking, and a wrong target is far cheaper to catch here than after a build.

Then make the changes. You do not need to wait for a reply at this point; the approval that
matters is in step 5, before anything leaves the machine.

## Step 3 — Make the changes

Work **only** inside the `worktree` path from step 1. Not the repository you opened.

Change dependency versions in the manifest, then regenerate the lockfile by running the
ecosystem's install command (`npm install`, `yarn install`, `pnpm install`, or the Gradle
or Maven equivalent) inside the worktree.

**You must not:**

- modify, skip, delete or disable any test
- edit `.trident/build.yaml`, CI config, or `.gitignore` to make checks pass
- add a Nexus IQ waiver, suppression or `.security-fix.yml` entry
- hand-edit a lockfile — regenerate it with the package manager
- use `--legacy-peer-deps`, `--force`, `resolutionStrategy.force`, `npm audit fix`,
  version ranges, exclusions, or a downgrade
- commit anything — `nexusfix publish` commits in step 5, after the build, the tests
  and the diff check have passed

These are checked automatically in step 4. A diff that does any of them is refused, and
re-running will not change that.

## Step 4 — Verify

**Run this from the directory in `run_commands_from` (see `run.json`)** — not from the run
directory and not from `wt/`. `nexusfix` reads `config.yml` and `.env` from the current
directory, so it only works from there.

```
nexusfix check --run-id <run_id from step 1>
```

This classifies the diff, then runs the real build and tests. It prints:

```json
{ "ok": true, "diff_classification": "MANIFEST_ONLY", "build_ok": true, "test_ok": true }
```

- `ok: true` → go to step 5.
- `ok: false` with `suspicious_reasons` → your diff broke a rule in step 3. Revert those
  changes. Do not try to work around the check.
- `ok: false` with `build_ok: false` or `test_ok: false` → read the output tail, fix the
  dependency change, and run `check` again. Fix the *change*, not the tests.
- `ok: false` with `contract_tests_ok: false` → the unit tests passed but this repo's
  contract tests (listed in `contract_test_tasks`) did not. A bump can change a
  serialised payload and break a consumer contract without any unit test noticing, so
  this is a real failure: fix the dependency change. **Do not modify or delete the
  contract tests.** If they fail because a broker or provider is unreachable from here
  rather than because of your change, say so and stop.

Repeat step 3 and step 4 until `ok` is true. If you cannot get there after a few
attempts, stop and report what failed — do not force it through.

## If the build fails on a 403 / quarantined artifact

A dependency can be **quarantined** in the repository manager, in which case downloading it
returns `403` with text like *"Requested item is quarantined"*. The build fails on it even
though it never appeared in `findings` — the scan could not download it either, so Nexus IQ
never saw it.

The full build output is in `nexusfix.log` in this directory. Read it there; do not re-run
the build to see it.

1. Take the exact component from the 403, e.g. `io.netty:netty-resolver-dns:4.1.100.Final`.
2. Ask Nexus IQ what version clears the policy — **do not choose a version yourself**:

   ```
   nexusfix remediate io.netty:netty-resolver-dns:4.1.100.Final --run-id <run_id>
   ```

   Pass the component in whichever of these forms matches what the error gave you. Do not
   try to build the coordinates yourself — the keys differ per ecosystem and the wrong ones
   are rejected:

   | Ecosystem | Write it as | Example |
   |---|---|---|
   | Maven / Gradle | `group:artifact:version` | `io.netty:netty-resolver-dns:4.1.100.Final` |
   | Maven with a type | `group:artifact:version:extension` | `io.netty:netty-bom:4.1.100.Final:pom` |
   | npm / yarn / pnpm | `name@version` | `postcss@8.5.10` |
   | scoped npm | `@scope/name@version` | `@charlietango/use-focus-trap@1.4.0` |
   | anything, as a purl | `pkg:<type>/<name>@<version>` | `pkg:maven/io.netty/netty-codec-http@4.1.100.Final` |

   Run it from the directory in `run_commands_from` (see `run.json`), as with `check` and
   `publish`.

   It returns:

   ```json
   {
     "current_version": "4.1.100.Final",
     "target_version": "4.1.118.Final",
     "remediation_type": "next-no-violations-with-dependencies",
     "all_offers": [ ... ],
     "message": "Upgrade to 4.1.118.Final."
   }
   ```

   Use `target_version` exactly. If it is `null`, the component cannot be fixed by bumping
   it — report that and stop.
3. Quarantined components are usually transitive, so the manifest will not name them. Find
   the parent that pulls it in:

   ```
   ./gradlew dependencies --configuration runtimeClasspath
   ./mvnw dependency:tree -Dverbose -Dincludes=io.netty
   ```

   Bump **that parent** to a version whose dependency is at or past the target.
4. Run `check` again.

**You must never work around a quarantine.** Do not add `mavenCentral()`, jcenter, or any
other repository; do not use `--offline`; do not exclude the dependency; do not pin it to a
version the repository refuses to serve. Quarantine is a security control. Finding a clean
version that the repository will serve is the fix; evading the block is not, and `check`
will refuse the diff if you try.

If no version works, say so and stop. Someone has to release the quarantine in Nexus
Firewall, and that is not something you can or should do.

## Step 5 — Publish

### Get the user's approval first. This is not optional.

`publish` is the first thing that leaves this machine — it commits, pushes a branch to the
remote, and cannot be silently undone. **Stop here and ask.**

Show what actually changed, read from `git status` and the diff in the worktree, **not**
from your memory of what you edited:

```
Ready to publish 3 change(s) to autofix/nexus/<run-id>:

  build.gradle
    org.bouncycastle:bcprov-jdk15on   1.49  -> 1.64
    xalan:xalan                       2.7.2 -> 2.7.3
  gradle.lockfile                     regenerated

  check: build passed, 412 tests passed, diff classified DEPENDENCY_ONLY

Push this branch to the remote? (yes / no)
```

Then **wait for an explicit yes.** Not silence, not "looks good, carry on" from earlier in
the conversation — an answer to this question. If the user says no, or says nothing, stop
and leave the branch unpushed; everything is still on disk and nothing is lost.

Read the diff before you summarise it. If it contains a file you did not expect to change,
say so rather than listing it as though you meant it.

Once they agree, again from `run_commands_from`, not from the run directory or `wt/`:

```
nexusfix publish --run-id <run_id>
```

This commits, pushes the fix branch, and rescans it in Nexus IQ to confirm the findings are
actually gone. It refuses to run unless step 4 recorded a passing verdict, so run `check`
first.

It does **not** open the pull request. It prints `open_a_pr_here` — a GitHub compare URL.
Report that URL to the user and stop; do not try to open the PR yourself.

If the rescan shows the findings are not cleared, it deletes the pushed branch and tells
you. That means the upgrade did not fix the vulnerability — report it, do not retry
blindly.

---

## If you get stuck

Stop and report rather than trying more variations. Point the user at
`nexusfix.log` in this directory — it holds the full IQ responses, the complete build and
test output, and the stack trace of anything that crashed, none of which is on the console.
Say which step failed and what the last command you ran was.

---

## Reporting back

When you are done, tell the user:

- which components you changed and from which version to which
- the outcome of `publish`, and the PR link if one was opened
- anything you did not fix, and why — including every `"actionable": false` finding
