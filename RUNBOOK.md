# Runbook: fix Nexus IQ dependency vulnerabilities

You are fixing dependency vulnerabilities in a repository. Follow these steps in order.
Do not skip steps and do not invent your own. Every command prints JSON on stdout.

`nexusfix` below is shorthand. Use the exact path in `nexusfix_executable` from `run.json` —
the bare name only resolves with the virtualenv activated, and on Windows the executable is
`.venv\Scripts\nexusfix.exe`.

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
  has a `reason_not_actionable` — report it to the user and leave it alone.
- `target_version` is decided by Nexus IQ. **Use it exactly.** Do not pick a different
  version because it looks newer, safer or tidier.
- `is_direct: false` with a non-empty `pulled_in_by` means the manifest probably does not
  name this component at all. It is pulled in by the listed parent(s). Say so rather than
  adding a new direct dependency to force the version.

## Step 2 — Make the changes

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
- commit anything — `nexusfix publish` commits in step 4, after the build, the tests
  and the diff check have passed

These are checked automatically in step 3. A diff that does any of them is refused, and
re-running will not change that.

## Step 3 — Verify

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

- `ok: true` → go to step 4.
- `ok: false` with `suspicious_reasons` → your diff broke a rule in step 2. Revert those
  changes. Do not try to work around the check.
- `ok: false` with `build_ok: false` or `test_ok: false` → read the output tail, fix the
  dependency change, and run `check` again. Fix the *change*, not the tests.

Repeat step 2 and step 3 until `ok` is true. If you cannot get there after a few
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

## Step 4 — Publish

Again from `run_commands_from`, not from the run directory or `wt/`.

```
nexusfix publish --run-id <run_id>
```

This commits, pushes the fix branch, and rescans it in Nexus IQ to confirm the findings are
actually gone. It refuses to run unless step 3 recorded a passing verdict, so run `check`
first.

It does **not** open the pull request. It prints `open_a_pr_here` — a GitHub compare URL.
Report that URL to the user and stop; do not try to open the PR yourself.

If the rescan shows the findings are not cleared, it deletes the pushed branch and tells
you. That means the upgrade did not fix the vulnerability — report it, do not retry
blindly.

---

## If a finding has no fix available

An entry with `"actionable": false` and a reason like *"IQ offers no remediation version"*
cannot be fixed by upgrading it. **Do not invent one** — do not pick a version IQ did not
offer, and do not delete the dependency.

To see what the options actually are:

```
nexusfix usage <component> --run-id <run_id>
```

It reports where the component is declared and referenced, and — the useful part — asks
Nexus IQ whether bumping whichever **parent** pulls it in would clear the violation. A
`parent_target_version` in the output is a real fix with IQ behind it: bump that parent
instead, then run `check`.

If there is no parent fix either, report it and stop. In particular:

- **"no reference found" does not mean unused.** A dependency can be loaded by name at
  runtime, named in a config file the search does not parse, or used only on a path the
  tests never take. A transitive dependency is used by its *parent*, not by this code, so
  finding no reference to it is the expected result and says nothing about safety.
- **Never remove a dependency to clear a finding.** Tests passing does not license it —
  that proves the paths the tests take still work, which is a much weaker claim. This is a
  decision for someone who knows the service. Report it as a suggestion for a human.

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
