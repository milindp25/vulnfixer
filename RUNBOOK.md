# Runbook: fix Nexus IQ dependency vulnerabilities

You are fixing dependency vulnerabilities in a repository. Follow these steps in order.
Do not skip steps and do not invent your own. Every command prints JSON on stdout.

Replace `nexusfix` below with the path to the executable if it is not on your PATH
(on Windows, typically `.venv\Scripts\nexusfix.exe`).

---

## Step 1 — Discover what needs fixing

```
nexusfix discover
```

This talks to Nexus IQ, scans the branch, works out which components need upgrading and
to which versions, and prepares a git worktree for you to edit. It changes nothing in the
repository you are sitting in.

It prints:

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

**Read `findings` carefully.**

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
- commit anything — committing is done for you in step 4

These are checked automatically in step 3. A diff that does any of them is refused, and
re-running will not change that.

## Step 3 — Verify

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

## Step 4 — Publish

```
nexusfix publish --run-id <run_id>
```

This commits, pushes the fix branch, rescans it in Nexus IQ to confirm the findings are
actually gone, and opens a pull request. It refuses to run unless step 3 recorded a
passing verdict, so run `check` first.

If the rescan shows the findings are not cleared, it deletes the pushed branch and tells
you. That means the upgrade did not fix the vulnerability — report it, do not retry
blindly.

---

## Reporting back

When you are done, tell the user:

- which components you changed and from which version to which
- the outcome of `publish`, and the PR link if one was opened
- anything you did not fix, and why — including every `"actionable": false` finding
