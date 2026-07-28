# Playbook — React / npm / Yarn

Injected when `.trident/build.yaml` declares `uses: npm`, `yarn`, or `pnpm`.

---

## Step 0 — Establish the React line and the package manager

### React version

Read `react` from `package.json`, and confirm the resolved version in the lockfile — a range like `^18.2.0` may resolve to `18.3.1`.

| Line | Status | What this means for remediation |
|---|---|---|
| **16, 17** | End of life, no patches from Meta | **Escalate.** These repos need modernization, not a version bump. Report the line and stop. |
| **18** | Security-only since React 19 shipped (Dec 2024) | Normal remediation. Most of the ecosystem was built against 18, so peer conflicts are rare. |
| **19** | Current, actively developed | Normal remediation. Peer conflicts are the common blocker — see below. |

**Never migrate React major versions.** 18 → 19 is a migration project with its own codemod and a long tail of third-party compatibility work. It is not a vulnerability fix. Escalate.

**Do not run `npx codemod` or any React migration recipe.** Those exist for planned upgrades, not for remediation runs.

### Node version

Read `node-version` from `.trident/build.yaml`. Cross-check `.nvmrc`, `.node-version`, and the `engines` field in `package.json` if present — a disagreement between them is worth reporting even though it is not yours to fix.

Support status as of mid-2026. Verify against the current Node release schedule, since these dates move:

| Line | Status | What this means |
|---|---|---|
| **16, 18, 20** | End of life | The runtime itself is an unsupported-component finding. **Report it.** Still remediate what you can, but expect newer package versions to refuse to install. |
| **Odd lines (21, 23, 25)** | Never entered LTS, all EOL | Same as above, plus the repo should not have been on one. |
| **22** | Maintenance LTS | Fine. Normal remediation. |
| **24** | Active LTS | Fine. Normal remediation. |
| **26** | Current | Fine, though some packages may not yet declare support. |

Node 20 reached EOL on 30 April 2026, so a repo declaring Node 20 is now in the same position Node 18 repos were a year earlier. That is a finding to surface in your report, not something to fix — the version is declared in `.trident/build.yaml`, which you must not edit.

### The `engines` constraint — the Node equivalent of the peer trap

A package version may declare a minimum Node version:

```json
"engines": { "node": ">=22.0.0" }
```

If the target version requires a newer Node than the repo declares, **stop and escalate.** npm warns by default and fails under `engine-strict`; Yarn 1 errors outright. Either way, adopting that version means a runtime upgrade, which is a platform change wearing a vulnerability fix as a disguise.

Report it in the same shape as a peer conflict: which package, what Node it requires, what the repo declares.

**Do not add `engine-strict=false`, `--ignore-engines`, or edit the `engines` field** to get past this.

### Package manager — from the lockfile, not convention

| Lockfile present | Manager | Install command |
|---|---|---|
| `package-lock.json` | npm | `npm install` |
| `yarn.lock` | Yarn | `yarn install` |
| `pnpm-lock.yaml` | pnpm | `pnpm install` |

If two lockfiles are present, **stop and escalate** — that is a repository hygiene problem, and picking one produces a change nobody can review safely.

**The manager changes how peer conflicts behave.** npm 7+ enforces peer dependency rules strictly and fails the install. Yarn 1 warns and continues. The same dependency change can therefore pass on a Yarn repo and fail on an npm one — and a Yarn repo that "passes" may still have a real incompatibility that surfaces at runtime as `Invalid hook call`. Read install warnings on Yarn repos; do not assume silence means success.

### npm ships with Node — two consequences

The npm version is determined by the Node version, not chosen independently.

| Node line | Bundled npm |
|---|---|
| 18 | 9.x |
| 20, 22 | 10.x |
| 24, 26 | 11.x |

**`overrides` requires npm 8.3 or later.** On any current line this is satisfied, but on an old EOL runtime an `overrides` block can be silently ignored — the install succeeds, the transitive is unchanged, and the finding remains. If you use an override on an old-Node repo, verify in the lockfile that the version actually changed.

**Lockfile format follows the npm major.** npm 9 and later write `lockfileVersion: 3`; npm 7–8 wrote version 2. If the lockfile in the repo was written by a different npm major than the one you are running, your install will rewrite the entire file. That produces a diff of thousands of lines that no human can review, and it buries the actual change.

If you see the whole lockfile rewritten rather than a handful of entries, **stop and report it**. Do not commit it. That is a signal the toolchain does not match what the repo was built with, which is an environment problem to escalate.

**If `package.json` contains a `packageManager` field**, that pins the Yarn or pnpm version via Corepack and is authoritative over whatever is on `PATH`. Do not change it.

## Lockfiles are regenerated, never edited

After changing `package.json`, run the install command so the lockfile updates. Do not hand-edit `package-lock.json` or `yarn.lock` — they contain integrity hashes and a resolved graph that cannot be maintained by hand.

The verification build runs `npm ci` / `yarn install --frozen-lockfile`, which **fails if the manifest and lockfile disagree**. Skipping regeneration will be caught.

---

## Direct dependency

The component appears in `dependencies` or `devDependencies`.

```diff
 "dependencies": {
-  "axios": "^1.6.0",
+  "axios": "^1.7.9",
   "react": "^18.3.1"
 }
```

Then run the install command. Both `package.json` and the lockfile must appear in your changes.

**Preserve the range operator.** If the original was `^1.6.0`, write `^1.7.9`, not `1.7.9`. Pinning a previously ranged dependency is a policy change beyond the scope of a vulnerability fix.

---

## Transitive dependency

This is where most findings land, and where the wrong fix is easy.

### Step 1 — Bump the direct parent (strongly preferred)

The findings list gives you the **dependency path**, showing which direct dependency pulls in the vulnerable package. When Nexus IQ supplies a **parent remediation**, it is included in the finding — use it.

```
minimist 1.2.5 → 1.2.8
  path: react-scripts@5.0.0 > ... > minimist@1.2.5
  parent remediation: react-scripts 5.0.0 → 5.0.1
```

The fix is bumping `react-scripts`:

```diff
 "devDependencies": {
-  "react-scripts": "5.0.0"
+  "react-scripts": "5.0.1"
 }
```

Correct because the parent's maintainer has already tested against the newer transitive. Nothing is being forced.

### Step 2 — Override, only when no parent version resolves it

If no version of the parent brings in a clean transitive, force it. This is a real risk: you are pairing a library with a dependency version its maintainer never tested against.

npm:
```json
"overrides": { "minimist": "1.2.8" }
```

Yarn:
```json
"resolutions": { "minimist": "1.2.8" }
```

pnpm:
```json
"pnpm": { "overrides": { "minimist": "1.2.8" } }
```

**State clearly in your summary that an override was used**, naming the CVE, the parent that could not be bumped, and the date. Overrides accumulate silently and nobody remembers why they exist. These PRs are never auto-merged.

---

## Peer dependencies — the trap

This is the single most common blocker, and the internet's standard advice for it is prohibited here.

A library version whose peer requirements no longer match the app breaks at install time on npm, or silently at runtime on Yarn with `Invalid hook call. Hooks can only be called inside of the body of a function component.`

### The rule

**If the target version changes a peer dependency requirement, stop and escalate.** Report which peer, what it requires, and what the app currently has.

Typical shape on a React 18 repo:

```
npm ERR! peer react@"^19.0.0" from @some/ui-library@4.0.0
npm ERR! node_modules/react
npm ERR!   react@"^18.3.1" from the root project
```

That is not a fix to force through. It means the library dropped React 18 support, and adopting it is a React 19 migration wearing a vulnerability fix as a disguise.

### Why `--legacy-peer-deps` is prohibited

Many guides recommend `npm install --legacy-peer-deps` as a quick workaround. **Do not use it here.** It does not resolve the conflict — it tells npm to ignore peer rules entirely, for every package, permanently. The incompatibility still exists and surfaces later somewhere much harder to diagnose. It also disables the check for every future install in that repo.

The same applies to `--force`.

### Libraries that support both lines

Many maintainers widen their peer range to `^18.3.1 || ^19.0.0` rather than dropping 18. If a newer version of the blocking library has done this, bumping to it is a legitimate fix — check the library's peer range before escalating. This is often the real answer on React 18 repos.

---

## Prohibited

- **`npm audit fix` / `npm audit fix --force`.** The force variant performs semver-major bumps blindly across the whole tree. Both read the npm advisory database, not the organizational policy that produced these findings — they fix things nobody asked for and miss things that matter.
- **Acting on `npm audit` output at all.** The findings list is authoritative.
- **`--legacy-peer-deps` or `--force`** in any form, including in `.npmrc` or a script.
- **Hand-editing any lockfile.**
- **Deleting a lockfile and regenerating from scratch.** That silently upgrades every dependency in the project and makes the diff unreviewable.
- **Loosening a version range** — changing `1.2.3` to `^1.2.3` or `*` to ease resolution.
- **Bumping `react` or `react-dom` across a major version.**
- **Running React migration codemods.**
- **Editing `.trident/build.yaml`** to change the declared Node version.
- **Editing the `engines` field**, or using `--ignore-engines` / `engine-strict=false` to bypass a Node requirement.
- **Editing the `packageManager` field.**
- **Committing a wholesale lockfile rewrite** caused by an npm major mismatch.

---

## Escalate when

- The repo is on React 16 or 17 — a modernization project, not a bump.
- Two lockfiles are present.
- The fix changes a peer dependency requirement and no version of the blocking library supports the current React line.
- **The target version's `engines` field requires a newer Node than the repo declares.**
- **The lockfile rewrites entirely on install** — the toolchain does not match what the repo was built with.
- The only clean version is a semver-major bump of a direct dependency.
- No parent version resolves a transitive **and** an override would force a version more than one major away from what the parent expects.
- `npm ci` fails after your change for reasons you cannot trace to your edit.
- The vulnerable package appears through multiple independent paths requiring conflicting versions.
- A Node version error appears — that is a toolchain problem.

## Always report, never fix

These are surfaced in your summary under NOTES, not acted on:

- The repo declares an **end-of-life Node line** (16, 18, 20, or any odd-numbered line).
- The repo is on **React 18**, which is security-only.
- `.trident/build.yaml`, `.nvmrc`, and `engines` **disagree** about the Node version.

---

## Dev versus runtime

If a finding is in a `devDependencies` package used only at build time, say so in your report. It is still a real finding, but a reviewer treats it differently from something shipping to production, and the distinction is easy to lose once it is in a diff.

Note also that React itself is a client-side bundle. Server-side scanners often under-report frontend dependencies, so findings that do surface here deserve accurate reporting rather than quiet handling.

---

## Worked examples

### Example 1 — direct dependency

Finding: `axios 1.6.0 → 1.7.9`, direct.

```diff
--- a/package.json
+++ b/package.json
 "dependencies": {
-  "axios": "^1.6.0",
+  "axios": "^1.7.9",
```

Then `npm install`. Both `package.json` and `package-lock.json` appear in the change.

### Example 2 — transitive fixed by parent bump

Finding: `nth-check 1.0.2 → 2.1.1`, transitive.
Path: `react-scripts > @svgr/webpack > ... > nth-check`
Parent remediation supplied: `react-scripts 5.0.0 → 5.0.1`

```diff
 "devDependencies": {
-  "react-scripts": "5.0.0"
+  "react-scripts": "5.0.1"
 }
```

`nth-check` is never named in `package.json`. The lockfile showing the resolved version change is the evidence the fix worked.

### Example 3 — override, no parent bump available

Finding: `minimist 1.2.5 → 1.2.8`, transitive through an unmaintained package with no newer release.

```diff
 "devDependencies": {
   "some-legacy-tool": "3.1.0"
 },
+"overrides": {
+  "minimist": "1.2.8"
+}
```

Report must state: override used because `some-legacy-tool` has no version pulling a clean `minimist`; forces a version the parent did not test against; CVE and date recorded. Requires human review.

### Example 4 — peer conflict on a React 18 repo

Finding: `@some/ui-library 3.2.0 → 4.0.0`. App is on React 18.3.1.

`npm install` fails:
```
npm ERR! peer react@"^19.0.0" from @some/ui-library@4.0.0
```

**Check first** whether an intermediate version widened its peer range rather than dropping 18 — for example `3.9.0` declaring `^18.3.1 || ^19.0.0`. If such a version clears the finding, that is the fix.

If not, escalate:

```
ESCALATED
  @some/ui-library 3.2.0 -> 4.0.0
    reason: 4.0.0 requires peer react ^19.0.0; app is on react 18.3.1.
            No 3.x version clears the finding. Adopting 4.0.0 requires a
            React 19 migration.
    suggested action: plan the React 19 upgrade separately, or evaluate
            replacing this library.
```

Do not force it with `--legacy-peer-deps`.
