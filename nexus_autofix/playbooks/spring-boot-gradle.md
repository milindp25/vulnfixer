# Playbook — Spring Boot with Gradle

Injected when `.trident/build.yaml` declares `uses: gradle`.

---

## Step 0 — Establish which Spring Boot line this repo is on

Read the Boot version from the `plugins` block before anything else. The correct mechanism differs by line, and using a 3.x mechanism on a 4.x repo silently does nothing.

```gradle
plugins {
    id 'org.springframework.boot' version '3.4.7'
}
```

| Line | Status | What this means for remediation |
|---|---|---|
| **1.x, 2.x** | End of life, no OSS patches | **Escalate everything.** No fix version will exist. Report the repo as being on an unsupported line. |
| **3.0 – 3.4** | Check OSS support status | Bump within the line if patches still ship; otherwise escalate. |
| **3.5** | Final 3.x minor, last on Spring Framework 6.2 | Normal remediation. When 3.5 leaves OSS support, findings here become unfixable. |
| **4.x** | Current — Spring Framework 7, Jakarta EE 11 | Normal remediation, but see the 4.x section below. Property names and modules differ. |

**Never migrate between major lines.** 2.x → 3.x and 3.x → 4.x are migration projects, not vulnerability fixes. Escalate.

---

## Step 1 — Find where the version actually comes from

In a Spring Boot project, `spring-boot-dependencies` (the BOM) manages the version of several hundred libraries. A dependency declared like this:

```gradle
implementation 'com.fasterxml.jackson.core:jackson-databind'
```

has **no version in the file at all**. Editing this line to add one is the wrong fix.

| Situation | How to tell | Go to |
|---|---|---|
| BOM-managed transitive | Not declared anywhere in the build file | Step 2 |
| BOM-managed direct | Declared without a version | Step 2, then 3 |
| Version catalog | `gradle/libs.versions.toml` exists and the alias resolves there | Step 4 |
| Explicitly versioned | Version literal present | Step 5 |

`./gradlew dependencies --configuration runtimeClasspath` shows the resolved graph and which version won.

---

## Step 2 — Bump the Spring Boot version

If a newer patch of the **same minor line** ships the target version, this is the correct fix. One line, and you inherit the entire compatibility set Spring tested together.

```gradle
plugins {
    id 'org.springframework.boot' version '3.4.7'   // was 3.4.1
}
```

Patch bumps within a minor (`3.4.1 → 3.4.7`) are always preferred. A minor bump (`3.4.x → 3.5.x`) is acceptable if the findings target requires it — note it in your report. A **major** bump is out of scope.

---

## Step 3 — Override the BOM's version property

When no Boot patch covers the target, override the property the BOM uses.

Groovy DSL:
```gradle
ext['jackson-bom.version'] = '2.17.2'
```

Kotlin DSL:
```kotlin
extra["jackson-bom.version"] = "2.17.2"
```

### Finding the correct property name

**A wrong property name fails silently.** The build succeeds, nothing changes, and the vulnerability remains. Never guess.

Three ways to get it right, in order of reliability:

1. **The Dependency Versions appendix for your exact Boot version.** Spring publishes a table of every managed library and the property that overrides it, per release. This is authoritative.
2. **Inspect the resolved BOM.** `./gradlew dependencies --configuration runtimeClasspath` confirms what version is in play before and after your change.
3. **Read `spring-boot-dependencies` directly** for your version — the properties block lists them all.

If the component is not in that table, it is not BOM-managed. Go to step 4 or 5.

**If you cannot determine the property name, escalate.** Do not guess a plausible-looking one.

---

## Step 4 — Version catalog

If `gradle/libs.versions.toml` exists and the component resolves through it, edit the catalog, not the module file.

```toml
[versions]
jackson = "2.17.2"        # was 2.15.3

[libraries]
jackson-databind = { module = "com.fasterxml.jackson.core:jackson-databind", version.ref = "jackson" }
```

In a multi-module build the catalog is the single source of truth. Editing an individual module's `build.gradle` when a catalog exists creates an inconsistency across modules.

---

## Step 5 — Dependency constraint

Only when the component is **not** BOM-managed and **not** in a catalog.

```gradle
dependencies {
    constraints {
        implementation('org.apache.commons:commons-text:1.10.0') {
            because 'CVE-2022-42889 — nexus-autofix, 2026-07-28'
        }
    }
}
```

Always include `because` naming the CVE and the date. Without it, nobody knows six months later why the constraint exists.

---

## Spring Boot 4.x — what differs

Applies only when the repo is already on 4.x. These are remediation differences, **not** an invitation to migrate anything from 3.x.

**Jackson 3 is the default.** Boot 4 ships Jackson 3 in `spring-boot-starter-json` and `spring-boot-starter-jackson`. Jackson 3 uses a different package namespace than Jackson 2. A `com.fasterxml.jackson.*` finding on a Boot 4 repo therefore usually points at the **Jackson 2 compatibility path** — either the `spring-boot-jackson2` module, or a transitive dependency that still uses Jackson 2. Both remain supported and both are still under dependency management, but they are governed by different properties than the Jackson 3 artifacts. Identify which is actually on the classpath before choosing a property.

**Some 3.x properties no longer exist.** Spring Authorization Server's version, for example, is now controlled through Spring Security's dependency management rather than a dedicated Boot property. If a property you expect is absent from the 4.x appendix, that management moved — find where, or escalate.

**Modules were split.** Boot 4 modularized into smaller jars, and some starters were renamed. War deployments use `spring-boot-starter-tomcat-runtime` in place of `spring-boot-starter-tomcat`. Never rename a starter as part of a vulnerability fix; if a finding appears to require it, escalate.

**Baselines:** Java 17 minimum (Java 25 supported), Jakarta EE 11, Servlet 6.1, Spring Framework 7, Gradle 8.14+ on the 8 line. If a build fails on any of these, it is an environment problem — escalate, do not edit `.trident/build.yaml`.

**Deprecations removed.** Everything deprecated across 3.x is gone in 4.0. A compilation error after a bump may be a removed API rather than anything your change caused. Report it; do not start rewriting source.

---

## Prohibited

- **`resolutionStrategy.force`** — bypasses the BOM invisibly. A later reader cannot see why a version was chosen, and it silently overrides deliberate decisions elsewhere.
- **Adding an explicit version to a BOM-managed dependency.** Writing `implementation 'com.fasterxml.jackson.core:jackson-databind:2.17.2'` desynchronizes that library from the tested set. It works today and breaks on the next Boot upgrade in a way that is very hard to trace.
- **Dynamic versions** — `1.2.+`, `latest.release`, `[1.0,2.0)`.
- **`exclude`** to remove a vulnerable transitive. This drops the class from the classpath and produces a runtime `NoClassDefFoundError`, not a build failure.
- **Editing `.trident/build.yaml`** to change the declared Java version.
- **Any major-line migration** — 2.x → 3.x, 3.x → 4.x. Jakarta namespace changes, modular starter renames, Jackson 3 package moves, Security auto-configuration changes. These are projects, not fixes.

---

## Escalate when

- The repo is on 1.x or 2.x — no fix versions exist.
- The only clean version requires the next major Boot line.
- The BOM property name cannot be determined from the appendix for this Boot version.
- The version comes from a parent POM or shared internal platform outside this repository.
- Two findings require conflicting versions of the same component.
- The build fails on a Java version, Gradle version, or Servlet baseline — that is a toolchain problem.
- A compilation error traces to an API removed in this Boot line rather than to your change.

---

## Worked examples

### Example 1 — direct dependency, patch bump

Finding: `org.apache.commons:commons-text 1.9 → 1.10.0`, direct, not BOM-managed.

```diff
 dependencies {
     implementation 'org.springframework.boot:spring-boot-starter-web'
-    implementation 'org.apache.commons:commons-text:1.9'
+    implementation 'org.apache.commons:commons-text:1.10.0'
 }
```

### Example 2 — BOM-managed transitive, fixed by the Boot version

Finding: `com.fasterxml.jackson.core:jackson-databind 2.15.3 → 2.17.2`, transitive via `spring-boot-starter-web`. Repo is on Boot 3.4.1.

Wrong instinct: add `jackson-databind` as a direct dependency with a version.
Correct fix: the Boot patch that ships it.

```diff
 plugins {
     id 'java'
-    id 'org.springframework.boot' version '3.4.1'
+    id 'org.springframework.boot' version '3.4.7'
     id 'io.spring.dependency-management' version '1.1.7'
 }
```

Nothing in the `dependencies` block changes. Verify:
`./gradlew dependencies --configuration runtimeClasspath | grep jackson-databind`

### Example 3 — BOM-managed, no Boot patch available

Finding: `org.yaml:snakeyaml 2.2 → 2.3`. No patch on this minor line ships 2.3.

```diff
 ext {
     set('springCloudVersion', "2024.0.0")
+    set('snakeyaml.version', "2.3")
 }
```

Or equivalently:

```diff
+ext['snakeyaml.version'] = '2.3'
```

The BOM continues to manage every other library. Only this property is overridden, visibly.

### Example 4 — Boot 4 repo, Jackson 2 compatibility path

Finding: `com.fasterxml.jackson.core:jackson-databind 2.17.0 → 2.18.2` on a repo running Boot 4.x.

Boot 4 defaults to Jackson 3, so this finding is not about the main JSON path. Confirm what is actually pulling Jackson 2:

```
./gradlew dependencies --configuration runtimeClasspath | grep -A2 jackson
```

If it arrives through `spring-boot-jackson2` or a third-party transitive, the fix is the property governing the **Jackson 2** managed version for this Boot line — not the Jackson 3 one. Look it up in the 4.x appendix rather than reusing the 3.x property name.

If the two are entangled, or the finding requires moving off the Jackson 2 compatibility module, escalate — that is a migration decision, not a version bump.
