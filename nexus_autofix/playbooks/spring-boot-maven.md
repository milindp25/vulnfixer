# Playbook — Spring Boot with Maven

Injected when `.trident/build.yaml` declares `uses: maven`.

---

## Step 0 — Establish which Spring Boot line this repo is on

Read the version from the `<parent>` block, or from the imported BOM if the project does not use `spring-boot-starter-parent`.

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.7</version>
</parent>
```

| Line | Status | What this means for remediation |
|---|---|---|
| **1.x, 2.x** | End of life, no OSS patches | **Escalate everything.** No fix version will exist. Report the repo as being on an unsupported line. |
| **3.0 – 3.4** | Check OSS support status | Bump within the line if patches still ship; otherwise escalate. |
| **3.5** | Final 3.x minor, last on Spring Framework 6.2 | Normal remediation. When 3.5 leaves OSS support, findings here become unfixable. |
| **4.x** | Current — Spring Framework 7, Jakarta EE 11 | Normal remediation, but see the 4.x section below. |

If the project imports `spring-boot-dependencies` in `<dependencyManagement>` rather than using the parent, the line is determined by that import's version. Check both.

**Never migrate between major lines.** 2.x → 3.x and 3.x → 4.x are migration projects. Escalate.

---

## Step 1 — Find where the version actually comes from

`spring-boot-starter-parent` (or the imported BOM) manages the version of several hundred libraries. A dependency declared like this:

```xml
<dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
</dependency>
```

has **no `<version>` element**. Adding one is the wrong fix.

| Situation | How to tell | Go to |
|---|---|---|
| Managed transitive | Not declared in this POM at all | Step 2 |
| Managed direct | Declared with no `<version>` | Step 2, then 3 |
| Multi-module | Version in a parent POM inside this repo | Edit that parent |
| Explicitly versioned | `<version>` literal present | Step 5 |

`./mvnw dependency:tree -Dverbose` shows the resolved graph and why each version won.

---

## Step 2 — Bump the Spring Boot parent version

If a newer patch of the **same minor line** ships the target version, this is the correct fix.

```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.7</version>          <!-- was 3.4.1 -->
    <relativePath/>
</parent>
```

Patch bumps within a minor are always preferred. A minor bump is acceptable if the findings target requires it — note it in your report. A **major** bump is out of scope.

---

## Step 3 — Override the managed version property

When no Boot patch covers the target, override the property the parent uses.

```xml
<properties>
    <java.version>17</java.version>
    <jackson-bom.version>2.17.2</jackson-bom.version>
</properties>
```

### Finding the correct property name

**A wrong property name fails silently.** The build succeeds, nothing changes, and the vulnerability remains. Never guess.

Three ways to get it right, in order of reliability:

1. **The Dependency Versions appendix for your exact Boot version.** Spring publishes a table of every managed library and the property that overrides it, per release. This is authoritative.
2. **`./mvnw help:effective-pom`** — shows the fully resolved POM including every inherited property.
3. **`./mvnw dependency:tree`** before and after, to confirm the version actually changed.

If the component is not in that table, it is not parent-managed. Go to step 4 or 5.

**If you cannot determine the property name, escalate.** Do not guess a plausible-looking one.

---

## Step 4 — `dependencyManagement` entry

When the component is not managed by the parent but appears as a transitive you need to pin:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.apache.commons</groupId>
            <artifactId>commons-text</artifactId>
            <version>1.10.0</version>
            <!-- CVE-2022-42889 — nexus-autofix, 2026-07-28 -->
        </dependency>
    </dependencies>
</dependencyManagement>
```

Always add the comment naming the CVE and the date.

---

## Step 5 — Direct version bump

The component is declared with an explicit `<version>`. Change it.

```xml
<dependency>
    <groupId>org.apache.commons</groupId>
    <artifactId>commons-text</artifactId>
    <version>1.10.0</version>
</dependency>
```

---

## Spring Boot 4.x — what differs

Applies only when the repo is already on 4.x. These are remediation differences, **not** an invitation to migrate anything from 3.x.

**Jackson 3 is the default.** Boot 4 ships Jackson 3 in `spring-boot-starter-json` and `spring-boot-starter-jackson`, using a different package namespace than Jackson 2. A `com.fasterxml.jackson.*` finding on a Boot 4 repo therefore usually points at the **Jackson 2 compatibility path** — either the `spring-boot-jackson2` module or a transitive that still uses Jackson 2. Both remain supported and under dependency management, but under different properties than the Jackson 3 artifacts. Identify which is on the classpath before choosing a property.

**Some 3.x properties no longer exist.** Spring Authorization Server's version, for example, is now controlled through Spring Security's dependency management rather than a dedicated Boot property. If a property you expect is absent from the 4.x appendix, that management moved — find where, or escalate.

**Modules were split and some starters renamed.** War deployments use `spring-boot-starter-tomcat-runtime` in place of `spring-boot-starter-tomcat`. Never rename a starter as part of a vulnerability fix; escalate if a finding appears to require it.

**Baselines:** Java 17 minimum (Java 25 supported), Jakarta EE 11, Servlet 6.1, Spring Framework 7. A build failure on any of these is an environment problem — escalate, do not edit `.trident/build.yaml`.

**Deprecations removed.** Everything deprecated across 3.x is gone in 4.0. A compilation error after a bump may be a removed API rather than anything your change caused. Report it; do not start rewriting source.

---

## Prohibited

- **Adding a `<version>` to a parent-managed dependency.** This desynchronizes that library from the tested set. It works today and breaks confusingly on the next Boot upgrade. Use the property override.
- **Version ranges** — `[1.0,2.0)`, `LATEST`, `RELEASE`.
- **`<exclusions>`** to remove a vulnerable transitive. This drops the class from the classpath and produces a runtime `NoClassDefFoundError`, not a build failure.
- **Editing `.trident/build.yaml`** to change the declared Java version.
- **Any major-line migration** — 2.x → 3.x, 3.x → 4.x.

---

## Escalate when

- The repo is on 1.x or 2.x — no fix versions exist.
- The only clean version requires the next major Boot line.
- The managed property name cannot be determined from the appendix for this Boot version.
- The version comes from a corporate parent POM outside this repository.
- Two findings require conflicting versions of the same component.
- The build fails on a Java version or Servlet baseline.
- A compilation error traces to an API removed in this Boot line rather than to your change.

---

## Worked examples

### Example 1 — direct dependency, patch bump

Finding: `org.apache.commons:commons-text 1.9 → 1.10.0`, explicitly versioned.

```diff
 <dependency>
     <groupId>org.apache.commons</groupId>
     <artifactId>commons-text</artifactId>
-    <version>1.9</version>
+    <version>1.10.0</version>
 </dependency>
```

### Example 2 — managed transitive, fixed by the parent version

Finding: `com.fasterxml.jackson.core:jackson-databind 2.15.3 → 2.17.2`, transitive via `spring-boot-starter-web`. Repo is on Boot 3.4.1.

```diff
 <parent>
     <groupId>org.springframework.boot</groupId>
     <artifactId>spring-boot-starter-parent</artifactId>
-    <version>3.4.1</version>
+    <version>3.4.7</version>
     <relativePath/>
 </parent>
```

No `<dependencies>` change. Verify:
`./mvnw dependency:tree | grep jackson-databind`

### Example 3 — managed, no parent patch available

Finding: `org.yaml:snakeyaml 2.2 → 2.3`. No patch on this minor line ships 2.3.

```diff
 <properties>
     <java.version>17</java.version>
+    <snakeyaml.version>2.3</snakeyaml.version>
 </properties>
```

Verify with `./mvnw help:effective-pom` that the property took effect, then `dependency:tree` that the version changed.

### Example 4 — Boot 4 repo, Jackson 2 compatibility path

Finding: `com.fasterxml.jackson.core:jackson-databind 2.17.0 → 2.18.2` on a repo running Boot 4.x.

Boot 4 defaults to Jackson 3, so this is not the main JSON path. Confirm what pulls Jackson 2:

```
./mvnw dependency:tree -Dincludes=com.fasterxml.jackson.core
```

If it arrives through `spring-boot-jackson2` or a third-party transitive, the fix is the property governing the **Jackson 2** managed version for this Boot line — not the Jackson 3 one. Look it up in the 4.x appendix rather than reusing the 3.x property name.

If the two are entangled, or the finding requires moving off the Jackson 2 compatibility module, escalate.
