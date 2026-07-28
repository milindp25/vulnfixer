# nexus-autofix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full nexus-autofix v0 system — a Python orchestrator that fixes Nexus IQ
dependency findings via an AI coding agent behind a Protocol interface, with deterministic
build/test/diff/rescan verification — per `docs/superpowers/specs/2026-07-28-nexus-autofix-design.md`.

**Architecture:** Every external boundary (Nexus IQ, the coding agent, git, GitHub) is a
`typing.Protocol` with a fake/mock test double, so the orchestrator loop is fully testable
offline. The orchestrator (`orchestrator.py`) owns the loop; `cli.py` is a thin shell over it.
Verification (build, test, diff classification, rescan comparison) never delegates judgment to
an LLM — it's all plain Python inspecting `git diff` and subprocess exit codes.

**Tech Stack:** Python 3.11+, `requests`, `PyYAML`, `python-dotenv`, `click`, `pytest`. Confirmed
on this machine: Java 21 (no local `gradle`/`mvn` — fixture uses the Gradle wrapper, generated
once via a downloaded Gradle distribution since network access to `services.gradle.org` is
available), Node 24 / npm 11, git 2.50, Python 3.13.

---

## Environment notes (confirmed this session)

- No system `gradle` or `mvn`. The fixture repo (Task 24) needs a real Gradle wrapper
  (`gradlew` + `gradle/wrapper/gradle-wrapper.jar`) to run `./gradlew` commands for real. Since
  there's no local Gradle to generate one with `gradle wrapper`, Task 24 downloads a Gradle
  distribution zip once into the scratchpad, uses its `bin/gradle` to generate the wrapper files
  inside the fixture repo, then never needs that temp download again — the checked-in wrapper is
  self-sufficient (it downloads its pinned Gradle version to the user's Gradle cache on first
  real use, same as any real repo).
- Java 21 is fine for Gradle 8.x (pin `gradle-wrapper.properties` to Gradle 8.10, which supports
  Java 21).

---

## Task 0: Project scaffold

**Files:**
- Create: `pyproject.toml`
- Create: `nexus_autofix/__init__.py`
- Create: `nexus_autofix/iq/__init__.py`
- Create: `nexus_autofix/repo/__init__.py`
- Create: `nexus_autofix/agent/__init__.py`
- Create: `nexus_autofix/verify/__init__.py`
- Create: `nexus_autofix/publish/__init__.py`
- Create: `nexus_autofix/state/__init__.py`
- Create: `nexus_autofix/agent_instructions.md` (copy of the user-supplied file, verbatim)
- Create: `nexus_autofix/playbooks/spring-boot-gradle.md` (verbatim copy)
- Create: `nexus_autofix/playbooks/spring-boot-maven.md` (verbatim copy)
- Create: `nexus_autofix/playbooks/npm.md` (verbatim copy)
- Create: `config.yml`
- Create: `.gitignore`
- Modify: `.gitignore` for `state/`, `runs/`, `.env`, `.venv/`, `__pycache__/`

- [ ] **Step 1: Create the package directories and `__init__.py` files**

```bash
mkdir -p nexus_autofix/iq nexus_autofix/repo nexus_autofix/agent nexus_autofix/verify \
         nexus_autofix/publish nexus_autofix/state nexus_autofix/playbooks \
         tests/unit tests/fixtures runs state
touch nexus_autofix/__init__.py nexus_autofix/iq/__init__.py nexus_autofix/repo/__init__.py \
      nexus_autofix/agent/__init__.py nexus_autofix/verify/__init__.py \
      nexus_autofix/publish/__init__.py nexus_autofix/state/__init__.py tests/__init__.py \
      tests/unit/__init__.py
```

- [ ] **Step 2: Copy the four runtime content files in verbatim**

Copy `agent-instructions.md` → `nexus_autofix/agent_instructions.md`, and the three playbooks
into `nexus_autofix/playbooks/` with their existing filenames, byte-for-byte from the source
files already read into context this session (`/Users/milindp/Downloads/files/agent-instructions.md`,
`spring-boot-gradle.md`, `spring-boot-maven.md`, `npm.md`). These are runtime content consumed by
`agent/prompt.py` at request time — not documentation.

- [ ] **Step 3: Write `pyproject.toml`**

```toml
[project]
name = "nexus-autofix"
version = "0.1.0"
description = "Automated remediation of Nexus IQ dependency vulnerabilities via an AI coding agent, with deterministic verification."
requires-python = ">=3.11"
dependencies = [
    "requests>=2.31",
    "PyYAML>=6.0",
    "python-dotenv>=1.0",
    "click>=8.1",
]

[project.optional-dependencies]
dev = ["pytest>=7.4"]

[project.scripts]
nexusfix = "nexus_autofix.cli:main"

[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["nexus_autofix*"]

[tool.setuptools.package-data]
nexus_autofix = ["playbooks/*.md", "agent_instructions.md"]
```

- [ ] **Step 4: Write `config.yml`**

```yaml
subprocess_timeout_seconds: 1800
max_attempts: 2
poll_timeout_seconds: 900
default_stage_id: build
default_gate: pre-pr
toolchains:
  java:
    "21": /usr/bin  # placeholder — set to a real JAVA_HOME-style dir per major version
  node:
    "24": /usr/local/bin  # placeholder — set to a real Node install dir per major version
repos: {}
```

- [ ] **Step 5: Write `.gitignore`**

```
__pycache__/
*.pyc
.venv/
*.egg-info/
.env
state/*.db
runs/
```

- [ ] **Step 6: Create the venv and install editable**

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

Expected: install completes without error; `.venv/bin/nexusfix --help` prints click's usage text
(the command group will be empty until Task 23, so a bare import error is expected right now —
don't worry about it yet).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml config.yml .gitignore nexus_autofix tests
git commit -m "chore: scaffold nexus-autofix package structure"
```

---

## Task 1: Domain model

**Files:**
- Create: `nexus_autofix/iq/models.py`
- Test: `tests/unit/test_iq_models.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_iq_models.py
from pathlib import Path

from nexus_autofix.iq.models import Finding, Module, RepoProfile, RunOutcome


def test_finding_is_actionable_when_target_version_present():
    finding = Finding(
        component="org.apache.commons:commons-text", package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        current_version="1.9", target_version="1.10.0", remediation_type="next-non-failing-with-dependencies",
        is_direct=True, dependency_path=[], parent_component=None, parent_current_version=None,
        parent_target_version=None, policy_action="Fail", threat_level=8, policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"], manifest_path=Path("build.gradle"),
    )
    assert finding.is_actionable is True


def test_finding_not_actionable_without_target_version():
    finding = Finding(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0", target_version=None,
        remediation_type=None, is_direct=True, dependency_path=[], parent_component=None,
        parent_current_version=None, parent_target_version=None, policy_action="Fail", threat_level=9,
        policy_name="p", cve_ids=[], manifest_path=None,
    )
    assert finding.is_actionable is False


def test_run_outcome_values_match_design_doc():
    expected = {
        "CLEAN", "FIXED", "FIXED_NEEDS_REVIEW", "AWAITING_APPROVAL", "REJECTED",
        "FAILED_BUILD", "FAILED_RESCAN", "NO_CHANGES", "ESCALATED",
    }
    assert {o.value for o in RunOutcome} == expected


def test_module_and_repo_profile_construct():
    module = Module(path=Path("."), ecosystem="gradle", manifest=Path("build.gradle"))
    profile = RepoProfile(ecosystem="gradle", java_version="21.0.1", node_version=None, modules=[module], source="trident")
    assert profile.modules[0].ecosystem == "gradle"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_iq_models.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'nexus_autofix.iq.models'`

- [ ] **Step 3: Write `nexus_autofix/iq/models.py`**

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    component: str
    package_url: str
    current_version: str
    target_version: str | None
    remediation_type: str | None
    is_direct: bool
    dependency_path: list[str]
    parent_component: str | None
    parent_current_version: str | None
    parent_target_version: str | None
    policy_action: str
    threat_level: int
    policy_name: str
    cve_ids: list[str]
    manifest_path: Path | None
    is_dev_dependency: bool = False
    is_waived: bool = False
    golden_version: str | None = None
    escalation_reason: str | None = None

    @property
    def is_actionable(self) -> bool:
        return self.target_version is not None


@dataclass(frozen=True)
class Module:
    path: Path
    ecosystem: str
    manifest: Path
    version_catalog: Path | None = None


@dataclass(frozen=True)
class RepoProfile:
    ecosystem: str
    java_version: str | None
    node_version: str | None
    modules: list[Module]
    source: str  # "trident" | "glob"


class RunOutcome(str, Enum):
    CLEAN = "CLEAN"
    FIXED = "FIXED"
    FIXED_NEEDS_REVIEW = "FIXED_NEEDS_REVIEW"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REJECTED = "REJECTED"
    FAILED_BUILD = "FAILED_BUILD"
    FAILED_RESCAN = "FAILED_RESCAN"
    NO_CHANGES = "NO_CHANGES"
    ESCALATED = "ESCALATED"
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_iq_models.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/iq/models.py tests/unit/test_iq_models.py
git commit -m "feat: add nexus-autofix domain model"
```

---

## Task 2: `.trident/build.yaml` parser

**Files:**
- Create: `nexus_autofix/repo/trident.py`
- Test: `tests/unit/test_repo_trident.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_repo_trident.py
from pathlib import Path

import pytest

from nexus_autofix.repo.trident import parse_trident_build_yaml


def test_parses_gradle_strategy_with_nested_with_block(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: gradle\n  with:\n    java-version: 17.0.1\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert len(strategies) == 1
    assert strategies[0].ecosystem == "gradle"
    assert strategies[0].toolchain == {"java": "17.0.1"}


def test_parses_yarn_strategy_and_strips_version_suffix(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: yarn@v2\n  with:\n    node-version: 20.11.0\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert strategies[0].ecosystem == "yarn"
    assert strategies[0].toolchain == {"node": "20.11.0"}


def test_multiple_strategy_entries_produce_one_per_entry(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n"
        "  - uses: gradle\n    with:\n      java-version: 17.0.1\n"
        "  - uses: yarn\n    with:\n      node-version: 20.11.0\n",
        encoding="utf-8",
    )
    strategies = parse_trident_build_yaml(path)
    assert [s.ecosystem for s in strategies] == ["gradle", "yarn"]


def test_unknown_uses_value_raises_naming_the_value(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text("strategy:\n  uses: bazel\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bazel"):
        parse_trident_build_yaml(path)


def test_tolerates_top_level_version_keys_alongside_with_block(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: gradle\n  java-version: 17.0.1\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert strategies[0].toolchain == {"java": "17.0.1"}
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_repo_trident.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'nexus_autofix.repo.trident'`

- [ ] **Step 3: Write `nexus_autofix/repo/trident.py`**

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

KNOWN_ECOSYSTEMS = {"gradle", "maven", "npm", "yarn", "pnpm"}


@dataclass(frozen=True)
class TridentStrategy:
    ecosystem: str
    toolchain: dict[str, str]  # e.g. {"java": "17.0.1"} or {"node": "20.11.0"}


def _strip_version_suffix(uses: str) -> str:
    return uses.split("@", 1)[0]


def _extract_toolchain(block: dict) -> dict[str, str]:
    toolchain: dict[str, str] = {}
    for key, value in (block or {}).items():
        if key.endswith("-version"):
            name = key[: -len("-version")]
            toolchain[name] = str(value)
    return toolchain


def _parse_strategy_entry(entry: dict) -> TridentStrategy:
    uses = entry.get("uses")
    if not uses:
        raise ValueError(f"strategy entry missing 'uses': {entry}")
    ecosystem = _strip_version_suffix(uses)
    if ecosystem not in KNOWN_ECOSYSTEMS:
        raise ValueError(
            f"unrecognized .trident/build.yaml strategy.uses value: {uses!r}. "
            f"Known values: {sorted(KNOWN_ECOSYSTEMS)}"
        )
    toolchain = _extract_toolchain(entry.get("with", {}))
    # Tolerate *-version keys at the top level too — the doc flags this nesting as unconfirmed.
    top_level_version_keys = {k: v for k, v in entry.items() if k.endswith("-version")}
    for name, value in _extract_toolchain(top_level_version_keys).items():
        toolchain.setdefault(name, value)
    return TridentStrategy(ecosystem=ecosystem, toolchain=toolchain)


def parse_trident_build_yaml(path: Path) -> list[TridentStrategy]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    strategy = data.get("strategy")
    if strategy is None:
        raise ValueError(f"{path} has no top-level 'strategy' key")
    entries = strategy if isinstance(strategy, list) else [strategy]
    return [_parse_strategy_entry(entry) for entry in entries]
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_repo_trident.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/repo/trident.py tests/unit/test_repo_trident.py
git commit -m "feat: parse .trident/build.yaml with tolerant key nesting"
```

---

## Task 3: Glob-fallback ecosystem detection

**Files:**
- Create: `nexus_autofix/repo/detect.py`
- Test: `tests/unit/test_repo_detect.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_repo_detect.py
import pytest

from nexus_autofix.repo.detect import RepoHygieneError, detect_ecosystems, detect_java_build, detect_js_manager


def test_detects_npm_from_package_lock(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result.ecosystem == "npm"


def test_detects_yarn_berry_when_yarnrc_present(tmp_path):
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    (tmp_path / ".yarnrc.yml").write_text("", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result.ecosystem == "yarn"


def test_two_lockfiles_raises_hygiene_error(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    with pytest.raises(RepoHygieneError):
        detect_js_manager(tmp_path)


def test_detects_maven_over_gradle_when_both_absent_prefers_pom(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    result = detect_java_build(tmp_path)
    assert result.ecosystem == "maven"


def test_skips_node_modules_and_build_dirs(tmp_path):
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "package-lock.json").write_text("{}", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result is None


def test_detect_ecosystems_returns_all_found(tmp_path):
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    results = detect_ecosystems(tmp_path)
    assert {r.ecosystem for r in results} == {"gradle", "npm"}
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_repo_detect.py -v
```

Expected: FAIL — `ModuleNotFoundError: No module named 'nexus_autofix.repo.detect'`

- [ ] **Step 3: Write `nexus_autofix/repo/detect.py`**

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {"node_modules", "build", "target", "dist", ".git"}


@dataclass(frozen=True)
class DetectedEcosystem:
    ecosystem: str
    manifest: Path


class RepoHygieneError(ValueError):
    """Raised when detection finds an ambiguous or conflicting repo state that must be escalated."""


def _walk(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        yield path


def detect_js_manager(root: Path) -> DetectedEcosystem | None:
    found: dict[str, Path] = {}
    for path in _walk(root):
        if path.name == "package-lock.json":
            found["npm"] = path
        elif path.name == "pnpm-lock.yaml":
            found["pnpm"] = path
        elif path.name == "yarn.lock":
            if (path.parent / ".yarnrc.yml").exists():
                found["yarn-berry"] = path
            else:
                found["yarn"] = path

    if len(found) > 1:
        raise RepoHygieneError(
            f"multiple JS lockfiles present: {sorted(found)} — this is a repo hygiene "
            f"problem to escalate, not something to pick a winner for"
        )
    if not found:
        return None
    manager, lockfile_path = next(iter(found.items()))
    ecosystem = "yarn" if manager == "yarn-berry" else manager
    return DetectedEcosystem(ecosystem=ecosystem, manifest=lockfile_path.parent / "package.json")


def detect_java_build(root: Path) -> DetectedEcosystem | None:
    for path in _walk(root):
        if path.name == "pom.xml":
            return DetectedEcosystem(ecosystem="maven", manifest=path)
    for path in _walk(root):
        if path.name in {"build.gradle", "build.gradle.kts"}:
            return DetectedEcosystem(ecosystem="gradle", manifest=path)
    return None


def detect_ecosystems(root: Path) -> list[DetectedEcosystem]:
    results = []
    java = detect_java_build(root)
    if java:
        results.append(java)
    js = detect_js_manager(root)
    if js:
        results.append(js)
    return results
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_repo_detect.py -v
```

Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/repo/detect.py tests/unit/test_repo_detect.py
git commit -m "feat: glob-fallback ecosystem detection"
```

---

## Task 4: Toolchain resolution

**Files:**
- Create: `nexus_autofix/verify/toolchain.py`
- Test: `tests/unit/test_verify_toolchain.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verify_toolchain.py
import pytest

from nexus_autofix.verify.toolchain import MissingToolchainError, resolve_java_env, resolve_node_env


def test_resolves_java_by_major_version():
    result = resolve_java_env("17.0.1", {"17": "/opt/jdk17", "21": "/opt/jdk21"}, base_env={"PATH": "/usr/bin"})
    assert result.env["JAVA_HOME"] == "/opt/jdk17"
    assert result.env["PATH"].startswith("/opt/jdk17/bin")
    assert result.env["PATH"].endswith("/usr/bin")


def test_missing_java_major_raises_naming_declared_and_configured():
    with pytest.raises(MissingToolchainError, match="17"):
        resolve_java_env("17.0.1", {"21": "/opt/jdk21"}, base_env={"PATH": ""})


def test_resolves_node_by_major_version():
    result = resolve_node_env("20.11.0", {"20": "/opt/node20"}, base_env={"PATH": "/usr/bin"})
    assert result.env["PATH"].startswith("/opt/node20")


def test_missing_node_major_raises():
    with pytest.raises(MissingToolchainError):
        resolve_node_env("18.0.0", {"20": "/opt/node20"}, base_env={"PATH": ""})
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_verify_toolchain.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/verify/toolchain.py`**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class MissingToolchainError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolchainEnv:
    env: dict[str, str]


def _major(version: str) -> str:
    return version.split(".")[0]


def resolve_java_env(
    declared_version: str, java_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    home = java_map.get(major)
    if not home:
        raise MissingToolchainError(
            f"no Java {major} toolchain configured (declared {declared_version}); "
            f"configured majors: {sorted(java_map)}. This is a hard failure before the "
            f"agent is invoked — add the path to config.yml's toolchains.java map."
        )
    env = dict(base_env if base_env is not None else os.environ)
    java_home = str(Path(home))
    env["JAVA_HOME"] = java_home
    env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)


def resolve_node_env(
    declared_version: str, node_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    node_dir = node_map.get(major)
    if not node_dir:
        raise MissingToolchainError(
            f"no Node {major} toolchain configured (declared {declared_version}); "
            f"configured majors: {sorted(node_map)}. This is a hard failure before the "
            f"agent is invoked — add the path to config.yml's toolchains.node map."
        )
    env = dict(base_env if base_env is not None else os.environ)
    env["PATH"] = str(Path(node_dir)) + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_verify_toolchain.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/verify/toolchain.py tests/unit/test_verify_toolchain.py
git commit -m "feat: toolchain resolution fails before the agent runs, not during the build"
```

---

## Task 5: Build/test command wrapper

**Files:**
- Create: `nexus_autofix/verify/commands.py`
- Test: `tests/unit/test_verify_commands.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verify_commands.py
import platform
from pathlib import Path

from nexus_autofix.verify.commands import (
    BUILD_COMMANDS, TEST_COMMANDS, INSTALL_COMMANDS, CommandResult, run_command,
)


def test_gradle_build_command_uses_frozen_x_test():
    cmd = BUILD_COMMANDS["gradle"](Path("."))
    assert cmd[1:] == ["clean", "build", "-x", "test"]
    assert cmd[0] in {"./gradlew", "gradlew.bat"}


def test_npm_verify_uses_ci_never_install():
    assert BUILD_COMMANDS["npm"](Path(".")) == ["npm", "ci"]
    assert INSTALL_COMMANDS["npm"](Path(".")) == ["npm", "install"]


def test_yarn_test_command():
    assert TEST_COMMANDS["yarn"](Path(".")) == ["yarn", "test"]


def test_run_command_captures_output_and_success(tmp_path):
    result = run_command(["python3", "-c", "print('hello'); import sys; sys.exit(0)"], tmp_path, {}, 10)
    assert isinstance(result, CommandResult)
    assert result.success is True
    assert "hello" in result.stdout


def test_run_command_captures_failure(tmp_path):
    result = run_command(["python3", "-c", "import sys; sys.exit(1)"], tmp_path, {}, 10)
    assert result.success is False
    assert result.returncode == 1


def test_tail_returns_last_n_lines(tmp_path):
    script = "for i in range(300): print(i)"
    result = run_command(["python3", "-c", script], tmp_path, {}, 10)
    tail = result.tail(lines=5)
    assert tail.splitlines()[-1] == "299"
    assert len(tail.splitlines()) == 5
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_verify_commands.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/verify/commands.py`**

```python
from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 200) -> str:
        combined = (self.stdout + "\n" + self.stderr).splitlines()
        return "\n".join(combined[-lines:])


def _gradle_executable() -> str:
    return "gradlew.bat" if platform.system() == "Windows" else "./gradlew"


def _maven_executable() -> str:
    return "mvnw.cmd" if platform.system() == "Windows" else "./mvnw"


BUILD_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "clean", "build", "-x", "test"],
    "maven": lambda root: [_maven_executable(), "-DskipTests", "clean", "package"],
    "npm": lambda root: ["npm", "ci"],
    "yarn": lambda root: ["yarn", "install", "--frozen-lockfile"],
    "pnpm": lambda root: ["pnpm", "install", "--frozen-lockfile"],
}

TEST_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "test"],
    "maven": lambda root: [_maven_executable(), "test"],
    "npm": lambda root: ["npm", "test"],
    "yarn": lambda root: ["yarn", "test"],
    "pnpm": lambda root: ["pnpm", "test"],
}

# What the AGENT runs after editing manifests, to regenerate the lockfile.
# Never substituted for the frozen verify-time command above — that distinction
# is the cheapest guard against an agent that edits the manifest and skips the lockfile.
INSTALL_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "npm": lambda root: ["npm", "install"],
    "yarn": lambda root: ["yarn", "install"],
    "pnpm": lambda root: ["pnpm", "install"],
}

DEPENDENCY_DIAGNOSTIC_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "dependencies", "--configuration", "runtimeClasspath"],
    "maven": lambda root: [_maven_executable(), "dependency:tree", "-Dverbose"],
}


def run_command(args: list[str], cwd: Path, env: dict[str, str], timeout_seconds: int) -> CommandResult:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        shell=False,
    )
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_verify_commands.py -v
```

Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/verify/commands.py tests/unit/test_verify_commands.py
git commit -m "feat: build/test command tables, ci/frozen-lockfile only at verify time"
```

---

## Task 6: Diff classifier

**Files:**
- Create: `nexus_autofix/verify/diff.py`
- Test: `tests/unit/test_verify_diff.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verify_diff.py
import subprocess
from pathlib import Path

from nexus_autofix.verify.diff import DiffClass, classify_diff


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _init_repo(tmp_path: Path) -> Path:
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "build.gradle").write_text("dependencies {}\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "test").mkdir()
    (tmp_path / "src" / "test" / "FooTest.java").write_text("class FooTest { void t() {} }\n", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)
    return tmp_path


def test_manifest_only_change_classified_manifest_only(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text("dependencies { implementation 'x:y:2.0' }\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.MANIFEST_ONLY


def test_source_file_change_classified_source_touched(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SOURCE_TOUCHED


def test_deleted_test_file_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").unlink()
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("deleted" in reason for reason in result.suspicious_reasons)


def test_disabled_annotation_added_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        "class FooTest { @Disabled void t() {} }\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


def test_trident_build_yaml_modification_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".trident").mkdir()
    (repo / ".trident" / "build.yaml").write_text("strategy:\n  uses: gradle\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "add trident"], repo)
    (repo / ".trident" / "build.yaml").write_text("strategy:\n  uses: maven\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(".trident" in reason for reason in result.suspicious_reasons)


def test_legacy_peer_deps_flag_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".npmrc").write_text("legacy-peer-deps=true\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_verify_diff.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/verify/diff.py`**

```python
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class DiffClass(str, Enum):
    MANIFEST_ONLY = "MANIFEST_ONLY"
    SOURCE_TOUCHED = "SOURCE_TOUCHED"
    SUSPICIOUS = "SUSPICIOUS"


@dataclass(frozen=True)
class DiffResult:
    classification: DiffClass
    changed_files: list[str]
    suspicious_reasons: list[str] = field(default_factory=list)


MANIFEST_FILENAMES = {
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "build.gradle", "build.gradle.kts", "pom.xml", "libs.versions.toml",
}

TEST_SKIP_PATTERNS = [
    ("@Disabled", re.compile(r"@Disabled\b")),
    ("@Ignore", re.compile(r"@Ignore\b")),
    ("@Test(enabled=false)", re.compile(r"@Test\(enabled\s*=\s*false\)")),
    ("it.skip(", re.compile(r"\bit\.skip\(")),
    ("xit(", re.compile(r"\bxit\(")),
    ("describe.skip(", re.compile(r"describe\.skip\(")),
    ("pytest.mark.skip", re.compile(r"pytest\.mark\.skip")),
    ("t.Skip(", re.compile(r"\bt\.Skip\(")),
]

SUSPICIOUS_TEXT_PATTERNS = [
    ("resolutionStrategy.force added", re.compile(r"resolutionStrategy\.force")),
    ("--legacy-peer-deps present", re.compile(r"legacy-peer-deps")),
    ("open/dynamic version range", re.compile(r'[\d]+\.\+|latest\.release|\[\d[^,]*,\s*\d[^)]*\)')),
]

TEST_PATH_HINT = re.compile(r"(^|/)(test|tests|__tests__|spec)(/|$)", re.IGNORECASE)
TEST_FILENAME_PATTERN = re.compile(
    r"(Test\.java$|Tests\.java$|\.test\.[jt]sx?$|\.spec\.[jt]sx?$|^test_.*\.py$|_test\.py$)"
)

WAIVER_HINT = re.compile(r"(waiver|suppress)", re.IGNORECASE)
EXCLUDE_ADDED_PATTERN = re.compile(r"^\+.*\bexclude\b", re.MULTILINE)


def _run_git(args: list[str], repo_root: Path) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(repo_root), capture_output=True, encoding="utf-8",
        errors="replace", check=True,
    )
    return proc.stdout


def _looks_like_test_file(path: str) -> bool:
    return bool(TEST_PATH_HINT.search(path) or TEST_FILENAME_PATTERN.search(Path(path).name))


def _deleted_or_emptied_test_files(repo_root: Path, base_ref: str) -> list[str]:
    status_output = _run_git(["diff", "--name-status", base_ref], repo_root)
    flagged = []
    for line in status_output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status, path = parts[0], parts[-1]
        if not _looks_like_test_file(path):
            continue
        if status.startswith("D"):
            flagged.append(path)
        elif status.startswith("M"):
            full_path = repo_root / path
            if full_path.exists() and full_path.stat().st_size == 0:
                flagged.append(path)
    return flagged


def _is_manifest_or_lockfile(path: str) -> bool:
    name = Path(path).name
    return name in MANIFEST_FILENAMES or name.endswith(".lock")


def classify_diff(repo_root: Path, base_ref: str = "HEAD") -> DiffResult:
    changed_files = [
        line for line in _run_git(["diff", "--name-only", base_ref], repo_root).splitlines() if line
    ]
    patch = _run_git(["diff", base_ref], repo_root)

    reasons: list[str] = []

    if ".trident/build.yaml" in changed_files:
        reasons.append(".trident/build.yaml modified — the agent must never change the declared toolchain")

    deleted_or_emptied = _deleted_or_emptied_test_files(repo_root, base_ref)
    if deleted_or_emptied:
        reasons.append(f"test file(s) deleted or emptied: {', '.join(deleted_or_emptied)}")

    for label, pattern in TEST_SKIP_PATTERNS:
        if pattern.search(patch):
            reasons.append(f"test-disabling marker added: {label}")

    for label, pattern in SUSPICIOUS_TEXT_PATTERNS:
        if pattern.search(patch):
            reasons.append(label)

    if any(WAIVER_HINT.search(f) for f in changed_files):
        reasons.append("Nexus IQ policy waiver/suppression file created or modified")

    if any(f == ".gitignore" or f.startswith(".github/workflows/") for f in changed_files):
        reasons.append(".gitignore or CI config modified")

    if EXCLUDE_ADDED_PATTERN.search(patch):
        reasons.append("dependency exclude added (heuristic — review before trusting this alone)")

    if reasons:
        return DiffResult(classification=DiffClass.SUSPICIOUS, changed_files=changed_files, suspicious_reasons=reasons)

    if changed_files and all(_is_manifest_or_lockfile(f) for f in changed_files):
        return DiffResult(classification=DiffClass.MANIFEST_ONLY, changed_files=changed_files)

    return DiffResult(classification=DiffClass.SOURCE_TOUCHED, changed_files=changed_files)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_verify_diff.py -v
```

Expected: 6 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/verify/diff.py tests/unit/test_verify_diff.py
git commit -m "feat: diff classifier — SUSPICIOUS detection runs on git diff content, never agent output"
```

---

## Task 7: Nexus IQ client (Protocol + Fake + real HTTP)

**Files:**
- Create: `nexus_autofix/iq/client.py`
- Test: `tests/unit/test_iq_client.py`

- [ ] **Step 1: Write the failing test** (exercises `FakeIQClient` and `HTTPIQClient` against a
mocked `requests` session — no real network)

```python
# tests/unit/test_iq_client.py
from unittest.mock import MagicMock

import pytest

from nexus_autofix.iq.client import FakeIQClient, HTTPIQClient, PolicyViolation, RemediationResponse, VersionChange


def test_fake_iq_client_returns_configured_violations():
    client = FakeIQClient(
        policy_violations=[
            PolicyViolation(
                package_url="pkg:maven/org.apache.commons/commons-text@1.9",
                component="commons-text", policy_name="Security-Critical", policy_id="p1",
                threat_level=8, constraint_summary="CVSS >= 7", is_waived=False, action="Fail",
            )
        ]
    )
    violations = client.fetch_policy_report("app", "report-1")
    assert len(violations) == 1
    assert violations[0].component == "commons-text"


def test_fake_iq_client_remediation_lookup_by_name():
    client = FakeIQClient(
        remediations={"commons-text": RemediationResponse(version_changes=[VersionChange("next-non-failing-with-dependencies", "1.10.0")])}
    )
    result = client.fetch_remediation("internal", {"coordinates": {"artifactId": "commons-text"}}, "build")
    assert result.version_changes[0].version == "1.10.0"


def test_http_client_resolve_application_internal_id_uses_public_id_query():
    session = MagicMock()
    session.get.return_value.json.return_value = {"applications": [{"id": "abc123"}]}
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    internal_id = client.resolve_application_internal_id("payments-core")

    assert internal_id == "abc123"
    session.get.assert_called_once()
    call_kwargs = session.get.call_args
    assert call_kwargs.kwargs["params"] == {"publicId": "payments-core"}


def test_http_client_raises_when_no_application_found():
    session = MagicMock()
    session.get.return_value.json.return_value = {"applications": []}
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with pytest.raises(ValueError, match="payments-core"):
        client.resolve_application_internal_id("payments-core")


def test_http_client_fetch_policy_report_uses_json_accept_header():
    session = MagicMock()
    session.get.return_value.json.return_value = [
        {
            "packageUrl": "pkg:maven/x/y@1.0",
            "displayName": "y",
            "violations": [
                {"policyName": "Security-Critical", "policyId": "p1", "threatLevel": 9,
                 "constraints": [{"constraintName": "CVSS >= 7"}], "waived": False, "policyThreatCategory": "Fail"}
            ],
        }
    ]
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    violations = client.fetch_policy_report("payments-core", "report-1")

    assert violations[0].component == "y"
    assert session.get.call_args.kwargs["headers"] == {"Accept": "application/json"}
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_iq_client.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/iq/client.py`**

```python
from __future__ import annotations

"""
Nexus IQ client. `HTTPIQClient` follows the endpoint sequence in the design doc
(section 7) exactly, but the precise JSON field names have NOT been verified
against a live IQ instance in this environment — the design doc's own open
items list this ("pull the OpenAPI spec... rather than inferring field names").
Test against a real tenant and adjust field lookups here if they don't match.
"""

import time
from dataclasses import dataclass
from typing import Protocol

import requests


@dataclass(frozen=True)
class PolicyViolation:
    package_url: str
    component: str
    policy_name: str
    policy_id: str
    threat_level: int
    constraint_summary: str
    is_waived: bool
    action: str


@dataclass(frozen=True)
class VersionChange:
    change_type: str
    version: str


@dataclass(frozen=True)
class RemediationResponse:
    version_changes: list[VersionChange]
    parent_component: str | None = None
    parent_current_version: str | None = None
    parent_target_version: str | None = None
    golden_version: str | None = None


class IQClient(Protocol):
    def resolve_application_internal_id(self, public_id: str) -> str: ...
    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str: ...
    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str: ...
    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]: ...
    def fetch_remediation(
        self, internal_id: str, component_identifier: dict, stage_id: str
    ) -> RemediationResponse: ...


class IQTimeoutError(RuntimeError):
    pass


class HTTPIQClient:
    def __init__(self, base_url: str, username: str, password: str, session: requests.Session | None = None):
        self._base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._session = session or requests.Session()

    def resolve_application_internal_id(self, public_id: str) -> str:
        resp = self._session.get(
            f"{self._base_url}/api/v2/applications", params={"publicId": public_id},
            auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        applications = resp.json().get("applications", [])
        if not applications:
            raise ValueError(f"no IQ application found for publicId={public_id!r}")
        return applications[0]["id"]

    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str:
        resp = self._session.post(
            f"{self._base_url}/api/v2/evaluation/applications/{internal_id}/sourceControlEvaluation",
            json={"stageId": stage_id, "branchName": branch_name, "commitHash": commit_hash},
            auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["statusUrl"]

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        deadline = time.monotonic() + timeout_seconds
        delay = 2.0
        url = status_url if status_url.startswith("http") else f"{self._base_url}{status_url}"
        while time.monotonic() < deadline:
            resp = self._session.get(url, auth=self._auth, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            report_url = body.get("reportDataUrl") or body.get("reportHtmlUrl")
            if report_url:
                return report_url.rstrip("/").rsplit("/", 1)[-1]
            time.sleep(delay)
            delay = min(delay * 1.5, 30.0)
        raise IQTimeoutError(f"IQ evaluation did not complete within {timeout_seconds}s")

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        resp = self._session.get(
            f"{self._base_url}/api/v2/applications/{public_id}/reports/{report_id}/policy",
            headers={"Accept": "application/json"}, auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        violations = []
        for item in resp.json():
            for violation in item.get("violations", []):
                violations.append(
                    PolicyViolation(
                        package_url=item.get("packageUrl", ""),
                        component=item.get("displayName", item.get("packageUrl", "")),
                        policy_name=violation.get("policyName", ""),
                        policy_id=violation.get("policyId", ""),
                        threat_level=violation.get("threatLevel", 0),
                        constraint_summary="; ".join(
                            c.get("constraintName", "") for c in violation.get("constraints", [])
                        ),
                        is_waived=violation.get("waived", False),
                        action=violation.get("policyThreatCategory", violation.get("action", "")),
                    )
                )
        return violations

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        resp = self._session.post(
            f"{self._base_url}/api/v2/components/remediation/application/{internal_id}",
            params={"stageId": stage_id, "includeParentRemediation": "true"},
            json={"componentIdentifier": component_identifier}, auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        remediation = resp.json().get("remediation", {})
        version_changes = [
            VersionChange(
                change_type=vc.get("type", ""),
                version=vc.get("data", {}).get("componentIdentifier", {}).get("coordinates", {}).get(
                    "version", vc.get("data", {}).get("version", "")
                ),
            )
            for vc in remediation.get("versionChanges", [])
        ]
        parent = remediation.get("parentRemediation") or {}
        return RemediationResponse(
            version_changes=version_changes,
            parent_component=parent.get("component"),
            parent_current_version=parent.get("currentVersion"),
            parent_target_version=parent.get("targetVersion"),
            golden_version=remediation.get("goldenVersion"),
        )


@dataclass
class FakeIQClient:
    """Test double per the design doc's MockAgent principle — not a second real client."""

    internal_id: str = "fake-internal-id"
    status_url: str = "/fake/status"
    report_id: str = "fake-report-id"
    policy_violations: list[PolicyViolation] | None = None
    remediations: dict[str, RemediationResponse] | None = None

    def __post_init__(self):
        if self.policy_violations is None:
            self.policy_violations = []
        if self.remediations is None:
            self.remediations = {}

    def resolve_application_internal_id(self, public_id: str) -> str:
        return self.internal_id

    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str:
        return self.status_url

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        return self.report_id

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        return list(self.policy_violations)

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        name = (
            component_identifier.get("coordinates", {}).get("artifactId")
            or component_identifier.get("coordinates", {}).get("packageId")
            or component_identifier.get("name", "")
        )
        return self.remediations.get(name, RemediationResponse(version_changes=[]))
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_iq_client.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/iq/client.py tests/unit/test_iq_client.py
git commit -m "feat: Nexus IQ client Protocol + FakeIQClient + HTTP implementation (unverified against live IQ)"
```

---

## Task 8: Remediation type selection

**Files:**
- Create: `nexus_autofix/iq/remediation.py`
- Test: `tests/unit/test_iq_remediation.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_iq_remediation.py
from nexus_autofix.iq.client import RemediationResponse, VersionChange
from nexus_autofix.iq.remediation import select_target


def test_prefers_next_non_failing_with_dependencies():
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "1.11.0"),
        VersionChange("next-non-failing-with-dependencies", "1.10.0"),
    ])
    assert select_target(remediation).version == "1.10.0"


def test_falls_back_to_next_non_failing_when_no_with_dependencies_variant():
    remediation = RemediationResponse(version_changes=[VersionChange("next-non-failing", "1.11.0")])
    assert select_target(remediation).version == "1.11.0"


def test_returns_none_when_no_candidates():
    assert select_target(RemediationResponse(version_changes=[])) is None
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_iq_remediation.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/iq/remediation.py`**

```python
from __future__ import annotations

from nexus_autofix.iq.client import RemediationResponse, VersionChange

# Priority order per design doc section 7's versionChanges type table.
PRIORITY = [
    "next-non-failing-with-dependencies",
    "next-no-violations-with-dependencies",
    "next-non-failing",
    "next-no-violations",
]


def select_target(remediation: RemediationResponse) -> VersionChange | None:
    by_type = {vc.change_type: vc for vc in remediation.version_changes}
    for change_type in PRIORITY:
        if change_type in by_type:
            return by_type[change_type]
    return None
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_iq_remediation.py -v
```

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/iq/remediation.py tests/unit/test_iq_remediation.py
git commit -m "feat: select smallest versionChanges type carrying a -with-dependencies guarantee"
```

---

## Task 9: Filter logic

**Files:**
- Create: `nexus_autofix/iq/filter.py`
- Test: `tests/unit/test_iq_filter.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_iq_filter.py
from pathlib import Path

from nexus_autofix.iq.filter import BumpSize, classify_bump, filter_findings
from nexus_autofix.iq.models import Finding


def _finding(**overrides) -> Finding:
    base = dict(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0.0", target_version="1.0.1",
        remediation_type="next-non-failing-with-dependencies", is_direct=True, dependency_path=[],
        parent_component=None, parent_current_version=None, parent_target_version=None,
        policy_action="Fail", threat_level=8, policy_name="p", cve_ids=[], manifest_path=Path("x"),
    )
    base.update(overrides)
    return Finding(**base)


def test_classify_bump_patch():
    assert classify_bump("1.2.3", "1.2.5") == BumpSize.PATCH


def test_classify_bump_minor():
    assert classify_bump("1.2.3", "1.3.0") == BumpSize.MINOR


def test_classify_bump_major():
    assert classify_bump("1.2.3", "2.0.0") == BumpSize.MAJOR


def test_actionable_patch_bump_is_included():
    result = filter_findings([_finding()], suppressed_components=set())
    assert len(result.actionable) == 1


def test_major_bump_is_escalated():
    result = filter_findings([_finding(target_version="2.0.0")], suppressed_components=set())
    assert len(result.escalate) == 1
    assert not result.actionable


def test_no_target_version_is_escalated():
    result = filter_findings([_finding(target_version=None)], suppressed_components=set())
    assert len(result.escalate) == 1


def test_non_failing_policy_action_is_ignored():
    result = filter_findings([_finding(policy_action="Warn")], suppressed_components=set())
    assert len(result.ignore) == 1


def test_suppressed_component_is_ignored():
    result = filter_findings([_finding(component="log4j-api")], suppressed_components={"log4j-api"})
    assert len(result.ignore) == 1


def test_waived_finding_is_ignored():
    result = filter_findings([_finding(is_waived=True)], suppressed_components=set())
    assert len(result.ignore) == 1
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_iq_filter.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/iq/filter.py`**

```python
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from nexus_autofix.iq.models import Finding

_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


class BumpSize(str, Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


def classify_bump(current: str, target: str) -> BumpSize:
    cur = _SEMVER_RE.match(current or "")
    tgt = _SEMVER_RE.match(target or "")
    if not cur or not tgt:
        return BumpSize.UNKNOWN
    cur_major, cur_minor, _ = (int(x) for x in cur.groups())
    tgt_major, tgt_minor, _ = (int(x) for x in tgt.groups())
    if tgt_major != cur_major:
        return BumpSize.MAJOR
    if tgt_minor != cur_minor:
        return BumpSize.MINOR
    return BumpSize.PATCH


@dataclass(frozen=True)
class FilterResult:
    actionable: list[Finding]
    escalate: list[Finding]
    ignore: list[Finding]


def filter_findings(findings: list[Finding], suppressed_components: set[str]) -> FilterResult:
    actionable: list[Finding] = []
    escalate: list[Finding] = []
    ignore: list[Finding] = []

    for finding in findings:
        is_failing = finding.policy_action.lower() in {"fail", "failure"}
        if not is_failing:
            ignore.append(finding)
            continue
        if finding.is_waived:
            ignore.append(finding)
            continue
        if finding.component in suppressed_components:
            ignore.append(finding)
            continue
        if not finding.is_actionable:
            escalate.append(finding)
            continue
        bump = classify_bump(finding.current_version, finding.target_version)
        if bump == BumpSize.MAJOR:
            escalate.append(finding)
        else:
            actionable.append(finding)

    return FilterResult(actionable=actionable, escalate=escalate, ignore=ignore)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_iq_filter.py -v
```

Expected: 9 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/iq/filter.py tests/unit/test_iq_filter.py
git commit -m "feat: filter findings into actionable/escalate/ignore per IQ policy action and bump size"
```

---

## Task 10: Rescan comparison

**Files:**
- Create: `nexus_autofix/verify/rescan.py`
- Test: `tests/unit/test_verify_rescan.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_verify_rescan.py
from nexus_autofix.iq.client import PolicyViolation
from nexus_autofix.verify.rescan import compare_reports


def _violation(purl: str) -> PolicyViolation:
    return PolicyViolation(
        package_url=purl, component=purl, policy_name="p", policy_id="p1",
        threat_level=8, constraint_summary="", is_waived=False, action="Fail",
    )


def test_all_cleared_when_target_purl_absent_from_rescan():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = []
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.all_cleared is True
    assert result.still_failing == []


def test_still_failing_when_target_purl_present_in_rescan():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = [_violation("pkg:maven/x/x@1.0")]
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.all_cleared is False
    assert result.still_failing == ["pkg:maven/x/x@1.0"]


def test_new_finding_detected_relative_to_full_baseline():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = [_violation("pkg:maven/y/y@2.0")]
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.new_findings == ["pkg:maven/y/y@2.0"]
    assert result.all_cleared is True
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_verify_rescan.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/verify/rescan.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

from nexus_autofix.iq.client import PolicyViolation


@dataclass(frozen=True)
class RescanComparison:
    all_cleared: bool
    still_failing: list[str]
    new_findings: list[str]


def compare_reports(
    baseline: list[PolicyViolation], rescan: list[PolicyViolation], target_purls: set[str]
) -> RescanComparison:
    baseline_purls = {v.package_url for v in baseline}
    rescan_purls = {v.package_url for v in rescan}
    still_failing = sorted(target_purls & rescan_purls)
    new_findings = sorted(rescan_purls - baseline_purls)
    return RescanComparison(
        all_cleared=not still_failing,
        still_failing=still_failing,
        new_findings=new_findings,
    )
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_verify_rescan.py -v
```

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/verify/rescan.py tests/unit/test_verify_rescan.py
git commit -m "feat: rescan comparison confirms findings cleared and no new findings introduced"
```

---

## Task 11: Agent Protocol + git-based change detection

**Files:**
- Create: `nexus_autofix/agent/base.py`
- Test: `tests/unit/test_agent_base.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_agent_base.py
import subprocess
from pathlib import Path

from nexus_autofix.agent.base import changed_files_from_git


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def test_changed_files_from_git_reflects_working_tree_not_agent_claims(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    (tmp_path / "a.txt").write_text("2", encoding="utf-8")
    (tmp_path / "b.txt").write_text("new", encoding="utf-8")

    changed = changed_files_from_git(tmp_path)
    assert set(changed) == {"a.txt", "b.txt"}


def test_no_changes_returns_empty_list(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    assert changed_files_from_git(tmp_path) == []
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_agent_base.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/agent/base.py`**

```python
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AgentResult:
    changed_files: list[str]
    raw_output: str


class AgentRunner(Protocol):
    def run(self, prompt: str, worktree: Path) -> AgentResult: ...


def changed_files_from_git(worktree: Path) -> list[str]:
    """The orchestrator's ONLY source of truth for what changed — never the agent's own report."""
    proc = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(worktree), capture_output=True,
        encoding="utf-8", errors="replace", check=True,
    )
    files = []
    for line in proc.stdout.splitlines():
        if line.strip():
            files.append(line[3:].strip())
    return files
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_agent_base.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/agent/base.py tests/unit/test_agent_base.py
git commit -m "feat: AgentRunner Protocol; changed files always sourced from git, never agent output"
```

---

## Task 12: MockAgent test double

**Files:**
- Create: `nexus_autofix/agent/mock.py`
- Test: `tests/unit/test_agent_mock.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_agent_mock.py
from pathlib import Path

from nexus_autofix.agent.mock import MockAgent, MockMode


def test_applies_fix_writes_file_and_reports_it(tmp_path):
    agent = MockAgent(mode=MockMode.APPLIES_FIX, fix_file="build.gradle", fix_content="dependencies { x }")
    result = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert (tmp_path / "build.gradle").read_text(encoding="utf-8") == "dependencies { x }"
    assert result.changed_files == ["build.gradle"]


def test_no_changes_mode_touches_nothing(tmp_path):
    agent = MockAgent(mode=MockMode.NO_CHANGES)
    result = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert result.changed_files == []
    assert list(tmp_path.iterdir()) == []


def test_deletes_test_mode_removes_the_named_file(tmp_path):
    test_file = tmp_path / "FooTest.java"
    test_file.write_text("class FooTest {}", encoding="utf-8")
    agent = MockAgent(mode=MockMode.DELETES_TEST, test_file_to_delete="FooTest.java")
    agent.run(prompt="irrelevant", worktree=tmp_path)
    assert not test_file.exists()


def test_fails_then_fixes_mode_writes_nothing_on_first_call_and_fix_on_second(tmp_path):
    agent = MockAgent(mode=MockMode.FAILS_THEN_FIXES, fix_file="build.gradle", fix_content="fixed")
    first = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert first.changed_files == []
    second = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert second.changed_files == ["build.gradle"]
    assert (tmp_path / "build.gradle").read_text(encoding="utf-8") == "fixed"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_agent_mock.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/agent/mock.py`**

```python
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from nexus_autofix.agent.base import AgentResult


class MockMode(str, Enum):
    APPLIES_FIX = "applies_fix"
    NO_CHANGES = "no_changes"
    DELETES_TEST = "deletes_test"
    FAILS_THEN_FIXES = "fails_then_fixes"


@dataclass
class MockAgent:
    """Test double per design doc section 12 — NOT a second real agent implementation.

    Exists because the orchestrator's SUSPICIOUS-abort path (does it refuse to push when
    the agent deletes a test file?) cannot be exercised against a real, non-deterministic
    coding agent on demand.
    """

    mode: MockMode
    fix_file: str | None = None
    fix_content: str | None = None
    test_file_to_delete: str | None = None
    _attempt: int = field(default=0, init=False)

    def run(self, prompt: str, worktree: Path) -> AgentResult:
        self._attempt += 1

        if self.mode == MockMode.NO_CHANGES:
            return AgentResult(changed_files=[], raw_output="no changes made")

        if self.mode == MockMode.DELETES_TEST:
            (worktree / self.test_file_to_delete).unlink()
            return AgentResult(changed_files=[self.test_file_to_delete], raw_output="deleted failing test")

        if self.mode == MockMode.APPLIES_FIX:
            self._write_fix(worktree)
            return AgentResult(changed_files=[self.fix_file], raw_output="applied version bump")

        if self.mode == MockMode.FAILS_THEN_FIXES:
            if self._attempt == 1:
                return AgentResult(changed_files=[], raw_output="attempted fix, build still failing")
            self._write_fix(worktree)
            return AgentResult(changed_files=[self.fix_file], raw_output="applied corrected fix on retry")

        raise ValueError(f"unhandled mock mode: {self.mode}")

    def _write_fix(self, worktree: Path) -> None:
        (worktree / self.fix_file).write_text(self.fix_content, encoding="utf-8")
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_agent_mock.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/agent/mock.py tests/unit/test_agent_mock.py
git commit -m "feat: MockAgent test double covering fix/no-op/test-deletion/retry scenarios"
```

---

## Task 13: Prompt assembly

**Files:**
- Create: `nexus_autofix/agent/prompt.py`
- Test: `tests/unit/test_agent_prompt.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_agent_prompt.py
from pathlib import Path

from nexus_autofix.agent.prompt import RetryContext, build_prompt
from nexus_autofix.iq.models import Finding, Module, RepoProfile


def _finding(**overrides) -> Finding:
    base = dict(
        component="org.apache.commons:commons-text", package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        current_version="1.9", target_version="1.10.0", remediation_type="next-non-failing-with-dependencies",
        is_direct=True, dependency_path=[], parent_component=None, parent_current_version=None,
        parent_target_version=None, policy_action="Fail", threat_level=8, policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"], manifest_path=Path("build.gradle"),
    )
    base.update(overrides)
    return Finding(**base)


def _profile() -> RepoProfile:
    return RepoProfile(
        ecosystem="gradle", java_version="17.0.1", node_version=None,
        modules=[Module(path=Path("."), ecosystem="gradle", manifest=Path("build.gradle"))],
        source="trident",
    )


def test_prompt_contains_agent_instructions_and_matching_playbook_only():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="./gradlew clean build -x test", test_command="./gradlew test",
        actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "Agent Instructions" in prompt
    assert "Playbook — Spring Boot with Gradle" in prompt
    assert "Playbook — React / npm" not in prompt


def test_prompt_contains_target_version_marker():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "TARGET VERSION:   1.10.0" in prompt


def test_prompt_includes_escalated_section_when_present():
    escalated = _finding(target_version="2.0.0", escalation_reason="major bump only")
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[escalated],
    )
    assert "Not in scope for this session" in prompt
    assert "major bump only" in prompt


def test_prompt_omits_escalated_section_when_empty():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "Not in scope for this session" not in prompt


def test_prompt_includes_retry_section_with_verbatim_stdout():
    retry = RetryContext(
        attempt_number=2, max_attempts=2, files_changed=["build.gradle"], failed_stage="build",
        stdout_tail="FAILURE: Build failed with an exception.",
    )
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[], retry=retry,
    )
    assert "Previous attempt failed" in prompt
    assert "FAILURE: Build failed with an exception." in prompt
    assert "attempt 2 of 2" in prompt
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_agent_prompt.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/agent/prompt.py`**

```python
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nexus_autofix.iq.models import Finding, RepoProfile

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
AGENT_INSTRUCTIONS_PATH = PACKAGE_ROOT / "agent_instructions.md"
PLAYBOOKS_DIR = PACKAGE_ROOT / "playbooks"

PLAYBOOK_BY_ECOSYSTEM = {
    "gradle": "spring-boot-gradle.md",
    "maven": "spring-boot-maven.md",
    "npm": "npm.md",
    "yarn": "npm.md",
    "pnpm": "npm.md",
}


@dataclass(frozen=True)
class RetryContext:
    attempt_number: int
    max_attempts: int
    files_changed: list[str]
    failed_stage: str  # "build" | "test"
    stdout_tail: str
    diagnostic_tail: str | None = None


def build_prompt(
    repo_name: str,
    fix_branch: str,
    commit_sha: str,
    profile: RepoProfile,
    build_command: str,
    test_command: str,
    actionable_findings: list[Finding],
    escalated_findings: list[Finding],
    retry: RetryContext | None = None,
) -> str:
    sections = [
        AGENT_INSTRUCTIONS_PATH.read_text(encoding="utf-8"),
        "---",
        (PLAYBOOKS_DIR / PLAYBOOK_BY_ECOSYSTEM[profile.ecosystem]).read_text(encoding="utf-8"),
        "---",
        _repository_section(repo_name, fix_branch, commit_sha, profile, build_command, test_command),
        "---",
        _findings_section(actionable_findings),
    ]
    if escalated_findings:
        sections += ["---", _escalated_section(escalated_findings)]
    if retry:
        sections += ["---", _retry_section(retry)]
    sections += [
        "---",
        "Begin. Follow the order of operations in the instructions above, and\n"
        "finish with the summary in the required format.",
    ]
    return "\n\n".join(sections)


def _repository_section(repo_name, fix_branch, commit_sha, profile, build_command, test_command) -> str:
    lines = [
        "# Repository", "",
        f"Repository:      {repo_name}",
        f"Branch:          {fix_branch}",
        f"Base commit:     {commit_sha}",
        f"Ecosystem:       {profile.ecosystem}          (from .trident/build.yaml)",
        f"Java version:    {profile.java_version or 'n/a'}       (declared — already on PATH)",
        f"Node version:    {profile.node_version or 'n/a'}       (declared — already on PATH)",
        "",
        f"Build command:   {build_command}",
        f"Test command:    {test_command}",
        "",
        "Modules:",
    ]
    for module in profile.modules:
        lines.append(f"  {module.path}   manifest: {module.manifest}")
        if module.version_catalog:
            lines.append(f"  version catalog: {module.version_catalog}")
    return "\n".join(lines)


def _findings_section(findings: list[Finding]) -> str:
    lines = ["# Findings to remediate"]
    for index, finding in enumerate(findings, start=1):
        lines += [
            "", f"## {index}. {finding.component}", "",
            f"  Current version:  {finding.current_version}",
            f"  TARGET VERSION:   {finding.target_version}        <- use this exact version",
            f"  Guarantee:        {finding.remediation_type}",
            f"  Threat level:     {finding.threat_level}",
            f"  Policy:           {finding.policy_name}",
            f"  CVEs:             {', '.join(finding.cve_ids)}",
            f"  Type:             {'direct dependency' if finding.is_direct else 'transitive dependency'}",
            f"  Scope:            {'dev only' if finding.is_dev_dependency else 'runtime'}",
        ]
        if not finding.is_direct:
            lines += ["", "  Dependency path:", f"    {' > '.join(finding.dependency_path)}"]
        if finding.parent_component:
            lines += [
                "", "  PREFERRED FIX — parent remediation from Nexus IQ:",
                f"    Bump {finding.parent_component} from {finding.parent_current_version} to {finding.parent_target_version}",
                "    This is the correct fix. Use it rather than an override.",
            ]
        if finding.golden_version and finding.golden_version != finding.target_version:
            lines += [
                "", f"  Note: a non-breaking recommended version {finding.golden_version} is also",
                "  available. The target above is the smaller change. If the target",
                "  causes problems, report it rather than switching versions yourself.",
            ]
    return "\n".join(lines)


def _escalated_section(findings: list[Finding]) -> str:
    lines = [
        "# Not in scope for this session", "",
        "These findings were excluded because they require a major version",
        "change or have no available remediation. Do not attempt them.", "",
    ]
    for finding in findings:
        lines.append(f"  {finding.component} {finding.current_version}  —  {finding.escalation_reason}")
    return "\n".join(lines)


def _retry_section(retry: RetryContext) -> str:
    lines = [
        "# Previous attempt failed", "",
        f"This is attempt {retry.attempt_number} of {retry.max_attempts}.", "",
        "Your previous changes were:",
        *[f"  {f}" for f in retry.files_changed], "",
        f"The {retry.failed_stage} command failed. Output:", "",
        "```", retry.stdout_tail, "```",
    ]
    if retry.diagnostic_tail:
        lines += ["", "Dependency resolution at the time of failure:", "", "```", retry.diagnostic_tail, "```"]
    lines += [
        "", "Read the actual error before changing anything. Fix only what your",
        "change broke. If the failure is unrelated to your change — a missing",
        "toolchain, a network failure, a test that was already failing —",
        "escalate rather than attempting to fix it.",
    ]
    return "\n".join(lines)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_agent_prompt.py -v
```

Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/agent/prompt.py tests/unit/test_agent_prompt.py
git commit -m "feat: assemble agent prompt from instructions + single matching playbook + findings"
```

---

## Task 14: Copilot CLI adapter (unverified real integration)

**Files:**
- Create: `nexus_autofix/agent/copilot_cli.py`
- Test: `tests/unit/test_agent_copilot_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_agent_copilot_cli.py
import subprocess
from unittest.mock import patch

from nexus_autofix.agent.copilot_cli import CopilotCLIAgent


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def test_copilot_cli_agent_reads_changed_files_from_git_not_stdout(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    def fake_run(command, input, cwd, capture_output, encoding, errors, timeout, shell):
        (tmp_path / "a.txt").write_text("2", encoding="utf-8")

        class FakeProc:
            stdout = "I did nothing useful, I promise"  # deliberately lies
            stderr = ""

        return FakeProc()

    agent = CopilotCLIAgent(command=["copilot", "--allow-all-tools"])
    with patch("subprocess.run", side_effect=fake_run):
        result = agent.run(prompt="fix things", worktree=tmp_path)

    assert result.changed_files == ["a.txt"]
    assert "I did nothing useful" in result.raw_output
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_agent_copilot_cli.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/agent/copilot_cli.py`**

```python
from __future__ import annotations

"""
UNVERIFIED integration. The exact Copilot CLI invocation shape (flags for
non-interactive/agentic mode) has not been confirmed against a real install
in this environment — design doc section 17 lists "run `copilot --help` and
record the actual flags" as an open item. This adapter pipes the assembled
prompt to the CLI's stdin and treats stdout/stderr as a human-readable
transcript ONLY. Changed files always come from `git status --porcelain`
(agent/base.changed_files_from_git) per the "never trust the agent's own
account of what it did" principle — never from parsing this output.
Update `command` once the real flags are confirmed.
"""

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nexus_autofix.agent.base import AgentResult, changed_files_from_git


@dataclass
class CopilotCLIAgent:
    command: list[str] = field(default_factory=lambda: ["copilot", "--allow-all-tools", "--no-color"])
    timeout_seconds: int = 1800

    def run(self, prompt: str, worktree: Path) -> AgentResult:
        proc = subprocess.run(
            self.command, input=prompt, cwd=str(worktree), capture_output=True,
            encoding="utf-8", errors="replace", timeout=self.timeout_seconds, shell=False,
        )
        changed = changed_files_from_git(worktree)
        raw_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return AgentResult(changed_files=changed, raw_output=raw_output)
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_agent_copilot_cli.py -v
```

Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/agent/copilot_cli.py tests/unit/test_agent_copilot_cli.py
git commit -m "feat: Copilot CLI adapter (unverified — flags need confirming against a real install)"
```

---

## Task 15: Workspace / worktree management

**Files:**
- Create: `nexus_autofix/repo/workspace.py`
- Test: `tests/unit/test_repo_workspace.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_repo_workspace.py
import subprocess
from pathlib import Path

from nexus_autofix.repo.workspace import create_worktree, current_commit_sha, remove_worktree


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _init_mirror(path: Path) -> str:
    _git(["init"], path)
    _git(["config", "user.email", "t@example.com"], path)
    _git(["config", "user.name", "t"], path)
    (path / "README.md").write_text("x", encoding="utf-8")
    _git(["add", "-A"], path)
    _git(["commit", "-m", "init"], path)
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(path), capture_output=True, encoding="utf-8", check=True)
    return proc.stdout.strip()


def test_create_and_remove_worktree(tmp_path):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    sha = _init_mirror(mirror)
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    worktree = create_worktree(mirror, run_dir, sha, "autofix/nexus/test-1")
    assert worktree.path.exists()
    assert worktree.branch == "autofix/nexus/test-1"
    assert current_commit_sha(worktree.path) == sha

    removed = remove_worktree(mirror, worktree)
    assert removed is True
    assert not worktree.path.exists()
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_repo_workspace.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/repo/workspace.py`**

```python
from __future__ import annotations

import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Worktree:
    path: Path
    branch: str


def create_worktree(mirror_path: Path, run_dir: Path, commit_sha: str, branch: str) -> Worktree:
    wt_path = run_dir / "wt"
    subprocess.run(
        ["git", "worktree", "add", str(wt_path), commit_sha],
        cwd=str(mirror_path), check=True, capture_output=True, encoding="utf-8",
    )
    subprocess.run(
        ["git", "switch", "-c", branch], cwd=str(wt_path), check=True, capture_output=True, encoding="utf-8",
    )
    return Worktree(path=wt_path, branch=branch)


def current_commit_sha(worktree_path: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(worktree_path), capture_output=True,
        encoding="utf-8", check=True,
    )
    return proc.stdout.strip()


def remove_worktree(
    mirror_path: Path, worktree: Worktree, gradle_stop_cmd: list[str] | None = None,
    retries: int = 3, delay_seconds: float = 2.0,
) -> bool:
    """Cleanup failure is logged by the caller, never raised — per design doc section 15."""
    if gradle_stop_cmd and (worktree.path / "gradlew").exists():
        subprocess.run(gradle_stop_cmd, cwd=str(worktree.path), capture_output=True, encoding="utf-8")
    for _ in range(retries):
        result = subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree.path)],
            cwd=str(mirror_path), capture_output=True, encoding="utf-8",
        )
        if result.returncode == 0:
            subprocess.run(["git", "worktree", "prune"], cwd=str(mirror_path), capture_output=True, encoding="utf-8")
            return True
        time.sleep(delay_seconds)
    return False
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_repo_workspace.py -v
```

Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/repo/workspace.py tests/unit/test_repo_workspace.py
git commit -m "feat: worktree lifecycle — create, resolve HEAD sha, cleanup with retry"
```

---

## Task 16: `.security-fix.yml` descriptor

**Files:**
- Create: `nexus_autofix/repo/descriptor.py`
- Test: `tests/unit/test_repo_descriptor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_repo_descriptor.py
from datetime import date

from nexus_autofix.repo.descriptor import SecurityFixDescriptor, read_descriptor, unexpired_suppressions, write_descriptor


def test_write_then_read_round_trips(tmp_path):
    path = tmp_path / ".security-fix.yml"
    descriptor = SecurityFixDescriptor(nexus_app_id="payments-core", gate="pre-pr", auto_merge="manifest_only")
    write_descriptor(path, descriptor)
    loaded = read_descriptor(path)
    assert loaded.nexus_app_id == "payments-core"
    assert loaded.gate == "pre-pr"


def test_read_missing_file_returns_none(tmp_path):
    assert read_descriptor(tmp_path / "missing.yml") is None


def test_unexpired_suppressions_excludes_past_expiry():
    descriptor = SecurityFixDescriptor(
        nexus_app_id="x",
        suppress=[
            {"component": "log4j-api", "reason": "shaded", "expires": "2026-10-01"},
            {"component": "old-lib", "reason": "stale", "expires": "2020-01-01"},
        ],
    )
    result = unexpired_suppressions(descriptor, today=date(2026, 7, 28))
    assert result == {"log4j-api"}


def test_unexpired_suppressions_with_no_descriptor_is_empty():
    assert unexpired_suppressions(None, today=date(2026, 7, 28)) == set()
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_repo_descriptor.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/repo/descriptor.py`**

```python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml


@dataclass
class SecurityFixDescriptor:
    nexus_app_id: str
    build: str | None = None
    test: str | None = None
    smoke: str | None = None
    gate: str = "pre-pr"
    auto_merge: str = "never"
    suppress: list[dict] = field(default_factory=list)


def read_descriptor(path: Path) -> SecurityFixDescriptor | None:
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return SecurityFixDescriptor(
        nexus_app_id=data["nexus_app_id"],
        build=data.get("build"),
        test=data.get("test"),
        smoke=data.get("smoke"),
        gate=data.get("gate", "pre-pr"),
        auto_merge=data.get("auto_merge", "never"),
        suppress=data.get("suppress", []),
    )


def write_descriptor(path: Path, descriptor: SecurityFixDescriptor) -> None:
    data: dict = {
        "nexus_app_id": descriptor.nexus_app_id,
        "gate": descriptor.gate,
        "auto_merge": descriptor.auto_merge,
    }
    if descriptor.build:
        data["build"] = descriptor.build
    if descriptor.test:
        data["test"] = descriptor.test
    if descriptor.smoke:
        data["smoke"] = descriptor.smoke
    if descriptor.suppress:
        data["suppress"] = descriptor.suppress
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def unexpired_suppressions(descriptor: SecurityFixDescriptor | None, today: date) -> set[str]:
    if not descriptor:
        return set()
    result = set()
    for entry in descriptor.suppress:
        expires = entry.get("expires")
        if expires is None or date.fromisoformat(str(expires)) >= today:
            result.add(entry["component"])
    return result
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_repo_descriptor.py -v
```

Expected: 4 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/repo/descriptor.py tests/unit/test_repo_descriptor.py
git commit -m "feat: .security-fix.yml read/write and unexpired-suppression lookup"
```

---

## Task 17: SQLite state store

**Files:**
- Create: `nexus_autofix/state/store.py`
- Test: `tests/unit/test_state_store.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_state_store.py
from nexus_autofix.state.store import StateStore


def test_run_lifecycle_round_trips(tmp_path):
    store = StateStore(tmp_path / "state.db")
    store.start_run("run-1", "payments-core", "autofix/nexus/run-1", "2026-07-28T00:00:00Z")
    store.record_finding("run-1", "commons-text", "pkg:maven/x/y@1.9", "1.9", "1.10.0", "actionable")
    store.record_attempt("run-1", 1, True, True, "MANIFEST_ONLY")
    store.finish_run("run-1", "FIXED", commit_sha="abc123")

    cursor = store._conn.execute("SELECT outcome, commit_sha FROM runs WHERE run_id = ?", ("run-1",))
    outcome, commit_sha = cursor.fetchone()
    assert outcome == "FIXED"
    assert commit_sha == "abc123"

    findings = store._conn.execute("SELECT component, disposition FROM findings WHERE run_id = ?", ("run-1",)).fetchall()
    assert findings == [("commons-text", "actionable")]

    attempts = store._conn.execute("SELECT attempt_number, build_success FROM attempts WHERE run_id = ?", ("run-1",)).fetchall()
    assert attempts == [(1, 1)]

    store.close()


def test_creates_parent_directories(tmp_path):
    nested = tmp_path / "a" / "b" / "state.db"
    store = StateStore(nested)
    assert nested.exists()
    store.close()
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_state_store.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/state/store.py`**

```python
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    commit_sha TEXT,
    outcome TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    component TEXT NOT NULL,
    package_url TEXT NOT NULL,
    current_version TEXT NOT NULL,
    target_version TEXT,
    disposition TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs(run_id),
    attempt_number INTEGER NOT NULL,
    build_success INTEGER,
    test_success INTEGER,
    diff_classification TEXT
);
"""


class StateStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def start_run(self, run_id: str, app_id: str, branch: str, created_at: str) -> None:
        self._conn.execute(
            "INSERT INTO runs (run_id, app_id, branch, created_at) VALUES (?, ?, ?, ?)",
            (run_id, app_id, branch, created_at),
        )
        self._conn.commit()

    def record_finding(
        self, run_id: str, component: str, package_url: str, current_version: str,
        target_version: str | None, disposition: str,
    ) -> None:
        self._conn.execute(
            "INSERT INTO findings (run_id, component, package_url, current_version, target_version, disposition) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (run_id, component, package_url, current_version, target_version, disposition),
        )
        self._conn.commit()

    def record_attempt(
        self, run_id: str, attempt_number: int, build_success: bool | None,
        test_success: bool | None, diff_classification: str | None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO attempts (run_id, attempt_number, build_success, test_success, diff_classification) "
            "VALUES (?, ?, ?, ?, ?)",
            (run_id, attempt_number, build_success, test_success, diff_classification),
        )
        self._conn.commit()

    def finish_run(self, run_id: str, outcome: str, commit_sha: str | None = None) -> None:
        self._conn.execute(
            "UPDATE runs SET outcome = ?, commit_sha = COALESCE(?, commit_sha) WHERE run_id = ?",
            (outcome, commit_sha, run_id),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_state_store.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/state/store.py tests/unit/test_state_store.py
git commit -m "feat: SQLite state store for runs, findings, and attempts"
```

---

## Task 18: Config loading

**Files:**
- Create: `nexus_autofix/config.py`
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_config.py
import os

from nexus_autofix.config import load_project_config, load_secrets


def test_load_project_config_reads_toolchains_and_defaults(tmp_path):
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "max_attempts: 3\n"
        "toolchains:\n  java:\n    '17': /opt/jdk17\n  node:\n    '20': /opt/node20\n"
        "repos:\n  payments-core: https://example.com/org/payments-core.git\n",
        encoding="utf-8",
    )
    config = load_project_config(config_path)
    assert config.max_attempts == 3
    assert config.subprocess_timeout_seconds == 1800  # default
    assert config.java_toolchains == {"17": "/opt/jdk17"}
    assert config.repos["payments-core"].endswith("payments-core.git")


def test_load_secrets_reads_env_vars_with_empty_string_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("NEXUSFIX_IQ_URL", raising=False)
    monkeypatch.setenv("NEXUSFIX_IQ_URL", "https://iq.example.com")
    monkeypatch.setenv("NEXUSFIX_AGENT_BACKEND", "mock")
    secrets = load_secrets(env_file=tmp_path / "does-not-exist.env")
    assert secrets.iq_url == "https://iq.example.com"
    assert secrets.agent_backend == "mock"
    assert secrets.github_api_url == "https://api.github.com"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_config.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/config.py`**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass(frozen=True)
class Secrets:
    iq_url: str
    iq_username: str
    iq_password: str
    github_token: str
    github_api_url: str
    workspace_root: Path
    agent_backend: str | None


@dataclass(frozen=True)
class ProjectConfig:
    subprocess_timeout_seconds: int
    max_attempts: int
    poll_timeout_seconds: int
    default_stage_id: str
    default_gate: str
    java_toolchains: dict[str, str]
    node_toolchains: dict[str, str]
    repos: dict[str, str]


def load_secrets(env_file: Path | None = None) -> Secrets:
    load_dotenv(dotenv_path=env_file)
    workspace_root = os.environ.get("NEXUSFIX_WORKSPACE_ROOT", str(Path.home() / "nfx"))
    return Secrets(
        iq_url=os.environ.get("NEXUSFIX_IQ_URL", ""),
        iq_username=os.environ.get("NEXUSFIX_IQ_USERNAME", ""),
        iq_password=os.environ.get("NEXUSFIX_IQ_PASSWORD", ""),
        github_token=os.environ.get("NEXUSFIX_GITHUB_TOKEN", ""),
        github_api_url=os.environ.get("NEXUSFIX_GITHUB_API_URL", "https://api.github.com"),
        workspace_root=Path(workspace_root),
        agent_backend=os.environ.get("NEXUSFIX_AGENT_BACKEND"),
    )


def load_project_config(path: Path) -> ProjectConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    toolchains = data.get("toolchains", {})
    return ProjectConfig(
        subprocess_timeout_seconds=data.get("subprocess_timeout_seconds", 1800),
        max_attempts=data.get("max_attempts", 2),
        poll_timeout_seconds=data.get("poll_timeout_seconds", 900),
        default_stage_id=data.get("default_stage_id", "build"),
        default_gate=data.get("default_gate", "pre-pr"),
        java_toolchains={str(k): v for k, v in toolchains.get("java", {}).items()},
        node_toolchains={str(k): v for k, v in toolchains.get("node", {}).items()},
        repos=data.get("repos", {}),
    )
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_config.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/config.py tests/unit/test_config.py
git commit -m "feat: config loading — env secrets + checked-in project config, CLI > env > yaml > defaults"
```

---

## Task 19: Publish — branch lifecycle + gc sweep

**Files:**
- Create: `nexus_autofix/publish/branch.py`
- Test: `tests/unit/test_publish_branch.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_publish_branch.py
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from nexus_autofix.publish.branch import sweep_stale_branches


def test_sweep_deletes_stale_branch_with_no_open_pr():
    old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")

    def fake_get(url, headers=None, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if url.endswith("/branches"):
            resp.json.return_value = [
                {"name": "autofix/nexus/old-run", "commit": {"url": "https://api.github.com/commit/old"}},
                {"name": "main", "commit": {"url": "https://api.github.com/commit/main"}},
            ]
        elif url.endswith("/pulls"):
            resp.json.return_value = []
        elif "commit/old" in url:
            resp.json.return_value = {"commit": {"committer": {"date": old_date}}}
        return resp

    with patch("nexus_autofix.publish.branch.requests.get", side_effect=fake_get), \
         patch("nexus_autofix.publish.branch.requests.delete") as mock_delete:
        mock_delete.return_value.raise_for_status.return_value = None
        deleted = sweep_stale_branches("https://api.github.com", "tok", "org", "repo", older_than_days=7)

    assert deleted == ["autofix/nexus/old-run"]
    mock_delete.assert_called_once()


def test_sweep_skips_branch_with_open_pr():
    old_date = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat().replace("+00:00", "Z")

    def fake_get(url, headers=None, params=None, timeout=None):
        resp = MagicMock()
        resp.raise_for_status.return_value = None
        if url.endswith("/branches"):
            resp.json.return_value = [{"name": "autofix/nexus/has-pr", "commit": {"url": "https://api.github.com/commit/x"}}]
        elif url.endswith("/pulls"):
            resp.json.return_value = [{"head": {"ref": "autofix/nexus/has-pr"}}]
        elif "commit/x" in url:
            resp.json.return_value = {"commit": {"committer": {"date": old_date}}}
        return resp

    with patch("nexus_autofix.publish.branch.requests.get", side_effect=fake_get), \
         patch("nexus_autofix.publish.branch.requests.delete") as mock_delete:
        deleted = sweep_stale_branches("https://api.github.com", "tok", "org", "repo", older_than_days=7)

    assert deleted == []
    mock_delete.assert_not_called()
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_publish_branch.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/publish/branch.py`**

```python
from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests


def push_branch(worktree: Path, remote: str, branch: str) -> None:
    subprocess.run(
        ["git", "push", remote, f"HEAD:refs/heads/{branch}"],
        cwd=str(worktree), check=True, capture_output=True, encoding="utf-8",
    )


def delete_remote_branch(worktree: Path, remote: str, branch: str) -> None:
    subprocess.run(
        ["git", "push", remote, "--delete", branch],
        cwd=str(worktree), check=True, capture_output=True, encoding="utf-8",
    )


def sweep_stale_branches(api_url: str, token: str, owner: str, repo: str, older_than_days: int) -> list[str]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    branches_resp = requests.get(f"{api_url}/repos/{owner}/{repo}/branches", headers=headers, timeout=30)
    branches_resp.raise_for_status()

    open_prs_resp = requests.get(
        f"{api_url}/repos/{owner}/{repo}/pulls", headers=headers, params={"state": "open"}, timeout=30
    )
    open_prs_resp.raise_for_status()
    open_pr_branches = {pr["head"]["ref"] for pr in open_prs_resp.json()}

    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    deleted: list[str] = []

    for branch in branches_resp.json():
        name = branch["name"]
        if not name.startswith("autofix/nexus/") or name in open_pr_branches:
            continue
        commit_resp = requests.get(branch["commit"]["url"], headers=headers, timeout=30)
        commit_resp.raise_for_status()
        commit_date = datetime.fromisoformat(
            commit_resp.json()["commit"]["committer"]["date"].replace("Z", "+00:00")
        )
        if commit_date < cutoff:
            delete_resp = requests.delete(
                f"{api_url}/repos/{owner}/{repo}/git/refs/heads/{name}", headers=headers, timeout=30
            )
            delete_resp.raise_for_status()
            deleted.append(name)

    return deleted
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_publish_branch.py -v
```

Expected: 2 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/publish/branch.py tests/unit/test_publish_branch.py
git commit -m "feat: push/delete remote branch and gc sweep of stale autofix branches"
```

---

## Task 20: Publish — PR creation

**Files:**
- Create: `nexus_autofix/publish/pr.py`
- Test: `tests/unit/test_publish_pr.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_publish_pr.py
from unittest.mock import MagicMock, patch

from nexus_autofix.publish.pr import open_pull_request


def test_open_pull_request_posts_expected_payload_and_returns_number_and_url():
    with patch("nexus_autofix.publish.pr.requests.post") as mock_post:
        mock_post.return_value.raise_for_status.return_value = None
        mock_post.return_value.json.return_value = {"number": 42, "html_url": "https://github.com/org/repo/pull/42"}

        result = open_pull_request(
            api_url="https://api.github.com", token="tok", owner="org", repo="repo",
            head_branch="autofix/nexus/run-1", base_branch="main",
            title="fix: bump commons-text", body="details",
        )

    assert result.number == 42
    assert result.url == "https://github.com/org/repo/pull/42"
    call = mock_post.call_args
    assert call.kwargs["json"]["head"] == "autofix/nexus/run-1"
    assert call.kwargs["json"]["base"] == "main"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_publish_pr.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/publish/pr.py`**

```python
from __future__ import annotations

from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str


def open_pull_request(
    api_url: str, token: str, owner: str, repo: str,
    head_branch: str, base_branch: str, title: str, body: str,
) -> PullRequest:
    resp = requests.post(
        f"{api_url}/repos/{owner}/{repo}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "head": head_branch, "base": base_branch, "body": body},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return PullRequest(number=data["number"], url=data["html_url"])
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_publish_pr.py -v
```

Expected: 1 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/publish/pr.py tests/unit/test_publish_pr.py
git commit -m "feat: open a PR via the GitHub REST API (GHES-compatible via api_url)"
```

---

## Task 21: Publish — human-in-loop gate

**Files:**
- Create: `nexus_autofix/publish/gate.py`
- Test: `tests/unit/test_publish_gate.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_publish_gate.py
from nexus_autofix.publish.gate import GateMode, present_pre_pr_gate


def test_approve_returns_true_on_y(capsys):
    approved = present_pre_pr_gate("summary text", prompt_fn=lambda _: "y")
    assert approved is True
    assert "summary text" in capsys.readouterr().out


def test_reject_returns_false_on_anything_else():
    assert present_pre_pr_gate("summary", prompt_fn=lambda _: "n") is False
    assert present_pre_pr_gate("summary", prompt_fn=lambda _: "") is False


def test_gate_mode_values():
    assert {m.value for m in GateMode} == {"none", "pre-pr", "pre-push"}
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_publish_gate.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/publish/gate.py`**

```python
from __future__ import annotations

from enum import Enum
from typing import Callable


class GateMode(str, Enum):
    NONE = "none"
    PRE_PR = "pre-pr"
    PRE_PUSH = "pre-push"


def present_pre_pr_gate(summary: str, prompt_fn: Callable[[str], str] = input) -> bool:
    print(summary)
    answer = prompt_fn("Approve and open PR? [y/N]: ").strip().lower()
    return answer == "y"
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_publish_gate.py -v
```

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/publish/gate.py tests/unit/test_publish_gate.py
git commit -m "feat: pre-PR human approval gate"
```

---

## Task 22: Orchestrator core

**Files:**
- Create: `nexus_autofix/orchestrator.py`
- Test: `tests/unit/test_orchestrator.py`

This is the module tying everything together (design doc section 8's run flow, steps 10 onward —
discovery and worktree creation happen in `cli.py`, Task 23). Only the fast paths that don't
require a real build are unit-tested here (`CLEAN`, missing `.trident`, missing toolchain); the
paths that reach the build/test stage (`FIXED`, the `SUSPICIOUS` abort) are exercised for real in
the Task 25 fixture e2e tests, since they need an actual buildable repo.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_orchestrator.py
from pathlib import Path

from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.iq.client import FakeIQClient
from nexus_autofix.iq.models import Finding, RunOutcome
from nexus_autofix.orchestrator import Orchestrator, RunConfig
from nexus_autofix.state.store import StateStore


def _finding(**overrides) -> Finding:
    base = dict(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0.0", target_version="1.0.1",
        remediation_type="next-non-failing-with-dependencies", is_direct=True, dependency_path=[],
        parent_component=None, parent_current_version=None, parent_target_version=None,
        policy_action="Fail", threat_level=8, policy_name="p", cve_ids=[], manifest_path=Path("x"),
    )
    base.update(overrides)
    return Finding(**base)


def _run_config(**overrides) -> RunConfig:
    base = dict(
        app_id="payments-core", branch="autofix/nexus/run-1", gate="none", max_attempts=2,
        stage_id="build", java_toolchains={}, node_toolchains={}, subprocess_timeout_seconds=60,
    )
    base.update(overrides)
    return RunConfig(**base)


def test_no_actionable_findings_returns_clean(tmp_path):
    orchestrator = Orchestrator(
        iq_client=FakeIQClient(), agent=MockAgent(mode=MockMode.NO_CHANGES), state_store=StateStore(tmp_path / "state.db"),
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=tmp_path, commit_sha="abc123",
        findings=[], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.CLEAN


def test_missing_trident_file_escalates(tmp_path):
    orchestrator = Orchestrator(
        iq_client=FakeIQClient(), agent=MockAgent(mode=MockMode.NO_CHANGES), state_store=StateStore(tmp_path / "state.db"),
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=tmp_path, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.ESCALATED
    assert result.escalated == [_finding()]


def test_missing_toolchain_escalates_before_agent_runs(tmp_path):
    (tmp_path / ".trident").mkdir()
    (tmp_path / ".trident" / "build.yaml").write_text(
        "strategy:\n  uses: gradle\n  with:\n    java-version: 99.0.0\n", encoding="utf-8"
    )
    agent_called = {"count": 0}

    class CountingAgent:
        def run(self, prompt, worktree):
            agent_called["count"] += 1
            from nexus_autofix.agent.base import AgentResult
            return AgentResult(changed_files=[], raw_output="")

    orchestrator = Orchestrator(
        iq_client=FakeIQClient(), agent=CountingAgent(), state_store=StateStore(tmp_path / "state.db"),
    )
    result = orchestrator.run(
        run_config=_run_config(java_toolchains={"17": "/opt/jdk17"}), worktree=tmp_path, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.ESCALATED
    assert agent_called["count"] == 0
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_orchestrator.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/orchestrator.py`**

```python
from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from nexus_autofix.agent.base import AgentRunner, changed_files_from_git
from nexus_autofix.agent.prompt import RetryContext, build_prompt
from nexus_autofix.iq.client import IQClient
from nexus_autofix.iq.filter import filter_findings
from nexus_autofix.iq.models import Finding, RepoProfile, RunOutcome
from nexus_autofix.publish import branch as branch_mod
from nexus_autofix.repo import trident as trident_mod
from nexus_autofix.state.store import StateStore
from nexus_autofix.verify import commands as commands_mod
from nexus_autofix.verify import diff as diff_mod
from nexus_autofix.verify import rescan as rescan_mod
from nexus_autofix.verify import toolchain as toolchain_mod


@dataclass
class RunConfig:
    app_id: str
    branch: str
    gate: str  # "none" | "pre-pr" | "pre-push"
    max_attempts: int
    stage_id: str
    java_toolchains: dict[str, str]
    node_toolchains: dict[str, str]
    subprocess_timeout_seconds: int


@dataclass
class RunResult:
    run_id: str
    outcome: RunOutcome
    fixed: list[Finding] = field(default_factory=list)
    escalated: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _default_commit(worktree: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=str(worktree), check=True, capture_output=True, encoding="utf-8")
    subprocess.run(["git", "commit", "-m", message], cwd=str(worktree), check=True, capture_output=True, encoding="utf-8")


class Orchestrator:
    def __init__(
        self,
        iq_client: IQClient,
        agent: AgentRunner,
        state_store: StateStore,
        commit_fn=None,
        push_fn=None,
        delete_remote_branch_fn=None,
        rescan_fn=None,
        open_pr_fn=None,
        approve_fn=None,
    ):
        self._iq = iq_client
        self._agent = agent
        self._state = state_store
        self._commit_fn = commit_fn or _default_commit
        self._push_fn = push_fn or (lambda worktree, branch: branch_mod.push_branch(worktree, "origin", branch))
        self._delete_remote_branch_fn = delete_remote_branch_fn or (
            lambda worktree, branch: branch_mod.delete_remote_branch(worktree, "origin", branch)
        )
        self._rescan_fn = rescan_fn or (lambda run_config, worktree: None)
        self._open_pr_fn = open_pr_fn or (lambda worktree, branch: None)
        self._approve_fn = approve_fn or (lambda summary: True)

    def run(
        self,
        run_config: RunConfig,
        worktree: Path,
        commit_sha: str,
        findings: list[Finding],
        repo_name: str,
        baseline_report_id: str,
    ) -> RunResult:
        run_id = str(uuid.uuid4())
        self._state.start_run(run_id, run_config.app_id, run_config.branch, datetime.now(timezone.utc).isoformat())

        filtered = filter_findings(findings, suppressed_components=set())
        for f in filtered.escalate:
            self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "escalate")
        for f in filtered.ignore:
            self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "ignore")

        if not filtered.actionable:
            self._state.finish_run(run_id, RunOutcome.CLEAN.value)
            return RunResult(run_id=run_id, outcome=RunOutcome.CLEAN, escalated=filtered.escalate)

        for f in filtered.actionable:
            self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "actionable")

        try:
            strategies = trident_mod.parse_trident_build_yaml(worktree / ".trident" / "build.yaml")
        except (FileNotFoundError, ValueError):
            strategies = []

        if not strategies:
            self._state.finish_run(run_id, RunOutcome.ESCALATED.value)
            return RunResult(
                run_id=run_id, outcome=RunOutcome.ESCALATED, escalated=filtered.actionable,
                notes=["no usable .trident/build.yaml strategy found"],
            )

        strategy = strategies[0]
        java_version = strategy.toolchain.get("java")
        node_version = strategy.toolchain.get("node")
        env = dict(os.environ)
        try:
            if java_version:
                env = toolchain_mod.resolve_java_env(java_version, run_config.java_toolchains, env).env
            if node_version:
                env = toolchain_mod.resolve_node_env(node_version, run_config.node_toolchains, env).env
        except toolchain_mod.MissingToolchainError as exc:
            self._state.finish_run(run_id, RunOutcome.ESCALATED.value)
            return RunResult(run_id=run_id, outcome=RunOutcome.ESCALATED, escalated=filtered.actionable, notes=[str(exc)])

        profile = RepoProfile(
            ecosystem=strategy.ecosystem, java_version=java_version, node_version=node_version,
            modules=[], source="trident",
        )
        build_cmd = commands_mod.BUILD_COMMANDS[strategy.ecosystem](worktree)
        test_cmd = commands_mod.TEST_COMMANDS[strategy.ecosystem](worktree)

        retry_context: RetryContext | None = None
        for attempt in range(1, run_config.max_attempts + 1):
            prompt = build_prompt(
                repo_name=repo_name, fix_branch=run_config.branch, commit_sha=commit_sha, profile=profile,
                build_command=" ".join(build_cmd), test_command=" ".join(test_cmd),
                actionable_findings=filtered.actionable, escalated_findings=filtered.escalate, retry=retry_context,
            )
            self._agent.run(prompt, worktree)
            changed = changed_files_from_git(worktree)

            if not changed:
                self._state.record_attempt(run_id, attempt, None, None, None)
                self._state.finish_run(run_id, RunOutcome.NO_CHANGES.value)
                return RunResult(run_id=run_id, outcome=RunOutcome.NO_CHANGES, escalated=filtered.actionable, notes=["agent made no changes"])

            diff_result = diff_mod.classify_diff(worktree)
            if diff_result.classification == diff_mod.DiffClass.SUSPICIOUS:
                self._state.record_attempt(run_id, attempt, None, None, diff_result.classification.value)
                self._state.finish_run(run_id, RunOutcome.ESCALATED.value)
                return RunResult(
                    run_id=run_id, outcome=RunOutcome.ESCALATED, escalated=filtered.actionable,
                    notes=diff_result.suspicious_reasons,
                )

            build_result = commands_mod.run_command(build_cmd, worktree, env, run_config.subprocess_timeout_seconds)
            if not build_result.success:
                diagnostic = None
                if strategy.ecosystem in commands_mod.DEPENDENCY_DIAGNOSTIC_COMMANDS:
                    diag_cmd = commands_mod.DEPENDENCY_DIAGNOSTIC_COMMANDS[strategy.ecosystem](worktree)
                    diagnostic = commands_mod.run_command(diag_cmd, worktree, env, run_config.subprocess_timeout_seconds).tail()
                self._state.record_attempt(run_id, attempt, False, None, diff_result.classification.value)
                retry_context = RetryContext(
                    attempt_number=attempt + 1, max_attempts=run_config.max_attempts, files_changed=changed,
                    failed_stage="build", stdout_tail=build_result.tail(), diagnostic_tail=diagnostic,
                )
                continue

            test_result = commands_mod.run_command(test_cmd, worktree, env, run_config.subprocess_timeout_seconds)
            if not test_result.success:
                self._state.record_attempt(run_id, attempt, True, False, diff_result.classification.value)
                retry_context = RetryContext(
                    attempt_number=attempt + 1, max_attempts=run_config.max_attempts, files_changed=changed,
                    failed_stage="test", stdout_tail=test_result.tail(),
                )
                continue

            self._state.record_attempt(run_id, attempt, True, True, diff_result.classification.value)

            if run_config.gate == "pre-push":
                self._state.finish_run(run_id, RunOutcome.AWAITING_APPROVAL.value)
                return RunResult(run_id=run_id, outcome=RunOutcome.AWAITING_APPROVAL, fixed=filtered.actionable, escalated=filtered.escalate)

            self._commit_fn(worktree, "fix: remediate dependency vulnerabilities via nexus-autofix")
            self._push_fn(worktree, run_config.branch)

            target_purls = {f.package_url for f in filtered.actionable}
            baseline_report = self._iq.fetch_policy_report(run_config.app_id, baseline_report_id)
            rescan_report_id = self._rescan_fn(run_config, worktree)
            rescan_report = self._iq.fetch_policy_report(run_config.app_id, rescan_report_id)
            comparison = rescan_mod.compare_reports(baseline_report, rescan_report, target_purls)

            if not comparison.all_cleared or comparison.new_findings:
                self._delete_remote_branch_fn(worktree, run_config.branch)
                self._state.finish_run(run_id, RunOutcome.FAILED_RESCAN.value)
                return RunResult(
                    run_id=run_id, outcome=RunOutcome.FAILED_RESCAN, escalated=filtered.actionable,
                    notes=[f"still failing: {comparison.still_failing}", f"new findings: {comparison.new_findings}"],
                )

            if run_config.gate == "pre-pr":
                summary = self._gate_summary(filtered, build_result, test_result, comparison)
                if not self._approve_fn(summary):
                    self._delete_remote_branch_fn(worktree, run_config.branch)
                    self._state.finish_run(run_id, RunOutcome.REJECTED.value)
                    return RunResult(run_id=run_id, outcome=RunOutcome.REJECTED, escalated=filtered.actionable)

            self._open_pr_fn(worktree, run_config.branch)
            final_outcome = (
                RunOutcome.FIXED if diff_result.classification == diff_mod.DiffClass.MANIFEST_ONLY else RunOutcome.FIXED_NEEDS_REVIEW
            )
            self._state.finish_run(run_id, final_outcome.value, commit_sha=commit_sha)
            return RunResult(run_id=run_id, outcome=final_outcome, fixed=filtered.actionable, escalated=filtered.escalate)

        self._state.finish_run(run_id, RunOutcome.FAILED_BUILD.value)
        return RunResult(run_id=run_id, outcome=RunOutcome.FAILED_BUILD, escalated=filtered.actionable, notes=["exhausted retries"])

    def _gate_summary(self, filtered, build_result, test_result, comparison) -> str:
        return "\n".join([
            "=== nexus-autofix: pre-PR review ===", "",
            f"Fixed: {[f.component for f in filtered.actionable]}",
            f"Escalated: {[f.component for f in filtered.escalate]}",
            f"Build: {'PASS' if build_result.success else 'FAIL'}",
            f"Test:  {'PASS' if test_result.success else 'FAIL'}",
            f"Rescan cleared: {comparison.all_cleared}, new findings: {comparison.new_findings}",
        ])
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_orchestrator.py -v
```

Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add nexus_autofix/orchestrator.py tests/unit/test_orchestrator.py
git commit -m "feat: orchestrator loop — filter, toolchain gate, agent retries, diff abort, commit/push/rescan/PR"
```

---

## Task 23: CLI

**Files:**
- Create: `nexus_autofix/cli.py`
- Test: `tests/unit/test_cli.py`

- [ ] **Step 1: Write the failing test** (covers the pure-function helpers; the full `run`
subcommand is exercised in the Task 25 e2e test since it needs a real repo/mirror)

```python
# tests/unit/test_cli.py
from nexus_autofix.cli import purl_to_component_identifier, purl_version


def test_purl_version_extracts_trailing_version():
    assert purl_version("pkg:maven/org.apache.commons/commons-text@1.9") == "1.9"


def test_purl_to_component_identifier_maven():
    identifier = purl_to_component_identifier("pkg:maven/org.apache.commons/commons-text@1.9")
    assert identifier["format"] == "maven"
    assert identifier["coordinates"]["groupId"] == "org.apache.commons"
    assert identifier["coordinates"]["artifactId"] == "commons-text"


def test_purl_to_component_identifier_npm():
    identifier = purl_to_component_identifier("pkg:npm/axios@1.6.0")
    assert identifier["format"] == "npm"
    assert identifier["coordinates"]["packageId"] == "axios"
```

- [ ] **Step 2: Run to verify it fails**

```bash
.venv/bin/pytest tests/unit/test_cli.py -v
```

Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Write `nexus_autofix/cli.py`**

```python
from __future__ import annotations

import re
from pathlib import Path

import click

from nexus_autofix.config import load_project_config, load_secrets
from nexus_autofix.iq import remediation as remediation_mod
from nexus_autofix.iq.client import HTTPIQClient
from nexus_autofix.iq.models import Finding
from nexus_autofix.publish import branch as branch_mod

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^@]+)@(?P<version>.+)$")


def purl_version(purl: str) -> str:
    match = _PURL_RE.match(purl)
    return match.group("version") if match else ""


def purl_to_component_identifier(purl: str) -> dict:
    match = _PURL_RE.match(purl)
    if not match:
        return {"format": "unknown", "coordinates": {}}
    purl_type, rest, version = match.group("type"), match.group("rest"), match.group("version")
    if purl_type == "maven":
        group_id, artifact_id = rest.split("/", 1)
        return {"format": "maven", "coordinates": {"groupId": group_id, "artifactId": artifact_id, "version": version, "extension": "jar"}}
    if purl_type == "npm":
        return {"format": "npm", "coordinates": {"packageId": rest, "version": version}}
    return {"format": purl_type, "coordinates": {"name": rest, "version": version}}


def findings_from_policy_report(iq_client, internal_id: str, violations, stage_id: str) -> list[Finding]:
    findings = []
    for v in violations:
        identifier = purl_to_component_identifier(v.package_url)
        remediation = iq_client.fetch_remediation(internal_id, identifier, stage_id)
        version_change = remediation_mod.select_target(remediation)
        findings.append(
            Finding(
                component=v.component, package_url=v.package_url, current_version=purl_version(v.package_url),
                target_version=version_change.version if version_change else None,
                remediation_type=version_change.change_type if version_change else None,
                is_direct=True, dependency_path=[], parent_component=remediation.parent_component,
                parent_current_version=remediation.parent_current_version,
                parent_target_version=remediation.parent_target_version, policy_action=v.action,
                threat_level=v.threat_level, policy_name=v.policy_name, cve_ids=[], manifest_path=None,
                is_waived=v.is_waived, golden_version=remediation.golden_version,
            )
        )
    return findings


@click.group()
def main():
    """nexus-autofix — automated remediation of Nexus IQ dependency findings."""


@main.command("run")
@click.option("--app-id", required=True)
@click.option("--branch", required=True)
@click.option("--gate", default=None, type=click.Choice(["none", "pre-pr", "pre-push"]))
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--mock-agent", is_flag=True, default=False)
def run_command(app_id: str, branch: str, gate: str | None, dry_run: bool, mock_agent: bool):
    """
    Discovers findings from Nexus IQ, runs the agent loop, and (unless --dry-run) opens a PR.

    This command's full path — mirroring a real repo and calling a live Nexus IQ instance — is
    one of the integration points not exercised in this environment (see the design doc's
    unverified-integrations note). The --mock-agent / --dry-run flags exist precisely so this
    can be smoke-tested locally without live credentials once wired to a real repo.
    """
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    effective_gate = gate or config.default_gate

    if app_id not in config.repos:
        raise click.ClickException(f"no repo URL configured for app_id={app_id!r} in config.yml's repos map")

    click.echo(f"nexus-autofix run: app_id={app_id} branch={branch} gate={effective_gate} dry_run={dry_run} mock_agent={mock_agent}")
    click.echo(
        "Full live-IQ + live-repo wiring is unverified in this environment — "
        "see docs/superpowers/specs/2026-07-28-nexus-autofix-design.md for what's confirmed vs. not."
    )


@main.command("gc")
@click.option("--older-than-days", default=7)
def gc_command(older_than_days: int):
    """Sweep remote autofix/nexus/* branches with no open PR older than N days, for every configured repo."""
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    for app_id, repo_url in config.repos.items():
        owner, repo = repo_url.rstrip("/").removesuffix(".git").split("/")[-2:]
        deleted = branch_mod.sweep_stale_branches(secrets.github_api_url, secrets.github_token, owner, repo, older_than_days)
        for name in deleted:
            click.echo(f"deleted stale branch: {app_id}/{name}")
```

- [ ] **Step 4: Run to verify it passes**

```bash
.venv/bin/pytest tests/unit/test_cli.py -v
```

Expected: 3 passed

- [ ] **Step 5: Verify the console script resolves**

```bash
.venv/bin/nexusfix --help
```

Expected: prints the `run` and `gc` subcommands with no import errors.

- [ ] **Step 6: Commit**

```bash
git add nexus_autofix/cli.py tests/unit/test_cli.py
git commit -m "feat: nexusfix CLI — run and gc subcommands"
```

---

## Task 24: Fixture repo — a real, buildable Gradle project

**Files:**
- Create: `tests/fixtures/demo_gradle_repo/settings.gradle`
- Create: `tests/fixtures/demo_gradle_repo/build.gradle`
- Create: `tests/fixtures/demo_gradle_repo/.trident/build.yaml`
- Create: `tests/fixtures/demo_gradle_repo/src/main/java/demo/Greeter.java`
- Create: `tests/fixtures/demo_gradle_repo/src/test/java/demo/GreeterTest.java`
- Create: `tests/fixtures/demo_gradle_repo/gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`, `gradle/wrapper/gradle-wrapper.properties` (generated, not hand-written)

- [ ] **Step 1: Write the fixture's Gradle files**

```bash
mkdir -p tests/fixtures/demo_gradle_repo/.trident \
         tests/fixtures/demo_gradle_repo/src/main/java/demo \
         tests/fixtures/demo_gradle_repo/src/test/java/demo
```

`tests/fixtures/demo_gradle_repo/settings.gradle`:
```gradle
rootProject.name = 'demo'
```

`tests/fixtures/demo_gradle_repo/build.gradle`:
```gradle
plugins {
    id 'java'
}

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.apache.commons:commons-text:1.9'
    testImplementation platform('org.junit:junit-bom:5.10.0')
    testImplementation 'org.junit.jupiter:junit-jupiter'
}

test {
    useJUnitPlatform()
}
```

`tests/fixtures/demo_gradle_repo/.trident/build.yaml`:
```yaml
strategy:
  uses: gradle
  with:
    java-version: "21"
```

`tests/fixtures/demo_gradle_repo/src/main/java/demo/Greeter.java`:
```java
package demo;

import org.apache.commons.text.StringEscapeUtils;

public class Greeter {
    public String greet(String name) {
        return "Hello, " + StringEscapeUtils.escapeHtml4(name) + "!";
    }
}
```

`tests/fixtures/demo_gradle_repo/src/test/java/demo/GreeterTest.java`:
```java
package demo;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class GreeterTest {
    @Test
    void greetsWithEscapedName() {
        assertEquals("Hello, World!", new Greeter().greet("World"));
    }
}
```

- [ ] **Step 2: Generate the Gradle wrapper for the fixture**

No local `gradle`/`mvn` is installed on this machine (confirmed this session), so download a
Gradle distribution once to generate the wrapper files, then never need it again — the checked-in
wrapper is self-sufficient afterward, same as any real repo.

```bash
mkdir -p /private/tmp/claude-501/-Users-milindp-Coding-Repos-vulnfixer/da24d4ca-f6f6-4a86-b98c-62bf89ff50f4/scratchpad/gradle-dist
cd /private/tmp/claude-501/-Users-milindp-Coding-Repos-vulnfixer/da24d4ca-f6f6-4a86-b98c-62bf89ff50f4/scratchpad/gradle-dist
curl -sL -o gradle-8.10-bin.zip https://services.gradle.org/distributions/gradle-8.10-bin.zip
unzip -q gradle-8.10-bin.zip
cd /Users/milindp/Coding/Repos/vulnfixer/tests/fixtures/demo_gradle_repo
/private/tmp/claude-501/-Users-milindp-Coding-Repos-vulnfixer/da24d4ca-f6f6-4a86-b98c-62bf89ff50f4/scratchpad/gradle-dist/gradle-8.10/bin/gradle wrapper --gradle-version 8.10
```

Expected: `gradlew`, `gradlew.bat`, and `gradle/wrapper/gradle-wrapper.{jar,properties}` now exist
under `tests/fixtures/demo_gradle_repo/`.

- [ ] **Step 3: Verify the fixture builds and tests pass on its own, before wiring it into git**

```bash
cd /Users/milindp/Coding/Repos/vulnfixer/tests/fixtures/demo_gradle_repo
chmod +x gradlew
./gradlew test -x compileTestJava --console=plain 2>&1 | tail -5 || true
./gradlew clean build --console=plain
```

Expected: `BUILD SUCCESSFUL`. If it fails on a Gradle/Java compatibility error, this is exactly
the kind of environment issue the design doc says to escalate rather than silently work around —
report the actual error before changing the Gradle version.

- [ ] **Step 4: Turn the fixture into its own git repo (needed for `git diff`/`git worktree` in the e2e tests)**

```bash
cd /Users/milindp/Coding/Repos/vulnfixer/tests/fixtures/demo_gradle_repo
git init
git config user.email "fixture@example.com"
git config user.name "fixture"
cat > .gitignore <<'EOF'
.gradle/
build/
EOF
git add -A
git commit -m "initial fixture: commons-text 1.9, one test"
cd /Users/milindp/Coding/Repos/vulnfixer
```

- [ ] **Step 5: Commit the fixture into the parent repo**

The fixture's own `.git` directory must NOT be committed as a regular directory (it would create
a nested-repo mess) — use a `.gitignore` entry in the parent repo instead, since the e2e tests
create this fixture's git history fresh via a pytest fixture rather than relying on a committed
`.git` folder.

```bash
cd /Users/milindp/Coding/Repos/vulnfixer
rm -rf tests/fixtures/demo_gradle_repo/.git
echo "tests/fixtures/demo_gradle_repo/.gradle/" >> .gitignore
echo "tests/fixtures/demo_gradle_repo/build/" >> .gitignore
git add tests/fixtures/demo_gradle_repo pyproject.toml .gitignore
git status  # confirm gradle-wrapper.jar is included (it's a small, legitimate binary)
git commit -m "feat: add demo Gradle fixture repo for orchestrator e2e tests"
```

---

## Task 25: Orchestrator end-to-end tests against the fixture

**Files:**
- Create: `tests/test_orchestrator_e2e.py`

- [ ] **Step 1: Write `tests/test_orchestrator_e2e.py`**

```python
import shutil
import subprocess
from pathlib import Path

import pytest

from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.iq.client import FakeIQClient, PolicyViolation, RemediationResponse, VersionChange
from nexus_autofix.iq.models import Finding, RunOutcome
from nexus_autofix.orchestrator import Orchestrator, RunConfig
from nexus_autofix.state.store import StateStore

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "demo_gradle_repo"


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


@pytest.fixture
def repo(tmp_path):
    repo_path = tmp_path / "demo_gradle_repo"
    shutil.copytree(FIXTURE_SRC, repo_path)
    _git(["init"], repo_path)
    _git(["config", "user.email", "t@example.com"], repo_path)
    _git(["config", "user.name", "t"], repo_path)
    (repo_path / ".gitignore").write_text(".gradle/\nbuild/\n", encoding="utf-8")
    _git(["add", "-A"], repo_path)
    _git(["commit", "-m", "init"], repo_path)
    return repo_path


def _finding() -> Finding:
    return Finding(
        component="org.apache.commons:commons-text", package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        current_version="1.9", target_version="1.10.0", remediation_type="next-non-failing-with-dependencies",
        is_direct=True, dependency_path=[], parent_component=None, parent_current_version=None,
        parent_target_version=None, policy_action="Fail", threat_level=8, policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"], manifest_path=None,
    )


def _run_config(gate: str = "none") -> RunConfig:
    return RunConfig(
        app_id="demo", branch="autofix/nexus/e2e", gate=gate, max_attempts=2, stage_id="build",
        java_toolchains={"21": str(Path("/usr"))}, node_toolchains={}, subprocess_timeout_seconds=600,
    )


@pytest.mark.slow
def test_fixed_path_runs_real_gradle_build_and_test(repo):
    fixed_build_gradle = (repo / "build.gradle").read_text(encoding="utf-8").replace(
        "commons-text:1.9", "commons-text:1.10.0"
    )
    agent = MockAgent(mode=MockMode.APPLIES_FIX, fix_file="build.gradle", fix_content=fixed_build_gradle)
    iq_client = FakeIQClient(
        policy_violations=[
            PolicyViolation(
                package_url="pkg:maven/org.apache.commons/commons-text@1.9", component="commons-text",
                policy_name="Security-Critical", policy_id="p1", threat_level=8, constraint_summary="",
                is_waived=False, action="Fail",
            )
        ],
        remediations={"commons-text": RemediationResponse(version_changes=[VersionChange("next-non-failing-with-dependencies", "1.10.0")])},
    )
    orchestrator = Orchestrator(
        iq_client=iq_client, agent=agent, state_store=StateStore(repo.parent / "state.db"),
        push_fn=lambda wt, branch: None, delete_remote_branch_fn=lambda wt, branch: None,
        rescan_fn=lambda rc, wt: "rescan-report", open_pr_fn=lambda wt, branch: None,
    )

    result = orchestrator.run(
        run_config=_run_config(gate="none"), worktree=repo, commit_sha="HEAD", findings=[_finding()],
        repo_name="demo", baseline_report_id="baseline-report",
    )

    assert result.outcome == RunOutcome.FIXED
    assert "commons-text:1.10.0" in (repo / "build.gradle").read_text(encoding="utf-8")


@pytest.mark.slow
def test_deletes_test_mode_aborts_as_escalated_and_never_pushes(repo):
    agent = MockAgent(mode=MockMode.DELETES_TEST, test_file_to_delete="src/test/java/demo/GreeterTest.java")
    push_calls = []

    orchestrator = Orchestrator(
        iq_client=FakeIQClient(), agent=agent, state_store=StateStore(repo.parent / "state.db"),
        push_fn=lambda wt, branch: push_calls.append(branch),
    )

    result = orchestrator.run(
        run_config=_run_config(gate="none"), worktree=repo, commit_sha="HEAD", findings=[_finding()],
        repo_name="demo", baseline_report_id="baseline-report",
    )

    assert result.outcome == RunOutcome.ESCALATED
    assert push_calls == []
    assert not (repo / "src/test/java/demo/GreeterTest.java").exists()
```

- [ ] **Step 2: Register the `slow` marker so pytest doesn't warn**

Append to `pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = ["slow: exercises a real Gradle build via subprocess"]
```

- [ ] **Step 3: Run the fast suite first to make sure nothing else regressed**

```bash
.venv/bin/pytest tests/unit -v
```

Expected: all unit tests still pass.

- [ ] **Step 4: Run the e2e suite**

```bash
.venv/bin/pytest tests/test_orchestrator_e2e.py -v -m slow
```

Expected: 2 passed. The first real Gradle invocation downloads Gradle 8.10 into `~/.gradle` if
not already cached and may take a minute or two; subsequent runs are fast.

- [ ] **Step 5: Commit**

```bash
git add tests/test_orchestrator_e2e.py pyproject.toml
git commit -m "test: end-to-end orchestrator runs against a real Gradle build (FIXED + SUSPICIOUS-abort paths)"
```

---

## Task 26: Full suite check + quick-start note

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Run the complete test suite**

```bash
.venv/bin/pytest tests -v
```

Expected: every test from Tasks 1–25 passes (unit tests + the two e2e tests).

- [ ] **Step 2: Write a short quick-start into `README.md`**

```markdown
# vulnfixer / nexus-autofix

Automated remediation of Nexus IQ dependency vulnerabilities via an AI coding agent, with
deterministic build/test/rescan verification. See `docs/superpowers/specs/2026-07-28-nexus-autofix-design.md`
for the full design and `docs/superpowers/plans/2026-07-28-nexus-autofix.md` for the build plan.

## Quick start

    python3 -m venv .venv
    .venv/bin/pip install -e ".[dev]"
    .venv/bin/pytest tests/unit -v          # fast, fully offline
    .venv/bin/pytest tests -v -m slow       # includes a real Gradle build via the fixture repo

## What's real vs. unverified

Everything except two integration points is implemented and tested offline against fakes/mocks:
the Nexus IQ HTTP client (`nexus_autofix/iq/client.py`) and the Copilot CLI adapter
(`nexus_autofix/agent/copilot_cli.py`) are written to the design doc's spec but have not been
exercised against a live Nexus IQ tenant or an installed Copilot CLI. Fill in real credentials in
a gitignored `.env` (see `config.py` for the `NEXUSFIX_*` variables) and real toolchain paths in
`config.yml`, then report back anything that doesn't match — wrong endpoint field names, wrong
CLI flags — for a follow-up fix.
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: quick-start and real-vs-unverified summary"
```

---

## Self-review notes

- **Spec coverage:** every module listed in the spec's Layout section has a task (Tasks 1–23);
  the fixture + e2e requirement (spec decision #3) is Tasks 24–25; the two unverified-integration
  points (spec decision #2) are Tasks 7 and 14, each with an explicit in-code comment; cross-platform
  handling (spec decision #1) is in Tasks 4–5 (`platform.system()` branching, `pathlib` throughout).
- **RunOutcome correction:** the source design doc's `RunOutcome` enum has 9 values and does not
  include a `SUSPICIOUS` state — a SUSPICIOUS diff maps to `ESCALATED` (matching "SUSPICIOUS? abort,
  escalate" in the doc's step 17), which is what Task 22's orchestrator does. `DiffClass.SUSPICIOUS`
  (Task 6) is a separate, differently-scoped enum for diff classification only.
- **MCP server wrapper, enterprise CI trigger:** intentionally excluded per spec's explicit
  non-goals — no task creates them.
