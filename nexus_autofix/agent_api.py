"""Machine-readable entry points for when a coding agent is the orchestrator.

The default design has nexus-autofix drive and the agent fix one step. This module
supports the inverse: the agent drives, reading a runbook, and calls these commands as
tools. It exists because some Copilot policies block unattended tool use, making the
agent-as-subroutine model unusable.

What is deliberately NOT given up: the checks that exist because an agent's account of
its own work cannot be trusted. `check` still classifies the diff and refuses a
SUSPICIOUS one, still runs the real build and test in the resolved toolchain, and still
reads changed files from git rather than from anything the agent says. An agent that
skips calling `check` gets no verdict at all, and `publish` refuses to run without one.

Everything here prints JSON on stdout and nothing else, so an agent can parse it. Human
logging goes to the run's log file as usual.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

from nexus_autofix.iq.models import Finding
from nexus_autofix.verify import commands as commands_mod
from nexus_autofix.verify import diff as diff_mod
from nexus_autofix.verify import toolchain as toolchain_mod

log = logging.getLogger(__name__)

#: Written into the run directory by `check`, read by `publish`. Publishing is gated on a
#: verdict this tool produced itself; without it there is nothing stopping an agent from
#: reporting success it did not earn.
VERDICT_FILENAME = "verdict.json"


@dataclass
class FindingView:
    """A finding as an agent should see it: what to change, and to what."""

    component: str
    package_url: str
    current_version: str
    target_version: str | None
    remediation_type: str | None
    threat_level: int
    policy_name: str
    is_direct: bool
    #: The purls that pull this in. Non-empty means the manifest almost certainly does not
    #: name this component at all and the bump belongs to one of these instead.
    pulled_in_by: list[str] = field(default_factory=list)
    actionable: bool = True
    reason_not_actionable: str | None = None


def finding_views(findings: list[Finding], min_threat_level: int) -> list[FindingView]:
    views = []
    for f in findings:
        if f.threat_level < min_threat_level or f.is_waived:
            continue
        views.append(
            FindingView(
                component=f.component,
                package_url=f.package_url,
                current_version=f.current_version,
                target_version=f.target_version,
                remediation_type=f.remediation_type,
                threat_level=f.threat_level,
                policy_name=f.policy_name,
                is_direct=f.is_direct,
                pulled_in_by=list(f.dependency_path or []),
                actionable=f.is_actionable,
                reason_not_actionable=None if f.is_actionable else (
                    f.escalation_reason or "Nexus IQ offered no newer version"
                ),
            )
        )
    return views


def as_json(payload: object) -> str:
    return json.dumps(payload, indent=2, default=str)


@dataclass
class CheckResult:
    """The verdict on whatever is currently in the worktree."""

    ok: bool
    worktree: str
    changed_files: list[str]
    diff_classification: str
    suspicious_reasons: list[str] = field(default_factory=list)
    build_ok: bool | None = None
    build_output_tail: str | None = None
    test_ok: bool | None = None
    test_output_tail: str | None = None
    #: Contract / integration test tasks found in the repo and run after `test`.
    #: Empty means none were found — NOT that none exist, if discovery failed.
    extra_test_tasks: list[str] = field(default_factory=list)
    extra_tests_ok: bool | None = None
    extra_test_output_tail: str | None = None
    message: str = ""


def check_worktree(
    worktree: Path,
    ecosystem: str,
    java_version: str | None,
    node_version: str | None,
    java_toolchains: dict[str, str],
    node_toolchains: dict[str, str],
    timeout_seconds: int,
    env: dict[str, str],
    base_ref: str = "HEAD",
    run_extra_tests: bool = True,
) -> CheckResult:
    """Classify the diff, then build and test — in that order, and stopping early.

    The order is the point. A SUSPICIOUS diff is refused BEFORE anything is built, because
    a diff that disables tests or waives the policy can be made to build and pass
    trivially. Running the build first and the classifier second would let exactly the
    changes this is meant to catch report a clean result.

    `base_ref` should be the commit the worktree was created at, NOT the default HEAD.
    Agents commit out of habit however firmly the runbook says not to, and against HEAD a
    committed change diffs to nothing — so the work would be reported as "nothing changed"
    and never verified. Diffing from the run's base commit gives the same answer whether
    the agent committed or not.
    """
    diff_result = diff_mod.classify_diff(worktree, base_ref)
    base = {
        "worktree": str(worktree),
        "changed_files": diff_result.changed_files,
        "diff_classification": diff_result.classification.value,
    }

    if not diff_result.changed_files:
        return CheckResult(
            ok=False, **base,
            message="nothing changed in the worktree — make the edits before checking",
        )

    if diff_result.classification == diff_mod.DiffClass.SUSPICIOUS:
        return CheckResult(
            ok=False, **base,
            suspicious_reasons=diff_result.suspicious_reasons,
            message=(
                "REFUSED: this diff does things a dependency fix must not do. Revert them "
                "and change only dependency versions. This is not negotiable and cannot be "
                "overridden by re-running check."
            ),
        )

    for version, table, resolve in (
        (java_version, java_toolchains, toolchain_mod.resolve_java_env),
        (node_version, node_toolchains, toolchain_mod.resolve_node_env),
    ):
        if version:
            try:
                env = resolve(version, table, env).env
            except toolchain_mod.MissingToolchainError as exc:
                return CheckResult(ok=False, **base, message=f"toolchain unavailable: {exc}")

    build_cmd = commands_mod.BUILD_COMMANDS[ecosystem](worktree)
    build = commands_mod.run_command(build_cmd, worktree, env, timeout_seconds)
    if not build.success:
        return CheckResult(
            ok=False, **base, build_ok=False, build_output_tail=build.tail(),
            message=f"build failed: {' '.join(build_cmd)}",
        )

    test_cmd = commands_mod.TEST_COMMANDS[ecosystem](worktree)
    test = commands_mod.run_command(test_cmd, worktree, env, timeout_seconds)
    if not test.success:
        return CheckResult(
            ok=False, **base, build_ok=True, test_ok=False, test_output_tail=test.tail(),
            message=(
                f"tests failed: {' '.join(test_cmd)}. Fix the dependency change so the "
                "existing tests pass. Do NOT modify, skip or delete tests."
            ),
        )

    # A repo can register contract, integration or Pact tests as tasks wired into neither
    # `test` nor `check`. Nothing above runs them, so a bump that breaks a consumer
    # contract reaches here reporting a clean result. Discovered per repo rather than
    # configured, because which of these exist differs from repo to repo.
    extra_tasks: list[str] = []
    if run_extra_tests and ecosystem == "gradle":
        extra_tasks = commands_mod.discover_extra_test_tasks(worktree, env, timeout_seconds)

    if not extra_tasks:
        return CheckResult(
            ok=True, **base, build_ok=True, test_ok=True,
            message="build and tests pass, and the diff contains only dependency changes",
        )

    log.info("running %d extra test task(s): %s", len(extra_tasks), ", ".join(extra_tasks))
    extra_cmd = [commands_mod._gradle_executable(worktree), *extra_tasks]
    extra = commands_mod.run_command(extra_cmd, worktree, env, timeout_seconds)
    if not extra.success:
        return CheckResult(
            ok=False, **base, build_ok=True, test_ok=True,
            extra_test_tasks=extra_tasks, extra_tests_ok=False,
            extra_test_output_tail=extra.tail(),
            message=(
                f"the unit tests pass but {' '.join(extra_tasks)} failed. These are "
                "contract or integration tests this repo defines outside `test`. If they "
                "need infrastructure that is not reachable from here rather than being "
                "broken by the change, re-run with extra tests disabled — do NOT modify "
                "or delete the tests."
            ),
        )

    return CheckResult(
        ok=True, **base, build_ok=True, test_ok=True,
        extra_test_tasks=extra_tasks, extra_tests_ok=True,
        message=(
            "build and tests pass, and the diff contains only dependency changes"
            + (f" (including {', '.join(extra_tasks)})" if extra_tasks else "")
        ),
    )


def write_verdict(run_dir: Path, result: CheckResult) -> Path:
    path = run_dir / VERDICT_FILENAME
    path.write_text(as_json(asdict(result)), encoding="utf-8")
    return path


def read_verdict(run_dir: Path) -> dict | None:
    path = run_dir / VERDICT_FILENAME
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


# --- run state, so `check` and `publish` can pick up where `discover` left off ---------
# Three separate process invocations, so what discover worked out has to survive on disk.
# Written into the run directory next to the log, which is already this run's audit trail.

STATE_FILENAME = "run.json"

RUNBOOK_FILENAME = "RUNBOOK.md"


def place_runbook(run_dir: Path) -> Path | None:
    """Copy the runbook into the run directory, beside the worktree but outside it.

    Two reasons it goes in `run_dir` rather than the worktree:

    * The worktree is a git checkout and `git status --porcelain` reports untracked files,
      so a runbook left inside it would land in the diff, be classified, and be committed
      onto the fix branch.
    * It means the agent only ever needs `run_dir` open, which contains the worktree and
      nothing else. The directory holding `.env` and `config.yml` stays out of its
      workspace entirely.
    """
    for candidate in (
        Path(__file__).resolve().parent.parent / RUNBOOK_FILENAME,  # editable install
        Path.cwd() / RUNBOOK_FILENAME,
    ):
        if candidate.is_file():
            destination = run_dir / RUNBOOK_FILENAME
            destination.write_text(candidate.read_text(encoding="utf-8"), encoding="utf-8")
            return destination
    log.warning(
        "could not find %s to copy into the run directory; point the agent at the copy in "
        "the repository instead", RUNBOOK_FILENAME,
    )
    return None


def save_run_state(run_dir: Path, state: dict) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / STATE_FILENAME
    path.write_text(as_json(state), encoding="utf-8")
    return path


def load_run_state(workspace_root: Path, run_id: str) -> dict:
    path = workspace_root / "runs" / run_id / STATE_FILENAME
    if not path.is_file():
        raise FileNotFoundError(
            f"no run state at {path}. Pass the run_id printed by `nexusfix discover`, and "
            "make sure NEXUSFIX_WORKSPACE_ROOT is the same as it was then."
        )
    return json.loads(path.read_text(encoding="utf-8"))
