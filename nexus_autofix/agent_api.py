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
    #: Nexus IQ named a target version, but a rule held it back — a major jump, most often.
    #: Distinct from "there is nothing to do": these CAN be fixed, once a human says so.
    #: The agent is expected to investigate these and recommend; `nexusfix approve` is how
    #: the human answers. False for a finding with no target version at all, which no
    #: amount of approving can help.
    needs_approval: bool = False
    #: Where this finding came from: "iq" (a Nexus IQ policy violation), "appsec" (the SCA
    #: worksheet), or both when the same component is reported by each. Defaults to "iq" so
    #: an ordinary `discover` run is unchanged.
    source: list[str] = field(default_factory=lambda: ["iq"])
    #: CVEs behind this finding. An AppSec library carries every CVE from the rows that
    #: folded into it — the export lists one row per CVE.
    cve_ids: list[str] = field(default_factory=list)
    #: What each source recommends, when there is an AppSec finding to compare. Both are
    #: populated even once resolved, so the PR shows what the choice was between.
    iq_version: str | None = None
    sheet_version: str | None = None
    #: RESOLVED / CONFLICT / SWAP_ONLY / NO_TARGET. None for a plain IQ finding.
    appsec_decision: str | None = None
    #: The only versions `nexusfix resolve` will accept. Empty unless CONFLICT.
    candidate_versions: list[str] = field(default_factory=list)
    #: Fixes the sheet proposes that name a DIFFERENT artifact — a migration rather than a
    #: bump. Recorded so a human can see them; never applied.
    swap_candidates: list[str] = field(default_factory=list)


def finding_views(
    findings: list[Finding],
    min_threat_level: int,
    not_actionable: dict[str, str] | None = None,
) -> list[FindingView]:
    """Turn findings into what the agent reads out of run.json.

    `not_actionable` maps package_url -> why, for findings `filter_findings` escalated —
    a major version jump, a target that is not actually newer, a suppressed component.
    Without it, `actionable` reflects only whether Nexus IQ named ANY target version, which
    is true even for a change no one should make unattended. The RUNBOOK tells the agent to
    use `target_version` exactly, so anything reaching it as actionable will be attempted.
    """
    escalated = not_actionable or {}
    views = []
    for f in findings:
        if f.threat_level < min_threat_level or f.is_waived:
            continue
        reason = escalated.get(f.package_url)
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
                actionable=f.is_actionable and reason is None,
                reason_not_actionable=reason or (None if f.is_actionable else (
                    f.escalation_reason or "Nexus IQ offered no newer version"
                )),
                cve_ids=list(f.cve_ids or []),
                # Held back by a rule, but IQ did name a version — so a human can release
                # it. A finding with no target version is not approvable at any price.
                needs_approval=reason is not None and f.is_actionable,
            )
        )
    return views


def appsec_finding_views(resolved: list[tuple]) -> list[FindingView]:
    """Turn resolved AppSec targets into the same view the agent already reads.

    Takes (target, component, package_url) triples: the component NAME has to come from the
    caller because it is only authoritative when the library matched an IQ violation —
    `_clean_component_name` produces "groupId:artifactId", which is what `merge_views`
    joins on, and a library with no group id cannot produce that on its own.

    Producing FindingView rather than a parallel shape is the whole reason `check`,
    `publish` and RUNBOOK.md need no structural change: an AppSec finding is just a finding
    with a different `source`.
    """
    from nexus_autofix.appsec.resolve import Decision

    views = []
    for target, component, package_url in resolved:
        library = target.library
        views.append(
            FindingView(
                component=component,
                package_url=package_url,
                current_version=target.current_version,
                target_version=target.target_version,
                remediation_type="appsec",
                # The sheet grades with CVSS3, not IQ's 0-10 threat level. Rounding one into
                # the other would invent a number IQ never produced, so this stays 0 and the
                # CVSS score travels in its own field.
                threat_level=0,
                policy_name="AppSec SCA worksheet",
                is_direct=bool(library.direct),
                actionable=target.actionable,
                reason_not_actionable=None if target.actionable else target.reason,
                source=["appsec"],
                cve_ids=list(library.cve_ids),
                iq_version=target.iq_version,
                sheet_version=target.sheet_version,
                appsec_decision=target.decision.value,
                candidate_versions=(
                    list(target.candidates) if target.decision is Decision.CONFLICT else []
                ),
                swap_candidates=[str(g) for g in target.swap_candidates],
            )
        )
    return views


def merge_views(iq_views: list[FindingView], appsec_views: list[FindingView]) -> list[FindingView]:
    """One entry per component, even when both sources report it.

    Two findings for one manifest line would hand the agent two instructions for the same
    edit. The IQ entry wins on the version — it comes from the policy engine and describes
    the branch being scanned — while the AppSec entry contributes its CVEs and the fact that
    AppSec is tracking this too.
    """
    by_component = {view.component: view for view in iq_views}
    merged = list(iq_views)

    for view in appsec_views:
        existing = by_component.get(view.component)
        if existing is None:
            merged.append(view)
            continue

        existing.source = sorted(set(existing.source) | set(view.source))
        existing.cve_ids = list(dict.fromkeys([*existing.cve_ids, *view.cve_ids]))
        existing.sheet_version = view.sheet_version
        existing.iq_version = view.iq_version
        existing.appsec_decision = view.appsec_decision
        existing.swap_candidates = view.swap_candidates

        # The AppSec decision was reached WITH IQ's remediation as one of its two inputs, so
        # it is the better-informed of the two — never the weaker one to discard. In
        # particular a CONFLICT must survive the merge: leaving IQ's target in place here
        # would quietly resolve, in IQ's favour, the exact disagreement a human is supposed
        # to settle, and `check` would let it through.
        if not view.actionable:
            existing.actionable = False
            existing.target_version = view.target_version
            existing.reason_not_actionable = view.reason_not_actionable
            existing.candidate_versions = view.candidate_versions
    return merged


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
    #: Contract tests run after the unit tests. Empty means either the repo has none,
    #: or `run_contract_tests` is off for it — NOT that none exist.
    contract_test_tasks: list[str] = field(default_factory=list)
    contract_tests_ok: bool | None = None
    contract_test_output_tail: str | None = None
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
    run_contract_tests: bool = False,
    contract_test_command: list[str] | None = None,
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

    # Contract tests are registered as tasks wired into neither `test` nor `check`, so
    # nothing above runs them and a bump that breaks a consumer contract reaches here
    # reporting a clean result. Off unless the repo asks for it: whether they can run
    # outside CI is a property of the repo, not something to assume.
    contract_cmd: list[str] = []
    tasks: list[str] = []
    if run_contract_tests:
        if contract_test_command:
            # Stated explicitly, for an ecosystem whose contract tests are a script name
            # of the repo's choosing rather than a discoverable task.
            contract_cmd = list(contract_test_command)
            contract_cmd[0] = commands_mod.resolve_program(contract_cmd[0], env)
            tasks = [" ".join(contract_test_command)]
        elif ecosystem == "gradle":
            tasks = commands_mod.discover_contract_test_tasks(worktree, env, timeout_seconds)
            if tasks:
                contract_cmd = [commands_mod._gradle_executable(worktree), *tasks]
        else:
            log.warning(
                "run_contract_tests is on for a %s repo, but contract tests can only be "
                "discovered for gradle. Set `contract_test_command` for this repo, or the "
                "contract tests will not run.", ecosystem,
            )

    if not contract_cmd:
        return CheckResult(
            ok=True, **base, build_ok=True, test_ok=True,
            message="build and tests pass, and the diff contains only dependency changes",
        )

    log.info("running contract tests: %s", ", ".join(tasks))
    contract = commands_mod.run_command(contract_cmd, worktree, env, timeout_seconds)
    if not contract.success:
        return CheckResult(
            ok=False, **base, build_ok=True, test_ok=True,
            contract_test_tasks=tasks, contract_tests_ok=False,
            contract_test_output_tail=contract.tail(),
            message=(
                f"the unit tests pass but the contract tests failed: {', '.join(tasks)}. "
                "A dependency bump can change a serialised payload and break a consumer "
                "contract without any unit test noticing, so treat this as a real failure "
                "and fix the change. Do NOT modify or delete the contract tests."
            ),
        )

    return CheckResult(
        ok=True, **base, build_ok=True, test_ok=True,
        contract_test_tasks=tasks, contract_tests_ok=True,
        message=(
            "build, tests and contract tests pass, and the diff contains only dependency "
            f"changes (contract tests: {', '.join(tasks)})"
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
