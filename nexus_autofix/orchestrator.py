from __future__ import annotations

import logging
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from nexus_autofix.agent.base import AgentRunner
from nexus_autofix.agent.prompt import RetryContext, build_prompt
from nexus_autofix.iq.client import IQClient
from nexus_autofix.iq.filter import DEFAULT_MIN_THREAT_LEVEL, filter_findings
from nexus_autofix.iq.models import Finding, RepoProfile, RunOutcome
from nexus_autofix.publish import branch as branch_mod
from nexus_autofix.publish.gate import GateMode
from nexus_autofix.repo import trident as trident_mod
from nexus_autofix.state.store import StateStore
from nexus_autofix.verify import commands as commands_mod
from nexus_autofix.verify import diff as diff_mod
from nexus_autofix.verify import rescan as rescan_mod
from nexus_autofix.verify import toolchain as toolchain_mod

log = logging.getLogger(__name__)

VALID_GATES = {mode.value for mode in GateMode}


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
    min_threat_level: int = DEFAULT_MIN_THREAT_LEVEL

    def __post_init__(self) -> None:
        # An unvalidated gate string is a fail-open: a typo like "pre_push" or
        # "PRE-PR" would silently fall through every gate check straight to the
        # full-auto publish path.
        if self.gate not in VALID_GATES:
            raise ValueError(
                f"invalid gate: {self.gate!r}, must be one of "
                f"{'/'.join(sorted(VALID_GATES))}"
            )


@dataclass
class RunResult:
    """The disposition of every finding this run saw.

    The four finding lists are meant to partition the input, so a human triaging a
    half-finished run can see what happened to everything:

    * ``fixed`` — remediated, verified, and published (or awaiting approval).
    * ``escalated`` — needs a human. Always includes the findings the filter itself
      routed away (major bumps, no remediation available). On the *environment*
      escalation paths (no usable .trident strategy, multi-ecosystem repo, missing
      toolchain) it additionally includes the actionable set, because in those cases
      the whole batch is escalated before the agent is ever invoked.
    * ``not_attempted`` — exactly the filter-routed-away set (``filtered.escalate``),
      on every path, with no environment-escalation overlay. This is the field to
      read when you want the unambiguous "the agent was never asked to touch these"
      answer.
    * ``attempted_but_unresolved`` — findings that WERE actionable and the agent DID
      attempt, but the run did not reach a fixed state (build/test exhausted, rescan
      failed, human rejected, no changes made, suspicious diff).
    """

    run_id: str
    outcome: RunOutcome
    fixed: list[Finding] = field(default_factory=list)
    escalated: list[Finding] = field(default_factory=list)
    not_attempted: list[Finding] = field(default_factory=list)
    attempted_but_unresolved: list[Finding] = field(default_factory=list)
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
        rescan_fn,
        open_pr_fn,
        approve_fn,
        commit_fn=None,
        push_fn=None,
        delete_remote_branch_fn=None,
    ):
        # rescan_fn / open_pr_fn / approve_fn are REQUIRED and deliberately have no
        # defaults: a no-op rescan, a no-op PR opener or an auto-approve default all
        # fail *open* — a caller who forgot to wire them would get a silent FIXED
        # outcome with nothing rescanned and no PR. commit/push/delete keep their
        # defaults because those do the real git work, not a fake success.
        self._iq = iq_client
        self._agent = agent
        self._state = state_store
        self._commit_fn = commit_fn or _default_commit
        self._push_fn = push_fn or (lambda worktree, branch: branch_mod.push_branch(worktree, "origin", branch))
        self._delete_remote_branch_fn = delete_remote_branch_fn or (
            lambda worktree, branch: branch_mod.delete_remote_branch(worktree, "origin", branch)
        )
        self._rescan_fn = rescan_fn
        self._open_pr_fn = open_pr_fn
        self._approve_fn = approve_fn

    def run(
        self,
        run_config: RunConfig,
        worktree: Path,
        commit_sha: str,
        findings: list[Finding],
        repo_name: str,
        baseline_report_id: str,
        suppressed_components: set[str] = frozenset(),
    ) -> RunResult:
        run_id = str(uuid.uuid4())
        self._state.start_run(run_id, run_config.app_id, run_config.branch, datetime.now(timezone.utc).isoformat())

        filtered = None
        pushed = False
        pr_opened = False
        try:
            filtered = filter_findings(
                findings,
                suppressed_components=set(suppressed_components),
                min_threat_level=run_config.min_threat_level,
            )
            for f in filtered.escalate:
                self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "escalate")
            for f in filtered.ignore:
                self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "ignore")

            log.info(
                "filter: %d actionable, %d escalated, %d ignored (threat level >= %d)",
                len(filtered.actionable), len(filtered.escalate), len(filtered.ignore),
                run_config.min_threat_level,
            )
            for f in filtered.escalate:
                log.info("  escalated: %s %s -> %s (%s)", f.component, f.current_version,
                         f.target_version or "no target", f.escalation_reason or "no remediation offered")

            if not filtered.actionable:
                log.info("nothing actionable — finishing without invoking the agent")
                return self._finish(
                    run_id, RunOutcome.CLEAN,
                    escalated=filtered.escalate, not_attempted=filtered.escalate,
                )

            for f in filtered.actionable:
                self._state.record_finding(run_id, f.component, f.package_url, f.current_version, f.target_version, "actionable")

            try:
                strategies = trident_mod.parse_trident_build_yaml(worktree / ".trident" / "build.yaml")
            except (FileNotFoundError, ValueError):
                strategies = []

            if not strategies:
                log.error("no usable strategy in %s — escalating", worktree / ".trident" / "build.yaml")
                return self._finish(
                    run_id, RunOutcome.ESCALATED,
                    escalated=filtered.escalate + filtered.actionable, not_attempted=filtered.escalate,
                    notes=["no usable .trident/build.yaml strategy found"],
                )

            if len(strategies) > 1:
                # Only strategies[0] would be built/tested, but `git add -A` commits the
                # WHOLE worktree — so a Gradle-backend + npm-frontend repo would publish
                # unverified frontend changes under a FIXED outcome. Per-module sessions
                # are the design's answer and aren't built yet; escalate honestly.
                log.error("repo declares %d .trident strategies (%s) — escalating rather than "
                          "publishing unverified changes from the modules that were not built",
                          len(strategies), [s.ecosystem for s in strategies])
                return self._finish(
                    run_id, RunOutcome.ESCALATED,
                    escalated=filtered.escalate + filtered.actionable, not_attempted=filtered.escalate,
                    notes=[
                        "repo declares multiple .trident strategies (multi-ecosystem: "
                        f"{[s.ecosystem for s in strategies]}); running one session per "
                        "module isn't implemented yet — escalate"
                    ],
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
                log.error("toolchain unavailable: %s — escalating", exc)
                return self._finish(
                    run_id, RunOutcome.ESCALATED,
                    escalated=filtered.escalate + filtered.actionable, not_attempted=filtered.escalate,
                    notes=[str(exc)],
                )

            profile = RepoProfile(
                ecosystem=strategy.ecosystem, java_version=java_version, node_version=node_version,
                modules=[], source="trident",
            )
            build_cmd = commands_mod.BUILD_COMMANDS[strategy.ecosystem](worktree)
            test_cmd = commands_mod.TEST_COMMANDS[strategy.ecosystem](worktree)
            log.info("ecosystem=%s java=%s node=%s", strategy.ecosystem, java_version, node_version)
            log.info("build command: %s", " ".join(build_cmd))
            log.info("test command:  %s", " ".join(test_cmd))

            retry_context: RetryContext | None = None
            for attempt in range(1, run_config.max_attempts + 1):
                prompt = build_prompt(
                    repo_name=repo_name, fix_branch=run_config.branch, commit_sha=commit_sha, profile=profile,
                    build_command=" ".join(build_cmd), test_command=" ".join(test_cmd),
                    actionable_findings=filtered.actionable, escalated_findings=filtered.escalate, retry=retry_context,
                )
                log.info("=== attempt %d of %d: invoking agent ===", attempt, run_config.max_attempts)
                self._agent.run(prompt, worktree, env)
                # Diff from the commit the worktree was created at, not from HEAD. With
                # --interactive-agent a person is at the keyboard and may commit despite
                # being told not to; against HEAD their work would diff to nothing and the
                # run would report NO_CHANGES — "the agent did nothing" — with the changes
                # sitting right there on the branch.
                diff_result = diff_mod.classify_diff(worktree, commit_sha)
                changed = diff_result.changed_files
                log.info("agent changed %d file(s): %s", len(changed), changed or "(none)")

                if not changed:
                    log.warning(
                        "the agent made no changes to the worktree. The run stops here — "
                        "nothing to build, verify or publish."
                    )
                    self._state.record_attempt(run_id, attempt, None, None, None)
                    return self._finish(
                        run_id, RunOutcome.NO_CHANGES,
                        escalated=filtered.escalate, not_attempted=filtered.escalate,
                        attempted_but_unresolved=filtered.actionable, notes=["agent made no changes"],
                    )

                log.info("diff classified as %s", diff_result.classification.value)
                if diff_result.classification == diff_mod.DiffClass.SUSPICIOUS:
                    log.error("refusing to publish a suspicious diff: %s",
                              "; ".join(diff_result.suspicious_reasons))
                    self._state.record_attempt(run_id, attempt, None, None, diff_result.classification.value)
                    return self._finish(
                        run_id, RunOutcome.ESCALATED,
                        escalated=filtered.escalate, not_attempted=filtered.escalate,
                        attempted_but_unresolved=filtered.actionable, notes=diff_result.suspicious_reasons,
                    )

                log.info("running build...")
                build_result = commands_mod.run_command(build_cmd, worktree, env, run_config.subprocess_timeout_seconds)
                log.info("build %s", "passed" if build_result.success else "FAILED")
                if not build_result.success:
                    log.warning("build output (tail):\n%s", build_result.tail())
                    diagnostic = None
                    # On the final attempt nothing will ever read diagnostic_tail --
                    # there is no retry prompt to put it in -- so don't pay for the
                    # subprocess.
                    is_final_attempt = attempt == run_config.max_attempts
                    if not is_final_attempt and strategy.ecosystem in commands_mod.DEPENDENCY_DIAGNOSTIC_COMMANDS:
                        diag_cmd = commands_mod.DEPENDENCY_DIAGNOSTIC_COMMANDS[strategy.ecosystem](worktree)
                        diagnostic = commands_mod.run_command(diag_cmd, worktree, env, run_config.subprocess_timeout_seconds).tail()
                    self._state.record_attempt(run_id, attempt, False, None, diff_result.classification.value)
                    retry_context = RetryContext(
                        attempt_number=attempt + 1, max_attempts=run_config.max_attempts, files_changed=changed,
                        failed_stage="build", stdout_tail=build_result.tail(), diagnostic_tail=diagnostic,
                    )
                    continue

                log.info("running tests...")
                test_result = commands_mod.run_command(test_cmd, worktree, env, run_config.subprocess_timeout_seconds)
                log.info("tests %s", "passed" if test_result.success else "FAILED")
                if not test_result.success:
                    log.warning("test output (tail):\n%s", test_result.tail())
                    self._state.record_attempt(run_id, attempt, True, False, diff_result.classification.value)
                    retry_context = RetryContext(
                        attempt_number=attempt + 1, max_attempts=run_config.max_attempts, files_changed=changed,
                        failed_stage="test", stdout_tail=test_result.tail(),
                    )
                    continue

                self._state.record_attempt(run_id, attempt, True, True, diff_result.classification.value)

                if run_config.gate == GateMode.PRE_PUSH.value:
                    log.info("gate=pre-push: stopping before push, awaiting approval")
                    return self._finish(
                        run_id, RunOutcome.AWAITING_APPROVAL,
                        fixed=filtered.actionable, escalated=filtered.escalate, not_attempted=filtered.escalate,
                    )

                log.info("committing and pushing %s", run_config.branch)
                self._commit_fn(worktree, "fix: remediate dependency vulnerabilities via nexus-autofix")
                self._push_fn(worktree, run_config.branch)
                pushed = True

                target_purls = {f.package_url for f in filtered.actionable}
                baseline_report = self._iq.fetch_policy_report(run_config.app_id, baseline_report_id)
                rescan_report_id = self._rescan_fn(run_config, worktree)
                rescan_report = self._iq.fetch_policy_report(run_config.app_id, rescan_report_id)
                comparison = rescan_mod.compare_reports(baseline_report, rescan_report, target_purls)
                log.info("rescan %s: still_failing=%s new_findings=%s",
                         "cleared" if comparison.all_cleared and not comparison.new_findings else "DID NOT CLEAR",
                         comparison.still_failing, comparison.new_findings)

                if not comparison.all_cleared or comparison.new_findings:
                    notes = [f"still failing: {comparison.still_failing}", f"new findings: {comparison.new_findings}"]
                    # Cleanup first, but never let a cleanup failure stop the outcome
                    # from being recorded -- the pipeline already made the right call.
                    cleanup_note = self._try_delete_remote_branch(worktree, run_config.branch)
                    if cleanup_note:
                        notes.append(cleanup_note)
                    return self._finish(
                        run_id, RunOutcome.FAILED_RESCAN,
                        escalated=filtered.escalate, not_attempted=filtered.escalate,
                        attempted_but_unresolved=filtered.actionable, notes=notes,
                    )

                if run_config.gate == GateMode.PRE_PR.value:
                    summary = self._gate_summary(filtered, build_result, test_result, comparison)
                    if not self._approve_fn(summary):
                        notes = []
                        cleanup_note = self._try_delete_remote_branch(worktree, run_config.branch)
                        if cleanup_note:
                            notes.append(cleanup_note)
                        return self._finish(
                            run_id, RunOutcome.REJECTED,
                            escalated=filtered.escalate, not_attempted=filtered.escalate,
                            attempted_but_unresolved=filtered.actionable, notes=notes,
                        )

                log.info("opening pull request for %s", run_config.branch)
                self._open_pr_fn(worktree, run_config.branch)
                pr_opened = True
                final_outcome = (
                    RunOutcome.FIXED if diff_result.classification == diff_mod.DiffClass.MANIFEST_ONLY else RunOutcome.FIXED_NEEDS_REVIEW
                )
                return self._finish(
                    run_id, final_outcome,
                    fixed=filtered.actionable, escalated=filtered.escalate, not_attempted=filtered.escalate,
                    commit_sha=commit_sha,
                )

            log.error("exhausted all %d attempt(s) without a passing build and test",
                      run_config.max_attempts)
            return self._finish(
                run_id, RunOutcome.FAILED_BUILD,
                escalated=filtered.escalate, not_attempted=filtered.escalate,
                attempted_but_unresolved=filtered.actionable, notes=["exhausted retries"],
            )
        except Exception as exc:  # noqa: BLE001 -- deliberate catch-all, see below
            # Without this net, any exception from the agent, git, a build subprocess,
            # IQ, or the PR opener leaves a `runs` row with outcome=NULL forever and,
            # if it happened after the push, an orphaned remote branch with no PR and
            # no record of why.
            log.exception("run failed with an unhandled exception")
            notes = [f"unhandled exception: {exc!r}"]
            if pushed and not pr_opened:
                cleanup_note = self._try_delete_remote_branch(worktree, run_config.branch)
                if cleanup_note:
                    notes.append(cleanup_note)
            escalate = list(filtered.escalate) if filtered is not None else []
            actionable = list(filtered.actionable) if filtered is not None else []
            return self._finish(
                run_id, RunOutcome.FAILED_BUILD,
                escalated=escalate, not_attempted=escalate,
                attempted_but_unresolved=actionable, notes=notes,
            )

    def _try_delete_remote_branch(self, worktree: Path, branch: str) -> str | None:
        """Best-effort remote cleanup. Returns a note on failure, never raises.

        `branch_mod.delete_remote_branch` runs git with check=True, so an
        already-deleted branch, a missing `origin`, or a protected ref all raise --
        and a raise here would either mask the original exception or (on the
        reject/failed-rescan paths) stop the outcome from being recorded at all.
        """
        try:
            self._delete_remote_branch_fn(worktree, branch)
            return None
        except Exception as exc:  # noqa: BLE001
            return f"remote branch cleanup failed for {branch!r}: {exc!r}"

    def _finish(
        self,
        run_id: str,
        outcome: RunOutcome,
        fixed: list[Finding] | None = None,
        escalated: list[Finding] | None = None,
        not_attempted: list[Finding] | None = None,
        attempted_but_unresolved: list[Finding] | None = None,
        notes: list[str] | None = None,
        commit_sha: str | None = None,
    ) -> RunResult:
        """Single exit point: record the outcome and build the result together.

        Every terminal return goes through here so an outcome can never be returned
        without also being persisted, and so the finding-disposition lists can't drift
        apart between exit points.
        """
        # Logged here rather than at each return so the outcome line cannot be missing
        # from a run, whichever of the dozen exit paths was taken.
        log.info(
            "=== outcome: %s === fixed=%d escalated=%d unresolved=%d",
            outcome.value, len(fixed or []), len(escalated or []),
            len(attempted_but_unresolved or []),
        )
        for note in notes or []:
            log.info("  note: %s", note)
        self._state.finish_run(run_id, outcome.value, commit_sha=commit_sha)
        return RunResult(
            run_id=run_id,
            outcome=outcome,
            fixed=list(fixed or []),
            escalated=list(escalated or []),
            not_attempted=list(not_attempted or []),
            attempted_but_unresolved=list(attempted_but_unresolved or []),
            notes=list(notes or []),
        )

    def _gate_summary(self, filtered, build_result, test_result, comparison) -> str:
        return "\n".join([
            "=== nexus-autofix: pre-PR review ===", "",
            f"Fixed: {[f.component for f in filtered.actionable]}",
            f"Escalated: {[f.component for f in filtered.escalate]}",
            f"Build: {'PASS' if build_result.success else 'FAIL'}",
            f"Test:  {'PASS' if test_result.success else 'FAIL'}",
            f"Rescan cleared: {comparison.all_cleared}, new findings: {comparison.new_findings}",
        ])
