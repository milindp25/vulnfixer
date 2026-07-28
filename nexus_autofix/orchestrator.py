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
