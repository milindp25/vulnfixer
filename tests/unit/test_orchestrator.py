import subprocess
from pathlib import Path

import pytest

from nexus_autofix.agent.base import AgentResult
from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.iq.client import FakeIQClient, PolicyViolation
from nexus_autofix.iq.models import Finding, RunOutcome
from nexus_autofix.orchestrator import Orchestrator, RunConfig
from nexus_autofix.state.store import StateStore
from nexus_autofix.verify import commands as commands_mod
from nexus_autofix.verify.commands import CommandResult


def _finding(**overrides) -> Finding:
    base = dict(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0.0", target_version="1.0.1",
        remediation_type="next-non-failing-with-dependencies", is_direct=True, dependency_path=[],
        parent_component=None, parent_current_version=None, parent_target_version=None,
        policy_action="Fail", threat_level=8, policy_name="p", cve_ids=[], manifest_path=Path("x"),
    )
    base.update(overrides)
    return Finding(**base)


def _major_bump_finding() -> Finding:
    """Filtered to `escalate` -- a major bump the agent is never asked to attempt."""
    return _finding(
        component="big", package_url="pkg:maven/big/big@1.0",
        current_version="1.0.0", target_version="3.0.0",
    )


def _run_config(**overrides) -> RunConfig:
    base = dict(
        app_id="payments-core", branch="autofix/nexus/run-1", gate="none", max_attempts=2,
        stage_id="build", java_toolchains={}, node_toolchains={}, subprocess_timeout_seconds=60,
    )
    base.update(overrides)
    return RunConfig(**base)


def _noop_rescan(run_config, worktree):
    return "rescan-report-1"


def _noop_open_pr(worktree, branch):
    return None


def _auto_approve(summary):
    return True


def _orchestrator(state_store, agent=None, iq_client=None, **overrides) -> Orchestrator:
    kwargs = dict(
        iq_client=iq_client or FakeIQClient(),
        agent=agent or MockAgent(mode=MockMode.NO_CHANGES),
        state_store=state_store,
        rescan_fn=_noop_rescan,
        open_pr_fn=_noop_open_pr,
        approve_fn=_auto_approve,
    )
    kwargs.update(overrides)
    return Orchestrator(**kwargs)


def _outcome_in_db(store: StateStore, run_id: str):
    row = store._conn.execute("SELECT outcome FROM runs WHERE run_id = ?", (run_id,)).fetchone()
    return row[0]


# --- shared git/worktree harness -------------------------------------------


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _init_repo(tmp_path: Path, strategy_yaml: str | None = None) -> Path:
    # Deliberately a SUBDIRECTORY of tmp_path: the state DB lives at
    # tmp_path/state.db and must not show up as an untracked file in the worktree.
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["init"], repo)
    _git(["config", "user.email", "t@example.com"], repo)
    _git(["config", "user.name", "t"], repo)
    (repo / "build.gradle").write_text("dependencies { implementation 'x:x:1.0.0' }\n", encoding="utf-8")
    (repo / ".trident").mkdir(exist_ok=True)
    (repo / ".trident" / "build.yaml").write_text(
        strategy_yaml if strategy_yaml is not None else "strategy:\n  uses: gradle\n", encoding="utf-8"
    )
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "init"], repo)
    return repo


class FixingAgent:
    """Edits the manifest only -- yields a MANIFEST_ONLY diff."""

    def __init__(self):
        self.calls = 0

    def run(self, prompt, worktree):
        self.calls += 1
        (worktree / "build.gradle").write_text(
            f"dependencies {{ implementation 'x:x:1.0.{self.calls}' }}\n", encoding="utf-8"
        )
        return AgentResult(changed_files=["build.gradle"], raw_output="bumped")


def _ok(*args, **kwargs):
    return CommandResult(returncode=0, stdout="ok", stderr="")


def _fail(*args, **kwargs):
    return CommandResult(returncode=1, stdout="boom", stderr="")


# --- existing behaviour (unchanged expectations) ----------------------------


def test_no_actionable_findings_returns_clean(tmp_path):
    orchestrator = _orchestrator(StateStore(tmp_path / "state.db"))
    result = orchestrator.run(
        run_config=_run_config(), worktree=tmp_path, commit_sha="abc123",
        findings=[], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.CLEAN


def test_missing_trident_file_escalates(tmp_path):
    orchestrator = _orchestrator(StateStore(tmp_path / "state.db"))
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
            return AgentResult(changed_files=[], raw_output="")

    orchestrator = _orchestrator(StateStore(tmp_path / "state.db"), agent=CountingAgent())
    result = orchestrator.run(
        run_config=_run_config(java_toolchains={"17": "/opt/jdk17"}), worktree=tmp_path, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.ESCALATED
    assert agent_called["count"] == 0


# --- item 1: exception safety net ------------------------------------------


def test_unhandled_exception_is_recorded_as_failed_build(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")

    def explode(*args, **kwargs):
        raise RuntimeError("gradle daemon exploded")

    monkeypatch.setattr(commands_mod, "run_command", explode)
    orchestrator = _orchestrator(store, agent=FixingAgent())

    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_BUILD
    assert any("unhandled exception" in n and "gradle daemon exploded" in n for n in result.notes)
    # The run row must not be left with outcome=NULL forever.
    assert _outcome_in_db(store, result.run_id) == RunOutcome.FAILED_BUILD.value


def test_exception_after_push_deletes_the_orphaned_remote_branch(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)
    deleted = []

    def exploding_rescan(run_config, worktree):
        raise RuntimeError("IQ unreachable")

    orchestrator = _orchestrator(
        store, agent=FixingAgent(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
        delete_remote_branch_fn=lambda worktree, branch: deleted.append(branch),
        rescan_fn=exploding_rescan,
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_BUILD
    assert deleted == ["autofix/nexus/run-1"]
    assert _outcome_in_db(store, result.run_id) == RunOutcome.FAILED_BUILD.value


def test_cleanup_failure_does_not_mask_the_original_exception(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)

    def exploding_rescan(run_config, worktree):
        raise RuntimeError("IQ unreachable")

    def exploding_delete(worktree, branch):
        raise RuntimeError("protected ref")

    orchestrator = _orchestrator(
        store, agent=FixingAgent(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
        delete_remote_branch_fn=exploding_delete,
        rescan_fn=exploding_rescan,
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_BUILD
    assert any("IQ unreachable" in n for n in result.notes)
    assert any("cleanup failed" in n for n in result.notes)


def test_agent_exception_is_caught_too(tmp_path):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")

    class ExplodingAgent:
        def run(self, prompt, worktree):
            raise RuntimeError("agent CLI crashed")

    orchestrator = _orchestrator(store, agent=ExplodingAgent())
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.FAILED_BUILD
    assert _outcome_in_db(store, result.run_id) == RunOutcome.FAILED_BUILD.value


# --- item 3: cleanup failure must not prevent the outcome being recorded ----


def _failed_rescan_iq():
    return FakeIQClient(
        policy_violations=[
            PolicyViolation(
                package_url="pkg:maven/x/x@1.0", component="x", policy_name="p", policy_id="1",
                threat_level=8, constraint_summary="", is_waived=False, action="Fail",
            )
        ]
    )


def test_failed_rescan_records_outcome_even_when_branch_delete_raises(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)

    def exploding_delete(worktree, branch):
        raise RuntimeError("branch already gone")

    orchestrator = _orchestrator(
        store, agent=FixingAgent(), iq_client=_failed_rescan_iq(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
        delete_remote_branch_fn=exploding_delete,
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_RESCAN
    assert _outcome_in_db(store, result.run_id) == RunOutcome.FAILED_RESCAN.value
    assert any("cleanup failed" in n for n in result.notes)


def test_rejected_records_outcome_even_when_branch_delete_raises(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)

    def exploding_delete(worktree, branch):
        raise RuntimeError("no origin configured")

    orchestrator = _orchestrator(
        store, agent=FixingAgent(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
        delete_remote_branch_fn=exploding_delete,
        approve_fn=lambda summary: False,
    )
    result = orchestrator.run(
        run_config=_run_config(gate="pre-pr"), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.REJECTED
    assert _outcome_in_db(store, result.run_id) == RunOutcome.REJECTED.value
    assert any("cleanup failed" in n for n in result.notes)


# --- item 4: finding disposition is unambiguous on every path ---------------


def test_failed_build_reports_both_not_attempted_and_attempted_findings(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _fail)

    orchestrator = _orchestrator(store, agent=FixingAgent())
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding(), _major_bump_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_BUILD
    # The major bump the filter routed away is visible, not silently dropped.
    assert result.escalated == [_major_bump_finding()]
    assert result.not_attempted == [_major_bump_finding()]
    # ...and so is the finding the agent actually tried and failed to land.
    assert result.attempted_but_unresolved == [_finding()]
    assert result.fixed == []


def test_rejected_reports_both_not_attempted_and_attempted_findings(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)

    orchestrator = _orchestrator(
        store, agent=FixingAgent(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
        delete_remote_branch_fn=lambda worktree, branch: None,
        approve_fn=lambda summary: False,
    )
    result = orchestrator.run(
        run_config=_run_config(gate="pre-pr"), worktree=repo, commit_sha="abc123",
        findings=[_finding(), _major_bump_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.REJECTED
    assert result.escalated == [_major_bump_finding()]
    assert result.not_attempted == [_major_bump_finding()]
    assert result.attempted_but_unresolved == [_finding()]


def test_fixed_reports_escalate_set_not_the_fixed_set(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    monkeypatch.setattr(commands_mod, "run_command", _ok)

    orchestrator = _orchestrator(
        store, agent=FixingAgent(),
        commit_fn=lambda worktree, message: None,
        push_fn=lambda worktree, branch: None,
    )
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding(), _major_bump_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FIXED
    assert result.fixed == [_finding()]
    assert result.escalated == [_major_bump_finding()]
    assert result.not_attempted == [_major_bump_finding()]
    assert result.attempted_but_unresolved == []


def test_no_changes_reports_attempted_findings(tmp_path):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    orchestrator = _orchestrator(store, agent=MockAgent(mode=MockMode.NO_CHANGES))
    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding(), _major_bump_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.NO_CHANGES
    assert result.attempted_but_unresolved == [_finding()]
    assert result.not_attempted == [_major_bump_finding()]


# --- item 5: no fail-open default callables --------------------------------


@pytest.mark.parametrize("missing", ["rescan_fn", "open_pr_fn", "approve_fn"])
def test_publish_callables_are_required(tmp_path, missing):
    kwargs = dict(
        iq_client=FakeIQClient(), agent=MockAgent(mode=MockMode.NO_CHANGES),
        state_store=StateStore(tmp_path / "state.db"),
        rescan_fn=_noop_rescan, open_pr_fn=_noop_open_pr, approve_fn=_auto_approve,
    )
    del kwargs[missing]
    with pytest.raises(TypeError, match=missing):
        Orchestrator(**kwargs)


# --- item 6: gate validation ------------------------------------------------


@pytest.mark.parametrize("gate", ["none", "pre-pr", "pre-push"])
def test_valid_gates_accepted(gate):
    assert _run_config(gate=gate).gate == gate


@pytest.mark.parametrize("gate", ["pre_push", "PRE-PR", "", "prepr", None])
def test_invalid_gate_rejected_at_construction(gate):
    with pytest.raises(ValueError, match="invalid gate"):
        _run_config(gate=gate)


# --- item 8: no diagnostic subprocess on the final attempt ------------------


def test_dependency_diagnostic_is_skipped_on_the_final_attempt(tmp_path, monkeypatch):
    repo = _init_repo(tmp_path)
    store = StateStore(tmp_path / "state.db")
    diagnostic_calls = []

    def recording_run(args, cwd, env, timeout):
        if "dependencies" in args:
            diagnostic_calls.append(args)
        return CommandResult(returncode=1, stdout="build failed", stderr="")

    monkeypatch.setattr(commands_mod, "run_command", recording_run)
    orchestrator = _orchestrator(store, agent=FixingAgent())
    result = orchestrator.run(
        run_config=_run_config(max_attempts=2), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.FAILED_BUILD
    # Attempt 1 feeds a retry prompt so the diagnostic is worth running; attempt 2
    # is the last one, so nothing would ever read its output.
    assert len(diagnostic_calls) == 1


# --- item 9: per-repo suppressions are honoured -----------------------------


def test_suppressed_components_are_filtered_out(tmp_path):
    store = StateStore(tmp_path / "state.db")
    orchestrator = _orchestrator(store)
    result = orchestrator.run(
        run_config=_run_config(), worktree=tmp_path, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
        suppressed_components={"x"},
    )
    assert result.outcome == RunOutcome.CLEAN
    dispositions = [
        row[0] for row in store._conn.execute(
            "SELECT disposition FROM findings WHERE run_id = ?", (result.run_id,)
        )
    ]
    assert dispositions == ["ignore"]


def test_suppressions_default_to_none_applied(tmp_path):
    store = StateStore(tmp_path / "state.db")
    orchestrator = _orchestrator(store)
    result = orchestrator.run(
        run_config=_run_config(), worktree=tmp_path, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )
    assert result.outcome == RunOutcome.ESCALATED  # actionable, but no .trident strategy


# --- item 10: multi-ecosystem repos escalate rather than half-publishing ----


def test_multiple_trident_strategies_escalate_before_the_agent_runs(tmp_path):
    repo = _init_repo(
        tmp_path,
        strategy_yaml="strategy:\n  - uses: gradle\n  - uses: npm\n",
    )
    store = StateStore(tmp_path / "state.db")
    agent = FixingAgent()
    orchestrator = _orchestrator(store, agent=agent)

    result = orchestrator.run(
        run_config=_run_config(), worktree=repo, commit_sha="abc123",
        findings=[_finding()], repo_name="demo", baseline_report_id="report-1",
    )

    assert result.outcome == RunOutcome.ESCALATED
    assert agent.calls == 0
    assert any("multiple .trident strategies" in n for n in result.notes)
    assert result.escalated == [_finding()]
