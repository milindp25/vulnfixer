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
