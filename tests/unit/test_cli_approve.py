"""`nexusfix approve` — releasing a finding the tool held back."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_autofix import agent_api
from nexus_autofix import cli as cli_mod


def _finding(**overrides) -> dict:
    base = {
        "component": "nanoid", "package_url": "pkg:npm/nanoid@3.3.7",
        "current_version": "3.3.7", "target_version": "5.0.9",
        "remediation_type": "next-no-violations", "threat_level": 9,
        "policy_name": "Security-Critical", "is_direct": False, "pulled_in_by": [],
        "actionable": False,
        "reason_not_actionable": "3.3.7 -> 5.0.9 crosses a major version.",
        "needs_approval": True, "source": ["iq"], "cve_ids": ["CVE-2024-55565"],
    }
    base.update(overrides)
    return base


@pytest.fixture
def run(tmp_path, monkeypatch):
    (tmp_path / "config.yml").write_text("repos:\n  demo: https://x/o/demo.git\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "ws"
    monkeypatch.setenv("NEXUSFIX_WORKSPACE_ROOT", str(workspace))
    run_dir = workspace / "runs" / "r1"
    agent_api.save_run_state(run_dir, {
        "run_id": "r1", "run_dir": str(run_dir), "worktree": str(run_dir / "wt"),
        "commit_sha": "abc", "target_purls": ["pkg:npm/xalan@2.7.2"],
        "findings": [_finding()],
    })
    return run_dir


def _state(run_dir):
    return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))


def test_approving_makes_the_finding_actionable(run):
    result = CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nanoid", "--version", "5.0.9",
    ])

    assert result.exit_code == 0, result.output
    finding = _state(run)["findings"][0]
    assert finding["actionable"] is True
    assert finding["needs_approval"] is False
    assert finding["reason_not_actionable"] is None
    assert finding["approved_by_human"] is True


def test_approving_adds_the_purl_so_publish_verifies_it(run):
    CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nanoid", "--version", "5.0.9",
    ])
    assert _state(run)["target_purls"] == ["pkg:npm/nanoid@3.3.7", "pkg:npm/xalan@2.7.2"]


def test_the_version_must_match_what_iq_recommended(run):
    # --version confirms which change is being approved; it never chooses one.
    result = CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nanoid", "--version", "4.0.0",
    ])

    assert result.exit_code != 0
    assert "is not what Nexus IQ recommended" in result.output
    assert _state(run)["findings"][0]["actionable"] is False


def test_a_finding_with_no_target_version_cannot_be_approved(run):
    state = _state(run)
    state["findings"] = [_finding(target_version=None, needs_approval=False,
                                  reason_not_actionable="Nexus IQ offered no version")]
    agent_api.save_run_state(run, state)

    result = CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nanoid", "--version", "5.0.9",
    ])
    assert result.exit_code != 0
    assert "not fixable at all" in result.output


def test_approving_an_already_actionable_finding_is_refused(run):
    state = _state(run)
    state["findings"] = [_finding(actionable=True, needs_approval=False)]
    agent_api.save_run_state(run, state)

    result = CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nanoid", "--version", "5.0.9",
    ])
    assert result.exit_code != 0
    assert "already being fixed" in result.output


def test_an_unknown_component_lists_what_is_awaiting_approval(run):
    result = CliRunner().invoke(cli_mod.approve_command, [
        "--run-id", "r1", "--component", "nope", "--version", "1.0.0",
    ])
    assert result.exit_code != 0
    assert "Awaiting approval: nanoid" in result.output
