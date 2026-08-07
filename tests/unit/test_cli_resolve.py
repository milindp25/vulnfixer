"""`nexusfix resolve`, and the `check` gate that makes it mandatory."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_autofix import agent_api
from nexus_autofix import cli as cli_mod


def _conflict_finding(**overrides) -> dict:
    base = {
        "component": "org.bouncycastle:bcprov-jdk15on",
        "package_url": "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.49",
        "current_version": "1.49",
        "target_version": None,
        "remediation_type": "appsec",
        "threat_level": 0,
        "policy_name": "AppSec SCA worksheet",
        "is_direct": False,
        "actionable": False,
        "reason_not_actionable": "Nexus IQ recommends 1.70, the AppSec sheet recommends 1.64.",
        "source": ["appsec"],
        "cve_ids": ["CVE-2016-1000352"],
        "iq_version": "1.70",
        "sheet_version": "1.64",
        "appsec_decision": "CONFLICT",
        "candidate_versions": ["1.70", "1.64"],
        "swap_candidates": [],
    }
    base.update(overrides)
    return base


@pytest.fixture
def run(tmp_path, monkeypatch):
    """A saved run with one unresolved AppSec conflict."""
    (tmp_path / "config.yml").write_text(
        "repos:\n  demo: https://example.com/o/demo.git\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "ws"
    monkeypatch.setenv("NEXUSFIX_WORKSPACE_ROOT", str(workspace))
    for var in ("IQ_URL", "IQ_USERNAME", "IQ_PASSWORD"):
        monkeypatch.setenv(f"NEXUSFIX_{var}", "x")

    run_dir = workspace / "runs" / "r1"
    state = {
        "run_id": "r1",
        "run_dir": str(run_dir),
        "worktree": str(run_dir / "wt"),
        "ecosystem": "gradle",
        "commit_sha": "deadbeef",
        "run_commands_from": str(tmp_path),
        "target_purls": [],
        "findings": [_conflict_finding()],
        "appsec": {"unresolved_conflicts": ["org.bouncycastle:bcprov-jdk15on"]},
    }
    agent_api.save_run_state(run_dir, state)
    return run_dir


def _state(run_dir):
    return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))


def _json_payload(output: str) -> dict:
    """The JSON an agent would parse off stdout.

    CliRunner folds stderr into `output`, and the run narrates itself to stderr via the
    logging console handler, so the JSON has log lines in front of it here. In a real
    terminal the two streams are separate — which is the whole reason `_agent_json` writes
    to stdout and `_echo_next_steps` to stderr.
    """
    return json.loads(output[output.index("{"):])


# --- the check gate -------------------------------------------------------------------

def test_check_refuses_while_a_conflict_is_open(run):
    result = CliRunner().invoke(cli_mod.check_command, ["--run-id", "r1"])

    assert result.exit_code != 0
    assert "awaiting a decision" in result.output
    # The exact command that settles it, not just a complaint.
    assert "nexusfix resolve --run-id r1" in result.output
    assert "1.70 or 1.64" in result.output


def test_check_gate_names_both_sources(run):
    result = CliRunner().invoke(cli_mod.check_command, ["--run-id", "r1"])
    assert "Nexus IQ: 1.70" in result.output
    assert "AppSec sheet: 1.64" in result.output


def test_check_proceeds_once_nothing_is_outstanding(run, monkeypatch):
    from unittest.mock import patch

    state = _state(run)
    state["findings"] = [_conflict_finding(appsec_decision="RESOLVED", actionable=True,
                                           target_version="1.64", candidate_versions=[])]
    agent_api.save_run_state(run, state)

    verdict = agent_api.CheckResult(
        ok=True, worktree=str(run / "wt"), changed_files=["build.gradle"],
        diff_classification="DEPENDENCY_ONLY",
    )
    with patch.object(agent_api, "check_worktree", return_value=verdict):
        result = CliRunner().invoke(cli_mod.check_command, ["--run-id", "r1"])

    assert result.exit_code == 0, result.output


def test_a_plain_iq_run_is_unaffected_by_the_gate(run):
    from unittest.mock import patch

    state = _state(run)
    state["findings"] = [{"component": "x", "appsec_decision": None, "actionable": True}]
    state.pop("appsec")
    agent_api.save_run_state(run, state)

    verdict = agent_api.CheckResult(
        ok=True, worktree=str(run / "wt"), changed_files=["a"], diff_classification="DEPENDENCY_ONLY",
    )
    with patch.object(agent_api, "check_worktree", return_value=verdict):
        result = CliRunner().invoke(cli_mod.check_command, ["--run-id", "r1"])

    assert result.exit_code == 0, result.output


# --- resolve --------------------------------------------------------------------------

def test_resolve_records_the_choice(run):
    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.64",
    ])

    assert result.exit_code == 0, result.output
    finding = _state(run)["findings"][0]
    assert finding["target_version"] == "1.64"
    assert finding["actionable"] is True
    assert finding["appsec_decision"] == "RESOLVED"
    assert finding["candidate_versions"] == []


def test_resolve_adds_the_purl_so_publish_verifies_it(run):
    CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.70",
    ])
    assert _state(run)["target_purls"] == ["pkg:maven/org.bouncycastle/bcprov-jdk15on@1.49"]


def test_resolve_clears_the_conflict_list(run):
    CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.70",
    ])
    assert _state(run)["appsec"]["unresolved_conflicts"] == []


def test_resolve_accepts_the_bare_artifact_name(run):
    # What a person reads off the sheet is "bcprov-jdk15on", not the full group:artifact.
    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "bcprov-jdk15on", "--version", "1.64",
    ])
    assert result.exit_code == 0, result.output
    assert _state(run)["findings"][0]["target_version"] == "1.64"


def test_resolve_refuses_a_third_version(run):
    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.99",
    ])

    assert result.exit_code != 0
    assert "not one of the candidates" in result.output
    # And nothing was written.
    assert _state(run)["findings"][0]["target_version"] is None


def test_resolve_refuses_an_unknown_component_and_says_what_is_open(run):
    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "nope", "--version", "1.64",
    ])

    assert result.exit_code != 0
    assert "no finding named 'nope'" in result.output
    assert "org.bouncycastle:bcprov-jdk15on" in result.output


def test_resolving_twice_is_refused(run):
    args = ["--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.64"]
    assert CliRunner().invoke(cli_mod.resolve_command, args).exit_code == 0

    second = CliRunner().invoke(cli_mod.resolve_command, [*args[:-1], "1.70"])
    assert second.exit_code != 0
    assert "not awaiting a decision" in second.output
    # The first decision stands.
    assert _state(run)["findings"][0]["target_version"] == "1.64"


def test_resolve_refuses_a_finding_that_is_not_a_conflict(run):
    state = _state(run)
    state["findings"] = [_conflict_finding(appsec_decision="SWAP_ONLY", candidate_versions=[])]
    agent_api.save_run_state(run, state)

    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.64",
    ])
    assert result.exit_code != 0
    assert "not awaiting a decision" in result.output


def test_resolve_reports_what_is_still_outstanding(run):
    state = _state(run)
    state["findings"].append(_conflict_finding(
        component="xalan:xalan", package_url="pkg:maven/xalan/xalan@2.7.2",
        current_version="2.7.2", iq_version="2.7.3", sheet_version="2.7.4",
        candidate_versions=["2.7.3", "2.7.4"],
    ))
    agent_api.save_run_state(run, state)

    result = CliRunner().invoke(cli_mod.resolve_command, [
        "--run-id", "r1", "--component", "org.bouncycastle:bcprov-jdk15on", "--version", "1.64",
    ])

    assert result.exit_code == 0, result.output
    assert _json_payload(result.output)["still_unresolved"] == ["xalan:xalan"]
