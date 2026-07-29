"""The agent-as-orchestrator path must keep the guarantees the agent cannot be trusted to.

When the agent drives, it decides which commands to call. These lock in the parts it
cannot talk its way past: a suspicious diff is refused before anything is built, and a
verdict is something this tool produces, never something the agent asserts.
"""

import json
import os
import subprocess

import pytest

from nexus_autofix import agent_api
from nexus_autofix.iq.models import Finding


def _repo(tmp_path):
    for args in (["init"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "package.json").write_text('{"name":"d","version":"1.0.0"}', encoding="utf-8")
    (tmp_path / "app.test.js").write_text("it('works', () => {})\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


def _check(worktree):
    return agent_api.check_worktree(
        worktree=worktree, ecosystem="npm", java_version=None, node_version=None,
        java_toolchains={}, node_toolchains={}, timeout_seconds=60, env=dict(os.environ),
    )


def test_an_unchanged_worktree_is_not_a_pass(tmp_path):
    # Otherwise an agent that did nothing could call check, get ok, and publish.
    result = _check(_repo(tmp_path))
    assert result.ok is False
    assert "nothing changed" in result.message


def test_a_test_disabling_diff_is_refused_before_anything_is_built(tmp_path):
    # The ordering is the safeguard: a diff that disables tests would BUILD AND PASS
    # trivially, so classifying after building would hand it a clean verdict.
    repo = _repo(tmp_path)
    (repo / "app.test.js").write_text("describe.skip('everything', () => {})\n", encoding="utf-8")

    result = _check(repo)

    assert result.ok is False
    assert result.diff_classification == "SUSPICIOUS"
    assert result.suspicious_reasons
    assert result.build_ok is None, "the build must not have been run at all"
    assert "cannot be overridden by re-running check" in result.message


def test_the_refusal_names_what_was_wrong_so_the_agent_can_revert_it(tmp_path):
    repo = _repo(tmp_path)
    (repo / "app.test.js").write_text("it.skip('works', () => {})\n", encoding="utf-8")

    reasons = " ".join(_check(repo).suspicious_reasons)

    assert "app.test.js" in reasons


def test_a_verdict_round_trips_through_the_run_directory(tmp_path):
    result = _check(_repo(tmp_path))
    agent_api.write_verdict(tmp_path, result)

    verdict = agent_api.read_verdict(tmp_path)
    assert verdict is not None
    assert verdict["ok"] is False


def test_no_verdict_reads_as_none_rather_than_raising(tmp_path):
    # publish distinguishes "never checked" from "checked and failed"; both block, but
    # the messages differ and neither may crash.
    assert agent_api.read_verdict(tmp_path) is None


def test_a_corrupt_verdict_is_treated_as_absent(tmp_path):
    (tmp_path / agent_api.VERDICT_FILENAME).write_text("{not json", encoding="utf-8")
    assert agent_api.read_verdict(tmp_path) is None


def test_run_state_round_trips(tmp_path):
    run_dir = tmp_path / "runs" / "abc"
    agent_api.save_run_state(run_dir, {"run_id": "abc", "worktree": "/x"})

    assert agent_api.load_run_state(tmp_path, "abc")["worktree"] == "/x"


def test_a_missing_run_state_says_how_to_get_one(tmp_path):
    with pytest.raises(FileNotFoundError, match="nexusfix discover"):
        agent_api.load_run_state(tmp_path, "nope")


# --- what the agent is shown -----------------------------------------------


def _finding(**overrides):
    base = dict(
        component="postcss", package_url="pkg:npm/postcss@8.5.10", current_version="8.5.10",
        target_version="8.5.18", remediation_type="next-no-violations", is_direct=False,
        dependency_path=["pkg:npm/parent@1.0"], parent_component=None,
        parent_current_version=None, parent_target_version=None,
        threat_level=9, policy_name="Security-High", cve_ids=[],
    )
    base.update(overrides)
    return Finding(**base)


def test_findings_below_the_threshold_are_not_shown_to_the_agent():
    views = agent_api.finding_views([_finding(threat_level=5)], min_threat_level=8)
    assert views == []


def test_waived_findings_are_not_shown_to_the_agent():
    assert agent_api.finding_views([_finding(is_waived=True)], min_threat_level=8) == []


def test_a_transitive_finding_tells_the_agent_who_pulls_it_in():
    # Without this the agent would add a direct dependency to force the version, which is
    # not the fix and is one of the prohibited moves.
    view = agent_api.finding_views([_finding()], min_threat_level=8)[0]
    assert view.is_direct is False
    assert view.pulled_in_by == ["pkg:npm/parent@1.0"]


def test_an_unfixable_finding_is_shown_with_its_reason_not_silently_dropped():
    view = agent_api.finding_views(
        [_finding(target_version=None, escalation_reason="IQ offered nothing newer")],
        min_threat_level=8,
    )[0]
    assert view.actionable is False
    assert view.reason_not_actionable == "IQ offered nothing newer"


def test_the_payload_is_json_serialisable():
    from dataclasses import asdict

    views = [asdict(v) for v in agent_api.finding_views([_finding()], min_threat_level=8)]
    assert json.loads(agent_api.as_json({"findings": views}))["findings"][0]["target_version"] == "8.5.18"


def test_the_runbook_is_placed_beside_the_worktree_not_inside_it(tmp_path):
    # Inside the worktree it would show up as an untracked file in git status, get
    # classified as part of the fix, and be committed onto the branch.
    run_dir = tmp_path / "runs" / "abc"
    run_dir.mkdir(parents=True)
    (run_dir / "wt").mkdir()

    placed = agent_api.place_runbook(run_dir)

    assert placed == run_dir / agent_api.RUNBOOK_FILENAME
    assert "nexusfix discover" in placed.read_text(encoding="utf-8"), "the real runbook"
    assert not (run_dir / "wt" / agent_api.RUNBOOK_FILENAME).exists()


def test_the_runbook_falls_back_to_the_working_directory(tmp_path, monkeypatch):
    # Covers a non-editable install, where the file does not sit next to the package.
    elsewhere = tmp_path / "pkg"
    elsewhere.mkdir()
    monkeypatch.setattr(agent_api, "__file__", str(elsewhere / "agent_api.py"))
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    (cwd / agent_api.RUNBOOK_FILENAME).write_text("# steps", encoding="utf-8")
    monkeypatch.chdir(cwd)

    placed = agent_api.place_runbook(tmp_path)

    assert placed.read_text(encoding="utf-8") == "# steps"


def test_a_missing_runbook_warns_rather_than_crashing_the_run(tmp_path, monkeypatch, caplog):
    import logging

    empty = tmp_path / "nowhere"
    empty.mkdir()
    monkeypatch.chdir(empty)
    monkeypatch.setattr(agent_api, "__file__", str(empty / "agent_api.py"))

    with caplog.at_level(logging.WARNING):
        assert agent_api.place_runbook(tmp_path) is None

    assert "could not find RUNBOOK.md" in caplog.text
