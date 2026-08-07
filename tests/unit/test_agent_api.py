"""The agent-as-orchestrator path must keep the guarantees the agent cannot be trusted to.

When the agent drives, it decides which commands to call. These lock in the parts it
cannot talk its way past: a suspicious diff is refused before anything is built, and a
verdict is something this tool produces, never something the agent asserts.
"""

import json
import os
import subprocess
from dataclasses import asdict

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


def test_changes_are_still_verified_when_the_agent_commits_them(tmp_path):
    # Agents commit out of habit however firmly the runbook says not to. Against HEAD a
    # committed change diffs to nothing, so the work would report as "nothing changed" and
    # never be verified. Diffing from the run's base commit is immune to that.
    repo = _repo(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, encoding="utf-8", check=True,
    ).stdout.strip()

    (repo / "package.json").write_text(
        '{"name":"d","version":"1.0.0","dependencies":{"postcss":"8.5.18"}}', encoding="utf-8"
    )
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "agent committed"], cwd=repo, check=True, capture_output=True)

    against_head = agent_api.check_worktree(
        worktree=repo, ecosystem="npm", java_version=None, node_version=None,
        java_toolchains={}, node_toolchains={}, timeout_seconds=60, env=dict(os.environ),
    )
    assert "nothing changed" in against_head.message, "the trap this guards against"

    against_base = agent_api.check_worktree(
        worktree=repo, ecosystem="npm", java_version=None, node_version=None,
        java_toolchains={}, node_toolchains={}, timeout_seconds=60, env=dict(os.environ),
        base_ref=base,
    )
    assert against_base.changed_files == ["package.json"], "the change is seen either way"
    assert "nothing changed" not in against_base.message


def test_a_committed_suspicious_diff_is_still_refused(tmp_path):
    # The classifier must not be escapable by committing first.
    repo = _repo(tmp_path)
    base = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, encoding="utf-8", check=True,
    ).stdout.strip()

    (repo / "app.test.js").write_text("describe.skip('all', () => {})\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "sneaky"], cwd=repo, check=True, capture_output=True)

    result = agent_api.check_worktree(
        worktree=repo, ecosystem="npm", java_version=None, node_version=None,
        java_toolchains={}, node_toolchains={}, timeout_seconds=60, env=dict(os.environ),
        base_ref=base,
    )

    assert result.ok is False
    assert result.diff_classification == "SUSPICIOUS"
    assert result.build_ok is None


def test_run_state_carries_the_findings_so_a_run_id_is_enough(tmp_path):
    # Whoever runs `discover` is often not who edits: you run it, then hand a run_id to an
    # agent in an editor that never saw the stdout. If the findings were not persisted, the
    # agent's only options would be re-running discover (a second IQ scan and worktree) or
    # scraping the log.
    run_dir = tmp_path / "runs" / "abc"
    findings = [asdict(v) for v in agent_api.finding_views([_finding()], min_threat_level=8)]
    agent_api.save_run_state(run_dir, {"run_id": "abc", "findings": findings})

    reloaded = agent_api.load_run_state(tmp_path, "abc")

    assert reloaded["findings"][0]["component"] == "postcss"
    assert reloaded["findings"][0]["current_version"] == "8.5.10"
    assert reloaded["findings"][0]["target_version"] == "8.5.18"
    assert reloaded["findings"][0]["pulled_in_by"] == ["pkg:npm/parent@1.0"]


# --- contract tests the repo defines outside `test` -----------------------------------

def _check_args(tmp_path, **overrides):
    base = dict(
        worktree=tmp_path, ecosystem="gradle", java_version=None, node_version=None,
        java_toolchains={}, node_toolchains={}, timeout_seconds=60, env={},
        base_ref="HEAD",
    )
    base.update(overrides)
    return base


def _clean_diff():
    from nexus_autofix.verify import diff as diff_mod

    return diff_mod.DiffResult(
        classification=diff_mod.DiffClass.MANIFEST_ONLY,
        changed_files=["build.gradle"], suspicious_reasons=[],
    )


def _passing(*_a, **_k):
    from nexus_autofix.verify.commands import CommandResult
    return CommandResult(0, "", "")


def test_contract_tests_are_off_unless_the_repo_asks(tmp_path):
    """Whether they can run outside CI is a property of the repo, not an assumption."""
    from unittest.mock import patch

    from nexus_autofix import agent_api

    with patch.object(agent_api.diff_mod, "classify_diff", return_value=_clean_diff()), \
            patch.object(agent_api.commands_mod, "run_command", side_effect=_passing), \
            patch.object(agent_api.commands_mod, "discover_contract_test_tasks") as discover:
        result = agent_api.check_worktree(**_check_args(tmp_path))

    assert result.ok is True
    assert result.contract_test_tasks == []
    discover.assert_not_called()


def test_both_consumer_and_provider_contract_tests_run_in_one_invocation(tmp_path):
    from unittest.mock import patch

    from nexus_autofix import agent_api

    with patch.object(agent_api.diff_mod, "classify_diff", return_value=_clean_diff()), \
            patch.object(agent_api.commands_mod, "run_command", side_effect=_passing) as run, \
            patch.object(agent_api.commands_mod, "discover_contract_test_tasks",
                         return_value=["contractTestConsumer", "contractTestProvider"]):
        result = agent_api.check_worktree(
            **_check_args(tmp_path, run_contract_tests=True)
        )

    assert result.ok is True
    assert result.contract_test_tasks == ["contractTestConsumer", "contractTestProvider"]
    assert result.contract_tests_ok is True
    assert run.call_args.args[0][-2:] == ["contractTestConsumer", "contractTestProvider"]


def test_a_failing_contract_test_fails_the_check_distinctly(tmp_path):
    """Distinct from test_ok, so a contract failure is not mistaken for a unit failure."""
    from unittest.mock import patch

    from nexus_autofix import agent_api
    from nexus_autofix.verify.commands import CommandResult

    calls = {"n": 0}

    def run(cmd, *_a, **_k):
        calls["n"] += 1
        return CommandResult(1, "pact verification failed", "") if calls["n"] == 3 \
            else CommandResult(0, "", "")

    with patch.object(agent_api.diff_mod, "classify_diff", return_value=_clean_diff()), \
            patch.object(agent_api.commands_mod, "run_command", side_effect=run), \
            patch.object(agent_api.commands_mod, "discover_contract_test_tasks",
                         return_value=["contractTestProvider"]):
        result = agent_api.check_worktree(
            **_check_args(tmp_path, run_contract_tests=True)
        )

    assert result.ok is False
    assert result.build_ok is True and result.test_ok is True
    assert result.contract_tests_ok is False
    assert "pact verification failed" in result.contract_test_output_tail
    assert "Do NOT modify or delete the contract tests" in result.message


def test_an_explicit_command_is_used_instead_of_discovery(tmp_path):
    """For an ecosystem whose contract tests are a script name of the repo's choosing."""
    from unittest.mock import patch

    from nexus_autofix import agent_api

    with patch.object(agent_api.diff_mod, "classify_diff", return_value=_clean_diff()), \
            patch.object(agent_api.commands_mod, "run_command", side_effect=_passing) as run, \
            patch.object(agent_api.commands_mod, "discover_contract_test_tasks") as discover:
        result = agent_api.check_worktree(**_check_args(
            tmp_path, ecosystem="yarn", run_contract_tests=True,
            contract_test_command=["yarn", "test:contract"],
        ))

    assert result.ok is True
    assert result.contract_tests_ok is True
    discover.assert_not_called()
    assert run.call_args.args[0][-1] == "test:contract"


def test_a_non_gradle_repo_without_a_command_warns_rather_than_silently_skipping(
    tmp_path, caplog
):
    """Otherwise `run_contract_tests: true` reads as coverage that is not happening."""
    import logging
    from unittest.mock import patch

    from nexus_autofix import agent_api

    with caplog.at_level(logging.WARNING, logger="nexus_autofix.agent_api"), \
            patch.object(agent_api.diff_mod, "classify_diff", return_value=_clean_diff()), \
            patch.object(agent_api.commands_mod, "run_command", side_effect=_passing):
        result = agent_api.check_worktree(**_check_args(
            tmp_path, ecosystem="yarn", run_contract_tests=True,
        ))

    assert result.ok is True
    assert result.contract_test_tasks == []
    assert "contract_test_command" in caplog.text


def _nanoid():
    from nexus_autofix.iq.models import Finding

    return Finding(
        component="nanoid", package_url="pkg:npm/nanoid@3.3.7", current_version="3.3.7",
        target_version="5.0.9", remediation_type="next-no-violations", is_direct=False,
        dependency_path=["pkg:npm/postcss@8.4.31"], parent_component=None,
        parent_current_version=None, parent_target_version=None, threat_level=9,
        policy_name="Security-Critical", cve_ids=["CVE-2024-55565"],
    )


def test_a_major_bump_reaches_the_agent_as_not_actionable():
    """Regression: `discover` used to hand major jumps over as work to do.

    `filter_findings` escalates a MAJOR, but that call lived only in the orchestrator, so
    the agent-driven path built run.json straight from the raw findings. `is_actionable` is
    just `bool(target_version)`, which is true for 3.3.7 -> 5.0.9 — so run.json said
    `actionable: true` and the RUNBOOK says to use target_version exactly. The agent was
    doing what it was told.
    """
    from nexus_autofix.agent_api import finding_views
    from nexus_autofix.cli import _escalation_reason
    from nexus_autofix.iq.filter import filter_findings

    filtered = filter_findings([_nanoid()], suppressed_components=set(), min_threat_level=8)
    assert not filtered.actionable and len(filtered.escalate) == 1

    reasons = {f.package_url: _escalation_reason(f) for f in filtered.escalate}
    view = finding_views(filtered.escalate, 8, reasons)[0]

    assert view.actionable is False
    assert view.needs_approval is True, "a human must be able to release it"
    assert "crosses a major version" in view.reason_not_actionable
    # The version IQ suggested stays visible so the agent can investigate it.
    assert view.target_version == "5.0.9"


def test_a_finding_with_no_target_version_is_not_approvable():
    from dataclasses import replace

    from nexus_autofix.agent_api import finding_views

    view = finding_views([replace(_nanoid(), target_version=None)], 8)[0]
    assert view.actionable is False
    assert view.needs_approval is False, "no version to approve at any price"


def test_an_ordinary_patch_bump_is_untouched_by_the_gate():
    from dataclasses import replace

    from nexus_autofix.agent_api import finding_views
    from nexus_autofix.iq.filter import filter_findings

    patch = replace(_nanoid(), current_version="3.3.7", target_version="3.3.8")
    filtered = filter_findings([patch], suppressed_components=set(), min_threat_level=8)

    assert len(filtered.actionable) == 1
    view = finding_views(filtered.actionable, 8, {})[0]
    assert view.actionable is True and view.needs_approval is False
