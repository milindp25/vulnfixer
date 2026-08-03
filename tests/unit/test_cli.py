from pathlib import Path

import pytest

from nexus_autofix.cli import (
    findings_from_policy_report,
    purl_to_component_identifier,
    purl_version,
)
from nexus_autofix.iq.client import FakeIQClient, PolicyViolation, RemediationResponse, VersionChange


def test_purl_version_extracts_trailing_version():
    assert purl_version("pkg:maven/org.apache.commons/commons-text@1.9") == "1.9"


def test_purl_to_component_identifier_maven():
    identifier = purl_to_component_identifier("pkg:maven/org.apache.commons/commons-text@1.9")
    assert identifier["format"] == "maven"
    assert identifier["coordinates"]["groupId"] == "org.apache.commons"
    assert identifier["coordinates"]["artifactId"] == "commons-text"


def test_purl_to_component_identifier_npm():
    identifier = purl_to_component_identifier("pkg:npm/axios@1.6.0")
    assert identifier["format"] == "npm"
    assert identifier["coordinates"]["packageId"] == "axios"


def test_purl_version_returns_empty_for_unparseable_purl():
    assert purl_version("not-a-purl") == ""


def test_purl_to_component_identifier_unknown_for_unparseable_purl():
    assert purl_to_component_identifier("not-a-purl") == {"format": "unknown", "coordinates": {}}


def test_purl_to_component_identifier_falls_back_to_name_for_other_types():
    identifier = purl_to_component_identifier("pkg:pypi/requests@2.31.0")
    assert identifier == {"format": "pypi", "coordinates": {"name": "requests", "version": "2.31.0"}}


def test_findings_from_policy_report_builds_findings_via_iq_client():
    violation = PolicyViolation(
        package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        component="commons-text",
        policy_name="Security-Critical",
        policy_id="p1",
        threat_level=9,
        constraint_summary="CVE",
        is_waived=False,
        action="fail",
    )
    client = FakeIQClient(
        remediations={
            "commons-text": RemediationResponse(
                version_changes=[VersionChange(change_type="next-non-failing", version="1.10.0")],
                parent_component="parent-bom",
                parent_current_version="1.0",
                parent_target_version="2.0",
                golden_version="1.12.0",
            )
        }
    )

    findings = findings_from_policy_report(client, "internal-1", [violation], "build")

    assert len(findings) == 1
    finding = findings[0]
    assert finding.component == "commons-text"
    assert finding.current_version == "1.9"
    assert finding.target_version == "1.10.0"
    assert finding.remediation_type == "next-non-failing"
    assert finding.parent_target_version == "2.0"
    assert finding.golden_version == "1.12.0"
    assert finding.threat_level == 9
    assert finding.is_actionable is True


def test_findings_from_policy_report_marks_finding_unactionable_without_remediation():
    violation = PolicyViolation(
        package_url="pkg:npm/axios@1.6.0",
        component="axios",
        policy_name="Security-High",
        policy_id="p2",
        threat_level=7,
        constraint_summary="CVE",
        is_waived=False,
        action="warn",
    )
    client = FakeIQClient()  # no remediations -> empty version_changes

    findings = findings_from_policy_report(client, "internal-1", [violation], "build")

    assert len(findings) == 1
    assert findings[0].target_version is None
    assert findings[0].remediation_type is None
    assert findings[0].is_actionable is False


# --------------------------------------------------------------------------------------
# Remediation is one POST per component against a live IQ instance. These lock in that it
# is only spent where it can change the outcome, and that a rejected component does not
# take the rest of the application down with it.
# --------------------------------------------------------------------------------------


def _violation(**overrides) -> PolicyViolation:
    base = dict(
        package_url="pkg:npm/axios@1.6.0", component="axios", policy_name="Security-High",
        policy_id="p1", threat_level=9, constraint_summary="CVE", is_waived=False,
        action="SECURITY",
        component_identifier={"format": "npm", "coordinates": {"packageId": "axios", "version": "1.6.0"}},
        current_version="1.6.0",
    )
    base.update(overrides)
    return PolicyViolation(**base)


class _CountingClient(FakeIQClient):
    """Counts remediation calls; optionally rejects one component the way IQ does."""

    def __init__(self, reject_component: str | None = None):
        super().__init__()
        self.calls: list[dict] = []
        self._reject = reject_component

    def fetch_remediation(self, internal_id, component_identifier, stage_id):
        self.calls.append(component_identifier)
        package_id = (component_identifier or {}).get("coordinates", {}).get("packageId")
        if self._reject is not None and package_id == self._reject:
            raise RuntimeError("400 Client Error: invalid component identifier packageUrl")
        return RemediationResponse(version_changes=[])


def test_below_threshold_components_never_cost_a_remediation_call():
    client = _CountingClient()
    violations = [
        _violation(threat_level=5, component="eol-thing"),
        _violation(threat_level=9, component="axios"),
    ]

    findings = findings_from_policy_report(client, "app-1", violations, "build", min_threat_level=8)

    assert len(client.calls) == 1, "only the level-9 component should be looked up"
    assert client.calls[0]["coordinates"]["packageId"] == "axios"
    assert len(findings) == 2, "the skipped component is still reported, just not remediated"
    skipped = next(f for f in findings if f.component == "eol-thing")
    assert skipped.escalation_reason == "threat level 5 below threshold 8"


def test_waived_components_never_cost_a_remediation_call():
    client = _CountingClient()
    findings = findings_from_policy_report(
        client, "app-1", [_violation(is_waived=True)], "build", min_threat_level=0
    )
    assert client.calls == []
    assert findings[0].is_waived is True


def test_a_rejected_component_escalates_and_the_run_continues():
    # The live failure: HTTP 400 "invalid component identifier packageUrl" on one component.
    # Before this, the exception propagated and the whole application run died on it.
    client = _CountingClient(reject_component="broken")
    violations = [
        _violation(component="broken", component_identifier={
            "format": "npm", "coordinates": {"packageId": "broken", "version": "1.0"}}),
        _violation(component="axios"),
    ]

    findings = findings_from_policy_report(client, "app-1", violations, "build", min_threat_level=8)

    assert len(findings) == 2, "the good component is still processed"
    broken = next(f for f in findings if f.component == "broken")
    assert broken.is_actionable is False
    assert "remediation lookup failed" in broken.escalation_reason
    assert "invalid component identifier" in broken.escalation_reason


def test_iq_identifier_is_preferred_over_one_rebuilt_from_the_purl():
    # The purl percent-encodes the "@"; IQ's own coordinates do not. Sending the rebuilt
    # one is what IQ rejects.
    client = _CountingClient()
    violation = _violation(
        package_url="pkg:npm/%40dfs-react-ui/core@1.4.6",
        component="@dfs-react-ui/core",
        component_identifier={
            "format": "npm",
            "coordinates": {"packageId": "@dfs-react-ui/core", "version": "1.4.6"},
        },
    )

    findings_from_policy_report(client, "app-1", [violation], "build", min_threat_level=8)

    assert client.calls[0]["coordinates"]["packageId"] == "@dfs-react-ui/core"
    assert "%40" not in client.calls[0]["coordinates"]["packageId"]


def test_each_remediation_post_is_logged_with_its_component_and_body(caplog):
    # So a run's POSTs can be tied to components and replayed by hand, without DEBUG.
    import logging as _logging

    client = _CountingClient()
    violations = [
        _violation(threat_level=5, component="eol-thing"),
        _violation(threat_level=9, component="axios"),
        _violation(threat_level=10, component="lodash", component_identifier={
            "format": "npm", "coordinates": {"packageId": "lodash", "version": "4.17.20"}}),
    ]

    with caplog.at_level(_logging.INFO):
        findings_from_policy_report(client, "app-1", violations, "build", min_threat_level=8)

    assert "remediation lookup 1/2: axios (threat 9)" in caplog.text
    assert "remediation lookup 2/2: lodash (threat 10)" in caplog.text
    assert '{"componentIdentifier": {"format": "npm"' in caplog.text
    # A skipped component costs no remediation POST. It does still get named in the
    # skipped list, so this asserts the absence of a *lookup* rather than the absence of
    # the name anywhere in the log.
    assert not any(
        "remediation lookup" in line and "eol-thing" in line
        for line in caplog.text.splitlines()
    ), "a skipped component must not cost a remediation POST"
    assert "eol-thing" in caplog.text, "but it must still be accounted for as skipped"
    assert "2 POST(s) sent, 1 skipped" in caplog.text


# --------------------------------------------------------------------------------------
# The CLI layer itself. A --flag whose name is not in the command function's signature
# raises TypeError only when the command actually runs, and nothing in the suite ran it —
# so `nexusfix run --interactive-agent` shipped broken with 297 tests green.
# --------------------------------------------------------------------------------------


def test_every_declared_option_is_accepted_by_its_command_function():
    """Introspective, so it covers flags added later — not just the one that broke."""
    import inspect

    from click import Command

    from nexus_autofix import cli as cli_mod

    checked = 0
    for name in dir(cli_mod):
        command = getattr(cli_mod, name)
        if not isinstance(command, Command) or command.callback is None:
            continue
        accepted = set(inspect.signature(command.callback).parameters)
        declared = {p.name for p in command.params}
        missing = declared - accepted
        assert not missing, (
            f"{command.name}: option(s) {sorted(missing)} are declared with @click.option "
            f"but absent from {command.callback.__name__}()'s signature — click passes them "
            "as keyword arguments, so invoking the command raises TypeError"
        )
        checked += 1
    assert checked, "no click commands were found to check"


def test_run_forwards_the_interactive_agent_flag_to_perform_run(tmp_path, monkeypatch):
    from unittest.mock import MagicMock, patch

    from click.testing import CliRunner

    from nexus_autofix import cli as cli_mod
    from nexus_autofix.iq.models import RunOutcome

    (tmp_path / "config.yml").write_text(
        "repos:\n  demo: https://example.com/o/demo.git\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    for var in ("IQ_URL", "IQ_USERNAME", "IQ_PASSWORD", "GITHUB_TOKEN"):
        monkeypatch.setenv(f"NEXUSFIX_{var}", "x")

    fake = MagicMock(return_value=cli_mod.RunResult(run_id="r1", outcome=RunOutcome.CLEAN))
    with patch.object(cli_mod, "perform_run", fake):
        result = CliRunner().invoke(
            cli_mod.run_command,
            ["--app-id", "demo", "--branch", "main", "--interactive-agent"],
        )

    assert result.exit_code == 0, result.output
    assert fake.call_args.kwargs["interactive_agent"] is True


def test_interactive_agent_defaults_to_off(tmp_path, monkeypatch):
    from unittest.mock import MagicMock, patch

    from click.testing import CliRunner

    from nexus_autofix import cli as cli_mod
    from nexus_autofix.iq.models import RunOutcome

    (tmp_path / "config.yml").write_text(
        "repos:\n  demo: https://example.com/o/demo.git\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    for var in ("IQ_URL", "IQ_USERNAME", "IQ_PASSWORD", "GITHUB_TOKEN"):
        monkeypatch.setenv(f"NEXUSFIX_{var}", "x")

    fake = MagicMock(return_value=cli_mod.RunResult(run_id="r1", outcome=RunOutcome.CLEAN))
    with patch.object(cli_mod, "perform_run", fake):
        result = CliRunner().invoke(
            cli_mod.run_command, ["--app-id", "demo", "--branch", "main"]
        )

    assert result.exit_code == 0, result.output
    assert fake.call_args.kwargs["interactive_agent"] is False


# --------------------------------------------------------------------------------------
# `discover` ends in a wall of JSON. Without a human summary the reader is left guessing
# what to do with it — but stdout is the machine contract, so the prose goes to stderr.
# --------------------------------------------------------------------------------------


def _discover_payload(**overrides):
    base = {
        "run_id": "run-123",
        "open_this_in_your_editor": "/ws/runs/run-123",
        "findings": [
            {"component": "brace-expansion", "current_version": "5.0.7",
             "target_version": "5.0.8", "threat_level": 9, "is_direct": False,
             "actionable": True},
        ],
    }
    base.update(overrides)
    return base


def test_the_next_steps_go_to_stderr_so_stdout_stays_parseable(capsys):
    import json as _json

    from nexus_autofix import cli as cli_mod

    payload = _discover_payload()
    cli_mod._agent_json(payload)
    cli_mod._echo_next_steps(payload)

    captured = capsys.readouterr()
    assert _json.loads(captured.out) == payload, "stdout must be JSON and nothing else"
    assert "NEXT STEPS" in captured.err
    assert "NEXT STEPS" not in captured.out


def test_the_summary_shows_the_version_change_and_the_commands(capsys):
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload())

    err = capsys.readouterr().err
    assert "brace-expansion  5.0.7 -> 5.0.8" in err
    assert "code /ws/runs/run-123" in err
    assert "Read RUNBOOK.md and follow it." in err
    assert "nexusfix check --run-id run-123" in err
    assert "nexusfix publish --run-id run-123" in err
    assert "leave them uncommitted" in err


def test_a_transitive_finding_is_flagged_as_such(capsys):
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload())

    assert "transitive" in capsys.readouterr().err


def test_an_unfixable_finding_is_listed_with_its_reason(capsys):
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload(findings=[
        {"component": "brace-expansion", "current_version": "5.0.7", "target_version": "5.0.8",
         "threat_level": 9, "is_direct": True, "actionable": True},
        {"component": "svgo", "current_version": "4.0.1", "target_version": None,
         "threat_level": 9, "is_direct": False, "actionable": False,
         "reason_not_actionable": "IQ offered 4.0.1, which is not an upgrade"},
    ]))

    err = capsys.readouterr().err
    assert "svgo  4.0.1 -> NOT FIXABLE" in err
    assert "not an upgrade" in err


def test_with_nothing_fixable_it_does_not_send_you_to_an_editor(capsys):
    # Opening a worktree to change nothing wastes the reader's time; the reasons are the
    # entire result of the run.
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload(findings=[
        {"component": "svgo", "current_version": "4.0.1", "target_version": None,
         "threat_level": 9, "is_direct": False, "actionable": False,
         "reason_not_actionable": "IQ offered 4.0.1, which is not an upgrade"},
    ]))

    err = capsys.readouterr().err
    assert "Nothing can be fixed automatically." in err
    assert "NEXT STEPS" not in err
    assert "Read RUNBOOK.md" not in err
    assert "nexusfix.log" in err, "point at where the reasons are recorded"


def test_the_next_steps_say_where_to_run_check_and_publish(capsys):
    # config.yml and .env are read from the CWD, so running these from the run directory —
    # which is exactly where the agent and the reader are — fails. The location has to be
    # on screen next to the commands.
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload(run_commands_from="/home/me/vulnfixer"))

    err = capsys.readouterr().err
    assert "FROM /home/me/vulnfixer" in err
    assert "will not" in err and "work from the run directory" in err


def test_a_missing_config_names_the_directory_to_run_from(tmp_path, monkeypatch):
    # Otherwise the failure is a bare "no such file" from inside yaml parsing, which does
    # not tell the reader they are simply standing in the wrong place.
    import click

    from nexus_autofix import cli as cli_mod

    monkeypatch.chdir(tmp_path)
    with pytest.raises(click.ClickException, match=r"Run this from: /home/me/vulnfixer"):
        cli_mod._config_for_run({"run_commands_from": "/home/me/vulnfixer"})


def test_a_missing_config_without_a_recorded_directory_still_explains(tmp_path, monkeypatch):
    import click

    from nexus_autofix import cli as cli_mod

    monkeypatch.chdir(tmp_path)
    with pytest.raises(click.ClickException, match="holding config.yml"):
        cli_mod._config_for_run({})


def test_the_printed_commands_use_the_resolved_executable(capsys):
    # "nexusfix" only resolves with the venv activated; on Windows it is
    # .venv\Scripts\nexusfix.exe. Printing the bare name makes the reader (or the agent)
    # work that out, which costs a failed command first.
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload(
        nexusfix_executable=r"C:\proj\.venv\Scripts\nexusfix.exe"
    ))

    err = capsys.readouterr().err
    assert r"C:\proj\.venv\Scripts\nexusfix.exe check --run-id run-123" in err
    assert r"C:\proj\.venv\Scripts\nexusfix.exe publish --run-id run-123" in err


def test_the_printed_commands_fall_back_to_the_bare_name(capsys):
    from nexus_autofix import cli as cli_mod

    cli_mod._echo_next_steps(_discover_payload())

    assert "nexusfix check --run-id run-123" in capsys.readouterr().err


def test_the_resolved_executable_is_an_absolute_path_when_argv0_is_real(monkeypatch, tmp_path):
    from nexus_autofix import cli as cli_mod

    fake = tmp_path / "nexusfix"
    fake.write_text("", encoding="utf-8")
    monkeypatch.setattr(cli_mod.sys, "argv", [str(fake)])

    assert cli_mod._this_executable() == str(fake.resolve())


def test_the_resolved_executable_degrades_to_the_bare_name(monkeypatch):
    # `python -m nexus_autofix.cli`, where argv[0] is not a file on disk.
    from nexus_autofix import cli as cli_mod

    monkeypatch.setattr(cli_mod.sys, "argv", ["-m"])
    assert cli_mod._this_executable() == "nexusfix"


def test_publish_does_not_open_a_pr_by_default():
    # Opening the PR is the only step needing NEXUSFIX_GITHUB_TOKEN; pushing uses git's own
    # credentials. Off by default so a token problem cannot fail a run whose real work — a
    # verified fix on a pushed branch — is already done.
    from click import Command

    from nexus_autofix import cli as cli_mod

    assert isinstance(cli_mod.publish_command, Command)
    option = next(p for p in cli_mod.publish_command.params if p.name == "open_pr")
    assert option.is_flag is True
    assert option.default is False
    assert "open_pr" in {p.name for p in cli_mod.publish_command.params}


# --------------------------------------------------------------------------------------
# `remediate` exists for components that never reached the policy report — a transitive
# dependency the scan could not resolve because the artifact is quarantined. The build
# names it in its 403; this turns that name into IQ's own recommended version.
# --------------------------------------------------------------------------------------


def test_a_maven_gav_uses_maven_coordinate_keys():
    # IQ rejects the wrong set with "coordinates containing the following incorrect
    # entries: packageId" — that is the npm key, and it was the reported failure.
    from nexus_autofix.cli import component_spec_to_identifier

    identifier = component_spec_to_identifier("io.netty:netty-codec-http:4.1.100.Final")

    assert identifier["format"] == "maven"
    assert identifier["coordinates"] == {
        "groupId": "io.netty", "artifactId": "netty-codec-http",
        "version": "4.1.100.Final", "extension": "jar",
    }
    assert "packageId" not in identifier["coordinates"]


def test_a_four_part_gav_keeps_its_extension():
    # The form Gradle's dependency report prints.
    from nexus_autofix.cli import component_spec_to_identifier

    identifier = component_spec_to_identifier("io.netty:netty-codec-http:4.1.100.Final:pom")
    assert identifier["coordinates"]["extension"] == "pom"


def test_an_npm_spec_uses_npm_coordinate_keys():
    from nexus_autofix.cli import component_spec_to_identifier

    identifier = component_spec_to_identifier("postcss@8.5.10")
    assert identifier == {"format": "npm", "coordinates": {"packageId": "postcss", "version": "8.5.10"}}


def test_a_scoped_npm_name_keeps_its_leading_at():
    # rpartition, not split: the leading @ is part of the name, not the version separator.
    from nexus_autofix.cli import component_spec_to_identifier

    identifier = component_spec_to_identifier("@charlietango/use-focus-trap@1.4.0")
    assert identifier["coordinates"]["packageId"] == "@charlietango/use-focus-trap"
    assert identifier["coordinates"]["version"] == "1.4.0"


def test_a_purl_is_accepted_too():
    from nexus_autofix.cli import component_spec_to_identifier

    identifier = component_spec_to_identifier("pkg:maven/io.netty/netty-codec-http@4.1.100.Final")
    assert identifier["coordinates"]["artifactId"] == "netty-codec-http"


def test_an_unreadable_spec_shows_the_accepted_forms():
    import click

    from nexus_autofix.cli import component_spec_to_identifier

    with pytest.raises(click.ClickException, match="io.netty:netty-codec-http"):
        component_spec_to_identifier("just-a-name")


def test_an_unexpected_failure_puts_its_traceback_in_the_run_log(tmp_path, monkeypatch):
    """The log file is what gets handed over when someone asks for help.

    Each command converts an unexpected exception into a one-line ClickException so the
    console stays readable. If that were all, the stack frames would exist nowhere — and
    the one artefact that gets shared would be the one that cannot say where it broke.
    """
    from unittest.mock import patch

    from click.testing import CliRunner

    from nexus_autofix import agent_api
    from nexus_autofix import cli as cli_mod

    (tmp_path / "config.yml").write_text(
        "repos:\n  demo: https://example.com/o/demo.git\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "ws"
    monkeypatch.setenv("NEXUSFIX_WORKSPACE_ROOT", str(workspace))
    for var in ("IQ_URL", "IQ_USERNAME", "IQ_PASSWORD"):
        monkeypatch.setenv(f"NEXUSFIX_{var}", "x")

    run_dir = workspace / "runs" / "r1"
    agent_api.save_run_state(run_dir, {
        "run_id": "r1",
        "run_dir": str(run_dir),
        "worktree": str(run_dir / "wt"),
        "ecosystem": "npm",
        "commit_sha": "deadbeef",
        "run_commands_from": str(tmp_path),
    })

    boom = RuntimeError("something deep in the diff walker went wrong")
    with patch.object(agent_api, "check_worktree", side_effect=boom):
        result = CliRunner().invoke(cli_mod.check_command, ["--run-id", "r1"])

    assert result.exit_code != 0
    # The console gets the short form...
    assert "RuntimeError: something deep in the diff walker went wrong" in result.output
    assert "Traceback" not in result.output
    # ...and the log file keeps the frames.
    logged = (run_dir / "nexusfix.log").read_text(encoding="utf-8")
    assert "Traceback (most recent call last)" in logged
    assert "something deep in the diff walker went wrong" in logged
    assert "nexusfix check" in logged


def test_every_agent_facing_command_logs_its_failures():
    """Introspective, so a command added later is covered without editing this test."""
    from nexus_autofix import cli as cli_mod

    for name in ("discover", "check", "publish", "remediate"):
        command = getattr(cli_mod, f"{name}_command")
        assert getattr(command.callback, "__wrapped__", None) is not None, (
            f"`{name}` is not wrapped in @logs_failures, so an unexpected exception "
            "reaches the console as a one-liner and leaves no traceback in nexusfix.log — "
            "which is the file a user sends when asking why it broke"
        )


def _skipped_violation(component, threat, waived=False, waiver_reason="", policy="Security-High",
               version="1.0.0"):
    from nexus_autofix.iq.client import PolicyViolation

    return PolicyViolation(
        package_url=f"pkg:npm/{component}@{version}",
        component=component,
        policy_name=policy,
        policy_id="p1",
        threat_level=threat,
        constraint_summary="",
        is_waived=waived,
        action="SECURITY",
        current_version=version,
        waiver_reason=waiver_reason,
    )


def test_skipped_components_are_named_with_their_reason(caplog):
    """A bare count cannot distinguish a well-tuned threshold from one hiding something."""
    import logging

    from nexus_autofix import cli as cli_mod

    with caplog.at_level(logging.INFO, logger="nexus_autofix.cli"):
        cli_mod._log_skipped(
            waived_out=[_skipped_violation("jackson-databind", 9, waived=True,
                                   waiver_reason="auto-waiver")],
            below_bar=[_skipped_violation("lodash", 5, policy="Security-Medium")],
            min_threat_level=8,
        )

    assert "jackson-databind 1.0.0" in caplog.text
    assert "auto-waiver" in caplog.text
    assert "lodash 1.0.0" in caplog.text
    assert "Security-Medium" in caplog.text
    assert "below min_threat_level=8" in caplog.text


def test_every_skipped_component_is_listed_not_a_top_n(caplog):
    """Truncating would read as full coverage while omitting the one being looked for."""
    import logging

    from nexus_autofix import cli as cli_mod

    below = [_skipped_violation(f"pkg-{i}", 3) for i in range(25)]
    with caplog.at_level(logging.INFO, logger="nexus_autofix.cli"):
        cli_mod._log_skipped(waived_out=[], below_bar=below, min_threat_level=8)

    for i in range(25):
        assert f"pkg-{i} " in caplog.text


def test_a_near_miss_says_how_to_include_it(caplog):
    import logging

    from nexus_autofix import cli as cli_mod

    with caplog.at_level(logging.INFO, logger="nexus_autofix.cli"):
        cli_mod._log_skipped(
            waived_out=[], below_bar=[_skipped_violation("almost", 7)], min_threat_level=8,
        )

    assert "one below the threshold" in caplog.text


def test_a_waiver_of_unstated_kind_says_so_rather_than_inventing_one(caplog):
    import logging

    from nexus_autofix import cli as cli_mod

    with caplog.at_level(logging.INFO, logger="nexus_autofix.cli"):
        cli_mod._log_skipped(
            waived_out=[_skipped_violation("mystery", 9, waived=True)], below_bar=[],
            min_threat_level=8,
        )

    assert "waiver kind not stated by IQ" in caplog.text


def _project_config(**overrides):
    from nexus_autofix.config import ProjectConfig

    base = dict(
        subprocess_timeout_seconds=60, max_attempts=1, poll_timeout_seconds=60,
        default_stage_id="build", default_gate="none", min_threat_level=8,
        java_toolchains={}, node_toolchains={}, repos={"demo": "https://x/o/demo.git"},
    )
    base.update(overrides)
    return ProjectConfig(**base)


def test_a_rescan_from_the_other_scanner_is_refused():
    """The one way this could ship a false success: compare_reports decides "cleared" by
    absence, so a deep baseline against a shallow rescan clears everything invisibly."""
    import click

    from nexus_autofix import cli as cli_mod

    with pytest.raises(click.ClickException) as exc:
        cli_mod._require_matching_scan_method(
            {"scan_method": "iq-cli"}, _project_config(iq_cli_jar=""),
        )

    assert "would report findings as cleared" in str(exc.value)
    assert "nexusfix discover" in str(exc.value)


def test_the_reverse_mismatch_is_refused_too():
    import click

    from nexus_autofix import cli as cli_mod

    with pytest.raises(click.ClickException):
        cli_mod._require_matching_scan_method(
            {"scan_method": "source-control"}, _project_config(iq_cli_jar="/x/iq.jar"),
        )


def test_a_matching_scan_method_passes():
    from nexus_autofix import cli as cli_mod

    cli_mod._require_matching_scan_method(
        {"scan_method": "iq-cli"}, _project_config(iq_cli_jar="/x/iq.jar")
    )
    cli_mod._require_matching_scan_method(
        {"scan_method": "source-control"}, _project_config()
    )


def test_a_run_from_before_scan_method_was_recorded_is_not_blocked():
    """Old run.json files have no scan_method. Those predate the CLI option entirely, so
    they can only have been source-control scans; refusing them would strand them."""
    from nexus_autofix import cli as cli_mod

    cli_mod._require_matching_scan_method({}, _project_config())


def test_without_the_jar_configured_the_scan_is_source_control():
    from unittest.mock import MagicMock

    from nexus_autofix import cli as cli_mod

    iq_client = MagicMock()
    iq_client.poll_evaluation.return_value = "report-1"

    report_id = cli_mod._scan_for_report(
        iq_client=iq_client, config=_project_config(), secrets=MagicMock(),
        app_id="demo", internal_id="i1", branch="main", worktree_path=Path("/tmp/wt"),
        run_dir=Path("/tmp/run"), ecosystem="gradle", java_version=None,
        node_version=None, label="baseline",
    )

    assert report_id == "report-1"
    iq_client.start_source_control_evaluation.assert_called_once()


def test_with_the_jar_configured_the_app_is_built_then_scanned(tmp_path):
    from unittest.mock import MagicMock, patch

    from nexus_autofix import cli as cli_mod
    from nexus_autofix.iq.cli_scan import CLIScanResult
    from nexus_autofix.verify.commands import CommandResult

    iq_client = MagicMock()
    build_ok = CommandResult(returncode=0, stdout="", stderr="")
    scanned = CLIScanResult(report_id="cli-report", policy_action="Failure",
                            result_file=tmp_path / "r.json")

    with patch.object(cli_mod.commands_mod, "run_command", return_value=build_ok) as build, \
            patch.object(cli_mod.cli_scan_mod, "run_cli_scan", return_value=scanned) as scan:
        report_id = cli_mod._scan_for_report(
            iq_client=iq_client, config=_project_config(iq_cli_jar=str(tmp_path / "iq.jar")),
            secrets=MagicMock(), app_id="demo", internal_id="i1", branch="main",
            worktree_path=tmp_path, run_dir=tmp_path, ecosystem="gradle",
            java_version=None, node_version=None, label="baseline",
        )

    assert report_id == "cli-report"
    build.assert_called_once()
    scan.assert_called_once()
    iq_client.start_source_control_evaluation.assert_not_called()


def test_a_failed_build_stops_rather_than_scanning_an_empty_directory(tmp_path):
    """Scanning nothing yields an application with no components, which reads exactly like
    an application with no problems."""
    import click
    from unittest.mock import MagicMock, patch

    from nexus_autofix import cli as cli_mod
    from nexus_autofix.verify.commands import CommandResult

    failed = CommandResult(returncode=1, stdout="compile error", stderr="")

    with patch.object(cli_mod.commands_mod, "run_command", return_value=failed), \
            patch.object(cli_mod.cli_scan_mod, "run_cli_scan") as scan, \
            pytest.raises(click.ClickException) as exc:
        cli_mod._scan_for_report(
            iq_client=MagicMock(),
            config=_project_config(iq_cli_jar=str(tmp_path / "iq.jar")),
            secrets=MagicMock(), app_id="demo", internal_id="i1", branch="main",
            worktree_path=tmp_path, run_dir=tmp_path, ecosystem="gradle",
            java_version=None, node_version=None, label="baseline",
        )

    assert "no artifacts to scan" in str(exc.value)
    assert "compile error" in str(exc.value)
    scan.assert_not_called()
