"""`appsec-discover` end to end, with Nexus IQ and the base discovery mocked out.

Proves the wiring the unit tests cannot: that sheet rows for THIS repo become findings in
run.json, that IQ is asked about each one, and that a disagreement survives all the way to
the file `check` reads.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from nexus_autofix import cli as cli_mod
from nexus_autofix.iq.client import PolicyViolation, RemediationResponse, VersionChange

ORG, REPO = "cardissuer-customerprofile-org", "ac-registration-app"
HEADERS = ["GITHUB_ORG", "GITHUB_REPO_NAME", "LIBRARY_NAME", "LIBRARY_FILENAME",
           "VULN_TOPFIX_RESOLUTION", "LIBRARY_TYPE", "VULN_NAME", "DIRECT_DEPENDENCY",
           "CVSS3 Score"]


def _sheet(tmp_path, rows):
    import openpyxl

    book = openpyxl.Workbook()
    book.active.append(HEADERS)
    for row in rows:
        book.active.append(row)
    path = tmp_path / "sca.xlsx"
    book.save(path)
    return path


def _row(filename, topfix, org=ORG, repo=REPO, vuln="CVE-2016-1", name="Lib"):
    return [org, repo, name, filename, topfix, "Java", vuln, "FALSE", 7.5]


@pytest.fixture
def env(tmp_path, monkeypatch):
    (tmp_path / "config.yml").write_text(
        f"repos:\n  demo: https://github.com/{ORG}/{REPO}.git\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    workspace = tmp_path / "ws"
    monkeypatch.setenv("NEXUSFIX_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("NEXUSFIX_APP_ID", "demo")
    monkeypatch.setenv("NEXUSFIX_BRANCH", "main")
    for var in ("IQ_URL", "IQ_USERNAME", "IQ_PASSWORD"):
        monkeypatch.setenv(f"NEXUSFIX_{var}", "x")
    return workspace / "runs" / "r1"


def _base_payload(run_dir, findings=()):
    return {
        "run_id": "r1", "run_dir": str(run_dir), "worktree": str(run_dir / "wt"),
        "fix_branch": "autofix/nexus/r1", "app_id": "demo", "base_branch": "main",
        "repo_url": f"https://github.com/{ORG}/{REPO}.git", "commit_sha": "abc123",
        "internal_id": "int-1", "baseline_report_id": "rep-1", "scan_method": "iq-cli",
        "ecosystem": "gradle", "java_version": "17", "node_version": None,
        "target_purls": [], "findings": list(findings),
        "runbook": str(run_dir / "RUNBOOK.md"), "open_this_in_your_editor": str(run_dir),
    }


def _run(sheet_path, run_dir, *, violations=(), remediation_versions=None, findings=()):
    """Invoke the command with IQ and the base discovery replaced."""
    client = MagicMock()
    client.fetch_policy_report.return_value = list(violations)

    def remediation(_internal, identifier, _stage):
        artifact = (identifier.get("coordinates") or {}).get("artifactId", "")
        version = (remediation_versions or {}).get(artifact)
        return RemediationResponse(
            version_changes=[VersionChange("next-no-violations", version)] if version else []
        )

    client.fetch_remediation.side_effect = remediation

    with patch.object(cli_mod, "perform_discovery", return_value=_base_payload(run_dir, findings)), \
         patch.object(cli_mod, "HTTPIQClient", return_value=client):
        result = CliRunner().invoke(
            cli_mod.appsec_discover_command, ["--sheet", str(sheet_path)]
        )
    return result, client


def _state(run_dir):
    return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))


def test_a_sheet_row_becomes_a_finding_in_run_json(env, tmp_path):
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    result, _ = _run(sheet, env)

    assert result.exit_code == 0, result.output
    findings = _state(env)["findings"]
    assert len(findings) == 1
    assert findings[0]["component"] == "xalan:xalan"
    assert findings[0]["target_version"] == "2.7.3"
    assert findings[0]["source"] == ["appsec"]
    assert findings[0]["actionable"] is True


def test_rows_for_another_repo_are_ignored(env, tmp_path):
    sheet = _sheet(tmp_path, [
        _row("xalan-2.7.2.jar", "xalan:xalan:2.7.3"),
        _row("other-1.0.jar", "g:other:2.0", org="someone-else", repo="another-app"),
    ])
    _run(sheet, env)

    state = _state(env)
    assert [f["component"] for f in state["findings"]] == ["xalan:xalan"]
    assert state["appsec"]["libraries_for_this_repo"] == 1
    assert state["appsec"]["libraries_total"] == 2


def test_iq_is_asked_about_each_library(env, tmp_path):
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    _, client = _run(sheet, env)

    client.fetch_remediation.assert_called_once()
    identifier = client.fetch_remediation.call_args[0][1]
    assert identifier["coordinates"]["artifactId"] == "xalan"
    assert identifier["coordinates"]["groupId"] == "xalan"


def test_a_disagreement_reaches_run_json_as_an_unresolved_conflict(env, tmp_path):
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    result, _ = _run(sheet, env, remediation_versions={"xalan": "2.7.9"})

    finding = _state(env)["findings"][0]
    assert finding["appsec_decision"] == "CONFLICT"
    assert finding["actionable"] is False
    assert finding["candidate_versions"] == ["2.7.9", "2.7.3"]
    assert _state(env)["appsec"]["unresolved_conflicts"] == ["xalan:xalan"]
    # And the human is told exactly how to settle it, on stderr.
    assert "nexusfix resolve --run-id r1" in result.output


def test_a_conflicted_finding_is_not_in_target_purls(env, tmp_path):
    # target_purls drives publish's rescan. A component nobody has decided on must not be
    # listed as something this run set out to fix.
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    _run(sheet, env, remediation_versions={"xalan": "2.7.9"})
    assert _state(env)["target_purls"] == []


def test_an_artifact_swap_is_reported_and_not_applied(env, tmp_path):
    sheet = _sheet(tmp_path, [_row(
        "bcprov-jdk15on-1.49.jar",
        "org.bouncycastle:bc-fips:2.1.3,org.bouncycastle:bcprov-lts8on:2.73.12",
    )])
    result, _ = _run(sheet, env)

    state = _state(env)
    assert state["findings"][0]["appsec_decision"] == "SWAP_ONLY"
    assert state["findings"][0]["actionable"] is False
    assert state["appsec"]["artifact_swaps"][0]["component"] == "bcprov-jdk15on"
    assert "migration" in result.output


def test_the_same_artifact_under_two_groups_is_left_ambiguous(env, tmp_path):
    sheet = _sheet(tmp_path, [_row(
        "jackson-core-2.18.6.jar",
        "com.fasterxml.jackson.core:jackson-core:2.18.8,tools.jackson.core:jackson-core:3.1.4",
    )])
    _run(sheet, env)

    state = _state(env)
    assert state["findings"][0]["appsec_decision"] == "AMBIGUOUS_GROUP"
    assert state["appsec"]["ambiguous_groups"][0]["component"] == "jackson-core"


def test_iqs_group_id_settles_an_ambiguous_library(env, tmp_path):
    """The policy report states the installed group, which the sheet never does."""
    violation = PolicyViolation(
        package_url="pkg:maven/com.fasterxml.jackson.core/jackson-core@2.18.6",
        component="com.fasterxml.jackson.core:jackson-core",
        policy_name="Security-High", policy_id="p", threat_level=7,
        constraint_summary="", is_waived=False, action="warn",
        component_identifier={"format": "maven", "coordinates": {
            "groupId": "com.fasterxml.jackson.core", "artifactId": "jackson-core",
            "version": "2.18.6", "extension": "jar"}},
        current_version="2.18.6",
    )
    sheet = _sheet(tmp_path, [_row(
        "jackson-core-2.18.6.jar",
        "com.fasterxml.jackson.core:jackson-core:2.18.8,tools.jackson.core:jackson-core:3.1.4",
    )])
    _run(sheet, env, violations=[violation])

    finding = _state(env)["findings"][0]
    assert finding["appsec_decision"] == "RESOLVED"
    assert finding["target_version"] == "2.18.8"
    # The Jackson 3 coordinate is kept, correctly labelled as a migration.
    assert finding["swap_candidates"] == ["tools.jackson.core:jackson-core:3.1.4"]


def test_an_iq_finding_and_a_sheet_row_for_one_component_merge(env, tmp_path):
    existing = {
        "component": "xalan:xalan", "package_url": "pkg:maven/xalan/xalan@2.7.2",
        "current_version": "2.7.2", "target_version": "2.7.3",
        "remediation_type": "next-no-violations", "threat_level": 9,
        "policy_name": "Security-Critical", "is_direct": True, "pulled_in_by": [],
        "actionable": True, "reason_not_actionable": None, "source": ["iq"],
        "cve_ids": ["CVE-2022-9"], "iq_version": None, "sheet_version": None,
        "appsec_decision": None, "candidate_versions": [], "swap_candidates": [],
    }
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3", vuln="CVE-2026-2")])
    _run(sheet, env, remediation_versions={"xalan": "2.7.3"}, findings=[existing])

    findings = _state(env)["findings"]
    assert len(findings) == 1, "the same component must not appear twice"
    assert findings[0]["source"] == ["appsec", "iq"]
    assert findings[0]["cve_ids"] == ["CVE-2022-9", "CVE-2026-2"]
    assert findings[0]["threat_level"] == 9


def test_nexus_iq_is_asked_about_the_mapped_application_name(env, tmp_path):
    """The config key and the IQ application ID are allowed to differ.

    `payments-core` in config.yml can be `card-payments-core` in Nexus IQ. Reports must be
    fetched under the IQ name; using the key would 404 against a real instance.
    """
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    payload = _base_payload(env)
    payload["iq_app_id"] = "card-demo"

    client = MagicMock()
    client.fetch_policy_report.return_value = []
    client.fetch_remediation.return_value = RemediationResponse(version_changes=[])

    with patch.object(cli_mod, "perform_discovery", return_value=payload), \
         patch.object(cli_mod, "HTTPIQClient", return_value=client):
        result = CliRunner().invoke(cli_mod.appsec_discover_command, ["--sheet", str(sheet)])

    assert result.exit_code == 0, result.output
    assert client.fetch_policy_report.call_args[0][0] == "card-demo"


def test_an_older_run_without_the_mapping_still_works(env, tmp_path):
    # run.json written before iq_app_id existed carries only app_id, and back then the two
    # were the same string by construction.
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    _, client = _run(sheet, env)
    assert client.fetch_policy_report.call_args[0][0] == "demo"


def test_the_sheet_is_recorded_with_its_checksum(env, tmp_path):
    sheet = _sheet(tmp_path, [_row("xalan-2.7.2.jar", "xalan:xalan:2.7.3")])
    _run(sheet, env)

    appsec = _state(env)["appsec"]
    assert appsec["sheet"] == str(sheet)
    assert len(appsec["sheet_sha256"]) == 64


def test_a_missing_sheet_is_refused_before_anything_runs(env, tmp_path):
    result = CliRunner().invoke(
        cli_mod.appsec_discover_command, ["--sheet", str(tmp_path / "nope.xlsx")]
    )
    assert result.exit_code != 0
    assert "no AppSec worksheet at" in result.output
    assert not (env / "run.json").exists()


def test_no_sheet_anywhere_names_every_way_to_supply_one(env):
    result = CliRunner().invoke(cli_mod.appsec_discover_command, [])
    assert result.exit_code != 0
    assert "--sheet" in result.output
    assert "appsec.sheet" in result.output
    assert "NEXUSFIX_APPSEC_SHEET" in result.output


def test_every_trident_ecosystem_has_a_library_type():
    """The map must cover what `.trident/build.yaml` can actually declare.

    A missing entry falls through to "no filter", which lets another ecosystem's rows be
    parsed with the wrong filename rules — the failure mode is a plausible-looking artifact
    that does not exist, not an error.
    """
    from nexus_autofix.repo.trident import KNOWN_ECOSYSTEMS

    assert set(cli_mod.APPSEC_LIBRARY_TYPES) == KNOWN_ECOSYSTEMS


def test_a_javascript_row_is_skipped_for_a_gradle_repo(env, tmp_path):
    sheet = _sheet(tmp_path, [
        _row("xalan-2.7.2.jar", "xalan:xalan:2.7.3"),
        [ORG, REPO, "Lodash", "lodash-4.17.20.tgz", "x:lodash:4.17.21", "JavaScript",
         "CVE-2021-1", "FALSE", 7.5],
    ])
    _run(sheet, env)

    state = _state(env)
    assert [f["component"] for f in state["findings"]] == ["xalan:xalan"]
    assert state["appsec"]["skipped_wrong_type"] == 1
