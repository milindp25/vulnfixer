import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from nexus_autofix.iq.cli_scan import (
    CLIScanResult,
    IQCLIScanError,
    _find_report_url,
    _redact,
    run_cli_scan,
)


def _jar(tmp_path: Path) -> Path:
    jar = tmp_path / "nexus-iq-cli.jar"
    jar.write_text("not really a jar", encoding="utf-8")
    return jar


def _target(tmp_path: Path) -> Path:
    build = tmp_path / "build"
    build.mkdir()
    return build


def _run(tmp_path, result_body=None, returncode=0, write_result=True, **kwargs):
    result_file = tmp_path / "result.json"

    def fake_run(args, **_):
        if write_result:
            body = result_body if result_body is not None else {
                "applicationId": "demo",
                "reportDataUrl": "api/v2/applications/demo/reports/abc123/raw",
                "policyAction": "Failure",
            }
            result_file.write_text(json.dumps(body), encoding="utf-8")
        return MagicMock(returncode=returncode, stdout="scan output", stderr="")

    with patch("nexus_autofix.iq.cli_scan.subprocess.run", side_effect=fake_run) as mock:
        result = run_cli_scan(
            jar_path=_jar(tmp_path), scan_target=_target(tmp_path), app_id="demo",
            iq_url="https://iq.example.com", username="u", password="p",
            stage_id="build", result_file=result_file, timeout_seconds=60, **kwargs,
        )
    return result, mock


def test_the_command_matches_the_invocation_already_used_in_ci(tmp_path):
    _, mock = _run(tmp_path)
    args = mock.call_args.args[0]
    joined = " ".join(args)

    assert args[0] == "java"
    assert "-jar" in args
    for flag, value in (("-i", "demo"), ("-s", "https://iq.example.com"),
                        ("-a", "u:p"), ("-t", "build")):
        assert f"{flag} {value}" in joined, f"missing {flag} {value}"
    assert args[-1].endswith("build"), "the scan target is the trailing positional argument"


def test_credentials_are_never_written_to_the_log(tmp_path, caplog):
    with caplog.at_level(logging.DEBUG, logger="nexus_autofix.iq.cli_scan"):
        _run(tmp_path)

    assert "u:p" not in caplog.text
    assert "***:***" in caplog.text


def test_redact_leaves_everything_except_the_credentials():
    line = _redact(["java", "-jar", "x.jar", "-a", "user:secret", "-t", "build"])
    assert "user:secret" not in line
    assert "***:***" in line
    assert "-t build" in line


def test_a_failing_policy_is_not_an_error(tmp_path):
    """A non-zero exit is the normal outcome for an app with a failing policy — which is
    exactly the app this tool exists to fix. Treating it as an error would make the tool
    refuse precisely the repos it is for."""
    result, _ = _run(tmp_path, returncode=1)

    assert isinstance(result, CLIScanResult)
    assert result.report_id == "abc123"
    assert result.policy_action == "Failure"


def test_no_result_file_is_an_error_and_reports_the_output(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        _run(tmp_path, returncode=2, write_result=False)

    assert "wrote no result file" in str(exc.value)
    assert "scan output" in str(exc.value)


def test_a_stale_result_file_is_not_read_as_this_runs_result(tmp_path):
    result_file = tmp_path / "result.json"
    result_file.write_text(json.dumps({"reportDataUrl": "api/v2/a/reports/STALE/raw"}),
                           encoding="utf-8")

    def fake_run(args, **_):
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("nexus_autofix.iq.cli_scan.subprocess.run", side_effect=fake_run), \
            pytest.raises(IQCLIScanError):
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_target=_target(tmp_path), app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=result_file, timeout_seconds=60,
        )


def test_an_unbuilt_target_says_so_rather_than_scanning_nothing(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_target=tmp_path / "build", app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=tmp_path / "r.json", timeout_seconds=60,
        )

    assert "has to be built" in str(exc.value)


def test_a_missing_jar_names_the_config_key(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=tmp_path / "absent.jar", scan_target=_target(tmp_path), app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=tmp_path / "r.json", timeout_seconds=60,
        )

    assert "iq_cli_jar" in str(exc.value)


@pytest.mark.parametrize("body,expected", [
    ({"reportDataUrl": "api/v2/applications/a/reports/r1/raw"}, "r1"),
    ({"reportHtmlUrl": "https://iq/ui/links/application/a/report/r2"}, "r2"),
    # Schema drift: the URL under some other key, or nested, is still found.
    ({"scan": {"links": {"policyReport": "https://iq/x/reports/r3/raw"}}}, "r3"),
    ({"results": [{"reportHtmlUrl": "https://iq/ui/links/application/a/report/r4"}]}, "r4"),
])
def test_the_report_id_is_found_whatever_the_result_file_calls_it(tmp_path, body, expected):
    """The result-file schema varies by CLI version and is not verified against the one in
    use, so a naming difference must not become "the scan produced nothing"."""
    result, _ = _run(tmp_path, result_body=body)
    assert result.report_id == expected


def test_the_data_url_wins_when_several_are_present(tmp_path):
    """It is the API form, so it is the shape verified against a live instance."""
    result, _ = _run(tmp_path, result_body={
        "reportHtmlUrl": "https://iq/ui/links/application/a/report/html-id",
        "reportDataUrl": "api/v2/applications/a/reports/data-id/raw",
    })
    assert result.report_id == "data-id"


def test_a_result_file_with_no_report_url_points_at_the_logged_contents(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        _run(tmp_path, result_body={"applicationId": "demo", "policyAction": "None"})

    assert "no report URL" in str(exc.value)
    assert "logged at INFO" in str(exc.value)


def test_the_whole_result_file_is_logged_so_a_schema_surprise_needs_one_round_trip(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="nexus_autofix.iq.cli_scan"):
        _run(tmp_path, result_body={
            "reportDataUrl": "api/v2/applications/demo/reports/abc123/raw",
            "somethingUnexpected": "worth seeing",
        })

    assert "somethingUnexpected" in caplog.text


def test_find_report_url_ignores_strings_that_are_not_reports():
    assert _find_report_url({"note": "no url here", "n": 3}) is None
    assert _find_report_url({"url": "https://iq/ui/dashboard"}) is None
