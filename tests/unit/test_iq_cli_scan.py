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
            jar_path=_jar(tmp_path), scan_targets=[_target(tmp_path)], app_id="demo",
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
            jar_path=_jar(tmp_path), scan_targets=[_target(tmp_path)], app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=result_file, timeout_seconds=60,
        )


def test_an_unbuilt_target_says_so_rather_than_scanning_nothing(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_targets=[tmp_path / "build"], app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=tmp_path / "r.json", timeout_seconds=60,
        )

    assert "do not exist" in str(exc.value)
    # The message has to cover both shapes of this mistake, because the live one was a
    # Node repo pointed at `build/` — where the fix is not "build it" but "scan the
    # lockfile instead".
    assert "build produced no output" in str(exc.value)
    assert "LOCKFILE" in str(exc.value)


def test_a_missing_jar_names_the_config_key(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=tmp_path / "absent.jar", scan_targets=[_target(tmp_path)], app_id="demo",
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


# --- ensure_jar -----------------------------------------------------------------------

def _download(tmp_path, payload=b"jar bytes", **kwargs):
    from nexus_autofix.iq.cli_scan import ensure_jar

    session = MagicMock()
    response = MagicMock()
    response.iter_content.return_value = [payload]
    response.raise_for_status.return_value = None
    session.get.return_value = response
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: None

    with patch("nexus_autofix.iq.cli_scan.make_session", return_value=session):
        return ensure_jar(tmp_path / "tools" / "iq.jar", **kwargs), session


def test_an_existing_jar_is_never_re_downloaded(tmp_path):
    from nexus_autofix.iq.cli_scan import ensure_jar

    jar = tmp_path / "iq.jar"
    jar.write_text("already here", encoding="utf-8")

    with patch("nexus_autofix.iq.cli_scan.make_session") as session:
        result = ensure_jar(jar, "https://example.com/iq.jar")

    assert result == jar
    session.assert_not_called()


def test_a_missing_jar_is_downloaded_from_the_configured_url(tmp_path):
    jar, session = _download(tmp_path, download_url="https://example.com/iq.jar")

    assert jar.is_file()
    assert jar.read_bytes() == b"jar bytes"
    session.get.assert_called_once()


def test_a_checksum_mismatch_installs_nothing(tmp_path):
    """A URL that quietly starts serving something else is not a failure anyone notices,
    and this jar runs with the IQ credentials on its command line."""
    with pytest.raises(IQCLIScanError) as exc:
        _download(tmp_path, download_url="https://example.com/iq.jar", sha256="0" * 64)

    assert "does not match the expected checksum" in str(exc.value)
    assert not (tmp_path / "tools" / "iq.jar").exists()
    assert not (tmp_path / "tools" / "iq.jar.partial").exists()


def test_a_matching_checksum_installs_the_jar(tmp_path):
    import hashlib

    expected = hashlib.sha256(b"jar bytes").hexdigest()
    jar, _ = _download(tmp_path, download_url="https://example.com/iq.jar", sha256=expected)

    assert jar.read_bytes() == b"jar bytes"


def test_downloading_without_a_checksum_warns_and_prints_the_one_to_pin(tmp_path, caplog):
    import hashlib

    with caplog.at_level(logging.WARNING, logger="nexus_autofix.iq.cli_scan"):
        _download(tmp_path, download_url="https://example.com/iq.jar")

    assert hashlib.sha256(b"jar bytes").hexdigest() in caplog.text
    assert "iq_cli_sha256" in caplog.text


def test_a_plain_http_url_is_refused(tmp_path):
    from nexus_autofix.iq.cli_scan import ensure_jar

    with pytest.raises(IQCLIScanError) as exc:
        ensure_jar(tmp_path / "iq.jar", "http://example.com/iq.jar")

    assert "non-HTTPS" in str(exc.value)


def test_an_interrupted_download_leaves_no_jar_behind(tmp_path):
    """A truncated jar would look present and fail obscurely on every later run."""
    from nexus_autofix.iq.cli_scan import ensure_jar

    session = MagicMock()
    session.__enter__ = lambda s: s
    session.__exit__ = lambda *a: None
    session.get.side_effect = OSError("connection reset")

    with patch("nexus_autofix.iq.cli_scan.make_session", return_value=session), \
            pytest.raises(IQCLIScanError) as exc:
        ensure_jar(tmp_path / "iq.jar", "https://example.com/iq.jar")

    assert "could not download" in str(exc.value)
    assert not (tmp_path / "iq.jar").exists()
    assert not (tmp_path / "iq.jar.partial").exists()


def test_no_jar_and_no_url_names_both_ways_to_fix_it(tmp_path):
    from nexus_autofix.iq.cli_scan import ensure_jar

    with pytest.raises(IQCLIScanError) as exc:
        ensure_jar(tmp_path / "iq.jar")

    assert "NEXUSFIX_IQ_CLI_URL" in str(exc.value)


# --- per-ecosystem scan targets --------------------------------------------------------

def _node_repo(tmp_path, *files):
    for name in files:
        (tmp_path / name).write_text("{}", encoding="utf-8")
    return tmp_path


def test_a_yarn_project_is_scanned_at_its_lockfile_and_manifest(tmp_path):
    """The live failure: a Node repo pointed at `build/` finds nothing and reports an
    application with no dependencies at all."""
    from nexus_autofix.iq.cli_scan import default_scan_targets

    _node_repo(tmp_path, "yarn.lock", "package.json")

    targets = default_scan_targets("yarn", tmp_path)

    assert [t.name for t in targets] == ["yarn.lock", "package.json"]


def test_an_npm_project_prefers_its_lockfile(tmp_path):
    from nexus_autofix.iq.cli_scan import default_scan_targets

    _node_repo(tmp_path, "package-lock.json", "package.json")

    assert [t.name for t in default_scan_targets("npm", tmp_path)] == [
        "package-lock.json", "package.json"
    ]


def test_a_pnpm_project_uses_its_own_lockfile_name(tmp_path):
    from nexus_autofix.iq.cli_scan import default_scan_targets

    _node_repo(tmp_path, "pnpm-lock.yaml", "package.json")

    assert [t.name for t in default_scan_targets("pnpm", tmp_path)] == [
        "pnpm-lock.yaml", "package.json"
    ]


def test_a_node_project_without_a_lockfile_falls_back_to_the_manifest(tmp_path):
    from nexus_autofix.iq.cli_scan import default_scan_targets

    _node_repo(tmp_path, "package.json")

    assert [t.name for t in default_scan_targets("npm", tmp_path)] == ["package.json"]


def test_a_gradle_project_is_scanned_at_its_build_output(tmp_path):
    from nexus_autofix.iq.cli_scan import default_scan_targets

    (tmp_path / "build").mkdir()

    assert [t.name for t in default_scan_targets("gradle", tmp_path)] == ["build"]


def test_a_maven_project_is_scanned_at_target(tmp_path):
    from nexus_autofix.iq.cli_scan import default_scan_targets

    (tmp_path / "target").mkdir()

    assert [t.name for t in default_scan_targets("maven", tmp_path)] == ["target"]


def test_a_java_project_with_no_conventional_output_dir_scans_the_whole_checkout(tmp_path):
    """A multi-module build puts artifacts under each module, not at the root."""
    from nexus_autofix.iq.cli_scan import default_scan_targets

    assert default_scan_targets("gradle", tmp_path) == [tmp_path]


def test_only_jvm_ecosystems_are_built_before_scanning():
    """Node lockfiles already pin the resolved tree, so an install adds nothing and costs
    minutes per run."""
    from nexus_autofix.iq.cli_scan import BUILD_BEFORE_SCAN

    assert "gradle" in BUILD_BEFORE_SCAN
    assert "maven" in BUILD_BEFORE_SCAN
    for ecosystem in ("npm", "yarn", "pnpm"):
        assert ecosystem not in BUILD_BEFORE_SCAN


def test_every_target_is_passed_to_the_cli_as_a_positional_argument(tmp_path):
    lock = tmp_path / "yarn.lock"
    manifest = tmp_path / "package.json"
    lock.write_text("{}", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    result_file = tmp_path / "result.json"

    def fake_run(args, **_):
        result_file.write_text(json.dumps(
            {"reportDataUrl": "api/v2/applications/a/reports/r/raw"}), encoding="utf-8")
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("nexus_autofix.iq.cli_scan.subprocess.run", side_effect=fake_run) as mock:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_targets=[lock, manifest], app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=result_file, timeout_seconds=60,
        )

    args = mock.call_args.args[0]
    assert args[-2:] == [str(lock), str(manifest)]


def test_no_scan_target_at_all_is_an_error_rather_than_scanning_nothing(tmp_path):
    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_targets=[], app_id="demo", iq_url="https://iq",
            username="u", password="p", stage_id="build",
            result_file=tmp_path / "r.json", timeout_seconds=60,
        )

    assert "no scan target was resolved" in str(exc.value)


def test_every_supported_ecosystem_has_defined_scan_behaviour():
    """Introspective, so an ecosystem added to the tool later cannot quietly fall through.

    Falling through is not a crash — it scans the whole checkout without building — which
    for a compiled ecosystem means fingerprinting a tree with no artifacts in it and
    reporting an application with no components.
    """
    from nexus_autofix.iq.cli_scan import (
        BUILD_BEFORE_SCAN,
        _NODE_MANIFESTS,
        _OUTPUT_DIRS,
    )
    from nexus_autofix.repo.trident import KNOWN_ECOSYSTEMS

    for ecosystem in KNOWN_ECOSYSTEMS:
        described = ecosystem in _NODE_MANIFESTS or ecosystem in _OUTPUT_DIRS
        assert described, (
            f"{ecosystem!r} has no scan target rule — it would scan the whole checkout. "
            "Add it to _NODE_MANIFESTS (lockfile-based) or _OUTPUT_DIRS (build output), "
            "and decide whether it belongs in BUILD_BEFORE_SCAN."
        )
        # A compiled ecosystem that is not built first has nothing to fingerprint.
        if ecosystem in _OUTPUT_DIRS:
            assert ecosystem in BUILD_BEFORE_SCAN, (
                f"{ecosystem!r} is scanned at its build output but is not built first"
            )
        if ecosystem in _NODE_MANIFESTS:
            assert ecosystem not in BUILD_BEFORE_SCAN, (
                f"{ecosystem!r} reads a lockfile, so building first only costs time"
            )


@pytest.mark.parametrize("ecosystem,files,dirs,expected", [
    ("yarn", ("yarn.lock", "package.json"), (), ["yarn.lock", "package.json"]),
    ("npm", ("package-lock.json", "package.json"), (), ["package-lock.json", "package.json"]),
    ("npm", ("npm-shrinkwrap.json", "package.json"), (),
     ["npm-shrinkwrap.json", "package.json"]),
    ("pnpm", ("pnpm-lock.yaml", "package.json"), (), ["pnpm-lock.yaml", "package.json"]),
    ("gradle", (), ("build",), ["build"]),
    ("maven", (), ("target",), ["target"]),
])
def test_a_realistic_checkout_resolves_to_the_right_cli_arguments(
    tmp_path, ecosystem, files, dirs, expected
):
    """End to end from a checkout on disk to the argv the CLI is handed."""
    from nexus_autofix.iq.cli_scan import default_scan_targets

    for name in files:
        (tmp_path / name).write_text("{}", encoding="utf-8")
    for name in dirs:
        (tmp_path / name).mkdir()

    targets = default_scan_targets(ecosystem, tmp_path)
    assert [t.name for t in targets] == expected

    result_file = tmp_path / "result.json"

    def fake_run(args, **_):
        result_file.write_text(
            json.dumps({"reportDataUrl": "api/v2/applications/a/reports/r/raw"}),
            encoding="utf-8",
        )
        return MagicMock(returncode=0, stdout="", stderr="")

    with patch("nexus_autofix.iq.cli_scan.subprocess.run", side_effect=fake_run) as mock:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_targets=targets, app_id="demo",
            iq_url="https://iq", username="u", password="p", stage_id="build",
            result_file=result_file, timeout_seconds=60,
        )

    argv = mock.call_args.args[0]
    assert argv[-len(expected):] == [str(tmp_path / name) for name in expected]


def test_a_node_repo_with_no_manifest_at_the_root_is_an_explicit_failure(tmp_path):
    """A monorepo whose package.json is in a subdirectory. Better to stop and be told than
    to scan the whole checkout and report whatever it happens to find."""
    from nexus_autofix.iq.cli_scan import default_scan_targets

    (tmp_path / "packages" / "app").mkdir(parents=True)
    (tmp_path / "packages" / "app" / "package.json").write_text("{}", encoding="utf-8")

    assert default_scan_targets("npm", tmp_path) == []

    with pytest.raises(IQCLIScanError) as exc:
        run_cli_scan(
            jar_path=_jar(tmp_path), scan_targets=[], app_id="demo", iq_url="https://iq",
            username="u", password="p", stage_id="build",
            result_file=tmp_path / "r.json", timeout_seconds=60,
        )
    assert "iq_cli_scan_target" in str(exc.value)
