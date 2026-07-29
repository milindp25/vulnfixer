from unittest.mock import MagicMock, patch

import pytest

from nexus_autofix.iq.client import (
    FakeIQClient,
    HTTPIQClient,
    IQEvaluationError,
    IQTimeoutError,
    PolicyViolation,
    RemediationResponse,
    VersionChange,
)


def test_fake_iq_client_returns_configured_violations():
    client = FakeIQClient(
        policy_violations=[
            PolicyViolation(
                package_url="pkg:maven/org.apache.commons/commons-text@1.9",
                component="commons-text", policy_name="Security-Critical", policy_id="p1",
                threat_level=8, constraint_summary="CVSS >= 7", is_waived=False, action="Fail",
            )
        ]
    )
    violations = client.fetch_policy_report("app", "report-1")
    assert len(violations) == 1
    assert violations[0].component == "commons-text"


def test_fake_iq_client_remediation_lookup_by_name():
    client = FakeIQClient(
        remediations={"commons-text": RemediationResponse(version_changes=[VersionChange("next-non-failing-with-dependencies", "1.10.0")])}
    )
    result = client.fetch_remediation("internal", {"coordinates": {"artifactId": "commons-text"}}, "build")
    assert result.version_changes[0].version == "1.10.0"


def test_http_client_resolve_application_internal_id_uses_public_id_query():
    session = MagicMock()
    session.get.return_value.json.return_value = {"applications": [{"id": "abc123"}]}
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    internal_id = client.resolve_application_internal_id("payments-core")

    assert internal_id == "abc123"
    session.get.assert_called_once()
    call_kwargs = session.get.call_args
    assert call_kwargs.kwargs["params"] == {"publicId": "payments-core"}


def test_http_client_raises_when_no_application_found():
    session = MagicMock()
    session.get.return_value.json.return_value = {"applications": []}
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with pytest.raises(ValueError, match="payments-core"):
        client.resolve_application_internal_id("payments-core")


def test_http_client_fetch_policy_report_uses_json_accept_header():
    session = MagicMock()
    session.get.return_value.json.return_value = [
        {
            "packageUrl": "pkg:maven/x/y@1.0",
            "displayName": "y",
            "violations": [
                {"policyName": "Security-Critical", "policyId": "p1", "threatLevel": 9,
                 "constraints": [{"constraintName": "CVSS >= 7"}], "waived": False, "policyThreatCategory": "Fail"}
            ],
        }
    ]
    session.get.return_value.raise_for_status.return_value = None
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    violations = client.fetch_policy_report("payments-core", "report-1")

    assert violations[0].component == "y"
    assert session.get.call_args.kwargs["headers"] == {"Accept": "application/json"}


# --- poll_evaluation: HTTP 200 does not mean "done" -------------------------
# IQ returns 200 with a pending status while the scan runs, so these cover the
# state machine that decides keep-polling / fail-fast / done.


def _status_response(payload: dict) -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = payload
    return resp


def test_poll_evaluation_keeps_polling_while_status_is_pending():
    session = MagicMock()
    session.get.side_effect = [
        _status_response({"status": "PENDING"}),
        _status_response({"status": "IN_PROGRESS"}),
        _status_response({"status": "COMPLETED", "reportDataUrl": "api/v2/reports/abc123"}),
    ]
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep"):
        report_id = client.poll_evaluation("/status/1", timeout_seconds=60)

    assert report_id == "abc123"
    assert session.get.call_count == 3


def test_poll_evaluation_treats_a_200_with_no_status_field_as_still_pending():
    session = MagicMock()
    session.get.side_effect = [
        _status_response({}),
        _status_response({"reportHtmlUrl": "https://iq.example.com/ui/links/report/xyz789"}),
    ]
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep"):
        assert client.poll_evaluation("/status/1", timeout_seconds=60) == "xyz789"


def test_poll_evaluation_fails_fast_on_a_failed_status_rather_than_burning_the_timeout():
    session = MagicMock()
    session.get.return_value = _status_response(
        {"status": "FAILED", "errorMessage": "scan could not resolve dependencies"}
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep") as sleep:
        with pytest.raises(IQEvaluationError, match="scan could not resolve dependencies"):
            client.poll_evaluation("/status/1", timeout_seconds=900)

    assert session.get.call_count == 1, "should not poll again after a terminal failure"
    sleep.assert_not_called()


def test_poll_evaluation_reports_terminal_success_with_no_report_url():
    session = MagicMock()
    session.get.return_value = _status_response({"status": "COMPLETED", "somethingElse": 1})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep"):
        with pytest.raises(IQEvaluationError, match="no recognisable report"):
            client.poll_evaluation("/status/1", timeout_seconds=60)


def test_poll_evaluation_timeout_message_includes_the_last_status():
    session = MagicMock()
    session.get.return_value = _status_response({"status": "RUNNING"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep"):
        with pytest.raises(IQTimeoutError, match="RUNNING"):
            client.poll_evaluation("/status/1", timeout_seconds=0.05)


def test_start_source_control_evaluation_errors_clearly_without_a_status_url():
    session = MagicMock()
    session.post.return_value = _status_response({"unexpected": "shape"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with pytest.raises(IQEvaluationError, match="statusUrl"):
        client.start_source_control_evaluation("id", "main", "build")


# --- behaviours confirmed against a live Nexus IQ instance ------------------


def test_start_evaluation_does_not_send_commit_hash():
    # The live endpoint rejects/ignores commitHash; only stageId and branchName go in.
    session = MagicMock()
    session.post.return_value = _status_response({"statusUrl": "api/v2/scan/status/1"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    client.start_source_control_evaluation("internal-1", "main", "build")

    assert session.post.call_args.kwargs["json"] == {"stageId": "build", "branchName": "main"}


def test_status_url_without_a_leading_slash_is_normalised():
    # Live IQ returns "api/v2/..." with no leading slash; joining it straight onto the
    # base URL yielded "https://iq.example.comapi/v2/...".
    session = MagicMock()
    session.post.return_value = _status_response({"statusUrl": "api/v2/scan/status/1"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    assert client.start_source_control_evaluation("internal-1", "main", "build") == "/api/v2/scan/status/1"


def test_status_url_that_already_has_a_slash_is_not_doubled():
    session = MagicMock()
    session.post.return_value = _status_response({"statusUrl": "/api/v2/scan/status/1"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    assert client.start_source_control_evaluation("internal-1", "main", "build") == "/api/v2/scan/status/1"


def test_an_absolute_status_url_is_left_alone():
    session = MagicMock()
    session.post.return_value = _status_response({"statusUrl": "https://iq.example.com/api/v2/status/1"})
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    assert (
        client.start_source_control_evaluation("internal-1", "main", "build")
        == "https://iq.example.com/api/v2/status/1"
    )


def test_normalised_status_url_joins_onto_the_base_url_correctly():
    """The end-to-end point of the fix: the polled URL must have exactly one slash."""
    session = MagicMock()
    session.post.return_value = _status_response({"statusUrl": "api/v2/scan/status/1"})
    session.get.return_value = _status_response(
        {"status": "COMPLETED", "reportDataUrl": "api/v2/reports/rep1"}
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    status_url = client.start_source_control_evaluation("internal-1", "main", "build")
    with patch("nexus_autofix.iq.client.time.sleep"):
        client.poll_evaluation(status_url, timeout_seconds=60)

    assert session.get.call_args.args[0] == "https://iq.example.com/api/v2/scan/status/1"
