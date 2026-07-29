import logging
from unittest.mock import MagicMock, patch

import pytest
import requests

from nexus_autofix.iq.client import (
    FakeIQClient,
    HTTPIQClient,
    IQEvaluationError,
    IQTimeoutError,
    _report_id_from_url,
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


# --- report id extraction (the /raw 404) ------------------------------------


@pytest.mark.parametrize(
    "url, expected",
    [
        # reportDataUrl — ends in /raw, which is what broke the policy fetch.
        ("api/v2/applications/test-demo/reports/a1b2c3d4e5/raw", "a1b2c3d4e5"),
        ("/api/v2/applications/test-demo/reports/a1b2c3d4e5/raw", "a1b2c3d4e5"),
        ("https://iq.example.com/api/v2/applications/demo/reports/a1b2c3d4e5/raw", "a1b2c3d4e5"),
        # reportHtmlUrl — singular "report", no trailing suffix.
        ("ui/links/application/test-demo/report/a1b2c3d4e5", "a1b2c3d4e5"),
        # other suffixes IQ appends
        ("api/v2/applications/demo/reports/a1b2c3d4e5/policy", "a1b2c3d4e5"),
        ("api/v2/applications/demo/reports/a1b2c3d4e5/printReport", "a1b2c3d4e5"),
        # trailing slash, query string
        ("api/v2/applications/demo/reports/a1b2c3d4e5/raw/", "a1b2c3d4e5"),
        ("api/v2/applications/demo/reports/a1b2c3d4e5/raw?foo=bar", "a1b2c3d4e5"),
    ],
)
def test_report_id_is_extracted_not_just_the_last_segment(url, expected):
    assert _report_id_from_url(url) == expected


def test_poll_returns_the_report_id_not_the_word_raw():
    session = MagicMock()
    session.get.return_value = _status_response(
        {"status": "COMPLETED", "reportDataUrl": "api/v2/applications/demo/reports/rep-42/raw"}
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with patch("nexus_autofix.iq.client.time.sleep"):
        assert client.poll_evaluation("/status/1", timeout_seconds=60) == "rep-42"


def test_policy_report_url_is_built_from_the_real_report_id():
    session = MagicMock()
    session.get.return_value = _status_response([])
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    client.fetch_policy_report("test-demo", "rep-42")

    assert (
        session.get.call_args.args[0]
        == "https://iq.example.com/api/v2/applications/test-demo/reports/rep-42/policy"
    )


# --- /policy response parsing (live shape) ----------------------------------


def _policy_body(components):
    return {"reportTime": 1, "reportTitle": "demo", "components": components}


def test_policy_report_is_an_object_with_components_not_a_bare_list():
    # Iterating the object directly yielded string keys ->
    # AttributeError: 'str' object has no attribute 'get'.
    session = MagicMock()
    session.get.return_value = _status_response(
        _policy_body([
            {
                "packageUrl": "pkg:maven/org.apache.commons/commons-text@1.9",
                "displayName": "commons-text 1.9",
                "violations": [
                    {"policyName": "Security-High", "policyId": "p1", "policyThreatLevel": 8,
                     "policyThreatCategory": "SECURITY", "waived": False},
                ],
            }
        ])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    violations = client.fetch_policy_report("demo", "rep-1")

    assert len(violations) == 1
    assert violations[0].component == "commons-text 1.9"
    assert violations[0].threat_level == 8


def test_highest_policy_threat_level_wins_for_a_component():
    session = MagicMock()
    session.get.return_value = _status_response(
        _policy_body([
            {
                "packageUrl": "pkg:maven/x/y@1.0",
                "displayName": "y",
                "violations": [
                    {"policyName": "Quality", "policyThreatLevel": 3, "waived": False},
                    {"policyName": "Security-Critical", "policyThreatLevel": 9, "waived": False},
                    {"policyName": "License", "policyThreatLevel": 6, "waived": False},
                ],
            }
        ])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    violations = client.fetch_policy_report("demo", "rep-1")

    assert len(violations) == 1, "one entry per component, not per violation"
    assert violations[0].threat_level == 9
    assert violations[0].policy_name == "Security-Critical"


def test_waived_violations_are_skipped_when_choosing_the_worst():
    session = MagicMock()
    session.get.return_value = _status_response(
        _policy_body([
            {
                "packageUrl": "pkg:maven/x/y@1.0", "displayName": "y",
                "violations": [
                    {"policyName": "Security-Critical", "policyThreatLevel": 10, "waived": True},
                    {"policyName": "Security-High", "policyThreatLevel": 8, "waived": False},
                ],
            }
        ])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    violation = client.fetch_policy_report("demo", "rep-1")[0]
    assert violation.threat_level == 8
    assert violation.is_waived is False


def test_a_component_whose_violations_are_all_waived_is_reported_waived():
    session = MagicMock()
    session.get.return_value = _status_response(
        _policy_body([
            {
                "packageUrl": "pkg:maven/x/y@1.0", "displayName": "y",
                "violations": [{"policyName": "S", "policyThreatLevel": 9, "waived": True}],
            }
        ])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    assert client.fetch_policy_report("demo", "rep-1")[0].is_waived is True


def test_components_without_violations_are_dropped():
    session = MagicMock()
    session.get.return_value = _status_response(
        _policy_body([
            {"packageUrl": "pkg:maven/clean/clean@1.0", "displayName": "clean", "violations": []},
            {"packageUrl": "pkg:maven/x/y@1.0", "displayName": "y",
             "violations": [{"policyName": "S", "policyThreatLevel": 9}]},
        ])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    violations = client.fetch_policy_report("demo", "rep-1")
    assert [v.component for v in violations] == ["y"]


def test_a_bare_list_response_is_still_accepted():
    session = MagicMock()
    session.get.return_value = _status_response(
        [{"packageUrl": "pkg:maven/x/y@1.0", "displayName": "y",
          "violations": [{"policyName": "S", "policyThreatLevel": 9}]}]
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    assert client.fetch_policy_report("demo", "rep-1")[0].threat_level == 9


# --------------------------------------------------------------------------------------
# Transcribed from a real /policy response off the user's Nexus IQ instance. Every key and
# nesting level below was read off that payload, not inferred. Keep it verbatim: it is the
# only record in the repo of what the endpoint actually returns.
# --------------------------------------------------------------------------------------

_LIVE_SCOPED_NPM_COMPONENT = {
    "packageUrl": "pkg:npm/%40charlietango/use-focus-trap@1.4.0",
    "hash": "003eaf91be7adc372e84",
    "componentIdentifier": {
        "format": "npm",
        "coordinates": {"packageId": "@charlietango/use-focus-trap", "version": "1.4.0"},
    },
    "displayName": "@charlietango/use-focus-trap : 1.4.0",
    "proprietary": False,
    "matchState": "exact",
    "pathnames": ["5a3e2e892a64405288e517265a5e5e4d/yarn.lock/@charlietango\\use-focus-trap:1.4.0"],
    "dependencyData": {
        "directDependency": False,
        "innerSource": False,
        "parentComponentPurls": ["pkg:npm/%40dfs-react-ui/core@1.4.6"],
        "innerSourceData": [
            {
                "ownerApplicationName": "digital-web-platform-ui-library",
                "ownerApplicationId": "b250bf2726754784946ab14e49d4f89e",
                "innerSourceComponentPurl": "pkg:npm/%40dfs-react-ui/core@1.4.6",
            }
        ],
    },
    "violations": [
        {
            "policyId": "e99c9ad11cea421b892e6a279b0d758b",
            "policyName": "End-Of-Life Component",
            "policyThreatCategory": "QUALITY",
            "policyThreatLevel": 5,
            "policyViolationId": "7b4da0b545e14cf4a1c69afaa7eaf5ad",
            "waived": False,
            "waivedWithAutoWaiver": False,
            "grandfathered": False,
            "legacyViolation": False,
            "constraints": [
                {
                    "constraintId": "1664c6bea1f44bd0bb893a799fa4c155",
                    "constraintName": "EOL",
                    "conditions": [
                        {
                            "conditionSummary": "End of Life is true",
                            "conditionReason": "Component status is End-of-Life (EOL)",
                        }
                    ],
                }
            ],
        }
    ],
}


def _live_report(components):
    """The real envelope: report metadata, a `counts` object, then `components`."""
    return {
        "reportTime": 1785334499538,
        "reportTitle": "Build Report",
        "commitHash": "d63e26acecd8e44513d3e15e565117bf36a5abbc",
        "initiator": "system",
        "application": {
            "id": "5a3e2e892a64405288e517265a5e5e4d",
            "publicId": "boardingwizard-static",
            "name": "boardingwizard-static",
            "organizationId": "07bd72d61caf4693a5a5e1890391a3b0",
            "contactUserName": None,
        },
        "counts": {
            "partiallyMatchedComponentCount": 0,
            "exactlyMatchedComponentCount": 1400,
            "totalComponentCount": 1400,
            "grandfatheredPolicyViolationCount": 0,
            "legacyViolationCount": 0,
        },
        "components": components,
    }


def _live_violation():
    session = MagicMock()
    session.get.return_value = _status_response(_live_report([_LIVE_SCOPED_NPM_COMPONENT]))
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    return client.fetch_policy_report("boardingwizard-static", "rep-1")[0]


def test_iq_component_identifier_is_carried_through_verbatim():
    # Rebuilding it from the purl gives packageId "%40charlietango/use-focus-trap" —
    # percent-encoded — and the remediation lookup finds nothing.
    assert _live_violation().component_identifier == {
        "format": "npm",
        "coordinates": {"packageId": "@charlietango/use-focus-trap", "version": "1.4.0"},
    }


def test_component_name_is_the_bare_coordinate_not_the_display_string():
    violation = _live_violation()
    assert violation.component == "@charlietango/use-focus-trap"
    assert violation.display_name == "@charlietango/use-focus-trap : 1.4.0"


def test_current_version_comes_from_coordinates():
    assert _live_violation().current_version == "1.4.0"


def test_transitive_dependency_is_not_reported_as_direct():
    violation = _live_violation()
    assert violation.is_direct is False
    assert violation.parent_purls == ["pkg:npm/%40dfs-react-ui/core@1.4.6"]


def test_a_component_with_no_dependency_data_defaults_to_direct():
    session = MagicMock()
    session.get.return_value = _status_response(
        _live_report([{
            "packageUrl": "pkg:maven/x/y@1.0",
            "componentIdentifier": {
                "format": "maven",
                "coordinates": {"groupId": "x", "artifactId": "y", "version": "1.0"},
            },
            "violations": [{"policyName": "S", "policyThreatLevel": 9}],
        }])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    violation = client.fetch_policy_report("demo", "rep-1")[0]
    assert violation.is_direct is True
    assert violation.component == "x:y"


def test_auto_waived_violations_are_treated_as_waived():
    session = MagicMock()
    session.get.return_value = _status_response(
        _live_report([{
            "packageUrl": "pkg:npm/z@1.0", "displayName": "z : 1.0",
            "violations": [
                {"policyName": "S", "policyThreatLevel": 9,
                 "waived": False, "waivedWithAutoWaiver": True},
            ],
        }])
    )
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    assert client.fetch_policy_report("demo", "rep-1")[0].is_waived is True


def test_the_constraint_name_is_carried_into_the_summary():
    assert _live_violation().constraint_summary == "EOL"


def test_a_quality_eol_violation_below_the_threshold_is_not_actioned():
    # policyThreatLevel 5 < 8: real payload, real policy, correctly left alone.
    from nexus_autofix.iq.filter import filter_findings
    from nexus_autofix.cli import findings_from_policy_report

    class _NoRemediation:
        def fetch_remediation(self, internal_id, component_identifier, stage_id):
            from nexus_autofix.iq.client import RemediationResponse

            return RemediationResponse(version_changes=[])

    findings = findings_from_policy_report(_NoRemediation(), "app-1", [_live_violation()], "build")
    assert filter_findings(findings, suppressed_components=set()).ignore


def test_an_empty_component_identifier_is_rejected_before_the_call():
    # IQ answers this with a bare 400 "invalid component identifier", which reads like a
    # server fault. Failing here names the real cause and spends no round trip.
    session = MagicMock()
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with pytest.raises(ValueError, match="empty component identifier"):
        client.fetch_remediation("app-1", {"format": "unknown", "coordinates": {}}, "build")

    session.post.assert_not_called()


def test_a_failed_post_logs_the_request_body_that_was_rejected(caplog):
    session = MagicMock()
    resp = MagicMock(status_code=400, text='{"message": "invalid component identifier packageUrl"}')
    resp.raise_for_status.side_effect = requests.HTTPError("400 Client Error")
    session.post.return_value = resp
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with caplog.at_level(logging.ERROR), pytest.raises(requests.HTTPError):
        client.fetch_remediation(
            "app-1",
            {"format": "npm", "coordinates": {"packageId": "%40scope/pkg", "version": "1.0"}},
            "build",
        )

    logged = caplog.text
    assert "invalid component identifier packageUrl" in logged, "IQ's objection"
    assert "%40scope/pkg" in logged, "and what it objected to"


def test_the_unfiltered_report_count_stays_out_of_the_normal_run_log(caplog):
    # A 1400-component app violates some policy on dozens of components while only a
    # couple are worth fixing. Announcing the big number at INFO made the run look like
    # it had 84 things to do. It is DEBUG now; the caller logs the post-gate count.
    session = MagicMock()
    session.get.return_value = _status_response(_live_report([
        {"packageUrl": "pkg:npm/a@1.0", "displayName": "a : 1.0",
         "violations": [{"policyName": "EOL", "policyThreatLevel": 5}]},
        {"packageUrl": "pkg:npm/b@1.0", "displayName": "b : 1.0",
         "violations": [{"policyName": "Sec", "policyThreatLevel": 9}]},
        {"packageUrl": "pkg:npm/c@1.0", "displayName": "c : 1.0",
         "violations": [{"policyName": "Sec", "policyThreatLevel": 10}]},
        {"packageUrl": "pkg:npm/d@1.0", "displayName": "d : 1.0",
         "violations": [{"policyName": "Lic", "policyThreatLevel": 2}]},
    ]))
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)

    with caplog.at_level(logging.INFO):
        violations = client.fetch_policy_report("demo", "rep-1")
    assert "component(s) with at least one violation" not in caplog.text

    caplog.clear()
    with caplog.at_level(logging.DEBUG):
        violations = client.fetch_policy_report("demo", "rep-1")

    assert len(violations) == 4, "every violating component is returned; gating happens later"
    assert "at all threat levels (unfiltered)" in caplog.text
    collapsed = " ".join(caplog.text.split())
    for band in ("Critical (10)", "Severe (8-9)", "Moderate (4-7)", "Low (2-3)"):
        assert f"{band} 1 component(s)" in collapsed, band


# --- remediation response: shape is UNVERIFIED against a live instance ------
# If these field names are wrong, a component with a perfectly good next-no-violations
# offer parses to zero version changes and is escalated as "no remediation". These lock
# in that the failure is loud rather than silent, and that both wrappers are tolerated.


def _remediation_response(payload):
    session = MagicMock()
    session.post.return_value = _status_response(payload)
    client = HTTPIQClient("https://iq.example.com", "user", "pass", session=session)
    return client.fetch_remediation(
        "app-1", {"format": "npm", "coordinates": {"packageId": "axios", "version": "1.0"}}, "build"
    )


_VERSION_CHANGE = {
    "type": "next-no-violations",
    "data": {"componentIdentifier": {"format": "npm", "coordinates": {"packageId": "axios", "version": "2.5.0"}}},
}


def test_version_changes_are_read_from_the_remediation_wrapper():
    result = _remediation_response({"remediation": {"versionChanges": [_VERSION_CHANGE]}})
    assert [(v.change_type, v.version) for v in result.version_changes] == [
        ("next-no-violations", "2.5.0")
    ]


def test_version_changes_are_read_without_the_remediation_wrapper():
    result = _remediation_response({"versionChanges": [_VERSION_CHANGE]})
    assert result.version_changes[0].version == "2.5.0"


def test_a_flat_version_field_is_also_accepted():
    result = _remediation_response(
        {"remediation": {"versionChanges": [{"type": "next-non-failing", "data": {"version": "3.1.0"}}]}}
    )
    assert result.version_changes[0].version == "3.1.0"


def test_a_response_that_parses_to_nothing_warns_with_the_raw_body(caplog):
    # The silent-escalation trap: IQ answered, this client understood none of it, and the
    # component looks identical to one IQ had no fix for.
    with caplog.at_level(logging.WARNING):
        result = _remediation_response({"someOtherShape": [{"type": "next-no-violations"}]})

    assert result.version_changes == []
    assert "parsed to zero version changes" in caplog.text
    assert "someOtherShape" in caplog.text, "the raw body must be in the log to diagnose it"


def test_a_change_type_with_an_unreadable_version_warns(caplog):
    with caplog.at_level(logging.WARNING):
        result = _remediation_response(
            {"remediation": {"versionChanges": [{"type": "next-no-violations", "data": {"v": "2.0"}}]}}
        )

    assert result.version_changes[0].version == ""
    assert "no version this client could read" in caplog.text
    assert "next-no-violations" in caplog.text
