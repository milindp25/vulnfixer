from unittest.mock import MagicMock

import pytest

from nexus_autofix.iq.client import FakeIQClient, HTTPIQClient, PolicyViolation, RemediationResponse, VersionChange


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
