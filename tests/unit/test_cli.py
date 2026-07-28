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
    assert finding.policy_action == "fail"
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
