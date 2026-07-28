from nexus_autofix.iq.client import RemediationResponse, VersionChange
from nexus_autofix.iq.remediation import select_target


def test_prefers_next_non_failing_with_dependencies():
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "1.11.0"),
        VersionChange("next-non-failing-with-dependencies", "1.10.0"),
    ])
    assert select_target(remediation).version == "1.10.0"


def test_falls_back_to_next_non_failing_when_no_with_dependencies_variant():
    remediation = RemediationResponse(version_changes=[VersionChange("next-non-failing", "1.11.0")])
    assert select_target(remediation).version == "1.11.0"


def test_returns_none_when_no_candidates():
    assert select_target(RemediationResponse(version_changes=[])) is None
