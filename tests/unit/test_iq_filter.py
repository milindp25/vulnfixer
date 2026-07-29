from pathlib import Path

from nexus_autofix.iq.filter import BumpSize, classify_bump, filter_findings
from nexus_autofix.iq.models import Finding


def _finding(**overrides) -> Finding:
    base = dict(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0.0", target_version="1.0.1",
        remediation_type="next-non-failing-with-dependencies", is_direct=True, dependency_path=[],
        parent_component=None, parent_current_version=None, parent_target_version=None,
        policy_action="Fail", threat_level=8, policy_name="p", cve_ids=[], manifest_path=Path("x"),
    )
    base.update(overrides)
    return Finding(**base)


def test_classify_bump_patch():
    assert classify_bump("1.2.3", "1.2.5") == BumpSize.PATCH


def test_classify_bump_handles_two_component_maven_versions():
    # Maven routinely publishes "1.9" rather than "1.9.0" — the missing patch
    # component must not make this UNKNOWN (which would escalate every routine
    # two-component bump instead of letting the agent attempt it).
    assert classify_bump("1.9", "1.10.0") == BumpSize.MINOR
    assert classify_bump("1.9", "1.9.5") == BumpSize.PATCH
    assert classify_bump("1.9", "2.0") == BumpSize.MAJOR


def test_two_component_version_finding_is_actionable_not_unknown():
    result = filter_findings([_finding(current_version="1.9", target_version="1.10.0")], suppressed_components=set())
    assert len(result.actionable) == 1
    assert not result.escalate


def test_classify_bump_minor():
    assert classify_bump("1.2.3", "1.3.0") == BumpSize.MINOR


def test_classify_bump_major():
    assert classify_bump("1.2.3", "2.0.0") == BumpSize.MAJOR


def test_actionable_patch_bump_is_included():
    result = filter_findings([_finding()], suppressed_components=set())
    assert len(result.actionable) == 1


def test_major_bump_is_escalated():
    result = filter_findings([_finding(target_version="2.0.0")], suppressed_components=set())
    assert len(result.escalate) == 1
    assert not result.actionable


def test_no_target_version_is_escalated():
    result = filter_findings([_finding(target_version=None)], suppressed_components=set())
    assert len(result.escalate) == 1


def test_threat_level_below_the_threshold_is_ignored():
    result = filter_findings([_finding(threat_level=7)], suppressed_components=set())
    assert len(result.ignore) == 1
    assert not result.actionable


def test_threat_level_at_the_threshold_is_actionable():
    result = filter_findings([_finding(threat_level=8)], suppressed_components=set())
    assert len(result.actionable) == 1


def test_threshold_is_configurable():
    findings = [_finding(threat_level=5)]
    assert len(filter_findings(findings, set(), min_threat_level=5).actionable) == 1
    assert len(filter_findings(findings, set(), min_threat_level=6).ignore) == 1


def test_policy_threat_category_does_not_gate_anything():
    # policyThreatCategory is SECURITY / LICENSE / QUALITY — never "Fail". Gating on it
    # would ignore every real finding, which is what happened before.
    result = filter_findings(
        [_finding(policy_action="SECURITY", threat_level=9)], suppressed_components=set()
    )
    assert len(result.actionable) == 1


def test_suppressed_component_is_ignored():
    result = filter_findings([_finding(component="log4j-api")], suppressed_components={"log4j-api"})
    assert len(result.ignore) == 1


def test_waived_finding_is_ignored():
    result = filter_findings([_finding(is_waived=True)], suppressed_components=set())
    assert len(result.ignore) == 1


def test_unknown_bump_is_escalated_not_guessed():
    result = filter_findings(
        [_finding(current_version="latest", target_version="1.2.3")], suppressed_components=set()
    )
    assert len(result.escalate) == 1
    assert not result.actionable


def test_an_empty_target_version_is_not_actionable():
    # A misparsed remediation response yields target_version == "", which passed the old
    # `is not None` check, reached classify_bump("8.5.18", ""), and was escalated as an
    # UNKNOWN bump — hiding the parse failure behind a plausible-looking outcome.
    assert _finding(target_version="").is_actionable is False
    result = filter_findings([_finding(target_version="")], suppressed_components=set())
    assert len(result.escalate) == 1
    assert not result.actionable
