
from nexus_autofix.iq.filter import (
    BumpSize,
    classify_bump,
    filter_findings,
    is_a_real_upgrade,
)
from nexus_autofix.iq.models import Finding


def _finding(**overrides) -> Finding:
    base = dict(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0.0", target_version="1.0.1",
        remediation_type="next-non-failing-with-dependencies", is_direct=True, dependency_path=[],
        parent_component=None, parent_current_version=None, parent_target_version=None, threat_level=8, policy_name="p", cve_ids=[],
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
        [_finding( threat_level=9)], suppressed_components=set()
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


# --------------------------------------------------------------------------------------
# IQ answers with the CURRENT version when nothing clears the violation. Observed live:
# postcss 8.5.10 -> 8.5.10, svgo 4.0.1 -> 4.0.1, brace-expansion 5.0.7 -> 5.0.7. All three
# were routed to the agent as upgrades, which is a no-op instruction.
# --------------------------------------------------------------------------------------


def test_a_target_equal_to_the_current_version_is_not_an_upgrade():
    assert is_a_real_upgrade("8.5.10", "8.5.10") is False
    assert is_a_real_upgrade("8.5.10", "8.5.18") is True


def test_a_lower_target_is_not_an_upgrade():
    # Downgrading is prohibited for the agent; a "clean" older version is not a fix.
    assert is_a_real_upgrade("8.5.18", "8.5.10") is False
    assert is_a_real_upgrade("2.0.0", "1.9.9") is False


def test_two_component_versions_are_ordered_correctly():
    assert is_a_real_upgrade("1.9", "1.10") is True
    assert is_a_real_upgrade("1.10", "1.9") is False
    assert is_a_real_upgrade("1.9", "1.9.0") is False, "1.9 and 1.9.0 are the same version"


def test_unparseable_versions_fall_through_to_the_bump_classifier():
    # Not rejected here — classify_bump routes them to UNKNOWN and escalates, which
    # already carries the right meaning.
    assert is_a_real_upgrade("latest", "1.2.3") is True


def test_a_no_op_remediation_is_escalated_not_handed_to_the_agent():
    # The live regression, end to end through the filter.
    result = filter_findings(
        [_finding(current_version="8.5.10", target_version="8.5.10")], suppressed_components=set()
    )
    assert len(result.escalate) == 1
    assert not result.actionable, "the agent must never be asked to change a version to itself"


def test_a_downgrade_is_escalated():
    result = filter_findings(
        [_finding(current_version="8.5.18", target_version="8.5.10")], suppressed_components=set()
    )
    assert len(result.escalate) == 1
    assert not result.actionable


def test_a_genuine_upgrade_is_still_actionable():
    result = filter_findings(
        [_finding(current_version="8.4.31", target_version="8.5.18")], suppressed_components=set()
    )
    assert len(result.actionable) == 1


def test_four_component_versions_are_ordered_on_all_four():
    # .NET and some Java artifacts publish 1.2.3.4. Truncating at three made 1.2.3.4 and
    # 1.2.3.9 compare equal, so a genuine upgrade was rejected as a no-op and escalated.
    assert is_a_real_upgrade("1.2.3.4", "1.2.3.9") is True
    assert is_a_real_upgrade("1.2.3.9", "1.2.3.4") is False
    assert is_a_real_upgrade("1.2.3.4", "1.2.3.4") is False


def test_versions_of_differing_length_compare_by_value_not_by_length():
    assert is_a_real_upgrade("1.9", "1.9.0") is False, "same version, written two ways"
    assert is_a_real_upgrade("1.9.0", "1.9") is False
    assert is_a_real_upgrade("1.9", "1.9.1") is True
    assert is_a_real_upgrade("1.9.1", "1.9") is False


def test_a_prerelease_suffix_does_not_count_as_an_upgrade_either_way():
    # Ordering ignores the suffix, so these compare equal and go to a human. Shipping a
    # pre-release as an unattended remediation is not something to do quietly.
    assert is_a_real_upgrade("8.5.10-beta", "8.5.10") is False
    assert is_a_real_upgrade("8.5.10", "8.5.10-beta") is False
    assert is_a_real_upgrade("8.5.10-beta", "8.5.11") is True
