from nexus_autofix.iq.client import PolicyViolation
from nexus_autofix.verify.rescan import compare_reports


def _violation(purl: str) -> PolicyViolation:
    return PolicyViolation(
        package_url=purl, component=purl, policy_name="p", policy_id="p1",
        threat_level=8, constraint_summary="", is_waived=False, action="Fail",
    )


def test_all_cleared_when_target_purl_absent_from_rescan():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = []
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.all_cleared is True
    assert result.still_failing == []


def test_still_failing_when_target_purl_present_in_rescan():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = [_violation("pkg:maven/x/x@1.0")]
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.all_cleared is False
    assert result.still_failing == ["pkg:maven/x/x@1.0"]


def test_new_finding_detected_relative_to_full_baseline():
    baseline = [_violation("pkg:maven/x/x@1.0")]
    rescan = [_violation("pkg:maven/y/y@2.0")]
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.new_findings == ["pkg:maven/y/y@2.0"]
    assert result.all_cleared is True


def test_still_failing_excludes_non_target_purl_present_in_both():
    # A pre-existing finding unrelated to this fix (not in target_purls) that
    # persists into the rescan is not "still failing" for THIS fix — it's an
    # unrelated pre-existing finding, not a target the agent was asked to clear.
    baseline = [_violation("pkg:maven/x/x@1.0"), _violation("pkg:maven/z/z@3.0")]
    rescan = [_violation("pkg:maven/z/z@3.0")]
    result = compare_reports(baseline, rescan, target_purls={"pkg:maven/x/x@1.0"})
    assert result.still_failing == []
    assert result.all_cleared is True
    assert result.new_findings == []
