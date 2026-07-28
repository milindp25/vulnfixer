from pathlib import Path

from nexus_autofix.iq.models import Finding, Module, RepoProfile, RunOutcome


def test_finding_is_actionable_when_target_version_present():
    finding = Finding(
        component="org.apache.commons:commons-text", package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        current_version="1.9", target_version="1.10.0", remediation_type="next-non-failing-with-dependencies",
        is_direct=True, dependency_path=[], parent_component=None, parent_current_version=None,
        parent_target_version=None, policy_action="Fail", threat_level=8, policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"], manifest_path=Path("build.gradle"),
    )
    assert finding.is_actionable is True


def test_finding_not_actionable_without_target_version():
    finding = Finding(
        component="x", package_url="pkg:maven/x/x@1.0", current_version="1.0", target_version=None,
        remediation_type=None, is_direct=True, dependency_path=[], parent_component=None,
        parent_current_version=None, parent_target_version=None, policy_action="Fail", threat_level=9,
        policy_name="p", cve_ids=[], manifest_path=None,
    )
    assert finding.is_actionable is False


def test_run_outcome_values_match_design_doc():
    expected = {
        "CLEAN", "FIXED", "FIXED_NEEDS_REVIEW", "AWAITING_APPROVAL", "REJECTED",
        "FAILED_BUILD", "FAILED_RESCAN", "NO_CHANGES", "ESCALATED",
    }
    assert {o.value for o in RunOutcome} == expected


def test_module_and_repo_profile_construct():
    module = Module(path=Path("."), ecosystem="gradle", manifest=Path("build.gradle"))
    profile = RepoProfile(ecosystem="gradle", java_version="21.0.1", node_version=None, modules=[module], source="trident")
    assert profile.modules[0].ecosystem == "gradle"
