"""Turning AppSec targets into findings, and folding them in with Nexus IQ's."""

from __future__ import annotations

from nexus_autofix.agent_api import FindingView, appsec_finding_views, merge_views
from nexus_autofix.appsec.resolve import decide
from nexus_autofix.appsec.sheet import AppsecLibrary, Gav


def _library(**overrides) -> AppsecLibrary:
    base = dict(
        github_org="org", github_repo_name="repo",
        library_filename="bcprov-jdk15on-1.49.jar", library_name="Bouncy Castle Provider",
        library_type="Java", artifact_id="bcprov-jdk15on", current_version="1.49",
        direct=False, cve_ids=("CVE-2016-1000352", "CVE-2018-1000613"), max_cvss3=7.5,
        sheet_version="1.64", group_id="org.bouncycastle",
        swap_candidates=(), topfix_discarded=(),
    )
    base.update(overrides)
    return AppsecLibrary(**base)


def _view(target, component="org.bouncycastle:bcprov-jdk15on",
          purl="pkg:maven/org.bouncycastle/bcprov-jdk15on@1.49") -> FindingView:
    return appsec_finding_views([(target, component, purl)])[0]


def _iq_view(**overrides) -> FindingView:
    base = dict(
        component="org.bouncycastle:bcprov-jdk15on",
        package_url="pkg:maven/org.bouncycastle/bcprov-jdk15on@1.49",
        current_version="1.49", target_version="1.70", remediation_type="next-no-violations",
        threat_level=9, policy_name="Security-Critical", is_direct=False,
        actionable=True, cve_ids=["CVE-2016-1000352"],
    )
    base.update(overrides)
    return FindingView(**base)


# --- building the view ----------------------------------------------------------------

def test_a_resolved_target_becomes_an_actionable_finding():
    view = _view(decide(_library(), "1.49", "1.64"))

    assert view.actionable
    assert view.target_version == "1.64"
    assert view.source == ["appsec"]
    assert view.cve_ids == ["CVE-2016-1000352", "CVE-2018-1000613"]
    assert view.appsec_decision == "RESOLVED"


def test_threat_level_is_not_invented_from_cvss():
    # The sheet grades with CVSS3; IQ's 0-10 threat level is a different scale. Mapping one
    # onto the other would put a number in run.json that Nexus IQ never produced.
    assert _view(decide(_library(), "1.49", "1.64")).threat_level == 0


def test_a_conflict_is_not_actionable_and_carries_both_candidates():
    view = _view(decide(_library(sheet_version="1.64"), "1.49", "1.70"))

    assert not view.actionable
    assert view.target_version is None
    assert view.candidate_versions == ["1.70", "1.64"]
    assert view.iq_version == "1.70" and view.sheet_version == "1.64"
    assert "resolve" in view.reason_not_actionable


def test_a_swap_only_target_records_what_was_proposed():
    library = _library(sheet_version=None, group_id=None,
                       swap_candidates=(Gav("org.bouncycastle", "bc-fips", "2.1.3"),))
    view = _view(decide(library, "1.49", None), component="bcprov-jdk15on", purl="")

    assert not view.actionable
    assert view.candidate_versions == []
    assert view.swap_candidates == ["org.bouncycastle:bc-fips:2.1.3"]


# --- merging --------------------------------------------------------------------------

def test_a_component_only_appsec_knows_about_is_appended():
    merged = merge_views([_iq_view(component="xalan:xalan")], [_view(decide(_library(), "1.49", "1.64"))])

    assert len(merged) == 2
    assert {v.component for v in merged} == {"xalan:xalan", "org.bouncycastle:bcprov-jdk15on"}


def test_the_same_component_from_both_sources_is_one_finding():
    # Both sources agree on 1.70, so there is nothing to settle.
    agreed = decide(_library(sheet_version="1.70"), "1.49", "1.70")
    merged = merge_views([_iq_view()], [_view(agreed)])

    assert len(merged) == 1
    assert merged[0].source == ["appsec", "iq"]
    # IQ's target stands, and the CVEs from both are pooled without duplicates.
    assert merged[0].target_version == "1.70"
    assert merged[0].cve_ids == ["CVE-2016-1000352", "CVE-2018-1000613"]


def test_a_conflict_survives_the_merge_and_blocks_the_finding():
    """The case that would otherwise ship a silently-chosen version.

    IQ has a target and is happy. The sheet disagrees with it. If the merge let IQ's
    actionable entry stand, the disagreement a human is supposed to settle would be
    resolved in IQ's favour by nobody, and `check` would find nothing to refuse.
    """
    conflict = decide(_library(sheet_version="1.64"), "1.49", "1.70")
    merged = merge_views([_iq_view(target_version="1.70")], [_view(conflict)])

    assert len(merged) == 1
    assert not merged[0].actionable
    assert merged[0].target_version is None
    assert merged[0].appsec_decision == "CONFLICT"
    assert merged[0].candidate_versions == ["1.70", "1.64"]
    # The IQ metadata is not thrown away in the process.
    assert merged[0].threat_level == 9
    assert merged[0].policy_name == "Security-Critical"


def test_merging_an_agreed_appsec_view_leaves_the_iq_finding_actionable():
    agreed = decide(_library(sheet_version="1.70"), "1.49", "1.70")
    merged = merge_views([_iq_view(target_version="1.70")], [_view(agreed)])

    assert merged[0].actionable
    assert merged[0].target_version == "1.70"
    assert merged[0].sheet_version == "1.70"


def test_merge_with_no_appsec_findings_changes_nothing():
    iq = [_iq_view()]
    merged = merge_views(iq, [])
    assert merged == iq
    assert merged[0].source == ["iq"]
