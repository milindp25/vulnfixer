from __future__ import annotations

from nexus_autofix.appsec.match import (
    current_version_for,
    identifier_for,
    match_to_violation,
    package_url_for,
)
from nexus_autofix.appsec.sheet import AppsecLibrary, Gav
from nexus_autofix.iq.client import PolicyViolation


def _library(**overrides) -> AppsecLibrary:
    base = dict(
        github_org="cardissuer-customerprofile-org",
        github_repo_name="ac-registration-app",
        library_filename="bcprov-jdk15on-1.49.jar",
        library_name="Bouncy Castle Provider",
        library_type="Java",
        artifact_id="bcprov-jdk15on",
        current_version="1.49",
        direct=False,
        cve_ids=("CVE-2016-1000352",),
        max_cvss3=7.5,
        sheet_version="1.64",
        group_id="org.bouncycastle",
        swap_candidates=(),
        topfix_discarded=(),
    )
    base.update(overrides)
    return AppsecLibrary(**base)


def _violation(artifact="bcprov-jdk15on", group="org.bouncycastle", version="1.52") -> PolicyViolation:
    return PolicyViolation(
        package_url=f"pkg:maven/{group}/{artifact}@{version}",
        component=f"{group}:{artifact}",
        policy_name="Security-High",
        policy_id="p1",
        threat_level=7,
        constraint_summary="",
        is_waived=False,
        action="warn",
        component_identifier={
            "format": "maven",
            "coordinates": {
                "groupId": group, "artifactId": artifact, "version": version, "extension": "jar",
            },
        },
        current_version=version,
    )


def test_matches_a_library_already_in_the_policy_report():
    violation = _violation()
    assert match_to_violation(_library(), [_violation(artifact="xalan"), violation]) is violation


def test_matches_on_artifact_regardless_of_version():
    # The sheet's version comes from whenever the Tableau export ran; the branch has moved on.
    assert match_to_violation(_library(current_version="1.49"), [_violation(version="1.52")]) is not None


def test_no_match_when_iq_has_never_seen_the_component():
    # The normal case for AppSec: IQ has not flagged it, so it is not in the report at all.
    assert match_to_violation(_library(), [_violation(artifact="xalan")]) is None


def test_identifier_prefers_iqs_own_object_verbatim():
    violation = _violation()
    assert identifier_for(_library(), violation) is violation.component_identifier


def test_identifier_is_built_from_the_sheet_when_iq_has_nothing():
    identifier = identifier_for(_library(), None)
    assert identifier == {
        "format": "maven",
        "coordinates": {
            "groupId": "org.bouncycastle", "artifactId": "bcprov-jdk15on",
            "version": "1.49", "extension": "jar",
        },
    }


def test_no_identifier_without_a_group_id():
    # LIBRARY_FILENAME never carries a group id; it only arrives via a same-artifact
    # candidate in the topfix column. Without one there is nothing valid to ask IQ.
    assert identifier_for(_library(group_id=None), None) is None


def test_current_version_prefers_iq_over_the_sheet():
    assert current_version_for(_library(current_version="1.49"), _violation(version="1.52")) == "1.52"
    assert current_version_for(_library(current_version="1.49"), None) == "1.49"


def test_package_url_falls_back_to_a_constructed_purl():
    assert package_url_for(_library(), None) == "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.49"
    assert package_url_for(_library(group_id=None), None) == ""
    assert package_url_for(_library(), _violation()) == "pkg:maven/org.bouncycastle/bcprov-jdk15on@1.52"


def test_swap_only_library_still_matches_by_artifact():
    library = _library(sheet_version=None, group_id=None,
                       swap_candidates=(Gav("org.bouncycastle", "bc-fips", "2.1.3"),))
    assert match_to_violation(library, [_violation()]) is not None
