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


def test_next_no_violations_alone_is_a_valid_target_not_an_escalation():
    # Both families land on a version that clears the policy. A component whose only
    # offer is next-no-violations must be fixed, not sent to a human.
    remediation = RemediationResponse(
        version_changes=[VersionChange("next-no-violations", "2.5.0")]
    )
    chosen = select_target(remediation)
    assert chosen is not None
    assert chosen.version == "2.5.0"
    assert chosen.change_type == "next-no-violations"


def test_next_no_violations_with_dependencies_beats_plain_next_non_failing():
    # The "-with-dependencies" variants are confirmed resolvable alongside the
    # component's own deps, so they outrank the plain forms regardless of family.
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "1.1.0"),
        VersionChange("next-no-violations-with-dependencies", "1.4.0"),
    ])
    assert select_target(remediation).change_type == "next-no-violations-with-dependencies"


def test_an_unrecognised_change_type_warns_by_name_instead_of_failing_silently(caplog):
    # Escalating looks identical to "IQ had no answer" unless the types are named. If IQ
    # grows a type this list does not know, the log has to say so.
    import logging

    remediation = RemediationResponse(
        version_changes=[VersionChange("next-something-new", "9.9.9")]
    )
    with caplog.at_level(logging.WARNING):
        assert select_target(remediation, "widget") is None

    assert "next-something-new" in caplog.text
    assert "belongs in PRIORITY" in caplog.text


def test_the_types_iq_offered_are_logged_for_a_successful_pick(caplog):
    import logging

    remediation = RemediationResponse(version_changes=[
        VersionChange("next-no-violations", "2.5.0"),
        VersionChange("next-non-failing", "2.1.0"),
    ])
    with caplog.at_level(logging.INFO):
        select_target(remediation, "axios")

    assert "axios" in caplog.text
    assert "next-no-violations" in caplog.text
    assert "taking 2.1.0 (next-non-failing)" in caplog.text
