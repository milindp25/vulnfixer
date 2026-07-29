from nexus_autofix.iq.client import RemediationResponse, VersionChange
from nexus_autofix.iq.remediation import select_target


def test_prefers_next_non_failing_with_dependencies():
    # Within the non-failing family, the with-dependencies variant still wins.
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
    # A component whose only offer is next-no-violations must be fixed, not sent to a
    # human — it is the strongest guarantee IQ gives, not a fallback.
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
    assert "taking 2.5.0 (next-no-violations)" in caplog.text


# --------------------------------------------------------------------------------------
# Type preference must never outrank "is this actually newer". IQ returns several
# versionChanges at once and some can equal the installed version — next-non-failing in
# particular, since a version that merely warns already counts as "not failing".
# --------------------------------------------------------------------------------------


def test_a_real_upgrade_beats_a_higher_priority_type_that_is_not_an_upgrade():
    # The live regression: brace-expansion 5.0.7 installed. next-non-failing outranks
    # next-no-violations by type, but offers the version already installed — so priority
    # took 5.0.7 and discarded the genuine 5.0.8 fix in the same response.
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "5.0.7"),
        VersionChange("next-no-violations", "5.0.8"),
    ])

    chosen = select_target(remediation, "brace-expansion", current_version="5.0.7")

    assert chosen is not None
    assert chosen.version == "5.0.8"
    assert chosen.change_type == "next-no-violations"


def test_clearing_all_violations_is_preferred_over_merely_not_failing():
    # next-non-failing only reaches "does not FAIL the policy" — a version that still
    # violates but only warns qualifies. Clearing the violation is the job, so the larger
    # jump is the right one here even though it is the larger jump.
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "5.0.8"),
        VersionChange("next-no-violations", "5.1.0"),
    ])
    chosen = select_target(remediation, "x", current_version="5.0.7")
    assert chosen.change_type == "next-no-violations"
    assert chosen.version == "5.1.0"


def test_with_dependencies_wins_within_the_no_violations_family():
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-no-violations", "5.2.0"),
        VersionChange("next-no-violations-with-dependencies", "5.1.0"),
    ])
    chosen = select_target(remediation, "x", current_version="5.0.7")
    assert chosen.change_type == "next-no-violations-with-dependencies", (
        "IQ has confirmed this one resolves with the component's own dependencies"
    )


def test_when_no_offer_is_newer_the_component_is_escalated_with_the_offers_named(caplog):
    import logging

    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "5.0.7"),
        VersionChange("next-no-violations", "5.0.6"),
    ])
    with caplog.at_level(logging.WARNING):
        assert select_target(remediation, "brace-expansion", current_version="5.0.7") is None

    assert "none newer than the installed 5.0.7" in caplog.text
    assert "5.0.7" in caplog.text and "5.0.6" in caplog.text


def test_the_offers_and_the_ignored_ones_are_logged(caplog):
    import logging

    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "5.0.7"),
        VersionChange("next-no-violations", "5.0.8"),
    ])
    with caplog.at_level(logging.INFO):
        select_target(remediation, "brace-expansion", current_version="5.0.7")

    assert "('next-non-failing', '5.0.7')" in caplog.text, "everything IQ offered"
    assert "taking 5.0.8" in caplog.text
    assert "ignored ['next-non-failing'] as not newer than 5.0.7" in caplog.text


def test_without_a_current_version_priority_alone_decides():
    # No installed version to compare against, so nothing can be discarded as a
    # non-upgrade and PRIORITY is the only signal left.
    remediation = RemediationResponse(version_changes=[
        VersionChange("next-non-failing", "5.0.7"),
        VersionChange("next-no-violations", "5.0.8"),
    ])
    assert select_target(remediation).change_type == "next-no-violations"
