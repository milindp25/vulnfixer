from __future__ import annotations

import pytest

from nexus_autofix.appsec.resolve import (
    Decision,
    ResolutionError,
    apply_choice,
    decide,
)
from nexus_autofix.appsec.sheet import AppsecLibrary, Gav


def _library(**overrides) -> AppsecLibrary:
    base = dict(
        github_org="org", github_repo_name="repo",
        library_filename="bcprov-jdk15on-1.49.jar", library_name="Bouncy Castle Provider",
        library_type="Java", artifact_id="bcprov-jdk15on", current_version="1.49",
        direct=False, cve_ids=("CVE-2016-1000352",), max_cvss3=7.5,
        sheet_version="1.64", group_id="org.bouncycastle",
        swap_candidates=(), topfix_discarded=(), ambiguous_candidates=(),
    )
    base.update(overrides)
    return AppsecLibrary(**base)


def test_agreement_resolves():
    target = decide(_library(sheet_version="1.64"), "1.49", "1.64")
    assert target.decision is Decision.RESOLVED
    assert target.target_version == "1.64"
    assert target.actionable


def test_iq_only_resolves():
    target = decide(_library(sheet_version=None), "1.49", "1.70")
    assert target.decision is Decision.RESOLVED and target.target_version == "1.70"


def test_sheet_only_resolves():
    target = decide(_library(sheet_version="1.64"), "1.49", None)
    assert target.decision is Decision.RESOLVED and target.target_version == "1.64"


def test_disagreement_is_a_conflict_and_picks_nothing():
    target = decide(_library(sheet_version="1.64"), "1.49", "1.70")
    assert target.decision is Decision.CONFLICT
    assert target.target_version is None
    assert not target.actionable
    assert target.candidates == ("1.70", "1.64")
    assert "resolve" in target.reason


def test_a_candidate_that_is_not_an_upgrade_is_ignored():
    # IQ answers with the CURRENT version when nothing clears the violation. Read naively
    # that becomes "upgrade 1.49 to 1.49".
    target = decide(_library(sheet_version="1.64"), "1.49", "1.49")
    assert target.decision is Decision.RESOLVED and target.target_version == "1.64"


def test_a_stale_sheet_version_older_than_installed_is_ignored():
    target = decide(_library(sheet_version="1.40"), "1.49", "1.64")
    assert target.decision is Decision.RESOLVED and target.target_version == "1.64"
    assert target.sheet_version is None


def test_swap_only_is_never_applied():
    library = _library(
        sheet_version=None, group_id=None,
        swap_candidates=(Gav("org.bouncycastle", "bc-fips", "2.1.3"),
                         Gav("org.bouncycastle", "bcprov-lts8on", "2.73.12")),
    )
    target = decide(library, "1.49", None)

    assert target.decision is Decision.SWAP_ONLY
    assert target.target_version is None
    assert "bc-fips:2.1.3" in target.reason and "migration" in target.reason


def test_iq_can_still_resolve_a_library_whose_sheet_rows_are_all_swaps():
    library = _library(sheet_version=None,
                       swap_candidates=(Gav("org.bouncycastle", "bc-fips", "2.1.3"),))
    target = decide(library, "1.49", "1.64")
    assert target.decision is Decision.RESOLVED and target.target_version == "1.64"


def test_an_ambiguous_group_is_never_chosen_between():
    library = _library(
        artifact_id="jackson-core", current_version="2.18.6", sheet_version=None, group_id=None,
        ambiguous_candidates=(Gav("com.fasterxml.jackson.core", "jackson-core", "2.18.8"),
                              Gav("tools.jackson.core", "jackson-core", "3.1.4")),
    )
    target = decide(library, "2.18.6", None)

    assert target.decision is Decision.AMBIGUOUS_GROUP
    assert target.target_version is None
    assert "more than one group id" in target.reason
    assert "tools.jackson.core:jackson-core:3.1.4" in target.reason


def test_iq_still_resolves_an_ambiguous_library():
    # IQ knows the installed group, so its answer is unaffected by the sheet's ambiguity.
    library = _library(
        artifact_id="jackson-core", current_version="2.18.6", sheet_version=None, group_id=None,
        ambiguous_candidates=(Gav("com.fasterxml.jackson.core", "jackson-core", "2.18.8"),
                              Gav("tools.jackson.core", "jackson-core", "3.1.4")),
    )
    target = decide(library, "2.18.6", "2.18.8")
    assert target.decision is Decision.RESOLVED and target.target_version == "2.18.8"


def test_nothing_anywhere_is_no_target():
    target = decide(_library(sheet_version=None), "1.49", None)
    assert target.decision is Decision.NO_TARGET
    assert "1.49" in target.reason


# --- apply_choice ---------------------------------------------------------------------

def _conflict():
    return decide(_library(sheet_version="1.64"), "1.49", "1.70")


def test_apply_choice_accepts_either_candidate():
    assert apply_choice(_conflict(), "1.70").target_version == "1.70"

    resolved = apply_choice(_conflict(), "1.64")
    assert resolved.decision is Decision.RESOLVED
    assert resolved.target_version == "1.64"
    assert "chosen by a human" in resolved.reason


def test_apply_choice_tolerates_surrounding_whitespace():
    assert apply_choice(_conflict(), "  1.70 ").target_version == "1.70"


def test_apply_choice_refuses_a_third_version():
    # The constraint that makes "the agent explains, the human decides" enforceable rather
    # than merely requested.
    with pytest.raises(ResolutionError) as exc:
        apply_choice(_conflict(), "1.99")
    assert "not one of the candidates" in str(exc.value)
    assert "1.70 or 1.64" in str(exc.value)


def test_apply_choice_refuses_when_there_is_nothing_to_decide():
    resolved = decide(_library(sheet_version="1.64"), "1.49", "1.64")
    with pytest.raises(ResolutionError) as exc:
        apply_choice(resolved, "1.64")
    assert "not awaiting a decision" in str(exc.value)


def test_apply_choice_refuses_a_downgrade_candidate():
    # Both candidates are upgrades by construction, so this guards the invariant rather
    # than a reachable path — cheap insurance if `decide` ever changes.
    conflict = _conflict()
    stale = type(conflict)(
        library=conflict.library, current_version="2.0",
        iq_version="1.70", sheet_version="1.64", target_version=None,
        decision=Decision.CONFLICT, reason="", swap_candidates=(),
    )
    with pytest.raises(ResolutionError) as exc:
        apply_choice(stale, "1.70")
    assert "not newer than" in str(exc.value)
