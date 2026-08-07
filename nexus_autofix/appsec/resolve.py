"""Decide a target version for an AppSec library, or refuse to.

Two sources disagree here, and neither is authoritative on its own:

  * Nexus IQ's remediation endpoint, which knows the policy but has not flagged this
    component yet — that is what makes it an AppSec finding rather than a normal one.
  * The sheet's VULN_TOPFIX_RESOLUTION, which is what AppSec expects you to do, produced
    by a different pipeline and sometimes stale.

Where they agree, or only one has an answer, there is nothing to decide. Where they differ
this module DOES NOT PICK. It records both and marks the decision as belonging to a human —
see `nexusfix resolve`. Choosing silently is how a tool that exists to be trustworthy stops
being trustworthy: the two candidates differ precisely when the answer is not obvious.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from nexus_autofix.appsec.sheet import AppsecLibrary, Gav
from nexus_autofix.iq.filter import is_a_real_upgrade


class Decision(str, Enum):
    #: One usable target. Ready for the agent.
    RESOLVED = "RESOLVED"
    #: IQ and the sheet both offer a real upgrade, and they differ. A human decides.
    CONFLICT = "CONFLICT"
    #: The sheet only ever proposes a DIFFERENT artifact — a migration, not a bump.
    SWAP_ONLY = "SWAP_ONLY"
    #: The sheet proposes this artifact under more than one group id, and nothing knows
    #: which is installed. Choosing would silently change the package.
    AMBIGUOUS_GROUP = "AMBIGUOUS_GROUP"
    #: Neither source offers anything newer than what is installed.
    NO_TARGET = "NO_TARGET"


@dataclass(frozen=True)
class AppsecTarget:
    library: AppsecLibrary
    current_version: str
    iq_version: str | None
    sheet_version: str | None
    target_version: str | None
    decision: Decision
    reason: str
    swap_candidates: tuple[Gav, ...] = ()

    @property
    def actionable(self) -> bool:
        return self.decision is Decision.RESOLVED and bool(self.target_version)

    @property
    def candidates(self) -> tuple[str, ...]:
        """The versions a human may choose between. Never more than these two."""
        return tuple(dict.fromkeys(v for v in (self.iq_version, self.sheet_version) if v))


def decide(
    library: AppsecLibrary, current_version: str, iq_version: str | None
) -> AppsecTarget:
    """Work out what — if anything — this library should be bumped to.

    Both candidates are put through `is_a_real_upgrade` first. IQ answers a remediation
    request with the CURRENT version when nothing clears the violation, and the sheet can
    name a version older than what is installed once the export goes stale; either read
    naively becomes an instruction the agent cannot carry out.
    """
    sheet_version = library.sheet_version

    iq_usable = iq_version if iq_version and is_a_real_upgrade(current_version, iq_version) else None
    sheet_usable = (
        sheet_version if sheet_version and is_a_real_upgrade(current_version, sheet_version) else None
    )

    def target(decision: Decision, version: str | None, reason: str) -> AppsecTarget:
        return AppsecTarget(
            library=library,
            current_version=current_version,
            iq_version=iq_usable,
            sheet_version=sheet_usable,
            target_version=version,
            decision=decision,
            reason=reason,
            swap_candidates=library.swap_candidates,
        )

    if iq_usable and sheet_usable:
        if iq_usable == sheet_usable:
            return target(Decision.RESOLVED, iq_usable, "Nexus IQ and the AppSec sheet agree")
        return target(
            Decision.CONFLICT, None,
            f"Nexus IQ recommends {iq_usable}, the AppSec sheet recommends {sheet_usable}. "
            f"Choose one with `nexusfix resolve`.",
        )

    if iq_usable:
        return target(
            Decision.RESOLVED, iq_usable,
            "from Nexus IQ; the AppSec sheet offered nothing newer than what is installed"
            if sheet_version else "from Nexus IQ; the AppSec sheet offered no version",
        )

    if sheet_usable:
        return target(
            Decision.RESOLVED, sheet_usable,
            "from the AppSec sheet; Nexus IQ offered no version that clears this",
        )

    if library.ambiguous_candidates:
        # Same artifact name, several group ids, and IQ could not say which is installed
        # (see sheet.narrow_to_group). "com.fasterxml.jackson.core:jackson-core:2.18.8" and
        # "tools.jackson.core:jackson-core:3.1.4" are different packages; taking the higher
        # version would change the group without anyone deciding to.
        offered = ", ".join(str(g) for g in library.ambiguous_candidates)
        return target(
            Decision.AMBIGUOUS_GROUP, None,
            f"the AppSec sheet proposes {library.artifact_id} under more than one group id "
            f"({offered}), and nothing states which is installed. Choosing would change the "
            f"package, not just the version. This needs a human.",
        )

    if library.swap_candidates:
        # bcprov-jdk15on -> bc-fips is a migration, not a dependency bump. `classify_diff`
        # would refuse the change anyway, and there is no ordering between two unrelated
        # artifacts that could tell an upgrade from a downgrade.
        offered = ", ".join(str(g) for g in library.swap_candidates)
        return target(
            Decision.SWAP_ONLY, None,
            f"the AppSec sheet only proposes a different artifact ({offered}), which is a "
            f"migration rather than a version bump. This needs a human.",
        )

    return target(
        Decision.NO_TARGET, None,
        f"neither Nexus IQ nor the AppSec sheet offers a version newer than "
        f"{current_version or 'the installed one'}",
    )


class ResolutionError(ValueError):
    """The version offered to `nexusfix resolve` cannot be accepted."""


def apply_choice(target: AppsecTarget, version: str) -> AppsecTarget:
    """Record a human's choice between the two candidates.

    Deliberately narrow. It accepts ONLY one of the two versions already on the table, so an
    agent cannot launder a version of its own choosing through the resolve command and have
    it arrive looking like a human decision. The whole point of routing this through the
    tool rather than letting the agent edit run.json is that the constraint is enforced
    rather than merely requested.
    """
    if target.decision is not Decision.CONFLICT:
        raise ResolutionError(
            f"{target.library.artifact_id} is not awaiting a decision (it is "
            f"{target.decision.value}). Only a CONFLICT can be resolved."
        )

    chosen = version.strip()
    if chosen not in target.candidates:
        raise ResolutionError(
            f"{chosen!r} is not one of the candidates for {target.library.artifact_id}. "
            f"Choose {' or '.join(target.candidates)}.\n"
            "  A version neither source proposed is not a decision between them — if both "
            "are wrong, fix the sheet or escalate rather than inventing a third."
        )
    if not is_a_real_upgrade(target.current_version, chosen):
        raise ResolutionError(
            f"{chosen} is not newer than the installed {target.current_version}."
        )

    return AppsecTarget(
        library=target.library,
        current_version=target.current_version,
        iq_version=target.iq_version,
        sheet_version=target.sheet_version,
        target_version=chosen,
        decision=Decision.RESOLVED,
        reason=(
            f"chosen by a human between Nexus IQ ({target.iq_version}) and the AppSec "
            f"sheet ({target.sheet_version})"
        ),
        swap_candidates=target.swap_candidates,
    )


def choose_for_view(view: dict, version: str) -> dict:
    """Apply a human's choice to a finding as it is stored in run.json.

    The same rule as `apply_choice`, against the persisted shape rather than the in-memory
    one: `nexusfix resolve` runs in a separate process from `appsec-discover`, and run.json
    is all that survives between them. The AppsecLibrary an AppsecTarget needs does not.

    Returns the updated view; raises ResolutionError if the choice is not allowed.
    """
    component = view.get("component", "?")
    if view.get("appsec_decision") != Decision.CONFLICT.value:
        raise ResolutionError(
            f"{component} is not awaiting a decision (it is "
            f"{view.get('appsec_decision') or 'a plain Nexus IQ finding'}). "
            "Only a CONFLICT can be resolved."
        )

    chosen = version.strip()
    candidates = list(view.get("candidate_versions") or [])
    if chosen not in candidates:
        raise ResolutionError(
            f"{chosen!r} is not one of the candidates for {component}. "
            f"Choose {' or '.join(candidates)}.\n"
            "  A version neither source proposed is not a decision between them — if both "
            "are wrong, fix the sheet or escalate rather than inventing a third."
        )

    current = view.get("current_version") or ""
    if not is_a_real_upgrade(current, chosen):
        raise ResolutionError(f"{chosen} is not newer than the installed {current}.")

    updated = dict(view)
    updated.update(
        target_version=chosen,
        actionable=True,
        appsec_decision=Decision.RESOLVED.value,
        reason_not_actionable=None,
        # Emptied so a second `resolve` on the same component is refused by the check
        # above rather than silently overwriting the first decision.
        candidate_versions=[],
    )
    return updated
