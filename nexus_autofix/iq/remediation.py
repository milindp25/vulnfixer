from __future__ import annotations

import logging

from nexus_autofix.iq.client import RemediationResponse, VersionChange
from nexus_autofix.iq.filter import is_a_real_upgrade

log = logging.getLogger(__name__)

#: Preference order among candidates that are ACTUALLY upgrades — see select_target.
#:
#: The two families are NOT equivalent, and the difference is the whole point of the tool:
#:   * next-no-violations — the nearest version with NO violations. This is what "fixed"
#:                          means, so it comes first.
#:   * next-non-failing   — the nearest version that does not FAIL the policy. A version
#:                          that still violates but only warns qualifies, so this can come
#:                          back as the version already installed. Reaching "not failing"
#:                          is not the job; clearing the violation is.
#: Within each family the "-with-dependencies" variant wins, because IQ has confirmed the
#: bump resolves together with the component's own dependencies and is likelier to build.
#:
#: next-non-failing used to lead this list, which is how brace-expansion 5.0.7 chose
#: next-non-failing at 5.0.7 and discarded a real next-no-violations fix in the same
#: response. Ordering alone was not the whole bug — select_target now also discards
#: non-upgrades before applying this — but leading with the weaker guarantee was wrong on
#: its own terms.
PRIORITY = [
    "next-no-violations-with-dependencies",
    "next-no-violations",
    "next-non-failing-with-dependencies",
    "next-non-failing",
]


def select_target(
    remediation: RemediationResponse, component: str = "", current_version: str = ""
) -> VersionChange | None:
    """Pick the best version IQ offers that is genuinely newer than what is installed.

    Type preference is a tie-break among usable candidates, never a reason to choose a
    version that is not an upgrade. IQ routinely returns several versionChanges at once
    and some of them can equal the installed version; picking one of those hands the agent
    an instruction it cannot carry out, and silently discards a real fix sitting in the
    same response.

    `current_version` is optional so existing callers keep working; without it every
    candidate is considered usable and the old priority-only behaviour applies.
    """
    label = component or "component"
    offers = [(vc.change_type, vc.version) for vc in remediation.version_changes]
    by_type = {vc.change_type: vc for vc in remediation.version_changes}

    if current_version:
        usable = {
            change_type: vc
            for change_type, vc in by_type.items()
            if is_a_real_upgrade(current_version, vc.version)
        }
    else:
        usable = by_type

    for change_type in PRIORITY:
        if change_type in usable:
            chosen = usable[change_type]
            skipped = sorted(set(by_type) - set(usable))
            log.info(
                "  %s: IQ offers %s -> taking %s (%s)%s",
                label, offers, chosen.version, change_type,
                f"; ignored {skipped} as not newer than {current_version}" if skipped else "",
            )
            return chosen

    if by_type and not usable:
        log.warning(
            "  %s: IQ offered %s, none newer than the installed %s. Escalating — this "
            "component probably cannot be fixed by bumping it directly (for a transitive "
            "dependency the fix belongs in a parent).",
            label, offers, current_version,
        )
    elif by_type:
        log.warning(
            "  %s: IQ returned version change type(s) %s, none of which are recognised. "
            "Escalating for manual review. If one of these is a valid upgrade target, it "
            "belongs in PRIORITY in nexus_autofix/iq/remediation.py.",
            label, sorted(by_type),
        )
    else:
        log.info("  %s: IQ offers no remediation version — escalating for manual review", label)
    return None
