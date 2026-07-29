from __future__ import annotations

import logging

from nexus_autofix.iq.client import RemediationResponse, VersionChange

log = logging.getLogger(__name__)

#: Priority order per design doc section 7's versionChanges type table.
#:
#: All four are acceptable targets — the order is preference, not a filter. Both families
#: land on a version that clears the policy:
#:   * next-non-failing   — the nearest version that does not FAIL the policy (a version
#:                          that only warns still qualifies)
#:   * next-no-violations — the nearest version with no violations at all
#: The "-with-dependencies" variants are preferred because IQ has confirmed the bump is
#: resolvable together with the component's own dependencies, which is far likelier to
#: build. Between the two families, next-non-failing comes first only because it is
#: usually the smaller jump; if IQ offers no non-failing target, next-no-violations is
#: taken rather than the component being escalated.
PRIORITY = [
    "next-non-failing-with-dependencies",
    "next-no-violations-with-dependencies",
    "next-non-failing",
    "next-no-violations",
]


def select_target(remediation: RemediationResponse, component: str = "") -> VersionChange | None:
    """Pick the best version IQ offers, or None if it offers nothing usable.

    Returning None escalates the component for a human, so an unrecognised change type
    must not look the same as "IQ had no answer" — the types IQ actually returned are
    logged either way, and a non-empty list that matches nothing is a warning naming the
    types, since that means PRIORITY is missing an entry rather than the component being
    genuinely unfixable.
    """
    label = component or "component"
    by_type = {vc.change_type: vc for vc in remediation.version_changes}

    for change_type in PRIORITY:
        if change_type in by_type:
            chosen = by_type[change_type]
            log.info(
                "  %s: IQ offers %s -> taking %s (%s)",
                label, sorted(by_type) or "nothing", chosen.version, change_type,
            )
            return chosen

    if by_type:
        log.warning(
            "  %s: IQ returned version change type(s) %s, none of which are recognised. "
            "Escalating for manual review. If one of these is a valid upgrade target, it "
            "belongs in PRIORITY in nexus_autofix/iq/remediation.py.",
            label, sorted(by_type),
        )
    else:
        log.info("  %s: IQ offers no remediation version — escalating for manual review", label)
    return None
