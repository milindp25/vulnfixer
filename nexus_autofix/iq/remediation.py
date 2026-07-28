from __future__ import annotations

from nexus_autofix.iq.client import RemediationResponse, VersionChange

# Priority order per design doc section 7's versionChanges type table.
PRIORITY = [
    "next-non-failing-with-dependencies",
    "next-no-violations-with-dependencies",
    "next-non-failing",
    "next-no-violations",
]


def select_target(remediation: RemediationResponse) -> VersionChange | None:
    by_type = {vc.change_type: vc for vc in remediation.version_changes}
    for change_type in PRIORITY:
        if change_type in by_type:
            return by_type[change_type]
    return None
