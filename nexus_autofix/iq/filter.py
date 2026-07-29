from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from nexus_autofix.iq.models import Finding

# Patch component is optional: Maven artifacts routinely publish two-component
# versions ("1.9", not "1.9.0") — requiring three components would escalate
# every one of those as UNKNOWN and never let the agent attempt a real fix.
_SEMVER_RE = re.compile(r"^v?(\d+)\.(\d+)(?:\.(\d+))?")


class BumpSize(str, Enum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    UNKNOWN = "unknown"


def classify_bump(current: str, target: str) -> BumpSize:
    cur = _SEMVER_RE.match(current or "")
    tgt = _SEMVER_RE.match(target or "")
    if not cur or not tgt:
        return BumpSize.UNKNOWN
    cur_major, cur_minor = int(cur.group(1)), int(cur.group(2))
    tgt_major, tgt_minor = int(tgt.group(1)), int(tgt.group(2))
    if tgt_major != cur_major:
        return BumpSize.MAJOR
    if tgt_minor != cur_minor:
        return BumpSize.MINOR
    return BumpSize.PATCH


def _version_tuple(version: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) for ordering comparisons, or None if unparseable."""
    match = _SEMVER_RE.match(version or "")
    if not match:
        return None
    return (int(match.group(1)), int(match.group(2)), int(match.group(3) or 0))


def is_a_real_upgrade(current: str, target: str) -> bool:
    """Whether moving current -> target is actually an upgrade.

    Nexus IQ answers a remediation request with the CURRENT version when no version
    clears the violation — its way of saying "this cannot be fixed by bumping this
    component", which is routine for a transitive dependency whose fix belongs in a
    parent. Read naively that comes back as "upgrade postcss 8.5.10 to 8.5.10", and the
    agent is handed a no-op it cannot satisfy.

    A lower target is refused too: downgrading is explicitly prohibited for the agent,
    and reaching a "clean" version by going backwards is not a fix anyone asked for.

    Unparseable versions return True so the decision falls through to classify_bump,
    which routes them to UNKNOWN and escalates — this function only rejects cases it can
    positively order.
    """
    if not current or not target:
        return False
    if current == target:
        return False
    current_parts, target_parts = _version_tuple(current), _version_tuple(target)
    if current_parts is None or target_parts is None:
        return True
    return target_parts > current_parts


#: IQ threat levels run 0-10. Only levels ABOVE this are worth an automated fix — 8+ is
#: what IQ labels Critical/Severe. Overridable via config.yml's `min_threat_level`.
DEFAULT_MIN_THREAT_LEVEL = 8


@dataclass(frozen=True)
class FilterResult:
    actionable: list[Finding]
    escalate: list[Finding]
    ignore: list[Finding]


def filter_findings(
    findings: list[Finding],
    suppressed_components: set[str],
    min_threat_level: int = DEFAULT_MIN_THREAT_LEVEL,
) -> FilterResult:
    """Split findings into what the agent may fix, what a human must see, and noise.

    The gate is the component's threat level, NOT `policy_action`: IQ's
    `policyThreatCategory` is a category (SECURITY / LICENSE / QUALITY), never an
    action like "Fail", so gating on it would drop everything. Each finding already
    carries the HIGHEST threat level among that component's violations.
    """
    actionable: list[Finding] = []
    escalate: list[Finding] = []
    ignore: list[Finding] = []

    for finding in findings:
        if finding.threat_level < min_threat_level:
            ignore.append(finding)
            continue
        if finding.is_waived:
            ignore.append(finding)
            continue
        if finding.component in suppressed_components:
            ignore.append(finding)
            continue
        if not finding.is_actionable:
            escalate.append(finding)
            continue
        if not is_a_real_upgrade(finding.current_version, finding.target_version):
            # IQ offered nothing better than what is already installed. Sending this to
            # the agent asks it to change a version to itself; it would either do nothing
            # (reported as NO_CHANGES, i.e. "the agent failed") or invent a version of its
            # own choosing to look productive. A human needs to see it instead.
            escalate.append(finding)
            continue
        bump = classify_bump(finding.current_version, finding.target_version)
        if bump in (BumpSize.MAJOR, BumpSize.UNKNOWN):
            escalate.append(finding)
        else:
            actionable.append(finding)

    return FilterResult(actionable=actionable, escalate=escalate, ignore=ignore)
