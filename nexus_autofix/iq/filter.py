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


@dataclass(frozen=True)
class FilterResult:
    actionable: list[Finding]
    escalate: list[Finding]
    ignore: list[Finding]


def filter_findings(findings: list[Finding], suppressed_components: set[str]) -> FilterResult:
    actionable: list[Finding] = []
    escalate: list[Finding] = []
    ignore: list[Finding] = []

    for finding in findings:
        is_failing = finding.policy_action.lower() in {"fail", "failure"}
        if not is_failing:
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
        bump = classify_bump(finding.current_version, finding.target_version)
        if bump in (BumpSize.MAJOR, BumpSize.UNKNOWN):
            escalate.append(finding)
        else:
            actionable.append(finding)

    return FilterResult(actionable=actionable, escalate=escalate, ignore=ignore)
