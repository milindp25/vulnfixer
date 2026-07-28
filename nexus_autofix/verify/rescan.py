from __future__ import annotations

from dataclasses import dataclass

from nexus_autofix.iq.client import PolicyViolation


@dataclass(frozen=True)
class RescanComparison:
    all_cleared: bool
    still_failing: list[str]
    new_findings: list[str]


def compare_reports(
    baseline: list[PolicyViolation], rescan: list[PolicyViolation], target_purls: set[str]
) -> RescanComparison:
    baseline_purls = {v.package_url for v in baseline}
    rescan_purls = {v.package_url for v in rescan}
    still_failing = sorted(target_purls & rescan_purls)
    new_findings = sorted(rescan_purls - baseline_purls)
    return RescanComparison(
        all_cleared=not still_failing,
        still_failing=still_failing,
        new_findings=new_findings,
    )
