from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    component: str
    package_url: str
    current_version: str
    target_version: str | None
    remediation_type: str | None
    is_direct: bool
    dependency_path: list[str]
    parent_component: str | None
    parent_current_version: str | None
    parent_target_version: str | None
    policy_action: str
    threat_level: int
    policy_name: str
    cve_ids: list[str]
    manifest_path: Path | None
    is_dev_dependency: bool = False
    is_waived: bool = False
    golden_version: str | None = None
    escalation_reason: str | None = None

    @property
    def is_actionable(self) -> bool:
        return self.target_version is not None


@dataclass(frozen=True)
class Module:
    path: Path
    ecosystem: str
    manifest: Path
    version_catalog: Path | None = None


@dataclass(frozen=True)
class RepoProfile:
    ecosystem: str
    java_version: str | None
    node_version: str | None
    modules: list[Module]
    source: str  # "trident" | "glob"


class RunOutcome(str, Enum):
    CLEAN = "CLEAN"
    FIXED = "FIXED"
    FIXED_NEEDS_REVIEW = "FIXED_NEEDS_REVIEW"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REJECTED = "REJECTED"
    FAILED_BUILD = "FAILED_BUILD"
    FAILED_RESCAN = "FAILED_RESCAN"
    NO_CHANGES = "NO_CHANGES"
    ESCALATED = "ESCALATED"
