from __future__ import annotations

"""
Nexus IQ client. `HTTPIQClient` follows the endpoint sequence in the design doc
(section 7) exactly, but the precise JSON field names have NOT been verified
against a live IQ instance in this environment — the design doc's own open
items list this ("pull the OpenAPI spec... rather than inferring field names").
Test against a real tenant and adjust field lookups here if they don't match.
"""

import time
from dataclasses import dataclass
from typing import Protocol

import requests


@dataclass(frozen=True)
class PolicyViolation:
    package_url: str
    component: str
    policy_name: str
    policy_id: str
    threat_level: int
    constraint_summary: str
    is_waived: bool
    action: str


@dataclass(frozen=True)
class VersionChange:
    change_type: str
    version: str


@dataclass(frozen=True)
class RemediationResponse:
    version_changes: list[VersionChange]
    parent_component: str | None = None
    parent_current_version: str | None = None
    parent_target_version: str | None = None
    golden_version: str | None = None


class IQClient(Protocol):
    def resolve_application_internal_id(self, public_id: str) -> str: ...
    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str: ...
    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str: ...
    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]: ...
    def fetch_remediation(
        self, internal_id: str, component_identifier: dict, stage_id: str
    ) -> RemediationResponse: ...


class IQTimeoutError(RuntimeError):
    pass


class HTTPIQClient:
    def __init__(self, base_url: str, username: str, password: str, session: requests.Session | None = None):
        self._base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._session = session or requests.Session()

    def resolve_application_internal_id(self, public_id: str) -> str:
        resp = self._session.get(
            f"{self._base_url}/api/v2/applications", params={"publicId": public_id},
            auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        applications = resp.json().get("applications", [])
        if not applications:
            raise ValueError(f"no IQ application found for publicId={public_id!r}")
        return applications[0]["id"]

    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str:
        resp = self._session.post(
            f"{self._base_url}/api/v2/evaluation/applications/{internal_id}/sourceControlEvaluation",
            json={"stageId": stage_id, "branchName": branch_name, "commitHash": commit_hash},
            auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["statusUrl"]

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        deadline = time.monotonic() + timeout_seconds
        delay = 2.0
        url = status_url if status_url.startswith("http") else f"{self._base_url}{status_url}"
        while time.monotonic() < deadline:
            resp = self._session.get(url, auth=self._auth, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            report_url = body.get("reportDataUrl") or body.get("reportHtmlUrl")
            if report_url:
                return report_url.rstrip("/").rsplit("/", 1)[-1]
            time.sleep(delay)
            delay = min(delay * 1.5, 30.0)
        raise IQTimeoutError(f"IQ evaluation did not complete within {timeout_seconds}s")

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        resp = self._session.get(
            f"{self._base_url}/api/v2/applications/{public_id}/reports/{report_id}/policy",
            headers={"Accept": "application/json"}, auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        violations = []
        for item in resp.json():
            for violation in item.get("violations", []):
                violations.append(
                    PolicyViolation(
                        package_url=item.get("packageUrl", ""),
                        component=item.get("displayName", item.get("packageUrl", "")),
                        policy_name=violation.get("policyName", ""),
                        policy_id=violation.get("policyId", ""),
                        threat_level=violation.get("threatLevel", 0),
                        constraint_summary="; ".join(
                            c.get("constraintName", "") for c in violation.get("constraints", [])
                        ),
                        is_waived=violation.get("waived", False),
                        action=violation.get("policyThreatCategory", violation.get("action", "")),
                    )
                )
        return violations

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        resp = self._session.post(
            f"{self._base_url}/api/v2/components/remediation/application/{internal_id}",
            params={"stageId": stage_id, "includeParentRemediation": "true"},
            json={"componentIdentifier": component_identifier}, auth=self._auth, timeout=30,
        )
        resp.raise_for_status()
        remediation = resp.json().get("remediation", {})
        version_changes = [
            VersionChange(
                change_type=vc.get("type", ""),
                version=vc.get("data", {}).get("componentIdentifier", {}).get("coordinates", {}).get(
                    "version", vc.get("data", {}).get("version", "")
                ),
            )
            for vc in remediation.get("versionChanges", [])
        ]
        parent = remediation.get("parentRemediation") or {}
        return RemediationResponse(
            version_changes=version_changes,
            parent_component=parent.get("component"),
            parent_current_version=parent.get("currentVersion"),
            parent_target_version=parent.get("targetVersion"),
            golden_version=remediation.get("goldenVersion"),
        )


@dataclass
class FakeIQClient:
    """Test double per the design doc's MockAgent principle — not a second real client."""

    internal_id: str = "fake-internal-id"
    status_url: str = "/fake/status"
    report_id: str = "fake-report-id"
    policy_violations: list[PolicyViolation] | None = None
    remediations: dict[str, RemediationResponse] | None = None

    def __post_init__(self):
        if self.policy_violations is None:
            self.policy_violations = []
        if self.remediations is None:
            self.remediations = {}

    def resolve_application_internal_id(self, public_id: str) -> str:
        return self.internal_id

    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str:
        return self.status_url

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        return self.report_id

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        return list(self.policy_violations)

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        name = (
            component_identifier.get("coordinates", {}).get("artifactId")
            or component_identifier.get("coordinates", {}).get("packageId")
            or component_identifier.get("name", "")
        )
        return self.remediations.get(name, RemediationResponse(version_changes=[]))
