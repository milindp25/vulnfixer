"""
Nexus IQ client. `HTTPIQClient` follows the endpoint sequence in the design doc
(section 7) exactly, but the precise JSON field names have NOT been verified
against a live IQ instance in this environment — the design doc's own open
items list this ("pull the OpenAPI spec... rather than inferring field names").
Test against a real tenant and adjust field lookups here if they don't match.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Protocol

import requests

log = logging.getLogger(__name__)


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


class IQEvaluationError(RuntimeError):
    """Nexus IQ reported the evaluation itself as failed — distinct from an HTTP error."""


# The status endpoint can return HTTP 200 while the evaluation is still running, so the
# HTTP code alone says nothing about completion. Field names and values are matched
# case-insensitively across several plausible spellings because the exact contract is
# unverified against a live instance — see the module docstring.
_STATUS_FIELDS = ("status", "evaluationStatus", "state", "resultStatus", "scanStatus")
_PENDING_STATUSES = {
    "PENDING", "IN_PROGRESS", "INPROGRESS", "IN-PROGRESS", "RUNNING", "QUEUED",
    "STARTED", "NOT_STARTED", "REQUESTED", "WAITING", "SUBMITTED", "SCANNING",
}
_FAILED_STATUSES = {
    "FAILED", "FAILURE", "ERROR", "ERRORED", "ABORTED", "CANCELLED", "CANCELED", "TIMED_OUT",
}
_SUCCESS_STATUSES = {"COMPLETED", "COMPLETE", "SUCCESS", "SUCCEEDED", "FINISHED", "DONE", "EVALUATED"}
_ERROR_MESSAGE_FIELDS = ("errorMessage", "error", "message", "failureReason", "statusMessage")


def _truncate(text: object, limit: int = 4000) -> str:
    as_text = str(text)
    if len(as_text) <= limit:
        return as_text
    return f"{as_text[:limit]}... [truncated, {len(as_text)} chars total]"


def _extract_status(body: dict) -> str | None:
    for field in _STATUS_FIELDS:
        value = body.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().upper().replace(" ", "_")
    return None


def _extract_error_message(body: dict) -> str:
    for field in _ERROR_MESSAGE_FIELDS:
        value = body.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "no error message supplied by IQ"


class HTTPIQClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        session: requests.Session | None = None,
        request_timeout_seconds: int = 30,
    ):
        self._base_url = base_url.rstrip("/")
        self._auth = (username, password)
        self._session = session or requests.Session()
        self._request_timeout = request_timeout_seconds

    # -- request plumbing -------------------------------------------------
    # Every call is logged: URL and request body at DEBUG, outcome at INFO, and the
    # full response body at ERROR when a call fails (IQ puts the real reason there).
    # Credentials are passed via `auth=` and never logged.

    def _log_response(self, method: str, url: str, resp, started: float) -> None:
        elapsed = time.monotonic() - started
        log.info("IQ %s %s -> HTTP %s in %.2fs", method, url, getattr(resp, "status_code", "?"), elapsed)
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            log.error(
                "IQ %s %s failed with HTTP %s. Response body:\n%s",
                method, url, getattr(resp, "status_code", "?"), _truncate(getattr(resp, "text", "")),
            )
            raise
        log.debug("IQ %s %s response body:\n%s", method, url, _truncate(getattr(resp, "text", "")))

    def _get(self, url: str, **kwargs):
        log.info("IQ GET %s", url)
        if kwargs.get("params"):
            log.debug("  params: %s", kwargs["params"])
        started = time.monotonic()
        try:
            resp = self._session.get(url, auth=self._auth, timeout=self._request_timeout, **kwargs)
        except requests.RequestException as exc:
            log.error("IQ GET %s raised %s: %s", url, type(exc).__name__, exc)
            raise
        self._log_response("GET", url, resp, started)
        return resp

    def _post(self, url: str, **kwargs):
        log.info("IQ POST %s", url)
        if kwargs.get("params"):
            log.debug("  params: %s", kwargs["params"])
        if kwargs.get("json") is not None:
            log.debug("  request body: %s", json.dumps(kwargs["json"], default=str))
        started = time.monotonic()
        try:
            resp = self._session.post(url, auth=self._auth, timeout=self._request_timeout, **kwargs)
        except requests.RequestException as exc:
            log.error("IQ POST %s raised %s: %s", url, type(exc).__name__, exc)
            raise
        self._log_response("POST", url, resp, started)
        return resp

    # -- endpoints --------------------------------------------------------

    def resolve_application_internal_id(self, public_id: str) -> str:
        resp = self._get(f"{self._base_url}/api/v2/applications", params={"publicId": public_id})
        applications = resp.json().get("applications", [])
        if not applications:
            raise ValueError(f"no IQ application found for publicId={public_id!r}")
        internal_id = applications[0]["id"]
        log.info("IQ application %r resolves to internal id %s", public_id, internal_id)
        return internal_id

    def start_source_control_evaluation(
        self, internal_id: str, branch_name: str, commit_hash: str, stage_id: str
    ) -> str:
        resp = self._post(
            f"{self._base_url}/api/v2/evaluation/applications/{internal_id}/sourceControlEvaluation",
            json={"stageId": stage_id, "branchName": branch_name, "commitHash": commit_hash},
        )
        body = resp.json()
        status_url = body.get("statusUrl")
        if not status_url:
            raise IQEvaluationError(
                "IQ did not return a 'statusUrl' when starting the evaluation. "
                f"Response body was: {_truncate(body)}"
            )
        log.info("IQ evaluation started for branch %s @ %s; status url: %s", branch_name, commit_hash, status_url)
        return status_url

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        """Poll until the evaluation finishes, then return the report id.

        A 200 response does NOT mean the scan is done — IQ returns 200 with a pending
        status while it works. We keep polling on a pending status, fail fast on a
        terminal failure status (rather than burning the whole timeout and reporting a
        misleading timeout), and finish as soon as a report URL appears.
        """
        deadline = time.monotonic() + timeout_seconds
        delay = 2.0
        attempt = 0
        url = status_url if status_url.startswith("http") else f"{self._base_url}{status_url}"
        last_body: dict = {}

        while time.monotonic() < deadline:
            attempt += 1
            resp = self._get(url)
            body = resp.json()
            last_body = body if isinstance(body, dict) else {"raw": body}
            status = _extract_status(last_body)

            if status in _FAILED_STATUSES:
                message = _extract_error_message(last_body)
                log.error("IQ evaluation failed with status %s: %s", status, message)
                raise IQEvaluationError(
                    f"Nexus IQ evaluation failed (status={status}): {message}. "
                    f"Full response: {_truncate(last_body)}"
                )

            report_url = last_body.get("reportDataUrl") or last_body.get("reportHtmlUrl")
            if report_url:
                report_id = str(report_url).rstrip("/").rsplit("/", 1)[-1]
                log.info(
                    "IQ evaluation complete after %d poll(s) (status=%s); report id: %s",
                    attempt, status or "n/a", report_id,
                )
                return report_id

            if status in _SUCCESS_STATUSES:
                # Terminal success but no report URL under any name we recognise — stop
                # rather than spin, and surface the body so the real field can be identified.
                raise IQEvaluationError(
                    f"IQ reported the evaluation as {status} but returned no recognisable report "
                    f"URL ('reportDataUrl'/'reportHtmlUrl'). Full response: {_truncate(last_body)}"
                )

            remaining = int(deadline - time.monotonic())
            log.info(
                "IQ evaluation still pending (attempt %d, status=%s); retrying in %.0fs, %ds left",
                attempt, status or "unreported", delay, remaining,
            )
            time.sleep(delay)
            delay = min(delay * 1.5, 30.0)

        log.error("IQ evaluation timed out after %ds. Last response: %s", timeout_seconds, _truncate(last_body))
        raise IQTimeoutError(
            f"IQ evaluation did not complete within {timeout_seconds}s after {attempt} poll(s). "
            f"Last status: {_extract_status(last_body) or 'unreported'}. "
            f"Last response: {_truncate(last_body)}"
        )

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        resp = self._get(
            f"{self._base_url}/api/v2/applications/{public_id}/reports/{report_id}/policy",
            headers={"Accept": "application/json"},
        )
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
        log.info("IQ policy report %s: %d violation(s)", report_id, len(violations))
        if not violations:
            log.debug(
                "No violations parsed from the policy report. If the IQ UI shows findings for "
                "this report, the JSON field names below may differ from what this client "
                "expects (packageUrl / displayName / violations[]) — check the DEBUG body above."
            )
        return violations

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        resp = self._post(
            f"{self._base_url}/api/v2/components/remediation/application/{internal_id}",
            params={"stageId": stage_id, "includeParentRemediation": "true"},
            json={"componentIdentifier": component_identifier},
        )
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
