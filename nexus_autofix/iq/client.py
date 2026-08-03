"""
Nexus IQ client. `HTTPIQClient` follows the endpoint sequence in the design doc
(section 7). Field names were originally inferred rather than taken from the OpenAPI
spec, so parts of this are still best-effort — but the following have now been
CONFIRMED against a live instance and should not be "corrected" back:

* ``sourceControlEvaluation`` takes only ``stageId`` and ``branchName``. It does not
  want ``commitHash``, despite the design doc recommending pinning to a commit.
* The ``statusUrl`` it returns has NO leading slash, so it must be normalised before
  being joined to the base URL.

Anything not listed above is still unverified; if a response parses as empty when the
IQ UI clearly shows data, compare against the DEBUG log, which records full response
bodies.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Protocol

import requests

from nexus_autofix.http import make_session

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
    #: IQ's own `componentIdentifier` object, copied out of the policy report verbatim and
    #: handed straight back to the remediation endpoint. Reconstructing it by parsing the
    #: purl gets scoped npm packages wrong — the purl percent-encodes the leading "@"
    #: (`pkg:npm/%40dfs-react-ui/core@1.4.6`) while IQ's coordinates carry the decoded
    #: `@dfs-react-ui/core`, so a rebuilt identifier finds no remediation.
    component_identifier: dict = field(default_factory=dict)
    #: `componentIdentifier.coordinates.version` — authoritative, unlike a purl suffix.
    current_version: str = ""
    #: `dependencyData.directDependency`. A transitive component cannot be bumped in the
    #: manifest directly; the agent has to move whichever parent pulls it in.
    is_direct: bool = True
    #: `dependencyData.parentComponentPurls` — who pulls this in, for the agent prompt.
    parent_purls: list[str] = field(default_factory=list)
    #: `displayName`, e.g. "hasown : 2.0.2" — for humans (PR body), not for matching.
    display_name: str = ""


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
        self, internal_id: str, branch_name: str, stage_id: str
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
    for name in _STATUS_FIELDS:
        value = body.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip().upper().replace(" ", "_")
    return None


#: Trailing path segments IQ appends to a report URL — the id sits *before* these.
_REPORT_URL_SUFFIXES = {"raw", "policy", "pdf", "printreport", "json", "dependencies"}


def _report_id_from_url(url: object) -> str:
    """Pull the report id out of a report URL.

    VERIFIED AGAINST A LIVE INSTANCE: `reportDataUrl` looks like
    ``api/v2/applications/<publicId>/reports/<reportId>/raw`` — it ends in ``/raw``, so
    simply taking the last path segment yields the literal string "raw", and the policy
    URL built from it (``.../reports/raw/policy``) 404s. The id is the segment following
    ``reports``/``report``; the html variant (``ui/links/application/<publicId>/report/<reportId>``)
    has no trailing suffix at all, which is why matching on the marker beats stripping
    a suffix.
    """
    parts = [segment for segment in str(url).split("?")[0].rstrip("/").split("/") if segment]
    for marker in ("reports", "report"):
        if marker in parts:
            index = parts.index(marker)
            if index + 1 < len(parts):
                return parts[index + 1]
    # No recognisable marker: fall back to dropping a known trailing suffix.
    if len(parts) >= 2 and parts[-1].lower() in _REPORT_URL_SUFFIXES:
        return parts[-2]
    return parts[-1] if parts else ""


def _components_from_policy_report(body: object) -> list[dict]:
    """The component list out of a /policy response.

    VERIFIED AGAINST A LIVE INSTANCE: the response is an OBJECT with a ``components``
    array, not a bare array. Iterating the object directly yields its string keys, which
    is where ``AttributeError: 'str' object has no attribute 'get'`` came from. A bare
    list is still accepted in case another IQ version returns one.
    """
    if isinstance(body, dict):
        for key in ("components", "componentPolicyViolations", "results"):
            value = body.get(key)
            if isinstance(value, list):
                return [entry for entry in value if isinstance(entry, dict)]
        return []
    if isinstance(body, list):
        return [entry for entry in body if isinstance(entry, dict)]
    return []


def _threat_level_of(violation: dict) -> int:
    """VERIFIED AGAINST A LIVE INSTANCE: the field is ``policyThreatLevel``, an int."""
    for name in ("policyThreatLevel", "threatLevel"):
        value = violation.get(name)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    return 0


def _severity_band(threat_level: int) -> str:
    """Nexus IQ's own severity bands for a 0-10 policy threat level.

    Only here so the log can be read against the IQ report page without translating
    numbers in your head. Nothing branches on it — the gate is the raw number.
    """
    if threat_level >= 10:
        return "Critical (10)"
    if threat_level >= 8:
        return "Severe (8-9)"
    if threat_level >= 4:
        return "Moderate (4-7)"
    if threat_level >= 2:
        return "Low (2-3)"
    return "Info (0-1)"


def _clean_component_name(component: dict) -> str:
    """A bare component name, with no version glued on.

    ``displayName`` is a human string — "hasown : 2.0.2", with spaces around the colon
    and the version baked in — so it can never match a plain name in the suppression
    list, and reads badly in a branch or PR title. The coordinates carry the real name.
    """
    coordinates = (component.get("componentIdentifier") or {}).get("coordinates") or {}
    if isinstance(coordinates, dict):
        group_id = coordinates.get("groupId")
        artifact_id = coordinates.get("artifactId")
        if group_id and artifact_id:
            return f"{group_id}:{artifact_id}"
        for key in ("artifactId", "packageId", "name"):
            value = coordinates.get(key)
            if isinstance(value, str) and value:
                return value
    display_name = component.get("displayName")
    if isinstance(display_name, str) and display_name:
        # Last resort: strip the " : <version>" tail off the human string.
        return display_name.split(" : ")[0].strip()
    return str(component.get("packageUrl") or "")


def _worst_violation_for_component(component: dict) -> PolicyViolation | None:
    """Collapse a component's violations to the single highest-threat one.

    A component routinely carries several violations at different threat levels. The
    highest is what decides whether the component is worth acting on, so that is the one
    represented. Waived violations are ignored when picking the worst — a waiver is a
    decision already made — and a component whose violations are *all* waived is
    reported as waived so the filter can drop it.
    """
    raw_violations = component.get("violations")
    if not isinstance(raw_violations, list):
        return None
    violations = [v for v in raw_violations if isinstance(v, dict)]
    if not violations:
        return None

    def is_waived(violation: dict) -> bool:
        # `waivedWithAutoWaiver` is a separate flag from `waived` in the live payload —
        # missing it would re-fix something a waiver already settled.
        return bool(
            violation.get("waived")
            or violation.get("waivedWithAutoWaiver")
            or violation.get("grandfathered")
        )

    considered = [v for v in violations if not is_waived(v)]
    all_waived = not considered
    if all_waived:
        considered = violations

    worst = max(considered, key=_threat_level_of)
    package_url = component.get("packageUrl") or ""
    constraints = worst.get("constraints")
    constraint_summary = (
        "; ".join(
            c.get("constraintName", "")
            for c in constraints
            if isinstance(c, dict)
        )
        if isinstance(constraints, list)
        else ""
    )

    identifier = component.get("componentIdentifier")
    identifier = identifier if isinstance(identifier, dict) else {}
    coordinates = identifier.get("coordinates")
    coordinates = coordinates if isinstance(coordinates, dict) else {}

    dependency_data = component.get("dependencyData")
    dependency_data = dependency_data if isinstance(dependency_data, dict) else {}
    parent_purls = dependency_data.get("parentComponentPurls")
    # A list of plain purl STRINGS in the live payload, not objects.
    parent_purls = [p for p in parent_purls if isinstance(p, str)] if isinstance(parent_purls, list) else []

    return PolicyViolation(
        package_url=package_url,
        component=_clean_component_name(component),
        policy_name=worst.get("policyName", ""),
        policy_id=worst.get("policyId", ""),
        threat_level=_threat_level_of(worst),
        constraint_summary=constraint_summary,
        is_waived=all_waived,
        # policyThreatCategory is a CATEGORY (SECURITY / LICENSE / QUALITY), never an
        # action like "Fail" — kept for the PR body, but the actionable/ignore decision
        # is made on threat level, not on this.
        action=worst.get("policyThreatCategory", ""),
        component_identifier=identifier,
        current_version=str(coordinates.get("version") or ""),
        # Absent means direct: only a component IQ positively marks transitive gets the
        # more conservative parent-bump treatment.
        is_direct=dependency_data.get("directDependency") is not False,
        parent_purls=parent_purls,
        display_name=str(component.get("displayName") or ""),
    )


def _dependency_coverage(components: list) -> tuple[int, int, int]:
    """Count how many components IQ marked direct / transitive / neither.

    Whether the scan resolved the dependency *tree* or only read the manifest is the
    single biggest determinant of what a run can possibly fix, and nothing else in the
    response says which happened. This is the closest thing to a direct measurement:
    a real tree resolution produces many transitive components, and a manifest-only
    read produces almost none.
    """
    direct = transitive = unknown = 0
    for component in components:
        if not isinstance(component, dict):
            continue
        data = component.get("dependencyData")
        flag = data.get("directDependency") if isinstance(data, dict) else None
        if flag is True:
            direct += 1
        elif flag is False:
            transitive += 1
        else:
            unknown += 1
    return direct, transitive, unknown


def _extract_error_message(body: dict) -> str:
    for name in _ERROR_MESSAGE_FIELDS:
        value = body.get(name)
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
        self._session = session or make_session()
        self._request_timeout = request_timeout_seconds

    # -- request plumbing -------------------------------------------------
    # Every call is logged: URL and request body at DEBUG, outcome at INFO, and the
    # full response body at ERROR when a call fails (IQ puts the real reason there).
    # Credentials are passed via `auth=` and never logged.

    def _log_response(self, method: str, url: str, resp, started: float, request_body=None) -> None:
        elapsed = time.monotonic() - started
        log.info("IQ %s %s -> HTTP %s in %.2fs", method, url, getattr(resp, "status_code", "?"), elapsed)
        try:
            resp.raise_for_status()
        except requests.HTTPError:
            # The request body goes in the ERROR log too, not just DEBUG: a 4xx is almost
            # always a complaint about what was sent, and reading IQ's objection without
            # seeing what it objected to means turning DEBUG on and reproducing the failure.
            sent = (
                f"\n  request body: {json.dumps(request_body, default=str)}"
                if request_body is not None else ""
            )
            log.error(
                "IQ %s %s failed with HTTP %s.%s\n  response body:\n%s",
                method, url, getattr(resp, "status_code", "?"), sent,
                _truncate(getattr(resp, "text", "")),
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
        self._log_response("GET", url, resp, started, request_body=kwargs.get("params"))
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
        self._log_response("POST", url, resp, started, request_body=kwargs.get("json"))
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
        self, internal_id: str, branch_name: str, stage_id: str
    ) -> str:
        # VERIFIED AGAINST A LIVE INSTANCE: the body carries only stageId and branchName.
        # An earlier version also sent commitHash (the design doc recommends pinning the
        # evaluation to a commit) but the real endpoint does not want it, so it is not sent.
        # The commit sha is still resolved and used everywhere else — it pins the worktree
        # and is recorded on the run.
        resp = self._post(
            f"{self._base_url}/api/v2/evaluation/applications/{internal_id}/sourceControlEvaluation",
            json={"stageId": stage_id, "branchName": branch_name},
        )
        body = resp.json()
        status_url = body.get("statusUrl")
        if not status_url:
            raise IQEvaluationError(
                "IQ did not return a 'statusUrl' when starting the evaluation. "
                f"Response body was: {_truncate(body)}"
            )
        # VERIFIED AGAINST A LIVE INSTANCE: statusUrl comes back WITHOUT a leading slash
        # (e.g. "api/v2/scan/applications/.../status/..."), so joining it straight onto the
        # base URL produced "https://iq.example.comapi/v2/...". Normalising here rather than
        # blindly prefixing keeps it correct if an instance ever returns the slash already,
        # or returns an absolute URL.
        if not status_url.startswith(("http://", "https://")):
            status_url = "/" + status_url.lstrip("/")
        log.info("IQ evaluation started for branch %s; status url: %s", branch_name, status_url)
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
                report_id = _report_id_from_url(report_url)
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
        components = _components_from_policy_report(resp.json())
        direct, transitive, unknown = _dependency_coverage(components)
        log.info(
            "IQ scanned %d component(s): %d direct, %d transitive, %d unmarked",
            len(components), direct, transitive, unknown,
        )
        if components and transitive == 0:
            # Loud, because the run will otherwise look like a clean success that simply
            # found little. A scan that never resolved the tree cannot report a vulnerable
            # transitive dependency, so "no findings" means "nothing found in the manifest"
            # — a much weaker claim than it appears, and not one this tool should make
            # silently. A lockfile (package-lock.json, yarn.lock) enumerates the tree, so
            # IQ sees transitives without resolving anything; a bare pom.xml or
            # build.gradle does not, and resolution can also be blocked by a quarantine.
            log.warning(
                "not one component in this report is marked transitive. IQ has very likely "
                "analysed the manifest without resolving the dependency tree, so only "
                "DIRECT dependencies are covered and a vulnerable transitive cannot appear "
                "in the findings at all. Check that a lockfile is committed for this repo, "
                "and that nothing in the build is blocking dependency resolution."
            )
        # Per component, so one oddly-shaped entry among hundreds cannot end the run. A
        # single unexpected null used to raise out of here as a bare
        # "AttributeError: 'NoneType' object has no attribute 'get'" with no indication of
        # WHICH component caused it, out of an eighty-plus component report.
        violations = []
        unparsable = []
        for component in components:
            try:
                worst = _worst_violation_for_component(component)
            except Exception as exc:  # noqa: BLE001 - see above
                unparsable.append(component.get("packageUrl") or component.get("displayName") or "?")
                log.error(
                    "could not parse one component from the policy report — skipping it and "
                    "continuing.\n  %s: %s\n  component: %s",
                    type(exc).__name__, exc, _truncate(component, 1200),
                )
                continue
            if worst is not None:
                violations.append(worst)
        if unparsable:
            log.warning(
                "%d component(s) in the policy report could not be parsed and were skipped: "
                "%s. They are NOT covered by this run — the full JSON for each is at ERROR "
                "above.", len(unparsable), unparsable,
            )
        # DEBUG, not INFO. This is EVERY component carrying any violation at any threat
        # level — the whole IQ report page, most of it far below the bar for an automated
        # fix. Putting it at INFO made the run announce a big number it had no intention
        # of acting on. The caller logs the count that matters, after gating.
        log.debug(
            "IQ policy report %s: %d component(s) with at least one violation, at all "
            "threat levels (unfiltered)", report_id, len(violations),
        )
        by_band: dict[str, int] = {}
        for violation in violations:
            band = _severity_band(violation.threat_level)
            by_band[band] = by_band.get(band, 0) + 1
        for band in ("Critical (10)", "Severe (8-9)", "Moderate (4-7)", "Low (2-3)", "Info (0-1)"):
            if by_band.get(band):
                log.debug("    %-15s %d component(s)", band, by_band[band])
        for violation in violations:
            log.debug(
                "  %s threat=%s policy=%s waived=%s",
                violation.component, violation.threat_level, violation.policy_name, violation.is_waived,
            )
        if components and not violations:
            log.debug(
                "Components were present but none carried a parsable violation — compare the "
                "DEBUG response body above against the field names this client reads "
                "(violations[].policyThreatLevel / policyName / waived)."
            )
        return violations

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        # IQ answers a malformed identifier with a flat 400 ("invalid component identifier"),
        # which reads like a server problem. Catching the empty case here names the actual
        # cause — an identifier that could not be built — and costs no round trip.
        coordinates = (component_identifier or {}).get("coordinates") or {}
        if not coordinates:
            raise ValueError(
                "refusing to request remediation with an empty component identifier: "
                f"{json.dumps(component_identifier, default=str)}. IQ needs populated "
                "coordinates; the policy report supplies them per component."
            )
        resp = self._post(
            f"{self._base_url}/api/v2/components/remediation/application/{internal_id}",
            params={"stageId": stage_id, "includeParentRemediation": "true"},
            json={"componentIdentifier": component_identifier},
        )
        body = resp.json()
        # VERIFIED AGAINST A LIVE INSTANCE. The full response for one component:
        #
        #   {"remediation": {"versionChanges": [
        #     {"type": "next-no-violations",
        #      "data": {"component": {
        #         "packageUrl": "pkg:npm/postcss@8.5.18",
        #         "hash": null,
        #         "componentIdentifier": {"format": "npm",
        #             "coordinates": {"packageId": "postcss", "version": "8.5.18"}},
        #         "displayName": "postcss : 8.5.18"}}}]}}
        #
        # The version sits under data.COMPONENT.componentIdentifier.coordinates.version.
        # This client previously read data.componentIdentifier... — one level too shallow —
        # so every change parsed to an empty version string and every component with a
        # perfectly good offer was escalated as unfixable.
        remediation = body.get("remediation") if isinstance(body, dict) else None
        if not isinstance(remediation, dict):
            remediation = body if isinstance(body, dict) else {}
        raw_changes = remediation.get("versionChanges")
        raw_changes = raw_changes if isinstance(raw_changes, list) else []

        version_changes = []
        for vc in raw_changes:
            if not isinstance(vc, dict):
                continue
            data = vc.get("data") if isinstance(vc.get("data"), dict) else {}
            component = data.get("component") if isinstance(data.get("component"), dict) else {}
            version = (
                ((component.get("componentIdentifier") or {}).get("coordinates") or {}).get("version")
                # Fallbacks for shapes seen in no live response, kept only so a variant
                # degrades to a warning below rather than a silent empty version.
                or ((data.get("componentIdentifier") or {}).get("coordinates") or {}).get("version")
                or data.get("version")
                or ""
            )
            version_changes.append(
                VersionChange(change_type=vc.get("type", ""), version=str(version))
            )

        # The full body at INFO, always. This is the most contested contract in the tool
        # and has now been misread twice; the responses are small (a real one measured
        # 549 bytes) and gating means only a handful are fetched per run. Printing what
        # IQ said next to what was parsed out of it makes a mismatch self-evident instead
        # of something to be inferred from a wrong version downstream.
        requested_version = ((component_identifier or {}).get("coordinates") or {}).get("version")
        log.info(
            "remediation for %s@%s -> parsed %s\n  raw response: %s",
            ((component_identifier or {}).get("coordinates") or {}).get("packageId")
            or ((component_identifier or {}).get("coordinates") or {}).get("artifactId")
            or "component",
            requested_version,
            [(vc.change_type, vc.version) for vc in version_changes] or "nothing",
            _truncate(body),
        )
        if not version_changes and body:
            log.warning(
                "remediation response parsed to zero version changes. If IQ did offer an "
                "upgrade here, this client is reading the wrong field names. Raw response:\n%s",
                _truncate(body),
            )
        else:
            missing = [vc.change_type for vc in version_changes if not vc.version]
            if missing:
                log.warning(
                    "remediation offered type(s) %s with no version this client could "
                    "read. Raw response:\n%s", missing, _truncate(body),
                )
            echoed = [vc.change_type for vc in version_changes if vc.version == requested_version]
            if echoed:
                # Either IQ genuinely has no upgrade, or the target is somewhere else in
                # the payload and the current version is being read by mistake. Those look
                # identical downstream, so say both are possible and show the evidence.
                log.warning(
                    "remediation type(s) %s came back at %s — the SAME version that was "
                    "requested. Either IQ has no version that clears this, or the upgrade "
                    "target sits elsewhere in the payload and this client is reading the "
                    "component it was asked about. Compare against the raw response above.",
                    echoed, requested_version,
                )
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
        self, internal_id: str, branch_name: str, stage_id: str
    ) -> str:
        return self.status_url

    def poll_evaluation(self, status_url: str, timeout_seconds: int) -> str:
        return self.report_id

    def fetch_policy_report(self, public_id: str, report_id: str) -> list[PolicyViolation]:
        return list(self.policy_violations)

    def fetch_remediation(self, internal_id: str, component_identifier: dict, stage_id: str) -> RemediationResponse:
        name = (
            (component_identifier.get("coordinates") or {}).get("artifactId")
            or (component_identifier.get("coordinates") or {}).get("packageId")
            or component_identifier.get("name", "")
        )
        return self.remediations.get(name, RemediationResponse(version_changes=[]))
