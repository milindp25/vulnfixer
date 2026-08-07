"""Tie a library named in the AppSec sheet to a real component.

The sheet knows an artifact and a version (from LIBRARY_FILENAME) and sometimes a group id
(from a same-artifact candidate in VULN_TOPFIX_RESOLUTION). Nexus IQ's remediation endpoint
needs a full `componentIdentifier`. This module bridges the two.

Two tiers, and the order matters. IQ's policy report carries its OWN componentIdentifier
for every component it saw, so when the library appears there that object is used verbatim —
it is authoritative, and reconstructing one by hand is lossy in ways that silently return no
remediation. Only when the library is absent from the report (the common case for AppSec
findings, which IQ has not flagged yet) is an identifier built from the sheet.
"""

from __future__ import annotations

import logging

from nexus_autofix.appsec.sheet import AppsecLibrary
from nexus_autofix.iq.client import PolicyViolation

log = logging.getLogger(__name__)


def _artifact_of(identifier: dict) -> str:
    """The artifact name out of an IQ componentIdentifier, whatever the format calls it."""
    coordinates = (identifier or {}).get("coordinates") or {}
    return str(coordinates.get("artifactId") or coordinates.get("packageId") or "").lower()


def match_to_violation(
    library: AppsecLibrary, violations: list[PolicyViolation]
) -> PolicyViolation | None:
    """The policy-report entry for this library, if IQ is already reporting on it.

    Matched on artifact name alone, not on version: the sheet's version comes from a
    filename captured whenever the Tableau report last ran, and the branch being scanned may
    well have moved since. The artifact is the stable half.
    """
    artifact = library.artifact_id.lower()
    for violation in violations:
        if _artifact_of(violation.component_identifier) == artifact:
            return violation
    return None


def identifier_for(library: AppsecLibrary, violation: PolicyViolation | None) -> dict | None:
    """The componentIdentifier to ask IQ about, or None if one cannot be built.

    Built here rather than reusing `cli.component_spec_to_identifier` only because cli.py
    imports this module — going the other way is a circular import.
    """
    if violation is not None and violation.component_identifier:
        return violation.component_identifier

    if not library.group_id:
        # LIBRARY_FILENAME carries the artifact and version but never the group, and the
        # only place the sheet states one is a same-artifact candidate in the topfix column.
        # Without it there is no valid Maven identifier to ask about.
        return None

    return {
        "format": "maven",
        "coordinates": {
            "groupId": library.group_id,
            "artifactId": library.artifact_id,
            "version": library.current_version,
            "extension": "jar",
        },
    }


def current_version_for(library: AppsecLibrary, violation: PolicyViolation | None) -> str:
    """The version actually installed.

    IQ's report wins when it has one: it describes the branch being scanned right now, while
    the sheet describes whenever the Tableau export last ran.
    """
    if violation is not None and violation.current_version:
        return violation.current_version
    return library.current_version


def package_url_for(library: AppsecLibrary, violation: PolicyViolation | None) -> str:
    """The purl for this component, or a constructed one when IQ has never seen it."""
    if violation is not None and violation.package_url:
        return violation.package_url
    if library.group_id:
        return f"pkg:maven/{library.group_id}/{library.artifact_id}@{library.current_version}"
    return ""
