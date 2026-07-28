from __future__ import annotations

import re
from pathlib import Path

import click

from nexus_autofix.config import load_project_config, load_secrets
from nexus_autofix.iq import remediation as remediation_mod
from nexus_autofix.iq.models import Finding
from nexus_autofix.publish import branch as branch_mod

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^@]+)@(?P<version>.+)$")

_DESIGN_DOC = "docs/superpowers/specs/2026-07-28-nexus-autofix-design.md"


def purl_version(purl: str) -> str:
    """Return the trailing @version of a package URL, or "" if it does not parse."""
    match = _PURL_RE.match(purl)
    return match.group("version") if match else ""


def purl_to_component_identifier(purl: str) -> dict:
    """Convert a package URL into the componentIdentifier shape the IQ remediation API expects."""
    match = _PURL_RE.match(purl)
    if not match:
        return {"format": "unknown", "coordinates": {}}
    purl_type, rest, version = match.group("type"), match.group("rest"), match.group("version")
    if purl_type == "maven":
        group_id, artifact_id = rest.split("/", 1)
        return {
            "format": "maven",
            "coordinates": {
                "groupId": group_id,
                "artifactId": artifact_id,
                "version": version,
                "extension": "jar",
            },
        }
    if purl_type == "npm":
        return {"format": "npm", "coordinates": {"packageId": rest, "version": version}}
    return {"format": purl_type, "coordinates": {"name": rest, "version": version}}


def findings_from_policy_report(iq_client, internal_id: str, violations, stage_id: str) -> list[Finding]:
    """Turn IQ policy violations into Findings, fetching remediation advice for each."""
    findings = []
    for v in violations:
        identifier = purl_to_component_identifier(v.package_url)
        remediation = iq_client.fetch_remediation(internal_id, identifier, stage_id)
        version_change = remediation_mod.select_target(remediation)
        findings.append(
            Finding(
                component=v.component,
                package_url=v.package_url,
                current_version=purl_version(v.package_url),
                target_version=version_change.version if version_change else None,
                remediation_type=version_change.change_type if version_change else None,
                is_direct=True,
                dependency_path=[],
                parent_component=remediation.parent_component,
                parent_current_version=remediation.parent_current_version,
                parent_target_version=remediation.parent_target_version,
                policy_action=v.action,
                threat_level=v.threat_level,
                policy_name=v.policy_name,
                cve_ids=[],
                manifest_path=None,
                is_waived=v.is_waived,
                golden_version=remediation.golden_version,
            )
        )
    return findings


@click.group()
def main():
    """nexus-autofix — automated remediation of Nexus IQ dependency findings."""


@main.command("run")
@click.option("--app-id", required=True)
@click.option("--branch", required=True)
@click.option("--gate", default=None, type=click.Choice(["none", "pre-pr", "pre-push"]))
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--mock-agent", is_flag=True, default=False)
def run_command(app_id: str, branch: str, gate: str | None, dry_run: bool, mock_agent: bool):
    """
    Discovers findings from Nexus IQ, runs the agent loop, and (unless --dry-run) opens a PR.

    This command's full path — mirroring a real repo and calling a live Nexus IQ instance — is
    one of the integration points not exercised in this environment (see the design doc's
    unverified-integrations note). The --mock-agent / --dry-run flags exist precisely so this
    can be smoke-tested locally without live credentials once wired to a real repo.
    """
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    effective_gate = gate or config.default_gate

    if app_id not in config.repos:
        raise click.ClickException(
            f"no repo URL configured for app_id={app_id!r} in config.yml's repos map"
        )

    click.echo(
        f"nexus-autofix run: app_id={app_id} branch={branch} gate={effective_gate} "
        f"dry_run={dry_run} mock_agent={mock_agent} iq_url={secrets.iq_url or '<unset>'}"
    )
    click.echo(
        "Full live-IQ + live-repo wiring is unverified in this environment — "
        f"see {_DESIGN_DOC} for what's confirmed vs. not."
    )


@main.command("gc")
@click.option("--older-than-days", default=7)
def gc_command(older_than_days: int):
    """Sweep remote autofix/nexus/* branches with no open PR older than N days, for every configured repo."""
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    for app_id, repo_url in config.repos.items():
        owner, repo = repo_url.rstrip("/").removesuffix(".git").split("/")[-2:]
        deleted = branch_mod.sweep_stale_branches(
            secrets.github_api_url, secrets.github_token, owner, repo, older_than_days
        )
        for name in deleted:
            click.echo(f"deleted stale branch: {app_id}/{name}")
