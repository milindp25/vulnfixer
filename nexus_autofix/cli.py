from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import date
from pathlib import Path

import click

from nexus_autofix.agent.copilot_cli import CopilotCLIAgent
from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.config import ProjectConfig, Secrets, load_project_config, load_secrets
from nexus_autofix.iq import remediation as remediation_mod
from nexus_autofix.iq.client import HTTPIQClient
from nexus_autofix.http import try_enable_os_trust_store, warn_if_insecure
from nexus_autofix.iq.models import Finding
from nexus_autofix.logging_setup import configure_logging
from nexus_autofix.orchestrator import Orchestrator, RunConfig, RunResult
from nexus_autofix.publish import branch as branch_mod
from nexus_autofix.publish.gate import present_pre_pr_gate
from nexus_autofix.publish.pr import open_pull_request
from nexus_autofix.repo.descriptor import read_descriptor, unexpired_suppressions
from nexus_autofix.repo.workspace import (
    clone_or_update_mirror,
    create_worktree,
    current_commit_sha,
    remove_worktree,
    resolve_branch_commit_sha,
)
from nexus_autofix.state.store import StateStore

log = logging.getLogger(__name__)

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^@]+)@(?P<version>.+)$")

_DESIGN_DOC = "docs/superpowers/specs/2026-07-28-nexus-autofix-design.md"


def _owner_repo_from_url(repo_url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a git clone URL — https or scp-style ssh."""
    owner, repo = repo_url.rstrip("/").removesuffix(".git").replace(":", "/").split("/")[-2:]
    return owner, repo


def purl_version(purl: str) -> str:
    """Return the trailing @version of a package URL, or "" if it does not parse."""
    match = _PURL_RE.match(purl)
    return match.group("version") if match else ""


def purl_to_component_identifier(purl: str) -> dict:
    """Convert a package URL into the componentIdentifier shape the IQ remediation API expects.

    FALLBACK ONLY. The policy report hands back IQ's own `componentIdentifier` for every
    component, and that is what `findings_from_policy_report` uses. This reconstruction
    is lossy: a purl percent-encodes the "@" of a scoped npm package
    (`pkg:npm/%40dfs-react-ui/core@1.4.6`), so the packageId rebuilt here is
    "%40dfs-react-ui/core" where IQ expects "@dfs-react-ui/core". Only reached when a
    violation carries no identifier of its own.
    """
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


def _finding_without_remediation(v, reason: str) -> Finding:
    """A Finding for a component we deliberately did not ask IQ to remediate.

    `target_version=None` makes it non-actionable, so the filter routes it to ignore (if it
    is below the threat threshold or waived) or to escalate (if the lookup failed), and it
    never reaches the agent.
    """
    return Finding(
        component=v.component,
        package_url=v.package_url,
        current_version=getattr(v, "current_version", "") or purl_version(v.package_url),
        target_version=None,
        remediation_type=None,
        is_direct=getattr(v, "is_direct", True),
        dependency_path=list(getattr(v, "parent_purls", []) or []),
        parent_component=None,
        parent_current_version=None,
        parent_target_version=None,
        policy_action=v.action,
        threat_level=v.threat_level,
        policy_name=v.policy_name,
        cve_ids=[],
        manifest_path=None,
        is_waived=v.is_waived,
        escalation_reason=reason,
    )


def findings_from_policy_report(
    iq_client, internal_id: str, violations, stage_id: str, min_threat_level: int = 0
) -> list[Finding]:
    """Turn IQ policy violations into Findings, fetching remediation advice for each.

    Remediation is one POST per component, so it is only spent on components that can
    actually be acted on. A large application reports violations on hundreds of components
    — mostly low-threat QUALITY ones — and asking IQ to remediate every one of them is
    hundreds of pointless round trips before the threat-level gate throws the answers away.
    The gate is therefore applied here, before the call, not after it.

    A remediation lookup that fails is not fatal to the run: the component is escalated for
    a human with IQ's own reason attached, and the remaining components still get their
    chance. One rejected component identifier must not sink the whole application.
    """
    findings = []
    skipped = 0
    looked_up = 0
    expected = sum(
        1 for v in violations if not v.is_waived and v.threat_level >= min_threat_level
    )
    for v in violations:
        if v.is_waived:
            findings.append(_finding_without_remediation(v, "waived in IQ"))
            skipped += 1
            continue
        if v.threat_level < min_threat_level:
            findings.append(
                _finding_without_remediation(
                    v, f"threat level {v.threat_level} below threshold {min_threat_level}"
                )
            )
            skipped += 1
            continue
        # Prefer IQ's own identifier over one rebuilt from the purl — see
        # purl_to_component_identifier for why the rebuild is lossy.
        identifier = getattr(v, "component_identifier", None) or purl_to_component_identifier(
            v.package_url
        )
        # Named at INFO, with the exact body, so every POST in the log can be tied to a
        # component and replayed by hand in Postman/curl without turning DEBUG on.
        looked_up += 1
        log.info(
            "remediation lookup %d/%d: %s (threat %d)  body=%s",
            looked_up, expected, v.component, v.threat_level,
            json.dumps({"componentIdentifier": identifier}, default=str),
        )
        try:
            remediation = iq_client.fetch_remediation(internal_id, identifier, stage_id)
        except Exception as exc:  # noqa: BLE001 - one bad component must not sink the run
            log.error(
                "remediation lookup failed for %s (purl %s)\n"
                "  identifier sent: %s\n"
                "  %s: %s\n"
                "  -> escalating this component for manual review and continuing",
                v.component, v.package_url,
                json.dumps(identifier, default=str),
                type(exc).__name__, exc,
            )
            findings.append(
                _finding_without_remediation(v, f"remediation lookup failed: {exc}")
            )
            continue
        version_change = remediation_mod.select_target(remediation)
        findings.append(
            Finding(
                component=v.component,
                package_url=v.package_url,
                current_version=getattr(v, "current_version", "") or purl_version(v.package_url),
                target_version=version_change.version if version_change else None,
                remediation_type=version_change.change_type if version_change else None,
                is_direct=getattr(v, "is_direct", True),
                dependency_path=list(getattr(v, "parent_purls", []) or []),
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
    log.info("remediation: %d POST(s) sent, %d skipped as below the bar or waived",
             looked_up, skipped)
    return findings


@click.group()
def main():
    """nexus-autofix — automated remediation of Nexus IQ dependency findings."""


def _require_secrets(secrets: Secrets, dry_run: bool) -> None:
    """Fail fast with an actionable message rather than a confusing HTTP error later."""
    missing = [
        name
        for name, value in (
            ("NEXUSFIX_IQ_URL", secrets.iq_url),
            ("NEXUSFIX_IQ_USERNAME", secrets.iq_username),
            ("NEXUSFIX_IQ_PASSWORD", secrets.iq_password),
        )
        if not value
    ]
    # A real (non-dry) run pushes a branch and opens a PR, so it needs a GitHub token too.
    if not dry_run and not secrets.github_token:
        missing.append("NEXUSFIX_GITHUB_TOKEN")
    if missing:
        raise click.ClickException(
            "missing required environment variables: "
            + ", ".join(missing)
            + ". Copy .env.example to .env and fill them in (see README 'Configuration')."
        )


def perform_run(
    app_id: str,
    branch: str,
    gate: str,
    dry_run: bool,
    mock_agent: bool,
    config: ProjectConfig,
    secrets: Secrets,
    verbose: bool = False,
) -> RunResult:
    """Run the full pipeline against a live Nexus IQ instance and a real repo.

    Discovery -> mirror -> worktree -> agent loop -> build/test -> push -> rescan -> PR.
    Everything here talks to the real services; the orchestrator owns the safety checks.
    """
    repo_url = config.repos[app_id]
    workspace_root = secrets.workspace_root

    # Set the run up first so every log line below — including the IQ calls — lands in
    # this run's own log file, which doubles as its audit trail.
    run_id = str(uuid.uuid4())
    run_dir = workspace_root / "runs" / run_id
    fix_branch = f"autofix/nexus/{run_id}"
    log_file = configure_logging(run_dir / "nexusfix.log", verbose=verbose)

    log.info("run %s starting: app_id=%s branch=%s gate=%s dry_run=%s mock_agent=%s",
             run_id, app_id, branch, gate, dry_run, mock_agent)
    log.info("full DEBUG log (incl. every IQ request/response body): %s", log_file)
    log.debug("TLS: OS trust store %s", try_enable_os_trust_store())
    warn_if_insecure()

    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)

    log.info("resolving Nexus IQ application %r at %s", app_id, secrets.iq_url)
    internal_id = iq_client.resolve_application_internal_id(app_id)

    mirror_path = workspace_root / "mirrors" / app_id
    log.info("mirroring %s -> %s", repo_url, mirror_path)
    clone_or_update_mirror(repo_url, mirror_path)
    commit_sha = resolve_branch_commit_sha(mirror_path, branch)
    log.info("branch %s resolves to %s", branch, commit_sha)

    log.info("starting Nexus IQ source control evaluation (stage=%s)", config.default_stage_id)
    status_url = iq_client.start_source_control_evaluation(
        internal_id, branch, config.default_stage_id
    )
    baseline_report_id = iq_client.poll_evaluation(status_url, config.poll_timeout_seconds)
    violations = iq_client.fetch_policy_report(app_id, baseline_report_id)

    # The headline is what will be worked on, not what the report contains. Everything
    # below the bar is counted in one trailing clause and otherwise stays out of the way;
    # run with -v if you ever want the full breakdown.
    candidates = [
        v for v in violations if v.threat_level >= config.min_threat_level and not v.is_waived
    ]
    log.info(
        "baseline report %s: %d component(s) to fix at threat level >= %d "
        "(%d further violating component(s) below that bar, ignored — raise or lower it "
        "with min_threat_level in config.yml)",
        baseline_report_id, len(candidates), config.min_threat_level,
        len(violations) - len(candidates),
    )
    for v in candidates:
        log.info("  to fix: %s %s threat=%d (%s)",
                 v.component, v.current_version, v.threat_level, v.policy_name)
    findings = findings_from_policy_report(
        iq_client, internal_id, violations, config.default_stage_id, config.min_threat_level
    )
    for f in findings:
        if f.threat_level < config.min_threat_level or f.is_waived:
            continue
        log.info("  finding: %s %s -> %s (%s)",
                 f.component, f.current_version, f.target_version or "no remediation",
                 f.remediation_type or "n/a")

    log.info("creating worktree on %s at %s", fix_branch, run_dir)
    worktree = create_worktree(mirror_path, run_dir, commit_sha, fix_branch)

    descriptor = read_descriptor(worktree.path / ".security-fix.yml")
    suppressed = unexpired_suppressions(descriptor, date.today())
    if suppressed:
        log.info("repo .security-fix.yml suppresses: %s", ", ".join(sorted(suppressed)))

    # MockAgent is a scripted test double: it must be told exactly which file and contents
    # to write, so it cannot generically "fix" an arbitrary repo. NO_CHANGES makes
    # --mock-agent a genuine smoke test of every real step up to and including agent
    # invocation (IQ discovery, mirror, worktree, toolchain resolution) without needing
    # the Copilot CLI installed.
    agent = MockAgent(mode=MockMode.NO_CHANGES) if mock_agent else CopilotCLIAgent()
    log.info("agent backend: %s", type(agent).__name__)

    run_config = RunConfig(
        app_id=app_id,
        branch=fix_branch,
        gate=gate,
        max_attempts=config.max_attempts,
        stage_id=config.default_stage_id,
        java_toolchains=config.java_toolchains,
        node_toolchains=config.node_toolchains,
        subprocess_timeout_seconds=config.subprocess_timeout_seconds,
        min_threat_level=config.min_threat_level,
    )

    def rescan_fn(rc: RunConfig, wt: Path) -> str:
        """Scan the pushed fix branch and return its report id for baseline comparison."""
        log.info("rescanning %s in Nexus IQ...", rc.branch)
        rescan_status_url = iq_client.start_source_control_evaluation(
            internal_id, rc.branch, config.default_stage_id
        )
        return iq_client.poll_evaluation(rescan_status_url, config.poll_timeout_seconds)

    def open_pr_fn(wt: Path, head_branch: str) -> None:
        owner, repo = _owner_repo_from_url(repo_url)
        log.info("opening PR on %s/%s: %s -> %s", owner, repo, head_branch, branch)
        pull_request = open_pull_request(
            api_url=secrets.github_api_url,
            token=secrets.github_token,
            owner=owner,
            repo=repo,
            head_branch=head_branch,
            base_branch=branch,
            title=f"fix: remediate Nexus IQ dependency findings ({app_id})",
            body=(
                f"Automated dependency remediation by nexus-autofix.\n\n"
                f"- Application: `{app_id}`\n"
                f"- Base branch: `{branch}` @ `{commit_sha}`\n"
                f"- Run id: `{run_id}`\n"
                f"- Baseline IQ report: `{baseline_report_id}`\n\n"
                f"Target versions were supplied by Nexus IQ policy analysis, not chosen by the "
                f"agent. The build and tests passed, and a follow-up IQ scan confirmed the "
                f"findings cleared with no new findings introduced."
            ),
        )
        log.info("opened PR #%s: %s", pull_request.number, pull_request.url)

    state_store = StateStore(workspace_root / "state" / "nexusfix.db")

    orchestrator_kwargs = {}
    if dry_run:
        # Exercise everything real (IQ, worktree, agent, build, test, diff classification)
        # but never mutate the remote.
        orchestrator_kwargs = {
            "commit_fn": lambda wt, message: log.info("[dry-run] would commit: %s", message),
            "push_fn": lambda wt, b: log.info("[dry-run] would push %s", b),
            "delete_remote_branch_fn": lambda wt, b: log.info("[dry-run] would delete remote %s", b),
        }

    orchestrator = Orchestrator(
        iq_client=iq_client,
        agent=agent,
        state_store=state_store,
        rescan_fn=rescan_fn,
        open_pr_fn=(
            (lambda wt, b: log.info("[dry-run] would open a PR for %s", b))
            if dry_run
            else open_pr_fn
        ),
        approve_fn=present_pre_pr_gate,
        **orchestrator_kwargs,
    )

    try:
        result = orchestrator.run(
            run_config=run_config,
            worktree=worktree.path,
            commit_sha=commit_sha,
            findings=findings,
            repo_name=app_id,
            baseline_report_id=baseline_report_id,
            suppressed_components=suppressed,
        )
        log.info("run %s finished with outcome %s", run_id, result.outcome.value)
        for note in result.notes:
            log.info("  note: %s", note)
        return result
    except Exception:
        log.exception("run %s failed with an unhandled exception", run_id)
        raise
    finally:
        if not remove_worktree(mirror_path, worktree):
            log.warning("could not clean up worktree at %s", worktree.path)
        state_store.close()
        log.info("full log for this run: %s", log_file)


def _echo_findings(label: str, findings: list[Finding]) -> None:
    if not findings:
        return
    click.echo(f"\n{label}:")
    for f in findings:
        target = f.target_version or "no remediation"
        click.echo(f"  {f.component}  {f.current_version} -> {target}")


@main.command("run")
@click.option("--app-id", default=None, help="IQ public application ID. Defaults to $NEXUSFIX_APP_ID.")
@click.option("--branch", default=None, help="Branch to scan and target the PR at. Defaults to $NEXUSFIX_BRANCH.")
@click.option("--gate", default=None, type=click.Choice(["none", "pre-pr", "pre-push"]))
@click.option("--dry-run", is_flag=True, default=False)
@click.option("--mock-agent", is_flag=True, default=False)
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Echo full IQ request/response bodies to the console (always in the log file).")
def run_command(
    app_id: str | None,
    branch: str | None,
    gate: str | None,
    dry_run: bool,
    mock_agent: bool,
    verbose: bool,
):
    """
    Discovers findings from Nexus IQ, runs the agent loop, and (unless --dry-run) opens a PR.

    Talks to the live Nexus IQ instance and repo configured in .env and config.yml.
    --dry-run performs every real step except mutating the remote; --mock-agent
    substitutes a no-op agent so the pipeline can be smoke-tested without the Copilot CLI.

    --app-id and --branch fall back to $NEXUSFIX_APP_ID / $NEXUSFIX_BRANCH when omitted,
    so the pair you work on most can live in .env. An explicit flag always wins.
    """
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    effective_gate = gate or config.default_gate

    app_id = app_id or secrets.default_app_id
    branch = branch or secrets.default_branch
    if not app_id:
        raise click.ClickException(
            "no application id: pass --app-id or set NEXUSFIX_APP_ID in .env. "
            "This is the Nexus IQ *public* application ID."
        )
    if not branch:
        raise click.ClickException("no branch: pass --branch or set NEXUSFIX_BRANCH in .env.")

    if app_id not in config.repos:
        raise click.ClickException(
            f"no repo URL configured for app_id={app_id!r} in config.yml's repos map"
        )
    _require_secrets(secrets, dry_run)

    try:
        result = perform_run(
            app_id=app_id,
            branch=branch,
            gate=effective_gate,
            dry_run=dry_run,
            mock_agent=mock_agent,
            config=config,
            secrets=secrets,
            verbose=verbose,
        )
    except Exception as exc:
        # The full traceback is already in the run's log file (perform_run logs it);
        # the console gets the actionable one-liner instead of a wall of stack frames.
        raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

    click.echo(f"\noutcome: {result.outcome.value}  (run {result.run_id})")
    _echo_findings("FIXED", result.fixed)
    _echo_findings("ESCALATED", result.escalated)
    _echo_findings("NOT ATTEMPTED", result.not_attempted)
    _echo_findings("ATTEMPTED BUT UNRESOLVED", result.attempted_but_unresolved)
    if result.notes:
        click.echo("\nNOTES:")
        for note in result.notes:
            click.echo(f"  {note}")


@main.command("gc")
@click.option("--older-than-days", default=7)
def gc_command(older_than_days: int):
    """Sweep remote autofix/nexus/* branches with no open PR older than N days, for every configured repo."""
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    for app_id, repo_url in config.repos.items():
        owner, repo = _owner_repo_from_url(repo_url)
        deleted = branch_mod.sweep_stale_branches(
            secrets.github_api_url, secrets.github_token, owner, repo, older_than_days
        )
        for name in deleted:
            click.echo(f"deleted stale branch: {app_id}/{name}")
