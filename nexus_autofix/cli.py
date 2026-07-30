from __future__ import annotations

import functools
import json
import logging
import os
import re
import subprocess
import sys
import uuid
from dataclasses import asdict
from datetime import date
from pathlib import Path

import click

from nexus_autofix import agent_api
from nexus_autofix.agent.copilot_cli import CopilotCLIAgent
from nexus_autofix.agent.interactive import InteractiveAgent
from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.config import ProjectConfig, Secrets, load_project_config, load_secrets
from nexus_autofix.iq import remediation as remediation_mod
from nexus_autofix.iq.client import HTTPIQClient
from nexus_autofix.iq.filter import is_a_real_upgrade
from nexus_autofix.http import try_enable_os_trust_store, warn_if_insecure
from nexus_autofix.iq.models import Finding
from nexus_autofix.logging_setup import configure_logging
from nexus_autofix.orchestrator import Orchestrator, RunConfig, RunResult
from nexus_autofix.publish import branch as branch_mod
from nexus_autofix.publish.gate import present_pre_pr_gate
from nexus_autofix.publish.pr import open_pull_request
from nexus_autofix.repo import trident as trident_mod
from nexus_autofix.repo.descriptor import read_descriptor, unexpired_suppressions
from nexus_autofix.repo.workspace import (
    clone_or_update_mirror,
    create_worktree,
    remove_worktree,
    resolve_branch_commit_sha,
)
from nexus_autofix.state.store import StateStore
from nexus_autofix.verify import commands as commands_mod
from nexus_autofix.verify import diff as diff_mod
from nexus_autofix.verify import rescan as rescan_mod

log = logging.getLogger(__name__)

_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>[^@]+)@(?P<version>.+)$")


def _this_executable() -> str:
    """The nexusfix executable currently running, as an absolute path where possible.

    argv[0] is the console-script wrapper, which is what a caller needs to invoke: the bare
    name "nexusfix" only resolves with the virtualenv activated. Falls back to the bare
    name if argv[0] is not a real file (running via `python -m`, for instance).
    """
    candidate = Path(sys.argv[0])
    if candidate.is_file():
        return str(candidate.resolve())
    return "nexusfix"


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


def component_spec_to_identifier(spec: str) -> dict:
    """Turn a component written by hand into the identifier the remediation API wants.

    Accepts what a person or an agent naturally has in front of them when a build fails —
    a Maven GAV from a stack trace, an npm name@version, or a purl:

        io.netty:netty-codec-http:4.1.100.Final
        pkg:maven/io.netty/netty-codec-http@4.1.100.Final
        postcss@8.5.10
        pkg:npm/postcss@8.5.10

    The coordinate keys differ by format and getting them wrong is the most likely mistake:
    Maven wants groupId/artifactId/version/extension, npm wants packageId/version. IQ
    rejects the wrong set with "coordinates containing the following incorrect entries".
    """
    spec = spec.strip()
    if spec.startswith("pkg:"):
        return purl_to_component_identifier(spec)

    parts = spec.split(":")
    if len(parts) == 3:
        group_id, artifact_id, version = parts
        return {
            "format": "maven",
            "coordinates": {
                "groupId": group_id, "artifactId": artifact_id,
                "version": version, "extension": "jar",
            },
        }
    if len(parts) == 4:
        # group:artifact:version:extension, as printed by Gradle's dependency report.
        group_id, artifact_id, version, extension = parts
        return {
            "format": "maven",
            "coordinates": {
                "groupId": group_id, "artifactId": artifact_id,
                "version": version, "extension": extension,
            },
        }
    if "@" in spec:
        # npm, including scoped names where the leading @ is part of the package.
        name, _, version = spec.rpartition("@")
        if name:
            return {"format": "npm", "coordinates": {"packageId": name, "version": version}}

    raise click.ClickException(
        f"could not read {spec!r} as a component. Use one of:\n"
        "  maven   io.netty:netty-codec-http:4.1.100.Final\n"
        "  npm     postcss@8.5.10\n"
        "  purl    pkg:maven/io.netty/netty-codec-http@4.1.100.Final"
    )


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
        threat_level=v.threat_level,
        policy_name=v.policy_name,
        cve_ids=[],
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
        version_change = remediation_mod.select_target(
            remediation, v.component,
            getattr(v, "current_version", "") or purl_version(v.package_url),
        )
        if version_change is not None and not is_a_real_upgrade(
            getattr(v, "current_version", "") or purl_version(v.package_url),
            version_change.version,
        ):
            # IQ returns the current version when nothing clears the violation. Say so
            # plainly here — otherwise the finding reads as a fix that was skipped.
            log.warning(
                "  %s: IQ's best offer (%s, %s) is not an upgrade over the installed %s. "
                "This usually means the violation cannot be cleared by bumping this "
                "component — for a transitive dependency the fix belongs in a parent. "
                "Escalating for manual review.",
                v.component, version_change.version, version_change.change_type,
                getattr(v, "current_version", "") or purl_version(v.package_url),
            )
            findings.append(
                _finding_without_remediation(
                    v,
                    f"IQ offered {version_change.version}, which is not an upgrade over "
                    f"{getattr(v, 'current_version', '') or purl_version(v.package_url)}",
                )
            )
            continue
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
                        threat_level=v.threat_level,
                policy_name=v.policy_name,
                cve_ids=[],
                        is_waived=v.is_waived,
                golden_version=remediation.golden_version,
            )
        )
    log.info("remediation: %d POST(s) sent, %d skipped as below the bar or waived",
             looked_up, skipped)
    return findings


def logs_failures(command: str):
    """Write the traceback to the run log before the console gets the one-liner.

    Each command turns an unexpected exception into a short ClickException so the console
    stays readable, and `nexusfix.log` is the artefact somebody hands over when asking for
    help. Those two facts combine badly without this: the one file that gets shared would
    be the one missing the stack frames that say where it broke.

    Deliberate exits pass through untouched — a ClickException is already a written
    explanation, and SystemExit is how a checked failure (a failed rescan, say) reports
    itself after printing its own JSON.

    The frames go out at DEBUG, which is exactly the split the two sinks were built for:
    the file handler is always DEBUG so they are always kept, the console handler is INFO
    so they stay off the terminal, and `-v` puts them on both.
    """
    def decorate(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (click.ClickException, click.Abort, SystemExit):
                raise
            except Exception as exc:
                log.debug(
                    "`nexusfix %s` failed with an unhandled exception", command, exc_info=True
                )
                raise click.ClickException(f"{type(exc).__name__}: {exc}") from exc

        return wrapper

    return decorate


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
    interactive_agent: bool,
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

    log.info("run %s starting: app_id=%s branch=%s gate=%s dry_run=%s mock_agent=%s interactive_agent=%s",
             run_id, app_id, branch, gate, dry_run, mock_agent, interactive_agent)
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
    if mock_agent:
        agent = MockAgent(mode=MockMode.NO_CHANGES)
    elif interactive_agent:
        # For orgs whose Copilot policy blocks unattended tool use: prepare everything,
        # then hand the keyboard over. Verification and publishing are unchanged.
        agent = InteractiveAgent()
    else:
        agent = CopilotCLIAgent()
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
@click.option(
    "--interactive-agent", is_flag=True, default=False,
    help="Prepare the worktree and prompt, then pause so you can run the coding agent "
         "by hand. Use when your org's Copilot policy blocks unattended tool use.",
)
@click.option("-v", "--verbose", is_flag=True, default=False,
              help="Echo full IQ request/response bodies to the console (always in the log file).")
def run_command(
    app_id: str | None,
    branch: str | None,
    gate: str | None,
    dry_run: bool,
    mock_agent: bool,
    interactive_agent: bool,
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
            interactive_agent=interactive_agent,
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


# ======================================================================================
# Agent-as-orchestrator commands.
#
# The default `run` command drives the pipeline and calls an agent for one step. These
# invert that: a coding agent reads RUNBOOK.md and calls these as tools. Built for orgs
# whose Copilot policy blocks unattended tool use, leaving an interactive agent as the
# only thing that can edit files.
#
# discover -> (agent edits) -> check -> publish. The safety checks stay on this side:
# `check` classifies the diff and refuses a SUSPICIOUS one before building anything, and
# `publish` will not run without a passing verdict that `check` itself wrote.
# ======================================================================================


def perform_discovery(
    app_id: str, branch: str, config: ProjectConfig, secrets: Secrets, verbose: bool = False
) -> dict:
    """Everything `run` does up to (not including) the agent, then stop and report.

    Deliberately stops at the worktree. The agent is the caller here, so handing it the
    findings and a prepared directory is the whole job.
    """
    repo_url = config.repos[app_id]
    workspace_root = secrets.workspace_root
    run_id = str(uuid.uuid4())
    run_dir = workspace_root / "runs" / run_id
    fix_branch = f"autofix/nexus/{run_id}"
    configure_logging(run_dir / "nexusfix.log", verbose=verbose)
    log.info("discover %s: app_id=%s branch=%s", run_id, app_id, branch)
    try_enable_os_trust_store()
    warn_if_insecure()

    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)
    internal_id = iq_client.resolve_application_internal_id(app_id)
    mirror_path = workspace_root / "mirrors" / app_id
    clone_or_update_mirror(repo_url, mirror_path)
    commit_sha = resolve_branch_commit_sha(mirror_path, branch)

    status_url = iq_client.start_source_control_evaluation(
        internal_id, branch, config.default_stage_id
    )
    baseline_report_id = iq_client.poll_evaluation(status_url, config.poll_timeout_seconds)
    violations = iq_client.fetch_policy_report(app_id, baseline_report_id)
    findings = findings_from_policy_report(
        iq_client, internal_id, violations, config.default_stage_id, config.min_threat_level
    )

    worktree = create_worktree(mirror_path, run_dir, commit_sha, fix_branch)
    try:
        strategies = trident_mod.parse_trident_build_yaml(
            worktree.path / ".trident" / "build.yaml"
        )
    except (FileNotFoundError, ValueError) as exc:
        raise click.ClickException(
            f"cannot determine how to build this repo: {exc}. A usable "
            ".trident/build.yaml is required before an agent can verify its own changes."
        ) from exc
    if len(strategies) > 1:
        raise click.ClickException(
            f"repo declares multiple .trident strategies ({[s.ecosystem for s in strategies]}). "
            "Verifying one and publishing all of them is not safe, so this is refused."
        )
    strategy = strategies[0]
    java_version = strategy.toolchain.get("java")
    node_version = strategy.toolchain.get("node")

    views = agent_api.finding_views(findings, config.min_threat_level)
    state = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "worktree": str(worktree.path),
        "fix_branch": fix_branch,
        "app_id": app_id,
        "base_branch": branch,
        "repo_url": repo_url,
        "commit_sha": commit_sha,
        "internal_id": internal_id,
        "baseline_report_id": baseline_report_id,
        "ecosystem": strategy.ecosystem,
        "java_version": java_version,
        "node_version": node_version,
        "target_purls": [f.package_url for f in findings if f.is_actionable],
        "build_command": " ".join(commands_mod.BUILD_COMMANDS[strategy.ecosystem](worktree.path)),
        "test_command": " ".join(commands_mod.TEST_COMMANDS[strategy.ecosystem](worktree.path)),
        # `check` and `publish` read config.yml and .env from the CWD, so they only work
        # from here. Recorded because whoever runs them — typically an agent sitting in the
        # run directory — is not standing where `discover` was run.
        "run_commands_from": str(Path.cwd().resolve()),
        # The literal executable that is running, so the follow-up commands can be copied
        # verbatim. "nexusfix" is only on PATH with the venv activated; on Windows it is
        # .venv\Scripts\nexusfix.exe, and an agent handed the bare name has to work that
        # out for itself.
        "nexusfix_executable": _this_executable(),
        # The findings go in run.json, not just on stdout. Whoever runs `discover` is often
        # not who does the editing: you run it, then hand a run_id to an agent in an editor
        # that never saw the stdout. Without them here its only options are to re-run
        # discover — a second IQ scan and a second worktree — or to scrape nexusfix.log,
        # which is human prose with no stable format.
        "findings": [asdict(v) for v in views],
    }
    agent_api.save_run_state(run_dir, state)

    runbook = agent_api.place_runbook(run_dir)
    log.info("discover %s prepared %s with %d finding(s)", run_id, worktree.path, len(views))
    return {
        **state,
        "runbook": str(runbook) if runbook else None,
        "open_this_in_your_editor": str(run_dir),
    }


def _agent_json(payload: object) -> None:
    """The ONLY thing these commands put on stdout, so an agent can parse it."""
    click.echo(agent_api.as_json(payload))


def _echo_next_steps(payload: dict) -> None:
    """Print what to do next, for a human, on STDERR.

    Stderr rather than stdout on purpose: stdout is the machine contract for these
    commands, and an agent doing `nexusfix discover | jq` must not have prose spliced into
    the JSON. Both still appear in a terminal, which is the point — a run that ends in a
    wall of JSON and nothing else leaves the reader guessing what to do with it.
    """
    run_dir = payload.get("open_this_in_your_editor") or payload.get("run_dir") or ""
    run_id = payload.get("run_id", "")
    findings = payload.get("findings") or []
    exe = payload.get("nexusfix_executable") or "nexusfix"
    actionable = [f for f in findings if f.get("actionable")]
    blocked = [f for f in findings if not f.get("actionable")]

    lines = ["", "=" * 78, "  WHAT NEEDS FIXING", "=" * 78, ""]
    if actionable:
        for f in actionable:
            transitive = " (transitive — the fix may belong in a parent)" if not f.get("is_direct") else ""
            lines.append(
                f"  {f['component']}  {f['current_version']} -> {f['target_version']}"
                f"  [threat {f['threat_level']}]{transitive}"
            )
    else:
        lines.append("  Nothing can be fixed automatically.")
    for f in blocked:
        lines.append(
            f"  {f['component']}  {f['current_version']} -> NOT FIXABLE"
            f"  ({f.get('reason_not_actionable') or 'no newer version from IQ'})"
        )

    if not actionable:
        # Sending someone to an editor to change nothing wastes their time; the reasons
        # above are the whole result of the run.
        lines += [
            "",
            "  No upgrade is available for any of these, so there is nothing to hand to an",
            "  agent. The reasons are listed above and in the log:",
            "",
            f"    {run_dir}\\nexusfix.log" if "\\" in str(run_dir) else f"    {run_dir}/nexusfix.log",
            "",
            "=" * 78,
            "",
        ]
        click.echo("\n".join(lines), err=True)
        return

    lines += [
        "",
        "=" * 78,
        "  NEXT STEPS",
        "=" * 78,
        "",
        "  1. Open the run directory in your editor (NOT this repo):",
        "",
        f"       code {run_dir}",
        "",
        "     It holds RUNBOOK.md, run.json, nexusfix.log, and wt/ — the checkout to edit.",
        "",
        "  2. In Copilot Chat (agent mode), or any coding agent, say:",
        "",
        "       Read RUNBOOK.md and follow it.",
        f"       The run_id is {run_id}",
        "",
        "  3. Or do the rest yourself — edit wt/ by hand, then run these",
        f"     FROM {payload.get('run_commands_from', 'the directory holding config.yml')}",
        "     (they read config.yml and .env from the current directory, so they will not",
        "      work from the run directory or from wt/):",
        "",
        f"       {exe} check --run-id {run_id}",
        f"       {exe} publish --run-id {run_id}",
        "",
        "  Edit files in wt/ but leave them uncommitted — `nexusfix publish` commits, after",
        "  the build, the tests and the diff check have passed. Committing early is not fatal",
        "  (it is verified from the run's base commit either way), it just skips nothing.",
        "",
        "=" * 78,
        "",
    ]
    click.echo("\n".join(lines), err=True)


@main.command("discover")
@click.option("--app-id", default=None, help="IQ public application ID. Defaults to $NEXUSFIX_APP_ID.")
@click.option("--branch", default=None, help="Branch to scan. Defaults to $NEXUSFIX_BRANCH.")
@click.option("-v", "--verbose", is_flag=True, default=False)
@logs_failures("discover")
def discover_command(app_id: str | None, branch: str | None, verbose: bool):
    """Find what needs fixing and prepare a worktree, without touching the agent.

    Prints the findings and the worktree path as JSON. Nothing is committed or pushed.
    """
    config = load_project_config(Path("config.yml"))
    secrets = load_secrets()
    app_id = app_id or secrets.default_app_id
    branch = branch or secrets.default_branch
    if not app_id or not branch:
        raise click.ClickException(
            "need --app-id and --branch (or NEXUSFIX_APP_ID / NEXUSFIX_BRANCH in .env)"
        )
    if app_id not in config.repos:
        raise click.ClickException(f"no repo URL configured for app_id={app_id!r} in config.yml")
    _require_secrets(secrets, dry_run=True)

    payload = perform_discovery(app_id, branch, config, secrets, verbose)
    _agent_json(payload)
    _echo_next_steps(payload)



def _config_for_run(state: dict) -> ProjectConfig:
    """Load config.yml, or explain where the command has to be run from.

    Relative path, so this depends on the CWD. Without the check the failure is a bare
    "no such file" from somewhere inside yaml parsing, which does not tell the reader that
    they are simply standing in the wrong directory.
    """
    expected = state.get("run_commands_from")
    if not Path("config.yml").is_file():
        raise click.ClickException(
            "config.yml is not in the current directory, and it is read from there.\n"
            + (f"  Run this from: {expected}" if expected else
               "  Run this from the directory holding config.yml and .env.")
        )
    return load_project_config(Path("config.yml"))


@main.command("check")
@click.option("--run-id", required=True, help="The run_id printed by `nexusfix discover`.")
@click.option("-v", "--verbose", is_flag=True, default=False)
@logs_failures("check")
def check_command(run_id: str, verbose: bool):
    """Classify the diff, then build and test the worktree. Records the verdict."""
    secrets = load_secrets()
    try:
        state = agent_api.load_run_state(secrets.workspace_root, run_id)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    config = _config_for_run(state)

    run_dir = Path(state["run_dir"])
    configure_logging(run_dir / "nexusfix.log", verbose=verbose)
    result = agent_api.check_worktree(
        worktree=Path(state["worktree"]),
        ecosystem=state["ecosystem"],
        java_version=state.get("java_version"),
        node_version=state.get("node_version"),
        java_toolchains=config.java_toolchains,
        node_toolchains=config.node_toolchains,
        timeout_seconds=config.subprocess_timeout_seconds,
        env=dict(os.environ),
        base_ref=state["commit_sha"],
    )
    agent_api.write_verdict(run_dir, result)
    _agent_json(asdict(result))


@main.command("publish")
@click.option("--run-id", required=True, help="The run_id printed by `nexusfix discover`.")
@click.option("--dry-run", is_flag=True, default=False, help="Do everything except mutate the remote.")
@click.option(
    "--open-pr", is_flag=True, default=False,
    help="Also open the pull request via the GitHub API. Off by default — the branch is "
         "pushed and verified either way, and the compare URL is printed so you can open "
         "the PR yourself.",
)
@click.option("-v", "--verbose", is_flag=True, default=False)
@logs_failures("publish")
def publish_command(run_id: str, dry_run: bool, open_pr: bool, verbose: bool):
    """Commit, push, rescan in IQ to confirm the fix, and open a PR.

    Refuses without a passing verdict from `check`. That gate is the point: the agent
    calling this is the same one that made the changes, so its own assurance that they
    are good is worth nothing. The verdict is written by `check` itself, from a real
    build and a real diff classification.
    """
    secrets = load_secrets()
    try:
        state = agent_api.load_run_state(secrets.workspace_root, run_id)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    config = _config_for_run(state)

    run_dir = Path(state["run_dir"])
    configure_logging(run_dir / "nexusfix.log", verbose=verbose)

    verdict = agent_api.read_verdict(run_dir)
    if verdict is None:
        raise click.ClickException(
            "no verdict recorded for this run — run `nexusfix check --run-id "
            f"{run_id}` first. Publishing without a verified build is not allowed."
        )
    if not verdict.get("ok"):
        raise click.ClickException(
            f"the last check did not pass: {verdict.get('message')}. Fix the changes and "
            "run check again. Publishing is blocked until it passes."
        )

    worktree = Path(state["worktree"])
    # Re-read the diff now, rather than trusting the verdict's copy: the worktree may have
    # been edited between check and publish, in which case what would be pushed is not
    # what was verified.
    current = diff_mod.classify_diff(worktree, state["commit_sha"])
    if sorted(current.changed_files) != sorted(verdict.get("changed_files", [])):
        raise click.ClickException(
            "the worktree changed since `check` ran — what would be published is not what "
            f"was verified. Run `nexusfix check --run-id {run_id}` again.\n"
            f"  verified: {sorted(verdict.get('changed_files', []))}\n"
            f"  now:      {sorted(current.changed_files)}"
        )
    if current.classification == diff_mod.DiffClass.SUSPICIOUS:
        raise click.ClickException(
            f"refusing to publish a suspicious diff: {'; '.join(current.suspicious_reasons)}"
        )

    _require_secrets(secrets, dry_run)
    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)
    fix_branch = state["fix_branch"]

    if dry_run:
        _agent_json({"ok": True, "dry_run": True, "would_push": fix_branch,
                     "changed_files": current.changed_files})
        return

    log.info("committing and pushing %s", fix_branch)
    subprocess.run(["git", "add", "-A"], cwd=str(worktree), check=True, capture_output=True)
    # `git commit` exits non-zero when there is nothing staged, which is exactly what
    # happens if the agent committed already despite the runbook. That is not an error —
    # the changes are present either way, and they were verified against the run's base
    # commit rather than HEAD, so the verdict still covers them.
    committed = subprocess.run(
        ["git", "commit", "-m", "fix: remediate dependency vulnerabilities via nexus-autofix"],
        cwd=str(worktree), capture_output=True, encoding="utf-8",
    )
    if committed.returncode != 0:
        if "nothing to commit" in (committed.stdout or "") + (committed.stderr or ""):
            log.info("already committed by the agent — pushing what is on the branch")
        else:
            raise click.ClickException(f"git commit failed: {committed.stderr or committed.stdout}")
    branch_mod.push_branch(worktree, "origin", fix_branch)

    log.info("rescanning %s to confirm the findings actually cleared", fix_branch)
    rescan_status_url = iq_client.start_source_control_evaluation(
        state["internal_id"], fix_branch, config.default_stage_id
    )
    rescan_report_id = iq_client.poll_evaluation(rescan_status_url, config.poll_timeout_seconds)
    comparison = rescan_mod.compare_reports(
        iq_client.fetch_policy_report(state["app_id"], state["baseline_report_id"]),
        iq_client.fetch_policy_report(state["app_id"], rescan_report_id),
        set(state.get("target_purls") or []),
    )

    if not comparison.all_cleared or comparison.new_findings:
        # The push is undone: an unverified branch left on the remote invites someone to
        # merge a fix that did not fix anything.
        branch_mod.delete_remote_branch(worktree, "origin", fix_branch)
        _agent_json({
            "ok": False,
            "message": "the rescan shows the findings did not clear; the pushed branch was deleted",
            "still_failing": list(comparison.still_failing),
            "new_findings": list(comparison.new_findings),
        })
        raise SystemExit(1)

    owner, repo = _owner_repo_from_url(state["repo_url"])
    compare_url = (
        f"https://github.com/{owner}/{repo}/compare/"
        f"{state['base_branch']}...{fix_branch}?expand=1"
    )

    if not open_pr:
        # Opening the PR is the one step that needs NEXUSFIX_GITHUB_TOKEN; pushing uses
        # git's own credentials. Keeping it opt-in means a token problem cannot fail a run
        # whose real work — the verified fix on a pushed branch — is already complete.
        log.info("branch pushed and verified; not opening a PR (pass --open-pr to)")
        _agent_json({
            "ok": True,
            "branch": fix_branch,
            "base_branch": state["base_branch"],
            "pull_request": None,
            "open_a_pr_here": compare_url,
            "message": (
                "Committed, pushed, and Nexus IQ confirmed the findings cleared. No PR was "
                "opened — open it from the URL above, or re-run with --open-pr."
            ),
        })
        return

    try:
        pull_request = open_pull_request(
            api_url=secrets.github_api_url, token=secrets.github_token, owner=owner, repo=repo,
            head_branch=fix_branch, base_branch=state["base_branch"],
            title=f"fix: remediate Nexus IQ dependency findings ({state['app_id']})",
        body=(
            f"Automated dependency remediation by nexus-autofix (agent-orchestrated).\n\n"
            f"- Application: `{state['app_id']}`\n"
            f"- Base branch: `{state['base_branch']}` @ `{state['commit_sha']}`\n"
            f"- Run id: `{run_id}`\n\n"
                f"Target versions came from Nexus IQ policy analysis, not from the agent. The "
                f"diff was classified as `{current.classification.value}`, the build and tests "
                f"passed, and a follow-up IQ scan confirmed the findings cleared."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - the work is done; only the PR call failed
        # The branch is pushed AND the rescan confirmed the fix, so the valuable part of the
        # run succeeded. Deleting the branch here would throw that away over a credential
        # problem, and raising without the compare URL leaves the reader with a verified
        # branch and no idea what to do with it. Opening the PR by hand finishes the job.
        log.error("the fix is pushed and verified, but opening the PR failed: %s", exc)
        _agent_json({
            "ok": False,
            "stage": "open_pull_request",
            "message": (
                "The branch is pushed and Nexus IQ confirmed the findings cleared — only the "
                "PR call failed, so nothing needs redoing. Open the PR from the URL below."
            ),
            "branch": fix_branch,
            "base_branch": state["base_branch"],
            "open_a_pr_here": compare_url,
            "error": f"{type(exc).__name__}: {exc}",
            "hint": (
                "HTTP 401 means NEXUSFIX_GITHUB_TOKEN was rejected — missing, malformed or "
                "expired. (403 would be a missing 'repo' scope; 404 usually means the token "
                "needs SSO authorisation for the org.) Pushing used your git credentials, "
                "which is why that half worked."
            ),
        })
        raise SystemExit(1) from exc

    _agent_json({"ok": True, "pull_request_url": pull_request.url,
                 "pull_request_number": pull_request.number, "branch": fix_branch})


@main.command("remediate")
@click.argument("component")
@click.option("--run-id", default=None, help="Use the application from an existing run.")
@click.option("--app-id", default=None, help="IQ public application ID. Defaults to $NEXUSFIX_APP_ID.")
@click.option("-v", "--verbose", is_flag=True, default=False)
@logs_failures("remediate")
def remediate_command(component: str, run_id: str | None, app_id: str | None, verbose: bool):
    """Ask Nexus IQ what version of COMPONENT clears the policy.

    For components that never reached the policy report — a transitive dependency the scan
    could not resolve because the artifact is quarantined, for instance. The build names it
    in its 403 and this turns that name into IQ's own recommended version, so nobody has to
    guess which version is safe.

    COMPONENT can be a Maven GAV, an npm name@version, or a purl:

        nexusfix remediate io.netty:netty-codec-http:4.1.100.Final
        nexusfix remediate postcss@8.5.10
        nexusfix remediate pkg:npm/%40scope/pkg@1.2.3
    """
    secrets = load_secrets()
    identifier = component_spec_to_identifier(component)
    current_version = (identifier.get("coordinates") or {}).get("version", "")

    if run_id:
        state = agent_api.load_run_state(secrets.workspace_root, run_id)
        config = _config_for_run(state)
        internal_id = state["internal_id"]
        configure_logging(Path(state["run_dir"]) / "nexusfix.log", verbose=verbose)
    else:
        config = load_project_config(Path("config.yml"))
        app_id = app_id or secrets.default_app_id
        if not app_id:
            raise click.ClickException(
                "need --run-id, or --app-id (or NEXUSFIX_APP_ID in .env) — remediation is "
                "evaluated against a specific application's policy set."
            )
        configure_logging(secrets.workspace_root / "runs" / "adhoc" / "nexusfix.log", verbose=verbose)
        internal_id = HTTPIQClient(
            secrets.iq_url, secrets.iq_username, secrets.iq_password
        ).resolve_application_internal_id(app_id)

    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)
    remediation = iq_client.fetch_remediation(internal_id, identifier, config.default_stage_id)

    chosen = remediation_mod.select_target(remediation, component, current_version)
    _agent_json({
        "component": component,
        "component_identifier": identifier,
        "current_version": current_version,
        "target_version": chosen.version if chosen else None,
        "remediation_type": chosen.change_type if chosen else None,
        # Everything IQ offered, so a caller can see what was rejected and why the chosen
        # one won, rather than having to trust the selection.
        "all_offers": [
            {"type": vc.change_type, "version": vc.version} for vc in remediation.version_changes
        ],
        "message": (
            f"Upgrade to {chosen.version}." if chosen else
            "Nexus IQ offered no version newer than this one. It cannot be fixed by bumping "
            "this component — bump whichever parent pulls it in, or escalate."
        ),
    })
