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
from nexus_autofix.appsec import match as appsec_match
from nexus_autofix.appsec import resolve as appsec_resolve
from nexus_autofix.appsec import sheet as appsec_sheet
from nexus_autofix.agent.interactive import InteractiveAgent
from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.config import ProjectConfig, Secrets, load_project_config, load_secrets
from nexus_autofix.iq import cli_scan as cli_scan_mod
from nexus_autofix.iq import remediation as remediation_mod
from nexus_autofix.iq.client import HTTPIQClient
from nexus_autofix.iq.filter import BumpSize, classify_bump, filter_findings, is_a_real_upgrade
from nexus_autofix.http import (
    CABundleError,
    ensure_ca_bundle,
    try_enable_os_trust_store,
    warn_if_insecure,
)
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
from nexus_autofix.verify import toolchain as toolchain_mod

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
    waived_out: list = []
    below_bar: list = []
    looked_up = 0
    expected = sum(
        1 for v in violations if not v.is_waived and v.threat_level >= min_threat_level
    )
    for v in violations:
        if v.is_waived:
            findings.append(_finding_without_remediation(v, "waived in IQ"))
            waived_out.append(v)
            continue
        if v.threat_level < min_threat_level:
            findings.append(
                _finding_without_remediation(
                    v, f"threat level {v.threat_level} below threshold {min_threat_level}"
                )
            )
            below_bar.append(v)
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
             looked_up, len(waived_out) + len(below_bar))
    _log_skipped(waived_out, below_bar, min_threat_level)
    return findings


def _log_skipped(waived_out: list, below_bar: list, min_threat_level: int) -> None:
    """Name every component the run decided not to fix, and why.

    A count alone ("6 skipped") is unauditable: it cannot distinguish a correctly-tuned
    threshold from one set high enough to skip something that mattered, and it hides a
    waiver that has quietly stopped being appropriate. Both lists are printed in full —
    truncating to a top-N would read as complete coverage while omitting the very entry
    somebody went looking for. Highest threat first, since the entries just under the
    threshold are the ones worth arguing about.
    """
    if waived_out:
        log.info("  skipped — waived in IQ (%d):", len(waived_out))
        for v in sorted(waived_out, key=lambda v: -v.threat_level):
            log.info(
                "    %-40s threat %-3s %s  [%s]",
                f"{v.component} {v.current_version}".strip(), v.threat_level,
                v.policy_name or "(no policy name)",
                # IQ omits the waiver's free-text comment from the policy report, so the
                # kind of waiver is as much as this can honestly say. The comment is in
                # the IQ UI against the component.
                getattr(v, "waiver_reason", "") or "waiver kind not stated by IQ",
            )
    if below_bar:
        log.info(
            "  skipped — below min_threat_level=%d (%d):", min_threat_level, len(below_bar)
        )
        for v in sorted(below_bar, key=lambda v: -v.threat_level):
            log.info(
                "    %-40s threat %-3s %s",
                f"{v.component} {v.current_version}".strip(), v.threat_level,
                v.policy_name or "(no policy name)",
            )
        highest = max(v.threat_level for v in below_bar)
        if highest == min_threat_level - 1:
            log.info(
                "    (the highest skipped is threat %d, one below the threshold — lower "
                "min_threat_level in config.yml to %d to include it)", highest, highest,
            )


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


def _setup_tls(secrets: Secrets) -> None:
    """Everything TLS, before the first HTTPS call.

    Called by every command that talks to Nexus IQ rather than just the two that used to
    do the trust-store dance. `ensure_ca_bundle` exports NEXUSFIX_CA_BUNDLE into the
    process, and each command is its own process — so leaving it out of `publish` would
    mean `discover` succeeding and `publish` failing on certificates, which reads like a
    bug in publish rather than a missing setup step.
    """
    log.debug("TLS: OS trust store %s", try_enable_os_trust_store())
    try:
        ensure_ca_bundle(secrets.workspace_root / "tools")
    except CABundleError as exc:
        raise click.ClickException(str(exc)) from exc
    warn_if_insecure()


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
    _setup_tls(secrets)

    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)

    # The config.yml key and the Nexus IQ application ID are allowed to differ; only IQ
    # calls use the latter. See ProjectConfig.iq_app_id_for.
    iq_app_id = config.iq_app_id_for(app_id)
    log.info("resolving Nexus IQ application %r at %s", iq_app_id, secrets.iq_url)
    internal_id = iq_client.resolve_application_internal_id(iq_app_id)

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
    violations = iq_client.fetch_policy_report(iq_app_id, baseline_report_id)

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
    worktree = create_worktree(mirror_path, run_dir, commit_sha, fix_branch, repo_url)

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
        iq_app_id=iq_app_id,
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
    # This talks to the GitHub API, so it needs the CA bundle like everything else. Without
    # it, a machine configured only with NEXUSFIX_CA_BUNDLE_URL fails here on certificates
    # while every other command works.
    _setup_tls(secrets)
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


def _scan_for_report(
    *, iq_client, config: ProjectConfig, secrets: Secrets, app_id: str, internal_id: str,
    branch: str, worktree_path: Path, run_dir: Path, ecosystem: str,
    java_version: str | None, node_version: str | None, label: str,
) -> str:
    """Scan the application and return the policy report id.

    Two scanners, and which one runs is decided solely by `iq_cli_jar` in config.yml.

    The SCM scan reads what is committed. For npm that is enough — the lockfile enumerates
    the entire pinned tree — but a `pom.xml` or `build.gradle` declares direct dependencies
    only, and the transitive closure is not in the repository at all. The CLI scans the
    built application and fingerprints what actually landed on the classpath, so it sees
    the whole tree; the cost is that the build must succeed first.

    `label` distinguishes the baseline from the post-fix rescan in the log. Both go through
    here so they cannot disagree about method — see `_require_matching_scan_method`.
    """
    if not config.uses_iq_cli:
        # Names the setting and its resolved value, not just the outcome. Asking for the
        # CLI and getting the API is the confusing failure here, and "scan_method=''"
        # says the setting never arrived, which is a different problem from it arriving
        # and being overruled.
        log.info(
            "%s scan: SOURCE CONTROL evaluation of %s  [scan_method=%r iq_cli_jar=%r "
            "iq_cli_download_url=%r]", label, branch, config.scan_method,
            config.iq_cli_jar, config.iq_cli_download_url,
        )
        log.info(
            "  reading the committed manifest, so for Maven/Gradle only DIRECT "
            "dependencies are visible. Set NEXUSFIX_IQ_CLI_URL (or NEXUSFIX_SCAN_METHOD="
            "iq-cli) to scan built artifacts instead."
        )
        status_url = iq_client.start_source_control_evaluation(
            internal_id, branch, config.default_stage_id
        )
        return iq_client.poll_evaluation(status_url, config.poll_timeout_seconds)

    if ecosystem in cli_scan_mod.BUILD_BEFORE_SCAN:
        env = dict(os.environ)
        for version, table, resolve in (
            (java_version, config.java_toolchains, toolchain_mod.resolve_java_env),
            (node_version, config.node_toolchains, toolchain_mod.resolve_node_env),
        ):
            if version:
                try:
                    env = resolve(version, table, env).env
                except toolchain_mod.MissingToolchainError as exc:
                    raise click.ClickException(f"toolchain unavailable: {exc}") from exc

        build_cmd = commands_mod.BUILD_COMMANDS[ecosystem](worktree_path)
        log.info(
            "%s scan: building first — a %s project has no components until a build "
            "produces them", label, ecosystem,
        )
        build = commands_mod.run_command(
            build_cmd, worktree_path, env, config.subprocess_timeout_seconds
        )
        if not build.success:
            # Not survivable, and saying so plainly beats scanning an empty directory and
            # reporting an application with no components as one with no problems.
            raise click.ClickException(
                f"the build failed, so there are no artifacts to scan: {' '.join(build_cmd)}\n"
                f"{build.tail()}\n"
                "Fix the build, or set NEXUSFIX_SCAN_METHOD=source-control to fall back to "
                "the source-control scan."
            )
    else:
        log.info(
            "%s scan: no build needed — a %s project's lockfile already pins the whole "
            "resolved tree, which is what the CLI reads", label, ecosystem,
        )

    prescan = config.prescan_command_for(app_id)
    if prescan:
        # For a repo whose scan target is a build artifact rather than a committed file —
        # an extracted `npm pack` tarball, say. Configured per repo because it describes
        # that repository's pipeline, and there is no way to infer it.
        log.info("%s scan: running prescan command: %s", label, " ".join(prescan))
        result = commands_mod.run_command(
            prescan, worktree_path, dict(os.environ), config.subprocess_timeout_seconds
        )
        if not result.success:
            raise click.ClickException(
                f"the prescan command failed: {' '.join(prescan)}\n{result.tail()}\n"
                f"It is configured as `prescan_command` under repos.{app_id} in config.yml."
            )

    configured = config.scan_targets_for(app_id)
    if configured:
        scan_targets = [worktree_path / t for t in configured]
        source = f"configured for {app_id}"
    else:
        scan_targets = cli_scan_mod.default_scan_targets(ecosystem, worktree_path)
        source = f"{ecosystem} default"
    log.info(
        "%s scan targets (%s): %s", label, source,
        ", ".join(str(t.relative_to(worktree_path)) for t in scan_targets) or "(none)",
    )
    missing = [t for t in scan_targets if not t.exists()]
    if missing and configured:
        # Names the setting AND where it came from. The live confusion was a Node repo
        # hunting for `build/` because of a global override, where the error described
        # only the symptom and left the cause to be guessed at.
        raise click.ClickException(
            "the configured scan target(s) do not exist in this repository: "
            + ", ".join(str(m.relative_to(worktree_path)) for m in missing) + "\n"
            f"  These came from an explicit setting, not from the {ecosystem} default. If "
            f"they describe a different repository — a `build` directory on a Node app, "
            f"say — clear NEXUSFIX_IQ_CLI_SCAN_TARGET and the global iq_cli_scan_target, "
            f"and set `scan_target` under repos.{app_id} in config.yml instead.\n"
            f"  Cleared entirely, the {ecosystem} default would scan: "
            + ", ".join(
                str(t.relative_to(worktree_path))
                for t in cli_scan_mod.default_scan_targets(ecosystem, worktree_path)
            )
        )
    # Default location, so setting only NEXUSFIX_IQ_CLI_URL is enough to get going: there
    # is then no path to keep in step across machines, and the jar is fetched once.
    jar_path = (
        Path(config.iq_cli_jar) if config.iq_cli_jar
        else secrets.workspace_root / "tools" / "nexus-iq-cli.jar"
    )
    jar_path = cli_scan_mod.ensure_jar(
        jar_path, config.iq_cli_download_url, config.iq_cli_sha256
    )
    result = cli_scan_mod.run_cli_scan(
        jar_path=jar_path,
        scan_targets=scan_targets,
        # The IQ identifier, not the config key — this is the -i argument the CLI sends to
        # Nexus IQ. Everything above (scan targets, stage, prescan) is keyed by the config
        # entry instead. Defaults to the same string, so a config where they match is
        # unaffected.
        app_id=config.iq_app_id_for(app_id),
        iq_url=secrets.iq_url,
        username=secrets.iq_username,
        password=secrets.iq_password,
        stage_id=config.stage_id_for(app_id),
        result_file=run_dir / f"{label}-{cli_scan_mod.RESULT_FILENAME}",
        timeout_seconds=config.subprocess_timeout_seconds,
        java_executable=config.java_executable,
    )
    return result.report_id


def _require_matching_scan_method(state: dict, config: ProjectConfig) -> None:
    """Refuse to compare a rescan against a baseline the other scanner produced.

    This is the one way this feature could ship a false success. `compare_reports` decides
    "cleared" by absence: a component in the baseline and not in the rescan is treated as
    fixed. A deep CLI baseline holds the whole transitive closure; a source-control rescan
    of a Gradle repo holds direct dependencies only. Compare the two and every transitive
    finding *vanishes*, `all_cleared` comes back true, and `publish` certifies a fix that
    was never verified and keeps the branch.

    A green result that means nothing is worse than a red one, so this stops the run.
    """
    baseline_method = state.get("scan_method")
    current_method = "iq-cli" if config.uses_iq_cli else "source-control"
    if baseline_method and baseline_method != current_method:
        raise click.ClickException(
            f"this run's baseline was scanned with {baseline_method!r} but config.yml now "
            f"selects {current_method!r}. The two see different sets of components, so a "
            "comparison between them would report findings as cleared that were only ever "
            "invisible to the second scan.\n"
            "  Restore iq_cli_jar in config.yml to what it was for this run, or start a "
            "new run with `nexusfix discover`."
        )


def _escalation_reason(finding: Finding) -> str:
    """Why this finding must not be attempted unattended, in words for a human.

    `filter_findings` returns escalated findings without saying which rule caught them, and
    "actionable: false" with no reason is exactly the message that gets ignored.
    """
    if not finding.is_actionable:
        return finding.escalation_reason or "Nexus IQ offered no version that clears this"
    if not is_a_real_upgrade(finding.current_version, finding.target_version or ""):
        return (
            f"Nexus IQ offered {finding.target_version}, which is not newer than the "
            f"installed {finding.current_version}. For a transitive dependency this usually "
            "means the fix belongs in whichever parent pulls it in."
        )
    bump = classify_bump(finding.current_version, finding.target_version or "")
    if bump is BumpSize.MAJOR:
        return (
            f"{finding.current_version} -> {finding.target_version} crosses a major version. "
            "A major bump can change the API and break whatever else depends on this "
            "package, which a passing build does not rule out. A human decides this one."
        )
    if bump is BumpSize.UNKNOWN:
        return (
            f"cannot tell how large the {finding.current_version} -> {finding.target_version} "
            "change is — neither version parses as a version number."
        )
    return finding.escalation_reason or "escalated by policy"


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
    _setup_tls(secrets)

    # `app_id` here is the config.yml key. Nexus IQ may know this application by a
    # different name, so everything IQ-facing goes through iq_app_id and everything else
    # (mirrors, per-repo settings, run state) stays keyed by what you typed.
    iq_app_id = config.iq_app_id_for(app_id)
    if iq_app_id != app_id:
        log.info("config key %r maps to Nexus IQ application %r", app_id, iq_app_id)

    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)
    internal_id = iq_client.resolve_application_internal_id(iq_app_id)
    mirror_path = workspace_root / "mirrors" / app_id
    clone_or_update_mirror(repo_url, mirror_path)
    commit_sha = resolve_branch_commit_sha(mirror_path, branch)

    # The checkout is made BEFORE the scan, not after. A CLI scan reads build output, so
    # the application has to exist and be built first. The SCM scan does not care about
    # the order, so doing it this way unconditionally keeps one code path rather than two.
    worktree = create_worktree(mirror_path, run_dir, commit_sha, fix_branch, repo_url)
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

    baseline_report_id = _scan_for_report(
        iq_client=iq_client, config=config, secrets=secrets, app_id=app_id,
        internal_id=internal_id, branch=branch, worktree_path=worktree.path,
        run_dir=run_dir, ecosystem=strategy.ecosystem, java_version=java_version,
        node_version=node_version, label="baseline",
    )
    violations = iq_client.fetch_policy_report(iq_app_id, baseline_report_id)
    findings = findings_from_policy_report(
        iq_client, internal_id, violations, config.default_stage_id, config.min_threat_level
    )

    # The SAME gate the `run` path applies, and previously the only place it was applied.
    # Without it `actionable` meant nothing more than "Nexus IQ named some version", which
    # is true of a 3.x -> 5.x jump — and the RUNBOOK tells the agent to use target_version
    # exactly. So major bumps, targets that are not upgrades, and suppressed components were
    # all being handed over as work to do.
    descriptor = read_descriptor(worktree.path / ".security-fix.yml")
    suppressed = unexpired_suppressions(descriptor, date.today())
    filtered = filter_findings(findings, suppressed, config.min_threat_level)
    log.info(
        "filter: %d actionable, %d escalated, %d ignored (threat level >= %d)",
        len(filtered.actionable), len(filtered.escalate), len(filtered.ignore),
        config.min_threat_level,
    )
    escalation_reasons = {f.package_url: _escalation_reason(f) for f in filtered.escalate}
    for finding in filtered.escalate:
        log.info("  escalated: %s %s -> %s — %s", finding.component, finding.current_version,
                 finding.target_version or "no target", escalation_reasons[finding.package_url])

    # `ignore` is dropped entirely: below the threat bar, waived, or suppressed. Escalated
    # findings stay visible, because a human is meant to see those.
    visible = [*filtered.actionable, *filtered.escalate]
    views = agent_api.finding_views(visible, config.min_threat_level, escalation_reasons)
    state = {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "worktree": str(worktree.path),
        "fix_branch": fix_branch,
        "app_id": app_id,
        # Both are recorded because `check` and `publish` need different ones: `check`
        # looks up this repo's per-repo settings by the config key, while `publish` fetches
        # reports from IQ by the IQ identifier. Storing one and deriving the other later
        # would need config.yml to be unchanged since the run started.
        "iq_app_id": iq_app_id,
        "base_branch": branch,
        "repo_url": repo_url,
        "commit_sha": commit_sha,
        "internal_id": internal_id,
        "baseline_report_id": baseline_report_id,
        # Which scanner produced the baseline. `publish` refuses to compare a rescan
        # from the other one — see _require_matching_scan_method.
        "scan_method": "iq-cli" if config.uses_iq_cli else "source-control",
        "ecosystem": strategy.ecosystem,
        "java_version": java_version,
        "node_version": node_version,
        # Only what this run actually set out to fix. An escalated finding left in here
        # makes publish's rescan see it still failing and delete the branch — throwing away
        # every good fix over one nobody attempted.
        "target_purls": [f.package_url for f in filtered.actionable],
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
        raise click.ClickException(
            f"{app_id!r} is not in config.yml's `repos:` map. That key is the name you "
            f"choose for the application, not necessarily what Nexus IQ calls it — set "
            f"`iq_app_id` under it if the two differ.\n"
            f"  Configured: {', '.join(sorted(config.repos)) or '(none)'}"
        )
    _require_secrets(secrets, dry_run=True)

    payload = perform_discovery(app_id, branch, config, secrets, verbose)
    _agent_json(payload)
    _echo_next_steps(payload)


# --- AppSec findings ------------------------------------------------------------------
# Findings from the AppSec SCA worksheet: libraries that are quarantined or about to be
# flagged, which Nexus IQ has NOT raised as policy violations yet. IQ's /policy endpoint
# returns only components carrying a violation, so `discover` cannot see these at all — and
# one that IS flagged below min_threat_level is filtered out before it reaches the agent.

#: LIBRARY_TYPE, by the ecosystem the repo declares in `.trident/build.yaml`.
#:
#: The repo's own declaration is the authority on what it is — the same rule the rest of
#: this tool follows, and the reason `discover` refuses to run without a usable trident
#: file rather than guessing from the files it finds. This map exists only to drop rows
#: for a DIFFERENT ecosystem: one export covers many repos, and a JavaScript row read with
#: jar-filename rules yields a plausible-looking artifact that does not exist.
#:
#: Covers every value in trident's KNOWN_ECOSYSTEMS. An unknown one runs unfiltered rather
#: than silently matching nothing, because a filter that excludes everything is
#: indistinguishable from a sheet with nothing in it.
APPSEC_LIBRARY_TYPES = {
    "gradle": "Java",
    "maven": "Java",
    "npm": "JavaScript",
    "yarn": "JavaScript",
    "pnpm": "JavaScript",
}


def perform_appsec_discovery(
    app_id: str, branch: str, sheet_path: Path, config: ProjectConfig, secrets: Secrets,
    verbose: bool = False,
) -> dict:
    """A normal discovery, plus this repo's rows from the AppSec worksheet.

    Folded into ONE run rather than a second one: both sets of changes touch the same
    manifest, so separate runs would mean two worktrees editing the same lines, two builds,
    and two PRs that conflict with each other.
    """
    payload = perform_discovery(app_id, branch, config, secrets, verbose)
    run_dir = Path(payload["run_dir"])
    ecosystem = payload["ecosystem"]
    owner, repo = _owner_repo_from_url(payload["repo_url"])

    library_type = APPSEC_LIBRARY_TYPES.get(ecosystem, "")
    if not library_type:
        log.warning(
            "no LIBRARY_TYPE is known for a %s repo, so AppSec rows are read unfiltered. "
            "Filename parsing assumes a jar-style name; anything else is reported as "
            "unreadable rather than guessed at.", ecosystem,
        )

    rows, stats = appsec_sheet.read_rows(
        sheet_path, columns=config.appsec_columns, library_type=library_type
    )
    libraries = appsec_sheet.dedupe(rows)
    mine = appsec_sheet.for_repo(libraries, owner, repo)
    log.info(
        "AppSec sheet: %d row(s) -> %d librar(ies), %d for %s/%s",
        len(rows), len(libraries), len(mine), owner, repo,
    )

    # Re-fetched rather than threaded out of perform_discovery: it is the same report id, so
    # the two cannot disagree, and `publish` already reads the baseline back the same way.
    iq_client = HTTPIQClient(secrets.iq_url, secrets.iq_username, secrets.iq_password)
    violations = iq_client.fetch_policy_report(
        payload.get("iq_app_id") or app_id, payload["baseline_report_id"]
    )
    stage_id = config.stage_id_for(app_id)

    resolved: list[tuple] = []
    for library in mine:
        violation = appsec_match.match_to_violation(library, violations)
        # IQ's report states the installed groupId, which the sheet never does. That is the
        # only thing able to settle a library whose candidates span several groups.
        known_group = ((violation.component_identifier or {}).get("coordinates") or {}).get(
            "groupId"
        ) if violation is not None else None
        if known_group:
            library = appsec_sheet.narrow_to_group(library, str(known_group))

        current_version = appsec_match.current_version_for(library, violation)
        identifier = appsec_match.identifier_for(library, violation)

        iq_version = None
        if identifier:
            remediation = iq_client.fetch_remediation(payload["internal_id"], identifier, stage_id)
            chosen = remediation_mod.select_target(remediation, library.artifact_id, current_version)
            iq_version = chosen.version if chosen else None
        else:
            # No group id anywhere: LIBRARY_FILENAME never carries one, and the only other
            # place it appears is a same-artifact candidate in the topfix column. Without
            # it there is no valid identifier, so IQ cannot be asked at all.
            log.info(
                "  %s: no group id available, so Nexus IQ cannot be asked about it",
                library.artifact_id,
            )

        target = appsec_resolve.decide(library, current_version, iq_version)
        component = (
            violation.component if violation is not None
            else (f"{library.group_id}:{library.artifact_id}" if library.group_id
                  else library.artifact_id)
        )
        resolved.append((target, component, appsec_match.package_url_for(library, violation)))
        log.info(
            "  %s %s: %s -> %s (%s)", component, current_version, target.decision.value,
            target.target_version or "-", target.reason,
        )

    appsec_views = agent_api.appsec_finding_views(resolved)
    iq_views = [agent_api.FindingView(**view) for view in payload.get("findings") or []]
    merged = agent_api.merge_views(iq_views, appsec_views)

    conflicts = [v for v in merged if v.appsec_decision == appsec_resolve.Decision.CONFLICT.value]
    state = {
        **{k: v for k, v in payload.items() if k not in ("runbook", "open_this_in_your_editor")},
        "findings": [asdict(v) for v in merged],
        # Every actionable purl, so `publish`'s rescan covers the AppSec bumps too. Where a
        # library was never a baseline violation this adds nothing false — compare_reports
        # intersects against the rescan — and where it WAS one below the threat threshold,
        # publish now correctly requires it to clear.
        "target_purls": sorted({v.package_url for v in merged if v.actionable and v.package_url}),
        "appsec": {
            "sheet": str(sheet_path),
            # The input is a file that gets re-exported; a run should be able to say which
            # version of it produced these findings.
            "sheet_sha256": _sha256_of(sheet_path),
            "rows_total": stats.rows_total,
            "rows_kept": stats.rows_kept,
            "libraries_total": len(libraries),
            "libraries_for_this_repo": len(mine),
            "skipped_missing_repo": stats.skipped_missing_repo,
            "skipped_missing_filename": stats.skipped_missing_filename,
            "skipped_wrong_type": stats.skipped_wrong_type,
            "skipped_unparsable_filename": stats.skipped_unparsable_filename,
            "unresolved_conflicts": [v.component for v in conflicts],
            "artifact_swaps": [
                {"component": v.component, "proposed": v.swap_candidates}
                for v in merged if v.appsec_decision == appsec_resolve.Decision.SWAP_ONLY.value
            ],
            # Same artifact name under several group ids, with nothing stating which is
            # installed. Reported rather than guessed at — see sheet.narrow_to_group.
            "ambiguous_groups": [
                {"component": v.component, "reason": v.reason_not_actionable}
                for v in merged
                if v.appsec_decision == appsec_resolve.Decision.AMBIGUOUS_GROUP.value
            ],
            # Tokens the topfix column contained that are not coordinates. Surfaced so a
            # candidate lost to a parsing gap is visible instead of silently absent.
            "discarded_topfix_tokens": sorted(
                {token for library in mine for token in library.topfix_discarded}
            ),
        },
    }
    agent_api.save_run_state(run_dir, state)
    return {
        **state,
        "runbook": payload.get("runbook"),
        "open_this_in_your_editor": payload.get("open_this_in_your_editor"),
    }


def _sha256_of(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _appsec_sheet_path(sheet: str | None, config: ProjectConfig) -> Path:
    # Tested BEFORE constructing a Path: Path("") is Path("."), whose str() is "." — which
    # is truthy, so an emptiness check on the Path never fires and the caller gets
    # "no AppSec worksheet at ." instead of being told how to supply one.
    configured = (sheet or config.appsec_sheet or "").strip()
    if not configured:
        raise click.ClickException(
            "need --sheet (or `appsec.sheet` in config.yml, or NEXUSFIX_APPSEC_SHEET in "
            ".env) — the AppSec worksheet is the only source of these findings."
        )
    path = Path(configured)
    if not path.is_file():
        raise click.ClickException(
            f"no AppSec worksheet at {path}. Download the export from Tableau and pass its "
            "path; a SharePoint or Tableau URL cannot be read here."
        )
    return path


@main.command("appsec-discover")
@click.option("--sheet", default=None, help="Path to the AppSec SCA worksheet (.xlsx).")
@click.option("--app-id", default=None, help="IQ public application ID. Defaults to $NEXUSFIX_APP_ID.")
@click.option("--branch", default=None, help="Branch to scan. Defaults to $NEXUSFIX_BRANCH.")
@click.option("-v", "--verbose", is_flag=True, default=False)
@logs_failures("appsec-discover")
def appsec_discover_command(sheet: str | None, app_id: str | None, branch: str | None, verbose: bool):
    """Discover Nexus IQ findings AND AppSec worksheet findings in one run.

    Everything `discover` does, plus the libraries the AppSec SCA export names for this
    repo — quarantined or soon-to-be-flagged components that IQ has not raised as policy
    violations, and which no IQ scan can therefore surface.

    Where Nexus IQ and the sheet recommend different versions the run does NOT choose. The
    finding is recorded as a CONFLICT with both candidates, `check` refuses until it is
    settled, and `nexusfix resolve` is how a human settles it.
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
        raise click.ClickException(
            f"{app_id!r} is not in config.yml's `repos:` map. That key is the name you "
            f"choose for the application, not necessarily what Nexus IQ calls it — set "
            f"`iq_app_id` under it if the two differ.\n"
            f"  Configured: {', '.join(sorted(config.repos)) or '(none)'}"
        )
    sheet_path = _appsec_sheet_path(sheet, config)
    _require_secrets(secrets, dry_run=True)

    payload = perform_appsec_discovery(app_id, branch, sheet_path, config, secrets, verbose)
    _agent_json(payload)
    _echo_next_steps(payload)
    _echo_appsec_summary(payload)


def _echo_appsec_summary(payload: dict) -> None:
    """What needs a human, on stderr — stdout stays the machine contract."""
    appsec = payload.get("appsec") or {}
    conflicts = appsec.get("unresolved_conflicts") or []
    swaps = appsec.get("artifact_swaps") or []
    if not conflicts and not swaps:
        return

    lines = [""]
    if conflicts:
        lines.append(f"  {len(conflicts)} AppSec finding(s) need a decision before `check` will run:")
        for view in payload.get("findings") or []:
            if view.get("component") in conflicts:
                candidates = " or ".join(view.get("candidate_versions") or [])
                lines.append(
                    f"    {view['component']} {view.get('current_version')} -> {candidates}"
                )
                lines.append(
                    f"      nexusfix resolve --run-id {payload['run_id']} "
                    f"--component {view['component']} --version <one of the above>"
                )
    if swaps:
        lines.append(
            f"  {len(swaps)} AppSec finding(s) propose a DIFFERENT artifact (a migration, "
            "not a bump). These are reported only and will not be fixed:"
        )
        for swap in swaps:
            lines.append(f"    {swap['component']} -> {', '.join(swap['proposed'])}")
    lines.append("")
    click.echo("\n".join(lines), err=True)


@main.command("approve")
@click.option("--run-id", required=True, help="The run_id printed by `discover`.")
@click.option("--component", required=True, help="The component to release, as it appears in run.json.")
@click.option(
    "--version", "version", required=True,
    help="The target version, typed out. Must match what Nexus IQ recommended.",
)
@logs_failures("approve")
def approve_command(run_id: str, component: str, version: str):
    """Allow a finding this tool held back — usually a major version jump.

    A major bump is escalated by default because it can change an API and break whatever
    depends on the package, which a passing build does not rule out. That default is
    deliberate: an unanswered finding is never attempted.

    This is how you say yes to one anyway. The agent is expected to investigate first and
    tell you what it found — whether the repo uses the affected API, what the changelog
    says, what else depends on it. It cannot run this for you; the decision is what makes
    the change permissible, and an agent approving its own work would mean nothing.

    `--version` must match what Nexus IQ recommended. It is a confirmation, not a choice:
    typing it out is what makes approving the wrong component hard.
    """
    secrets = load_secrets()
    try:
        state = agent_api.load_run_state(secrets.workspace_root, run_id)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    configure_logging(Path(state["run_dir"]) / "nexusfix.log")

    findings = state.get("findings") or []
    matches = [f for f in findings if f.get("component") == component]
    if not matches:
        matches = [f for f in findings if f.get("component", "").split(":")[-1] == component]
    if not matches:
        waiting = [f["component"] for f in findings if f.get("needs_approval")]
        raise click.ClickException(
            f"no finding named {component!r} in this run.\n"
            + (f"  Awaiting approval: {', '.join(waiting)}" if waiting
               else "  Nothing in this run is awaiting approval.")
        )
    if len(matches) > 1:
        raise click.ClickException(
            f"{component!r} matches {len(matches)} findings. Use the full group:artifact name."
        )

    finding = matches[0]
    if not finding.get("needs_approval"):
        raise click.ClickException(
            f"{finding['component']} is not awaiting approval — it is "
            + ("already being fixed." if finding.get("actionable") else
               f"not fixable at all: {finding.get('reason_not_actionable')}")
        )
    if version.strip() != (finding.get("target_version") or ""):
        raise click.ClickException(
            f"{version.strip()!r} is not what Nexus IQ recommended for "
            f"{finding['component']} — that is {finding.get('target_version')!r}.\n"
            "  --version confirms which change you are approving; it does not choose one. "
            "To use a different version, fix it by hand."
        )

    finding.update(actionable=True, needs_approval=False, reason_not_actionable=None,
                   approved_by_human=True)
    if finding.get("package_url"):
        state["target_purls"] = sorted({*(state.get("target_purls") or []), finding["package_url"]})
    agent_api.save_run_state(Path(state["run_dir"]), state)

    log.info("approved %s -> %s", finding["component"], finding["target_version"])
    _agent_json({
        "ok": True,
        "component": finding["component"],
        "current_version": finding.get("current_version"),
        "target_version": finding["target_version"],
        "still_awaiting_approval": [f["component"] for f in findings if f.get("needs_approval")],
        "message": (
            f"{finding['component']} will now be upgraded to {finding['target_version']}. "
            "Re-run check after the change is made."
        ),
    })


@main.command("resolve")
@click.option("--run-id", required=True, help="The run_id printed by `appsec-discover`.")
@click.option("--component", required=True, help="The component to settle, as it appears in run.json.")
@click.option("--version", "version", required=True, help="One of the two candidate versions.")
@logs_failures("resolve")
def resolve_command(run_id: str, component: str, version: str):
    """Record which version to use where Nexus IQ and the AppSec sheet disagree.

    Accepts ONLY one of the two versions already proposed. A third version is refused: the
    point of routing the decision through this command rather than letting an agent edit
    run.json is that "the agent explains, the human decides" is enforced rather than asked
    for. If both candidates are wrong, fix the sheet or escalate.
    """
    secrets = load_secrets()
    try:
        state = agent_api.load_run_state(secrets.workspace_root, run_id)
    except FileNotFoundError as exc:
        raise click.ClickException(str(exc)) from exc
    configure_logging(Path(state["run_dir"]) / "nexusfix.log")

    findings = state.get("findings") or []
    matches = [f for f in findings if f.get("component") == component]
    if not matches:
        # Matching the artifact half too, because that is what a person reads off the
        # sheet — "bcprov-jdk15on" rather than "org.bouncycastle:bcprov-jdk15on".
        matches = [f for f in findings if f.get("component", "").split(":")[-1] == component]
    if not matches:
        awaiting = [
            f["component"] for f in findings
            if f.get("appsec_decision") == appsec_resolve.Decision.CONFLICT.value
        ]
        raise click.ClickException(
            f"no finding named {component!r} in this run.\n"
            + (f"  Awaiting a decision: {', '.join(awaiting)}" if awaiting
               else "  Nothing in this run is awaiting a decision.")
        )
    if len(matches) > 1:
        raise click.ClickException(
            f"{component!r} matches {len(matches)} findings "
            f"({', '.join(m['component'] for m in matches)}). Use the full group:artifact name."
        )

    try:
        updated = appsec_resolve.choose_for_view(matches[0], version)
    except appsec_resolve.ResolutionError as exc:
        raise click.ClickException(str(exc)) from exc

    state["findings"] = [updated if f is matches[0] else f for f in findings]
    if updated.get("package_url"):
        state["target_purls"] = sorted({*(state.get("target_purls") or []), updated["package_url"]})
    still_open = [
        f["component"] for f in state["findings"]
        if f.get("appsec_decision") == appsec_resolve.Decision.CONFLICT.value
    ]
    state.setdefault("appsec", {})["unresolved_conflicts"] = still_open
    agent_api.save_run_state(Path(state["run_dir"]), state)

    log.info("resolved %s to %s", updated["component"], updated["target_version"])
    _agent_json({
        "ok": True,
        "component": updated["component"],
        "current_version": updated.get("current_version"),
        "target_version": updated["target_version"],
        "still_unresolved": still_open,
        "message": (
            f"{updated['component']} will be upgraded to {updated['target_version']}."
            + ("" if still_open else " Nothing else is awaiting a decision; `check` can run.")
        ),
    })


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


def _require_appsec_conflicts_resolved(state: dict, run_id: str) -> None:
    """Refuse to check while a version decision is still outstanding.

    The gate lives here rather than in `check_worktree` because it is a property of the
    RUN, not of the worktree — `check_worktree` is given a directory and knows nothing
    about where its instructions came from.

    Without this the agent is free to pick either candidate, or neither, and a passing
    build would look like the disagreement had been settled. It has not: a build proves the
    code compiles, not that the right version was chosen.
    """
    unresolved = [
        finding for finding in state.get("findings") or []
        if finding.get("appsec_decision") == appsec_resolve.Decision.CONFLICT.value
    ]
    if not unresolved:
        return

    lines = [
        (
            f"{len(unresolved)} AppSec finding(s) are still awaiting a decision — Nexus IQ "
            "and the AppSec sheet recommend different versions, and nothing may be verified "
            "until you say which to use:"
        ),
    ]
    for finding in unresolved:
        candidates = finding.get("candidate_versions") or []
        lines.append(
            f"  {finding['component']} {finding.get('current_version')} -> "
            f"{' or '.join(candidates)}   (Nexus IQ: {finding.get('iq_version')}, "
            f"AppSec sheet: {finding.get('sheet_version')})"
        )
        lines.append(
            f"    nexusfix resolve --run-id {run_id} --component {finding['component']} "
            f"--version {candidates[0] if candidates else '<version>'}"
        )
    raise click.ClickException("\n".join(lines))


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
    _require_appsec_conflicts_resolved(state, run_id)
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
        # .get: a run.json written before this existed has no app_id, and an older run
        # should still be checkable rather than crashing on a missing key.
        run_contract_tests=config.run_contract_tests_for(state.get("app_id", "")),
        contract_test_command=config.contract_test_command_for(state.get("app_id", "")),
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
    _setup_tls(secrets)
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
    _require_matching_scan_method(state, config)
    if config.uses_iq_cli:
        # Scans the local checkout, which `check` already built and which `publish` has
        # just confirmed is byte-for-byte what was verified. The pushed branch and this
        # directory hold the same tree.
        rescan_report_id = _scan_for_report(
            iq_client=iq_client, config=config, secrets=secrets, app_id=state["app_id"],
            internal_id=state["internal_id"], branch=fix_branch, worktree_path=worktree,
            run_dir=run_dir, ecosystem=state["ecosystem"],
            java_version=state.get("java_version"), node_version=state.get("node_version"),
            label="rescan",
        )
    else:
        rescan_status_url = iq_client.start_source_control_evaluation(
            state["internal_id"], fix_branch, config.default_stage_id
        )
        rescan_report_id = iq_client.poll_evaluation(
            rescan_status_url, config.poll_timeout_seconds
        )
    # .get with a fallback: a run.json written before `iq_app_id` existed has only app_id,
    # and back then the two were the same string by construction.
    iq_app_id = state.get("iq_app_id") or state["app_id"]
    comparison = rescan_mod.compare_reports(
        iq_client.fetch_policy_report(iq_app_id, state["baseline_report_id"]),
        iq_client.fetch_policy_report(iq_app_id, rescan_report_id),
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
    _setup_tls(secrets)

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
        ).resolve_application_internal_id(config.iq_app_id_for(app_id))

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
