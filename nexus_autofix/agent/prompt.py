from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nexus_autofix.iq.models import Finding, RepoProfile

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
AGENT_INSTRUCTIONS_PATH = PACKAGE_ROOT / "agent_instructions.md"
PLAYBOOKS_DIR = PACKAGE_ROOT / "playbooks"

PLAYBOOK_BY_ECOSYSTEM = {
    "gradle": "spring-boot-gradle.md",
    "maven": "spring-boot-maven.md",
    "npm": "npm.md",
    "yarn": "npm.md",
    "pnpm": "npm.md",
}


@dataclass(frozen=True)
class RetryContext:
    attempt_number: int
    max_attempts: int
    files_changed: list[str]
    failed_stage: str  # "build" | "test"
    stdout_tail: str
    diagnostic_tail: str | None = None


def build_prompt(
    repo_name: str,
    fix_branch: str,
    commit_sha: str,
    profile: RepoProfile,
    build_command: str,
    test_command: str,
    actionable_findings: list[Finding],
    escalated_findings: list[Finding],
    retry: RetryContext | None = None,
) -> str:
    sections = [
        AGENT_INSTRUCTIONS_PATH.read_text(encoding="utf-8"),
        "---",
        (PLAYBOOKS_DIR / PLAYBOOK_BY_ECOSYSTEM[profile.ecosystem]).read_text(encoding="utf-8"),
        "---",
        _repository_section(repo_name, fix_branch, commit_sha, profile, build_command, test_command),
        "---",
        _findings_section(actionable_findings),
    ]
    if escalated_findings:
        sections += ["---", _escalated_section(escalated_findings)]
    if retry:
        sections += ["---", _retry_section(retry)]
    sections += [
        "---",
        "Begin. Follow the order of operations in the instructions above, and\n"
        "finish with the summary in the required format.",
    ]
    return "\n\n".join(sections)


def _repository_section(repo_name, fix_branch, commit_sha, profile, build_command, test_command) -> str:
    lines = [
        "# Repository", "",
        f"Repository:      {repo_name}",
        f"Branch:          {fix_branch}",
        f"Base commit:     {commit_sha}",
        f"Ecosystem:       {profile.ecosystem}          (from .trident/build.yaml)",
        f"Java version:    {profile.java_version or 'n/a'}       (declared — already on PATH)",
        f"Node version:    {profile.node_version or 'n/a'}       (declared — already on PATH)",
        "",
        f"Build command:   {build_command}",
        f"Test command:    {test_command}",
        "",
        "Modules:",
    ]
    for module in profile.modules:
        lines.append(f"  {module.path}   manifest: {module.manifest}")
        if module.version_catalog:
            lines.append(f"  version catalog: {module.version_catalog}")
    return "\n".join(lines)


def _findings_section(findings: list[Finding]) -> str:
    lines = ["# Findings to remediate"]
    for index, finding in enumerate(findings, start=1):
        lines += [
            "", f"## {index}. {finding.component}", "",
            f"  Current version:  {finding.current_version}",
            f"  TARGET VERSION:   {finding.target_version}        <- use this exact version",
            f"  Guarantee:        {finding.remediation_type}",
            f"  Threat level:     {finding.threat_level}",
            f"  Policy:           {finding.policy_name}",
            f"  CVEs:             {', '.join(finding.cve_ids)}",
            f"  Type:             {'direct dependency' if finding.is_direct else 'transitive dependency'}",
            f"  Scope:            {'dev only' if finding.is_dev_dependency else 'runtime'}",
        ]
        if not finding.is_direct:
            lines += ["", "  Dependency path:", f"    {' > '.join(finding.dependency_path)}"]
        if finding.parent_component:
            lines += [
                "", "  PREFERRED FIX — parent remediation from Nexus IQ:",
                f"    Bump {finding.parent_component} from {finding.parent_current_version} to {finding.parent_target_version}",
                "    This is the correct fix. Use it rather than an override.",
            ]
        elif not finding.is_direct:
            # No parent to bump, so the only correct edit is an override. Spelled out
            # because an agent told merely "do not add a direct dependency" will invent
            # something — adding the package to devDependencies, in the case that prompted
            # this. That does not pin the transitive version at all.
            lines += [
                "", "  HOW TO FIX — this package is NOT in the manifest:",
                f'    npm:        "overrides":    {{ "{finding.component}": "{finding.target_version}" }}',
                f'    yarn/pnpm:  "resolutions":  {{ "{finding.component}": "{finding.target_version}" }}',
                "    Then regenerate the lockfile.",
                "    Do NOT add it to dependencies or devDependencies — that makes it a",
                "    direct dependency of the application instead of constraining what the",
                "    rest of the tree resolves to, and can leave the vulnerable copy in place.",
                "    On Gradle/Maven there is no safe equivalent: report it and stop.",
            ]
        if finding.golden_version and finding.golden_version != finding.target_version:
            lines += [
                "", f"  Note: a non-breaking recommended version {finding.golden_version} is also",
                "  available. The target above is the smaller change. If the target",
                "  causes problems, report it rather than switching versions yourself.",
            ]
    return "\n".join(lines)


def _escalated_section(findings: list[Finding]) -> str:
    lines = [
        "# Not in scope for this session", "",
        "These findings were excluded because they require a major version",
        "change or have no available remediation. Do not attempt them.", "",
    ]
    for finding in findings:
        lines.append(f"  {finding.component} {finding.current_version}  —  {finding.escalation_reason}")
    return "\n".join(lines)


def _retry_section(retry: RetryContext) -> str:
    lines = [
        "# Previous attempt failed", "",
        f"This is attempt {retry.attempt_number} of {retry.max_attempts}.", "",
        "Your previous changes were:",
        *[f"  {f}" for f in retry.files_changed], "",
        f"The {retry.failed_stage} command failed. Output:", "",
        "```", retry.stdout_tail, "```",
    ]
    if retry.diagnostic_tail:
        lines += ["", "Dependency resolution at the time of failure:", "", "```", retry.diagnostic_tail, "```"]
    lines += [
        "", "Read the actual error before changing anything. Fix only what your",
        "change broke. If the failure is unrelated to your change — a missing",
        "toolchain, a network failure, a test that was already failing —",
        "escalate rather than attempting to fix it.",
    ]
    return "\n".join(lines)
