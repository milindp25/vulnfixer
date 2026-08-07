from pathlib import Path

from nexus_autofix.agent.prompt import RetryContext, build_prompt
from nexus_autofix.iq.models import Finding, Module, RepoProfile


def _finding(**overrides) -> Finding:
    base = dict(
        component="org.apache.commons:commons-text", package_url="pkg:maven/org.apache.commons/commons-text@1.9",
        current_version="1.9", target_version="1.10.0", remediation_type="next-non-failing-with-dependencies",
        is_direct=True, dependency_path=[], parent_component=None, parent_current_version=None,
        parent_target_version=None, threat_level=8, policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"],
    )
    base.update(overrides)
    return Finding(**base)


def _profile() -> RepoProfile:
    return RepoProfile(
        ecosystem="gradle", java_version="17.0.1", node_version=None,
        modules=[Module(path=Path("."), ecosystem="gradle", manifest=Path("build.gradle"))],
        source="trident",
    )


def test_prompt_contains_agent_instructions_and_matching_playbook_only():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="./gradlew clean build -x test", test_command="./gradlew test",
        actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "Agent Instructions" in prompt
    assert "Playbook — Spring Boot with Gradle" in prompt
    assert "Playbook — React / npm" not in prompt


def test_prompt_contains_target_version_marker():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "TARGET VERSION:   1.10.0" in prompt


def test_prompt_includes_escalated_section_when_present():
    escalated = _finding(target_version="2.0.0", escalation_reason="major bump only")
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[escalated],
    )
    assert "Not in scope for this session" in prompt
    assert "major bump only" in prompt


def test_prompt_omits_escalated_section_when_empty():
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[],
    )
    assert "Not in scope for this session" not in prompt


def test_prompt_includes_retry_section_with_verbatim_stdout():
    retry = RetryContext(
        attempt_number=2, max_attempts=2, files_changed=["build.gradle"], failed_stage="build",
        stdout_tail="FAILURE: Build failed with an exception.",
    )
    prompt = build_prompt(
        repo_name="demo", fix_branch="autofix/x", commit_sha="abc123", profile=_profile(),
        build_command="b", test_command="t", actionable_findings=[_finding()], escalated_findings=[], retry=retry,
    )
    assert "Previous attempt failed" in prompt
    assert "FAILURE: Build failed with an exception." in prompt
    assert "attempt 2 of 2" in prompt


def test_a_transitive_finding_with_no_parent_is_told_to_use_an_override():
    """The gap that let an agent add the package to devDependencies instead.

    Telling it only "do not add a direct dependency" leaves it to invent something, and
    what it invented does not pin the transitive version at all.
    """
    from nexus_autofix.agent.prompt import _findings_section

    finding = _finding(
        component="nanoid", current_version="3.3.7", target_version="3.3.8",
        is_direct=False, dependency_path=["pkg:npm/postcss@8.4.31"], parent_component=None,
    )
    text = _findings_section([finding])

    assert '"overrides"' in text and '"resolutions"' in text
    assert '"nanoid": "3.3.8"' in text
    assert "Do NOT add it to dependencies or devDependencies" in text


def test_a_parent_remediation_still_wins_over_an_override():
    from nexus_autofix.agent.prompt import _findings_section

    finding = _finding(
        component="nanoid", is_direct=False, dependency_path=["pkg:npm/postcss@8.4.31"],
        parent_component="postcss", parent_current_version="8.4.31",
        parent_target_version="8.4.32",
    )
    text = _findings_section([finding])

    assert "PREFERRED FIX" in text
    # The override block is the fallback for when there is no parent, not an alternative.
    assert "HOW TO FIX" not in text


def test_a_direct_finding_gets_no_override_advice():
    from nexus_autofix.agent.prompt import _findings_section

    text = _findings_section([_finding(is_direct=True)])
    assert "overrides" not in text
