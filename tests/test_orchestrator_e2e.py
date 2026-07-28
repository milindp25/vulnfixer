"""End-to-end orchestrator runs against a REAL Gradle project.

Nothing here is mocked except the two genuinely external services: Nexus IQ
(`FakeIQClient`) and the coding agent (`MockAgent`). Every `git` invocation and
every `./gradlew` invocation is a real subprocess against a real working tree,
which is the whole point — these are the only tests that prove the orchestrator's
verify-then-publish sequencing survives contact with a real build.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from xml.etree import ElementTree

import pytest

from nexus_autofix.agent.mock import MockAgent, MockMode
from nexus_autofix.iq.client import (
    FakeIQClient,
    PolicyViolation,
    RemediationResponse,
    VersionChange,
)
from nexus_autofix.iq.models import Finding, RunOutcome
from nexus_autofix.orchestrator import Orchestrator, RunConfig
from nexus_autofix.state.store import StateStore

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "demo_gradle_repo"

COMPONENT = "org.apache.commons:commons-text"
PACKAGE_URL = "pkg:maven/org.apache.commons/commons-text@1.9"
TEST_FILE = "src/test/java/demo/GreeterTest.java"


def _git(args, cwd) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8"
    )
    return proc.stdout


def _real_java_home(major: str = "21") -> str | None:
    """Locate a REAL JDK of the given major version, or None.

    `toolchain.resolve_java_env` verifies the configured path exists and has
    `bin/java`, so a placeholder like /opt/jdk17 would escalate the run before the
    agent is ever invoked. This has to be an actual install on this machine.
    """
    mac_helper = Path("/usr/libexec/java_home")
    if mac_helper.exists():
        proc = subprocess.run(
            [str(mac_helper), "-v", major], capture_output=True, encoding="utf-8"
        )
        if proc.returncode == 0:
            home = Path(proc.stdout.strip())
            if (home / "bin" / "java").exists():
                return str(home)
    java_on_path = shutil.which("java")
    if java_on_path:
        home = Path(java_on_path).resolve().parent.parent
        if (home / "bin" / "java").exists():
            return str(home)
    return None


@pytest.fixture
def repo(tmp_path):
    """A real, committed git repo containing a real, buildable Gradle project."""
    repo_path = tmp_path / "demo_gradle_repo"
    shutil.copytree(
        FIXTURE_SRC, repo_path, ignore=shutil.ignore_patterns(".gradle", "build")
    )
    _git(["init"], repo_path)
    _git(["config", "user.email", "t@example.com"], repo_path)
    _git(["config", "user.name", "t"], repo_path)
    _git(["add", "-A"], repo_path)
    _git(["commit", "-m", "init"], repo_path)
    return repo_path


def _finding() -> Finding:
    # Real Maven version string for this artifact (two-component, no patch) —
    # classify_bump now treats the missing patch as 0, so this reaches actionable.
    return Finding(
        component=COMPONENT,
        package_url=PACKAGE_URL,
        current_version="1.9",
        target_version="1.10.0",
        remediation_type="next-non-failing-with-dependencies",
        is_direct=True,
        dependency_path=[],
        parent_component=None,
        parent_current_version=None,
        parent_target_version=None,
        policy_action="Fail",
        threat_level=8,
        policy_name="Security-Critical",
        cve_ids=["CVE-2022-42889"],
        manifest_path=Path("build.gradle"),
    )


def _fake_iq() -> FakeIQClient:
    return FakeIQClient(
        policy_violations=[
            PolicyViolation(
                package_url=PACKAGE_URL,
                component=COMPONENT,
                policy_name="Security-Critical",
                policy_id="pol-1",
                threat_level=8,
                constraint_summary="CVE-2022-42889",
                is_waived=False,
                action="Fail",
            )
        ],
        remediations={
            "commons-text": RemediationResponse(
                version_changes=[
                    VersionChange(
                        change_type="next-non-failing-with-dependencies",
                        version="1.10.0",
                    )
                ]
            )
        },
    )


def _run_config(java_home: str, **overrides) -> RunConfig:
    base = dict(
        app_id="demo",
        branch="autofix/nexus/e2e",
        gate="none",
        max_attempts=2,
        stage_id="build",
        java_toolchains={"21": java_home},  # matches .trident/build.yaml's java-version
        node_toolchains={},
        subprocess_timeout_seconds=600,
    )
    base.update(overrides)
    return RunConfig(**base)


@pytest.fixture
def java_home():
    home = _real_java_home("21")
    if home is None:
        pytest.skip("no real JDK 21 installation found on this machine")
    return home


@pytest.mark.slow
def test_fixed_path_runs_real_gradle_build_and_test(repo, tmp_path, java_home):
    """The happy path, all the way through a real `./gradlew clean build` + `test`.

    If this reports FIXED, a real Gradle build of commons-text 1.10.0 really did
    succeed and the real JUnit test really did pass — the orchestrator returns
    FAILED_BUILD on any non-zero exit from either command.
    """
    original = (repo / "build.gradle").read_text(encoding="utf-8")
    assert "commons-text:1.9" in original
    fixed_gradle = original.replace("commons-text:1.9", "commons-text:1.10.0")

    agent = MockAgent(
        mode=MockMode.APPLIES_FIX, fix_file="build.gradle", fix_content=fixed_gradle
    )
    iq = _fake_iq()
    store = StateStore(tmp_path / "state" / "state.db")

    def rescan_fn(run_config, worktree):
        # The rescan is of the FIXED tree, so IQ no longer reports the violation.
        # The orchestrator fetches the baseline report before calling this, so
        # mutating the fake here is what makes baseline != rescan.
        iq.policy_violations = []
        return "rescan-report"

    opened_prs = []
    pushed = []

    orchestrator = Orchestrator(
        iq_client=iq,
        agent=agent,
        state_store=store,
        rescan_fn=rescan_fn,
        open_pr_fn=lambda worktree, branch: opened_prs.append(branch),
        approve_fn=lambda summary: True,
        # No real remote exists, so push/delete are stubbed. Commit is NOT stubbed:
        # the real `git add -A && git commit` runs, and is asserted on below.
        push_fn=lambda worktree, branch: pushed.append(branch),
        delete_remote_branch_fn=lambda worktree, branch: None,
    )

    head_sha = _git(["rev-parse", "HEAD"], repo).strip()
    result = orchestrator.run(
        run_config=_run_config(java_home),
        worktree=repo,
        commit_sha=head_sha,
        findings=[_finding()],
        repo_name="demo_gradle_repo",
        baseline_report_id="baseline-report",
    )

    assert result.outcome == RunOutcome.FIXED, result.notes
    assert [f.component for f in result.fixed] == [COMPONENT]
    assert result.attempted_but_unresolved == []

    # The bump was really committed by the real git commit_fn, not just left dirty.
    committed = _git(["show", "HEAD:build.gradle"], repo)
    assert "commons-text:1.10.0" in committed
    assert "commons-text:1.9'" not in committed
    assert _git(["rev-parse", "HEAD"], repo).strip() != head_sha

    # And a real Gradle build actually ran in this worktree: real bytecode was
    # produced against commons-text 1.10.0, and the real JUnit test really executed
    # and really passed (a green run with zero tests would be worthless here).
    assert (repo / "build" / "classes" / "java" / "main" / "demo" / "Greeter.class").exists()
    results = repo / "build" / "test-results" / "test" / "TEST-demo.GreeterTest.xml"
    suite = ElementTree.parse(results).getroot()
    assert int(suite.attrib["tests"]) == 1
    assert int(suite.attrib["failures"]) == 0
    assert int(suite.attrib["errors"]) == 0
    assert int(suite.attrib["skipped"]) == 0

    assert pushed == ["autofix/nexus/e2e"]
    assert opened_prs == ["autofix/nexus/e2e"]


@pytest.mark.slow
def test_deletes_test_mode_aborts_as_escalated_and_never_pushes(repo, tmp_path, java_home):
    """The reason `MockAgent` exists: an agent that deletes a test must never publish.

    The SUSPICIOUS diff classification has to fire *before* build/test/commit/push,
    so nothing about this run reaches a remote — even though the build would have
    gone green with the test file gone.
    """
    agent = MockAgent(mode=MockMode.DELETES_TEST, test_file_to_delete=TEST_FILE)
    store = StateStore(tmp_path / "state" / "state.db")

    pushed: list[str] = []

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("publish-path function called on a SUSPICIOUS diff")

    orchestrator = Orchestrator(
        iq_client=_fake_iq(),
        agent=agent,
        state_store=store,
        # Everything past the diff gate is wired to blow up. The orchestrator's
        # catch-all would turn any such call into FAILED_BUILD, so the ESCALATED
        # assertion below is itself proof none of them ran.
        rescan_fn=_must_not_be_called,
        open_pr_fn=_must_not_be_called,
        approve_fn=_must_not_be_called,
        commit_fn=_must_not_be_called,
        push_fn=lambda worktree, branch: pushed.append(branch),
        delete_remote_branch_fn=_must_not_be_called,
    )

    head_sha = _git(["rev-parse", "HEAD"], repo).strip()
    result = orchestrator.run(
        run_config=_run_config(java_home),
        worktree=repo,
        commit_sha=head_sha,
        findings=[_finding()],
        repo_name="demo_gradle_repo",
        baseline_report_id="baseline-report",
    )

    assert result.outcome == RunOutcome.ESCALATED, result.notes
    assert pushed == []
    assert result.fixed == []
    assert [f.component for f in result.attempted_but_unresolved] == [COMPONENT]
    assert any(TEST_FILE in note for note in result.notes), result.notes

    # The mock really deleted a real file on disk...
    assert not (repo / TEST_FILE).exists()
    # ...and nothing was committed, so HEAD is untouched and still has the test.
    assert _git(["rev-parse", "HEAD"], repo).strip() == head_sha
    assert "GreeterTest" in _git(["show", f"HEAD:{TEST_FILE}"], repo)

    # No build ever ran: the abort happened before the first ./gradlew invocation.
    assert not (repo / "build").exists()
