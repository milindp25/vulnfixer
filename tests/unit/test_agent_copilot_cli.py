import logging
import subprocess
from unittest.mock import patch

import pytest

from nexus_autofix.agent.copilot_cli import (
    AgentFailedError,
    AgentUnavailableError,
    CopilotCLIAgent,
)

_real_subprocess_run = subprocess.run  # captured before any patching, so the git-status
# call below can fall through to the real command and reflect real ground truth.


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _repo(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)
    return tmp_path


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def _agent_run(tmp_path, proc, on_invoke=None, prompt="fix things"):
    """Run the agent with its CLI faked, letting the internal git status call hit real git."""
    def fake_run(command, *args, **kwargs):
        if command[:2] == ["git", "status"]:
            return _real_subprocess_run(command, *args, **kwargs)
        if on_invoke is not None:
            on_invoke()
        return proc

    agent = CopilotCLIAgent(command=["copilot", "--allow-all-tools"])
    # The binary does not exist in CI; the PATH probe is a separate behaviour, tested below.
    with patch("nexus_autofix.agent.copilot_cli.shutil.which", return_value="/usr/bin/copilot"):
        with patch("subprocess.run", side_effect=fake_run):
            return agent.run(prompt=prompt, worktree=tmp_path)


def test_copilot_cli_agent_reads_changed_files_from_git_not_stdout(tmp_path):
    repo = _repo(tmp_path)
    result = _agent_run(
        repo,
        _FakeProc(returncode=0, stdout="I did nothing useful, I promise"),  # deliberately lies
        on_invoke=lambda: (repo / "a.txt").write_text("2", encoding="utf-8"),
    )

    assert result.changed_files == ["a.txt"]
    assert "I did nothing useful" in result.raw_output


# --- the agent must never fail quietly -------------------------------------
# Every one of these produces zero changed files, which is indistinguishable from the
# agent legitimately deciding nothing needed fixing. Reported as NO_CHANGES, a broken
# invocation looks like a healthy run.


def test_a_missing_binary_is_named_rather_than_reported_as_no_changes(tmp_path):
    agent = CopilotCLIAgent(command=["copilot"])
    with patch("nexus_autofix.agent.copilot_cli.shutil.which", return_value=None):
        with pytest.raises(AgentUnavailableError, match="not found on PATH"):
            agent.run(prompt="p", worktree=tmp_path)


def test_a_nonzero_exit_raises_with_the_command_and_the_cli_output(tmp_path):
    repo = _repo(tmp_path)
    with pytest.raises(AgentFailedError) as exc:
        _agent_run(repo, _FakeProc(returncode=2, stderr="error: unknown flag --allow-all-tools"))

    message = str(exc.value)
    assert "exited with code 2" in message
    assert "unknown flag --allow-all-tools" in message, "the CLI's own complaint"
    assert "copilot --allow-all-tools" in message, "and what was run"
    assert "copilot --help" in message, "and how to fix it"


def test_a_timeout_is_reported_as_a_failure_not_as_no_changes(tmp_path):
    repo = _repo(tmp_path)

    def fake_run(command, *args, **kwargs):
        if command[:2] == ["git", "status"]:
            return _real_subprocess_run(command, *args, **kwargs)
        raise subprocess.TimeoutExpired(cmd=command, timeout=1, output="partial work")

    agent = CopilotCLIAgent(command=["copilot"], timeout_seconds=1)
    with patch("nexus_autofix.agent.copilot_cli.shutil.which", return_value="/usr/bin/copilot"):
        with patch("subprocess.run", side_effect=fake_run):
            with pytest.raises(AgentFailedError, match="did not finish within 1s"):
                agent.run(prompt="p", worktree=repo)


def test_a_clean_exit_that_changed_nothing_warns_with_the_output(tmp_path, caplog):
    # Legitimate on a run with nothing to do, so not an error — but if the prompt never
    # reached the CLI, or it is not in agentic mode, this is the only visible symptom.
    repo = _repo(tmp_path)
    with caplog.at_level(logging.WARNING):
        result = _agent_run(repo, _FakeProc(returncode=0, stdout="usage: copilot [options]"))

    assert result.changed_files == []
    assert "exited 0 but changed no files" in caplog.text
    assert "usage: copilot" in caplog.text


def test_the_invocation_is_logged_so_it_can_be_reproduced_by_hand(tmp_path, caplog):
    repo = _repo(tmp_path)
    with caplog.at_level(logging.INFO):
        _agent_run(repo, _FakeProc(returncode=0))

    assert "invoking agent: /usr/bin/copilot --allow-all-tools" in caplog.text
    assert "agent exited with code 0" in caplog.text
