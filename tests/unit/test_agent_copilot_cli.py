import subprocess
from unittest.mock import patch

from nexus_autofix.agent.copilot_cli import CopilotCLIAgent

_real_subprocess_run = subprocess.run  # captured before any patching, so the git-status
# call below can fall through to the real command and reflect real ground truth.


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def test_copilot_cli_agent_reads_changed_files_from_git_not_stdout(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    def fake_run(command, *args, **kwargs):
        # subprocess.run is patched process-wide, so this also intercepts the
        # `git status --porcelain` call made internally by
        # agent/base.changed_files_from_git. Only the *agent's own* CLI
        # invocation should be faked (with a lying stdout); the git-status
        # call must hit real git so changed_files reflects real ground truth.
        if command[:2] == ["git", "status"]:
            return _real_subprocess_run(command, *args, **kwargs)

        (tmp_path / "a.txt").write_text("2", encoding="utf-8")

        class FakeProc:
            stdout = "I did nothing useful, I promise"  # deliberately lies
            stderr = ""

        return FakeProc()

    agent = CopilotCLIAgent(command=["copilot", "--allow-all-tools"])
    with patch("subprocess.run", side_effect=fake_run):
        result = agent.run(prompt="fix things", worktree=tmp_path)

    assert result.changed_files == ["a.txt"]
    assert "I did nothing useful" in result.raw_output
