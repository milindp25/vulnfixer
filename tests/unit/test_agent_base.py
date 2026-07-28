import subprocess
from pathlib import Path

from nexus_autofix.agent.base import changed_files_from_git


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def test_changed_files_from_git_reflects_working_tree_not_agent_claims(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    (tmp_path / "a.txt").write_text("2", encoding="utf-8")
    (tmp_path / "b.txt").write_text("new", encoding="utf-8")

    changed = changed_files_from_git(tmp_path)
    assert set(changed) == {"a.txt", "b.txt"}


def test_no_changes_returns_empty_list(tmp_path):
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "a.txt").write_text("1", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)

    assert changed_files_from_git(tmp_path) == []
