import subprocess
from pathlib import Path
from unittest.mock import patch

from nexus_autofix.repo.workspace import Worktree, create_worktree, current_commit_sha, remove_worktree


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _init_mirror(path: Path) -> str:
    _git(["init"], path)
    _git(["config", "user.email", "t@example.com"], path)
    _git(["config", "user.name", "t"], path)
    (path / "README.md").write_text("x", encoding="utf-8")
    _git(["add", "-A"], path)
    _git(["commit", "-m", "init"], path)
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(path), capture_output=True, encoding="utf-8", check=True)
    return proc.stdout.strip()


def test_create_and_remove_worktree(tmp_path):
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    sha = _init_mirror(mirror)
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    worktree = create_worktree(mirror, run_dir, sha, "autofix/nexus/test-1")
    assert worktree.path.exists()
    assert worktree.branch == "autofix/nexus/test-1"
    assert current_commit_sha(worktree.path) == sha

    removed = remove_worktree(mirror, worktree)
    assert removed is True
    assert not worktree.path.exists()


def test_remove_worktree_returns_false_after_exhausting_retries(tmp_path):
    # A worktree path that was never actually created via `git worktree add` — every
    # `git worktree remove` attempt against it fails, exercising the retry-exhaustion
    # path. `time.sleep` is mocked so this doesn't really wait retries * delay_seconds.
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    _init_mirror(mirror)
    bogus_worktree = Worktree(path=tmp_path / "does-not-exist", branch="autofix/nexus/missing")

    with patch("nexus_autofix.repo.workspace.time.sleep") as mock_sleep:
        removed = remove_worktree(mirror, bogus_worktree, retries=3, delay_seconds=2.0)

    assert removed is False
    assert mock_sleep.call_count == 3
