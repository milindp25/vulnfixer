import subprocess
from pathlib import Path
from unittest.mock import patch

from nexus_autofix.repo.workspace import (
    Worktree,
    clone_or_update_mirror,
    create_worktree,
    current_commit_sha,
    remove_worktree,
    resolve_branch_commit_sha,
)


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


def _init_remote(path: Path) -> str:
    """A real local git repo usable as a clone source — no network involved."""
    path.mkdir(parents=True, exist_ok=True)
    _git(["init"], path)
    _git(["checkout", "-B", "main"], path)
    _git(["config", "user.email", "t@example.com"], path)
    _git(["config", "user.name", "t"], path)
    return _commit(path, "first", "one")


def _commit(path: Path, filename: str, message: str) -> str:
    (path / filename).write_text(message, encoding="utf-8")
    _git(["add", "-A"], path)
    _git(["commit", "-m", message], path)
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(path), capture_output=True, encoding="utf-8", check=True
    )
    return proc.stdout.strip()


def test_clone_or_update_mirror_clones_when_absent(tmp_path):
    remote = tmp_path / "remote"
    sha = _init_remote(remote)
    mirror = tmp_path / "mirrors" / "demo"

    clone_or_update_mirror(f"file://{remote}", mirror)

    assert (mirror / ".git").exists()
    assert (mirror / "first").read_text(encoding="utf-8") == "one"
    assert resolve_branch_commit_sha(mirror, "main") == sha


def test_clone_or_update_mirror_fetches_when_already_cloned(tmp_path):
    remote = tmp_path / "remote"
    first_sha = _init_remote(remote)
    mirror = tmp_path / "mirrors" / "demo"

    clone_or_update_mirror(f"file://{remote}", mirror)
    assert resolve_branch_commit_sha(mirror, "main") == first_sha

    # A new commit lands on the remote AFTER the initial clone; the second call must
    # fetch rather than re-clone, and the mirror must see the new commit.
    second_sha = _commit(remote, "second", "two")
    assert second_sha != first_sha

    clone_or_update_mirror(f"file://{remote}", mirror)

    assert resolve_branch_commit_sha(mirror, "main") == second_sha
    # Fetched, not re-cloned: the object is present without a fresh working tree.
    subprocess.run(
        ["git", "cat-file", "-e", f"{second_sha}^{{commit}}"],
        cwd=str(mirror), check=True, capture_output=True, encoding="utf-8",
    )


def test_resolve_branch_commit_sha_resolves_a_non_default_branch(tmp_path):
    remote = tmp_path / "remote"
    main_sha = _init_remote(remote)
    _git(["checkout", "-b", "release"], remote)
    release_sha = _commit(remote, "release-notes", "rel")
    _git(["checkout", "main"], remote)

    mirror = tmp_path / "mirrors" / "demo"
    clone_or_update_mirror(f"file://{remote}", mirror)

    assert resolve_branch_commit_sha(mirror, "main") == main_sha
    assert resolve_branch_commit_sha(mirror, "release") == release_sha
