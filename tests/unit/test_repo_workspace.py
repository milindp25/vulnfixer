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


def test_the_checkout_has_a_real_dot_git_directory(tmp_path):
    """The whole reason this is a clone and not a `git worktree`.

    In a linked worktree `.git` is a file holding `gitdir: <path>`, and build tooling that
    goes through JGit (Gradle's `gradle-git-properties`) or otherwise assumes the classic
    layout fails with `RepositoryNotFoundException`. That looks like the dependency bump
    broke the build, which is the most expensive kind of wrong.
    """
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    sha = _init_mirror(mirror)
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    worktree = create_worktree(mirror, run_dir, sha, "autofix/nexus/test-1")

    dot_git = worktree.path / ".git"
    assert dot_git.is_dir(), (
        f"{dot_git} is not a directory — this is a linked git worktree again. Build "
        "tooling that reads .git directly breaks in one."
    )
    assert (dot_git / "objects").is_dir()
    assert not (dot_git / "commondir").exists()


def test_a_commit_only_on_a_remote_tracking_ref_can_still_be_checked_out(tmp_path):
    """`resolve_branch_commit_sha` returns a sha from `origin/<branch>`, which need not be
    on any local branch of the mirror. A clone copies the object store wholesale, so the
    sha is present; `switch -c` is what makes it reachable again."""
    remote = tmp_path / "remote"
    remote.mkdir()
    _init_mirror(remote)
    _git(["checkout", "-b", "feature"], remote)
    (remote / "feature.txt").write_text("x", encoding="utf-8")
    _git(["add", "-A"], remote)
    _git(["commit", "-m", "feature only"], remote)
    feature_sha = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(remote), capture_output=True,
        encoding="utf-8", check=True,
    ).stdout.strip()
    _git(["checkout", "-"], remote)

    mirror = tmp_path / "mirror"
    clone_or_update_mirror(str(remote), mirror)
    local_heads = subprocess.run(
        ["git", "branch", "--format=%(refname:short)"], cwd=str(mirror),
        capture_output=True, encoding="utf-8", check=True,
    ).stdout.split()
    assert "feature" not in local_heads, "precondition: the sha is only on origin/feature"

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    worktree = create_worktree(mirror, run_dir, feature_sha, "autofix/nexus/test-2")

    assert current_commit_sha(worktree.path) == feature_sha


def test_origin_points_at_the_real_remote_not_the_mirror(tmp_path):
    """`publish` pushes to `origin`. Left pointing at the mirror it would push into the
    local cache — succeeding silently while shipping nothing."""
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    sha = _init_mirror(mirror)
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    worktree = create_worktree(
        mirror, run_dir, sha, "autofix/nexus/test-3", "https://github.com/o/r.git"
    )

    origin = subprocess.run(
        ["git", "remote", "get-url", "origin"], cwd=str(worktree.path),
        capture_output=True, encoding="utf-8", check=True,
    ).stdout.strip()
    assert origin == "https://github.com/o/r.git"


def test_remove_worktree_returns_false_after_exhausting_retries(tmp_path):
    # Stands in for the Windows case this retry loop exists for: a Gradle daemon or a
    # file indexer still holding a handle, so every delete attempt leaves the directory
    # in place. `time.sleep` is mocked so this doesn't really wait retries * delay.
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    stuck = tmp_path / "wt"
    stuck.mkdir()
    worktree = Worktree(path=stuck, branch="autofix/nexus/stuck")

    with patch("nexus_autofix.repo.workspace.shutil.rmtree") as mock_rmtree, \
            patch("nexus_autofix.repo.workspace.time.sleep") as mock_sleep:
        removed = remove_worktree(mirror, worktree, retries=3, delay_seconds=2.0)

    assert removed is False
    assert mock_rmtree.call_count == 3
    assert mock_sleep.call_count == 3


def test_removing_an_already_gone_checkout_succeeds(tmp_path):
    """Cleanup runs in a `finally`, so it can land after an earlier failure removed it."""
    mirror = tmp_path / "mirror"
    mirror.mkdir()
    gone = Worktree(path=tmp_path / "does-not-exist", branch="autofix/nexus/gone")

    assert remove_worktree(mirror, gone) is True


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
