"""The per-run checkout the agent edits, and the mirror it is made from.

Note that "worktree" here means "the working tree for this run" in the plain-English
sense. It is deliberately **not** a `git worktree` — see `create_worktree`.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Worktree:
    path: Path
    branch: str


def clone_or_update_mirror(repo_url: str, mirror_path: Path) -> None:
    """Clone repo_url into mirror_path if absent, else fetch it up to date.

    The `HEAD` check covers a bare mirror; `.git` covers a normal clone.
    """
    if (mirror_path / ".git").exists() or (mirror_path / "HEAD").exists():
        subprocess.run(
            ["git", "fetch", "--all", "--prune"], cwd=str(mirror_path),
            check=True, capture_output=True, encoding="utf-8",
        )
    else:
        mirror_path.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", repo_url, str(mirror_path)],
            check=True, capture_output=True, encoding="utf-8",
        )


def resolve_branch_commit_sha(mirror_path: Path, branch: str) -> str:
    """Resolve a branch name in the mirror to the sha of its remote-tracking ref.

    Deliberately resolves `origin/<branch>` rather than `<branch>`: the local branch in
    a mirror can lag behind what was just fetched. Call `clone_or_update_mirror` first
    so the remote-tracking ref is current.
    """
    proc = subprocess.run(
        ["git", "rev-parse", f"origin/{branch}"], cwd=str(mirror_path),
        capture_output=True, encoding="utf-8",
    )
    if proc.returncode != 0:
        # A typo'd or non-existent branch is the likeliest cause, and git's own message
        # ("unknown revision or path not in the working tree") does not make that obvious.
        available = subprocess.run(
            ["git", "branch", "--remotes", "--format=%(refname:short)"],
            cwd=str(mirror_path), capture_output=True, encoding="utf-8",
        )
        names = [
            stripped.removeprefix("origin/")
            for stripped in (line.strip() for line in (available.stdout or "").splitlines())
            # Skip the bare `origin` entry, which is the origin/HEAD symref, not a branch.
            if stripped.startswith("origin/") and "->" not in stripped
        ]
        raise ValueError(
            f"branch {branch!r} does not exist on the remote. "
            + (f"Available branches: {', '.join(sorted(names))}." if names else
               "No remote branches were found — check the repo URL and your git credentials.")
        )
    return proc.stdout.strip()


def create_worktree(
    mirror_path: Path, run_dir: Path, commit_sha: str, branch: str, repo_url: str | None = None
) -> Worktree:
    """Make the per-run checkout: a real clone off the mirror, not a `git worktree`.

    This used `git worktree add`, which is faster and lighter. It also breaks builds. In a
    linked worktree `.git` is a *file* holding `gitdir: <path>`, and the directory it points
    at has no `objects/` — only a `commondir` file pointing back to the shared repository.
    Any tool that opens `.git` expecting a directory has to follow both hops, and a lot of
    build tooling does not: JGit (so Gradle's `gradle-git-properties`, which fails with
    `RepositoryNotFoundException`), Maven's `buildnumber-maven-plugin`, and various IDE
    integrations. Those failures look like the dependency bump broke the build, when the
    layout of the checkout is the only thing that is wrong.

    A clone gives an ordinary `.git` directory, so every one of them works. Cloning from a
    local path hardlinks the object store, so this stays cheap in both time and disk, and
    the checkout is self-contained rather than aliased into the mirror.

    `commit_sha` need only be *present* in the mirror, not on one of its local branches:
    the object store is copied wholesale, and `switch -c` makes the sha reachable again.

    `repo_url` re-points `origin` at the real remote. Without it `origin` is the mirror
    directory and `publish` would push the fix branch into the local cache, which succeeds
    silently and ships nothing.
    """
    wt_path = run_dir / "wt"
    subprocess.run(
        # --no-checkout: `switch -c` below does the one checkout that is needed.
        ["git", "clone", "--no-checkout", str(mirror_path), str(wt_path)],
        check=True, capture_output=True, encoding="utf-8",
    )
    subprocess.run(
        ["git", "switch", "-c", branch, commit_sha],
        cwd=str(wt_path), check=True, capture_output=True, encoding="utf-8",
    )
    if repo_url:
        subprocess.run(
            ["git", "remote", "set-url", "origin", repo_url],
            cwd=str(wt_path), check=True, capture_output=True, encoding="utf-8",
        )
    return Worktree(path=wt_path, branch=branch)


def current_commit_sha(worktree_path: Path) -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(worktree_path), capture_output=True,
        encoding="utf-8", check=True,
    )
    return proc.stdout.strip()


def remove_worktree(
    mirror_path: Path, worktree: Worktree, gradle_stop_cmd: list[str] | None = None,
    retries: int = 3, delay_seconds: float = 2.0,
) -> bool:
    """Cleanup failure is logged by the caller, never raised — per design doc section 15.

    The checkout is a standalone clone, so deleting the directory is the whole job: there
    is no administrative entry in the mirror to unregister, and nothing here can corrupt
    the mirror. `mirror_path` is kept for call-site compatibility and is unused.

    Retries are for Windows, where a Gradle daemon or a file indexer can hold a handle
    open for a few seconds after the build exits.
    """
    if gradle_stop_cmd and (worktree.path / "gradlew").exists():
        subprocess.run(gradle_stop_cmd, cwd=str(worktree.path), capture_output=True, encoding="utf-8")
    for _ in range(retries):
        if not worktree.path.exists():
            return True
        shutil.rmtree(worktree.path, ignore_errors=True)
        if not worktree.path.exists():
            return True
        time.sleep(delay_seconds)
    return not worktree.path.exists()
