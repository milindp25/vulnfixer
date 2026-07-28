from __future__ import annotations

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
        capture_output=True, encoding="utf-8", check=True,
    )
    return proc.stdout.strip()


def create_worktree(mirror_path: Path, run_dir: Path, commit_sha: str, branch: str) -> Worktree:
    wt_path = run_dir / "wt"
    subprocess.run(
        ["git", "worktree", "add", str(wt_path), commit_sha],
        cwd=str(mirror_path), check=True, capture_output=True, encoding="utf-8",
    )
    subprocess.run(
        ["git", "switch", "-c", branch], cwd=str(wt_path), check=True, capture_output=True, encoding="utf-8",
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
    """Cleanup failure is logged by the caller, never raised — per design doc section 15."""
    if gradle_stop_cmd and (worktree.path / "gradlew").exists():
        subprocess.run(gradle_stop_cmd, cwd=str(worktree.path), capture_output=True, encoding="utf-8")
    for _ in range(retries):
        result = subprocess.run(
            ["git", "worktree", "remove", "--force", str(worktree.path)],
            cwd=str(mirror_path), capture_output=True, encoding="utf-8",
        )
        if result.returncode == 0:
            subprocess.run(["git", "worktree", "prune"], cwd=str(mirror_path), capture_output=True, encoding="utf-8")
            return True
        time.sleep(delay_seconds)
    return False
