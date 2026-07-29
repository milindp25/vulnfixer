from __future__ import annotations

import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from nexus_autofix.http import tls_verify

BRANCH_PREFIX = "autofix/nexus/"


def push_branch(worktree: Path, remote: str, branch: str) -> None:
    subprocess.run(
        ["git", "push", remote, f"HEAD:refs/heads/{branch}"],
        cwd=str(worktree), check=True, capture_output=True, encoding="utf-8",
    )


def delete_remote_branch(worktree: Path, remote: str, branch: str) -> None:
    subprocess.run(
        ["git", "push", remote, "--delete", branch],
        cwd=str(worktree), check=True, capture_output=True, encoding="utf-8",
    )


def sweep_stale_branches(api_url: str, token: str, owner: str, repo: str, older_than_days: int) -> list[str]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    branches_resp = requests.get(f"{api_url}/repos/{owner}/{repo}/branches", headers=headers, timeout=30, verify=tls_verify())
    branches_resp.raise_for_status()

    open_prs_resp = requests.get(
        f"{api_url}/repos/{owner}/{repo}/pulls", headers=headers, params={"state": "open"}, timeout=30, verify=tls_verify()
    )
    open_prs_resp.raise_for_status()
    open_pr_branches = {pr["head"]["ref"] for pr in open_prs_resp.json()}

    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    deleted: list[str] = []

    for branch in branches_resp.json():
        name = branch["name"]
        if not name.startswith(BRANCH_PREFIX) or name in open_pr_branches:
            continue
        commit_resp = requests.get(branch["commit"]["url"], headers=headers, timeout=30, verify=tls_verify())
        commit_resp.raise_for_status()
        commit_date = datetime.fromisoformat(
            commit_resp.json()["commit"]["committer"]["date"].replace("Z", "+00:00")
        )
        if commit_date < cutoff:
            delete_resp = requests.delete(
                f"{api_url}/repos/{owner}/{repo}/git/refs/heads/{name}", headers=headers, timeout=30
            )
            delete_resp.raise_for_status()
            deleted.append(name)

    return deleted
