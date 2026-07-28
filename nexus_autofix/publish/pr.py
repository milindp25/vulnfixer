from __future__ import annotations

from dataclasses import dataclass

import requests


@dataclass(frozen=True)
class PullRequest:
    number: int
    url: str


def open_pull_request(
    api_url: str, token: str, owner: str, repo: str,
    head_branch: str, base_branch: str, title: str, body: str,
) -> PullRequest:
    resp = requests.post(
        f"{api_url}/repos/{owner}/{repo}/pulls",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
        json={"title": title, "head": head_branch, "base": base_branch, "body": body},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    return PullRequest(number=data["number"], url=data["html_url"])
