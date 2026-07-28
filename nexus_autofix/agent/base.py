from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AgentResult:
    changed_files: list[str]
    raw_output: str


class AgentRunner(Protocol):
    def run(self, prompt: str, worktree: Path) -> AgentResult: ...


def changed_files_from_git(worktree: Path) -> list[str]:
    """The orchestrator's ONLY source of truth for what changed — never the agent's own report."""
    proc = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(worktree), capture_output=True,
        encoding="utf-8", errors="replace", check=True,
    )
    files = []
    for line in proc.stdout.splitlines():
        if line.strip():
            files.append(line[3:].strip())
    return files
