"""
UNVERIFIED integration. The exact Copilot CLI invocation shape (flags for
non-interactive/agentic mode) has not been confirmed against a real install
in this environment — design doc section 17 lists "run `copilot --help` and
record the actual flags" as an open item. This adapter pipes the assembled
prompt to the CLI's stdin and treats stdout/stderr as a human-readable
transcript ONLY. Changed files always come from `git status --porcelain`
(agent/base.changed_files_from_git) per the "never trust the agent's own
account of what it did" principle — never from parsing this output.
Update `command` once the real flags are confirmed.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nexus_autofix.agent.base import AgentResult, changed_files_from_git


@dataclass
class CopilotCLIAgent:
    command: list[str] = field(default_factory=lambda: ["copilot", "--allow-all-tools", "--no-color"])
    timeout_seconds: int = 1800

    def run(self, prompt: str, worktree: Path) -> AgentResult:
        proc = subprocess.run(
            self.command, input=prompt, cwd=str(worktree), capture_output=True,
            encoding="utf-8", errors="replace", timeout=self.timeout_seconds, shell=False,
        )
        changed = changed_files_from_git(worktree)
        raw_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return AgentResult(changed_files=changed, raw_output=raw_output)
