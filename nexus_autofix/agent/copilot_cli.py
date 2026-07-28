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
from nexus_autofix.verify.commands import resolve_program


@dataclass
class CopilotCLIAgent:
    command: list[str] = field(default_factory=lambda: ["copilot", "--allow-all-tools", "--no-color"])
    timeout_seconds: int = 1800

    def run(self, prompt: str, worktree: Path, env: dict[str, str] | None = None) -> AgentResult:
        # On Windows the CLI is a `copilot.cmd` shim that CreateProcess won't find by
        # bare name; resolve_program applies PATHEXT. No-op elsewhere.
        command = [resolve_program(self.command[0], env), *self.command[1:]]
        # env=None inherits this process's environment, which is what carries the
        # Copilot CLI's own stored credentials — nexus-autofix never handles those.
        # When the orchestrator supplies a toolchain-resolved env it is passed through
        # so the agent builds against the same JDK/Node the verification step uses.
        proc = subprocess.run(
            command, input=prompt, cwd=str(worktree), env=env, capture_output=True,
            encoding="utf-8", errors="replace", timeout=self.timeout_seconds, shell=False,
        )
        changed = changed_files_from_git(worktree)
        raw_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return AgentResult(changed_files=changed, raw_output=raw_output)
