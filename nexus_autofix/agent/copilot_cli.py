"""
UNVERIFIED integration. The exact Copilot CLI invocation shape (flags for
non-interactive/agentic mode, and whether the prompt goes on stdin or in an
argument) has NOT been confirmed against a real install — design doc section 17
lists "run `copilot --help` and record the actual flags" as an open item.

Because the shape is unverified, this adapter's job is to fail LOUDLY when the
CLI does not do what is expected, never to return a quiet "the agent made no
changes". A wrong flag, a missing binary and an unauthenticated CLI all produce
zero changed files, which is indistinguishable from the agent legitimately
deciding nothing needed fixing — so each is turned into an explicit error naming
the command that was run and what the CLI said.

Changed files always come from `git status --porcelain`
(agent/base.changed_files_from_git) per the "never trust the agent's own account
of what it did" principle — never from parsing this output.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from nexus_autofix.agent.base import AgentResult, changed_files_from_git
from nexus_autofix.verify.commands import resolve_program

log = logging.getLogger(__name__)


class AgentUnavailableError(RuntimeError):
    """The coding agent could not be run at all — not the same as it making no changes."""


class AgentFailedError(RuntimeError):
    """The agent ran and exited non-zero."""


@dataclass
class CopilotCLIAgent:
    command: list[str] = field(default_factory=lambda: ["copilot", "--allow-all-tools", "--no-color"])
    timeout_seconds: int = 1800

    def run(self, prompt: str, worktree: Path, env: dict[str, str] | None = None) -> AgentResult:
        # On Windows the CLI is a `copilot.cmd` shim that CreateProcess won't find by
        # bare name; resolve_program applies PATHEXT. No-op elsewhere.
        program = resolve_program(self.command[0], env)
        if not Path(program).is_absolute() and shutil.which(program) is None:
            raise AgentUnavailableError(
                f"the coding agent {self.command[0]!r} was not found on PATH. Install the "
                "GitHub Copilot CLI and make sure `copilot --version` works in the same "
                "shell you run nexusfix from, or pass --mock-agent to exercise every other "
                "step without it."
            )
        command = [program, *self.command[1:]]

        log.info("invoking agent: %s (cwd=%s)", " ".join(command), worktree)
        log.debug("agent prompt:\n%s", prompt)
        try:
            # env=None inherits this process's environment, which is what carries the
            # Copilot CLI's own stored credentials — nexus-autofix never handles those.
            # When the orchestrator supplies a toolchain-resolved env it is passed through
            # so the agent builds against the same JDK/Node the verification step uses.
            proc = subprocess.run(
                command, input=prompt, cwd=str(worktree), env=env, capture_output=True,
                encoding="utf-8", errors="replace", timeout=self.timeout_seconds, shell=False,
            )
        except FileNotFoundError as exc:
            raise AgentUnavailableError(
                f"could not execute {command[0]!r}: {exc}. Check that the Copilot CLI is "
                "installed and on PATH."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise AgentFailedError(
                f"the agent did not finish within {self.timeout_seconds}s. Partial output:\n"
                f"{(exc.stdout or '') if isinstance(exc.stdout, str) else ''}"
            ) from exc

        raw_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        log.info("agent exited with code %s", proc.returncode)
        log.debug("agent output:\n%s", raw_output)

        if proc.returncode != 0:
            # Silently returning "no changes" here is what makes a broken invocation look
            # like a healthy run that had nothing to do. The flags in `command` are
            # unverified, so a usage error is a likely cause and must be visible.
            raise AgentFailedError(
                f"the agent exited with code {proc.returncode}.\n"
                f"  command: {' '.join(command)}\n"
                f"  output:\n{raw_output.strip() or '(no output)'}\n"
                "If this is a usage/unknown-flag error, the invocation in "
                "nexus_autofix/agent/copilot_cli.py needs the real flags — run "
                "`copilot --help` and update `command`."
            )

        changed = changed_files_from_git(worktree)
        if not changed:
            log.warning(
                "the agent exited 0 but changed no files. If it was expected to fix "
                "something, check the output above — the prompt may not have reached it, "
                "or the invocation may not be running in agentic mode.\n%s",
                raw_output.strip() or "(no output)",
            )
        return AgentResult(changed_files=changed, raw_output=raw_output)
