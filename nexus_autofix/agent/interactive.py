"""Human-in-the-loop agent: nexus-autofix prepares the work, a person drives the agent.

Written for organisations whose Copilot policy blocks unattended tool use — the mode
`--allow-all-tools` asks for, which returns "Access denied by policy settings". Interactive
Copilot, where a human approves each action, is normally still permitted. This adapter
gives up on driving the CLI and hands the job to whoever is at the keyboard instead.

Nothing downstream changes. The orchestrator only ever believed `git status --porcelain`
about what an agent did (see agent/base.changed_files_from_git), so it cannot tell — and
does not care — whether Copilot, a different agent, or a person made the edits. Diff
classification, build, test, rescan, the approval gate and the PR all run exactly as they
do for an automated run.
"""

from __future__ import annotations

import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from nexus_autofix.agent.base import AgentResult, changed_files_from_git

log = logging.getLogger(__name__)

#: Written into the worktree for convenience, then REMOVED before this returns. It must
#: not survive: the orchestrator reads changed files straight from git status, which
#: includes untracked files, so leaving it behind would put PROMPT.md in the diff, get it
#: classified, and commit it into the fix branch.
PROMPT_FILENAME = "PROMPT.md"


class AgentAbortedError(RuntimeError):
    """The person driving the agent chose to stop, or could not be asked."""


@dataclass
class InteractiveAgent:
    """Write the prompt out, wait for a human to run the agent, then read git."""

    #: Injected so tests do not need a terminal. Returns the line the user typed.
    input_fn = staticmethod(input)

    def run(self, prompt: str, worktree: Path, env: dict[str, str] | None = None) -> AgentResult:
        prompt_path = worktree / PROMPT_FILENAME
        prompt_path.write_text(prompt, encoding="utf-8")

        # Both destinations are deliberate: the file is what you paste from, the log is
        # the permanent record of exactly what was asked for on this run, since the file
        # is deleted below.
        log.info("prompt written to %s", prompt_path)
        log.info("full prompt for this run:\n%s", prompt)

        banner = _instructions(worktree, prompt_path)
        print(banner)
        log.info("waiting for the agent step to be completed by hand")

        try:
            answer = self.input_fn("Press Enter when the agent has finished, or 'q' to abort: ")
        except (EOFError, KeyboardInterrupt) as exc:
            # No terminal (CI, a pipe) or Ctrl-C. Aborting is the only honest option:
            # returning normally would report "the agent made no changes", which reads as
            # the agent having run and found nothing to do.
            raise AgentAbortedError(
                "the interactive agent step needs a terminal to wait on, and none was "
                "available. Run nexusfix from an interactive shell, or drop "
                "--interactive-agent to use the automated backend."
            ) from exc
        finally:
            # Before changed_files_from_git is called, on every path.
            prompt_path.unlink(missing_ok=True)

        if answer.strip().lower() in {"q", "quit", "abort", "n", "no"}:
            raise AgentAbortedError("aborted at the interactive agent step")

        changed = changed_files_from_git(worktree)
        log.info("git reports %d changed file(s) after the manual step", len(changed))
        return AgentResult(
            changed_files=changed,
            raw_output=f"interactive agent step completed by hand in {worktree}",
        )


def _instructions(worktree: Path, prompt_path: Path) -> str:
    # `copilot` bare, NOT --allow-all-tools: that flag is what the org policy rejects, and
    # approving each action is the whole point of running this mode.
    quoted = f'"{worktree}"' if " " in str(worktree) else str(worktree)
    return f"""
{'=' * 78}
  AGENT STEP — over to you
{'=' * 78}

  The prepared worktree is at:

      {quoted}

  Use whichever of these suits you. Only what git sees matters, so it makes no
  difference which one made the edits:

    * Copilot CLI      cd {quoted}
                       copilot
                       then paste PROMPT.md

    * VS Code          code {quoted}
                       open Copilot Chat in agent mode, attach or paste PROMPT.md

    * By hand          edit the manifest yourself

  The prompt is at:

      {prompt_path}

  (also printed in full in this run's log, since the file is removed afterwards)

  The prompt is plain text — no MCP server or tool integration is needed, so an
  org policy blocking third-party MCP servers does not affect this step.

  When the changes are made, leave them uncommitted and come back here. This tool
  does the committing, building, testing, rescanning and PR.

{'=' * 78}
"""
