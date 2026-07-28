from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from nexus_autofix.agent.base import AgentResult


class MockMode(str, Enum):
    APPLIES_FIX = "applies_fix"
    NO_CHANGES = "no_changes"
    DELETES_TEST = "deletes_test"
    FAILS_THEN_FIXES = "fails_then_fixes"


@dataclass
class MockAgent:
    """Test double per design doc section 12 — NOT a second real agent implementation.

    Exists because the orchestrator's SUSPICIOUS-abort path (does it refuse to push when
    the agent deletes a test file?) cannot be exercised against a real, non-deterministic
    coding agent on demand.
    """

    mode: MockMode
    fix_file: str | None = None
    fix_content: str | None = None
    test_file_to_delete: str | None = None
    _attempt: int = field(default=0, init=False)

    def run(self, prompt: str, worktree: Path) -> AgentResult:
        self._attempt += 1

        if self.mode == MockMode.NO_CHANGES:
            return AgentResult(changed_files=[], raw_output="no changes made")

        if self.mode == MockMode.DELETES_TEST:
            (worktree / self.test_file_to_delete).unlink()
            return AgentResult(changed_files=[self.test_file_to_delete], raw_output="deleted failing test")

        if self.mode == MockMode.APPLIES_FIX:
            self._write_fix(worktree)
            return AgentResult(changed_files=[self.fix_file], raw_output="applied version bump")

        if self.mode == MockMode.FAILS_THEN_FIXES:
            if self._attempt == 1:
                return AgentResult(changed_files=[], raw_output="attempted fix, build still failing")
            self._write_fix(worktree)
            return AgentResult(changed_files=[self.fix_file], raw_output="applied corrected fix on retry")

        raise ValueError(f"unhandled mock mode: {self.mode}")

    def _write_fix(self, worktree: Path) -> None:
        (worktree / self.fix_file).write_text(self.fix_content, encoding="utf-8")
