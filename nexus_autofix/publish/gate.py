from __future__ import annotations

from enum import Enum
from typing import Callable


class GateMode(str, Enum):
    NONE = "none"
    PRE_PR = "pre-pr"
    PRE_PUSH = "pre-push"


def present_pre_pr_gate(summary: str, prompt_fn: Callable[[str], str] = input) -> bool:
    print(summary)
    answer = prompt_fn("Approve and open PR? [y/N]: ").strip().lower()
    return answer == "y"
