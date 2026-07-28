from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        return self.returncode == 0

    def tail(self, lines: int = 200) -> str:
        # Split stdout/stderr independently before concatenating: joining the
        # raw strings with a literal "\n" first (stdout + "\n" + stderr)
        # introduces a spurious blank line whenever stderr is empty, which
        # throws off the "last N lines" count.
        combined = self.stdout.splitlines() + self.stderr.splitlines()
        return "\n".join(combined[-lines:])


def _gradle_executable() -> str:
    return "gradlew.bat" if platform.system() == "Windows" else "./gradlew"


def _maven_executable() -> str:
    return "mvnw.cmd" if platform.system() == "Windows" else "./mvnw"


BUILD_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "clean", "build", "-x", "test"],
    "maven": lambda root: [_maven_executable(), "-DskipTests", "clean", "package"],
    "npm": lambda root: ["npm", "ci"],
    "yarn": lambda root: ["yarn", "install", "--frozen-lockfile"],
    "pnpm": lambda root: ["pnpm", "install", "--frozen-lockfile"],
}

TEST_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "test"],
    "maven": lambda root: [_maven_executable(), "test"],
    "npm": lambda root: ["npm", "test"],
    "yarn": lambda root: ["yarn", "test"],
    "pnpm": lambda root: ["pnpm", "test"],
}

# What the AGENT runs after editing manifests, to regenerate the lockfile.
# Never substituted for the frozen verify-time command above -- that distinction
# is the cheapest guard against an agent that edits the manifest and skips the lockfile.
INSTALL_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "npm": lambda root: ["npm", "install"],
    "yarn": lambda root: ["yarn", "install"],
    "pnpm": lambda root: ["pnpm", "install"],
}

DEPENDENCY_DIAGNOSTIC_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(), "dependencies", "--configuration", "runtimeClasspath"],
    "maven": lambda root: [_maven_executable(), "dependency:tree", "-Dverbose"],
}


def run_command(args: list[str], cwd: Path, env: dict[str, str], timeout_seconds: int) -> CommandResult:
    proc = subprocess.run(
        args,
        cwd=str(cwd),
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        shell=False,
    )
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")
