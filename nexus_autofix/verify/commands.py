from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
import time
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


log = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"


def _gradle_executable(root: Path) -> str:
    """Absolute path to the repo's Gradle wrapper.

    Absolute rather than "./gradlew" because on Windows CreateProcess resolves a bare
    or relative program name against the *parent* process's directory, not the `cwd=`
    handed to the child — so a relative wrapper name can silently fail to be found.
    """
    return str(root / ("gradlew.bat" if _IS_WINDOWS else "gradlew"))


def _maven_executable(root: Path) -> str:
    return str(root / ("mvnw.cmd" if _IS_WINDOWS else "mvnw"))


def resolve_program(program: str, env: dict[str, str] | None = None) -> str:
    """Resolve a bare program name to a full path, honouring Windows' PATHEXT.

    On Windows, npm/yarn/pnpm/copilot are installed as `.cmd` shims. `subprocess` with
    `shell=False` calls CreateProcess, which does NOT apply PATHEXT, so `["npm", "ci"]`
    raises FileNotFoundError even though npm works fine in the terminal. `shutil.which`
    does apply PATHEXT, and the resolved `...\\npm.cmd` executes correctly.

    Programs given as an explicit path are returned untouched.
    """
    if os.sep in program or (os.altsep and os.altsep in program):
        return program
    search_path = (env or {}).get("PATH") or os.environ.get("PATH")
    return shutil.which(program, path=search_path) or program


BUILD_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(root), "clean", "build", "-x", "test"],
    "maven": lambda root: [_maven_executable(root), "-DskipTests", "clean", "package"],
    "npm": lambda root: ["npm", "ci"],
    "yarn": lambda root: ["yarn", "install", "--frozen-lockfile"],
    "pnpm": lambda root: ["pnpm", "install", "--frozen-lockfile"],
}

#: Task-name fragments that mark a CONTRACT test. Matched case-insensitively.
#:
#: Contract tests only, deliberately. They are self-contained — a consumer test writes a
#: pact from its own expectations, a provider test replays one against the service — so
#: they run here as they do in CI. Integration, component, e2e and acceptance tests are
#: the opposite: they need the other systems up, so running them from a developer machine
#: fails for reasons that have nothing to do with the dependency change, and a red check
#: nobody believes is worse than no check.
_CONTRACT_TEST_MARKERS = ("contracttest", "contracttests", "contract", "pact")

#: Never run these even when the name matches. `contractTestConsumerClasses` COMPILES the
#: contract tests and is a Build task, not a Verification one — running it proves nothing
#: and reports success. Getting this wrong turns "we now run your contract tests" into a
#: no-op that looks like coverage.
_NOT_A_TEST_PREFIXES = ("compile", "process", "clean", "generate", "extract")
_NOT_A_TEST_SUFFIXES = ("classes", "jar", "sources", "javadoc", "report", "reports")

#: Already covered: `test` is the main test command, and `check` would re-run it plus
#: everything else, doubling the work.
_ALREADY_RUN = {"test", "check", "build"}

_TASK_LINE = re.compile(r"^([A-Za-z][\w.:'-]*)(?:\s+-\s+(.*))?$")
_SECTION_LINE = re.compile(r"^(.+) tasks$")


def parse_gradle_tasks(output: str) -> list[tuple[str, str]]:
    """Parse `gradlew tasks --all` into (section, task_name) pairs.

    Sections matter: a repo's contract tests are normally registered under `verification`,
    while the tasks that merely COMPILE them sit under `build` with names one character
    away. Keeping the section lets those be told apart by where Gradle filed them rather
    than by guessing from the name.
    """
    pairs: list[tuple[str, str]] = []
    section = ""
    for raw in output.splitlines():
        line = raw.rstrip()
        if not line or set(line) <= {"-", "="}:
            continue
        heading = _SECTION_LINE.match(line.strip())
        if heading:
            section = heading.group(1).strip().lower()
            continue
        if line.startswith(" "):
            continue
        match = _TASK_LINE.match(line.strip())
        if match and section:
            pairs.append((section, match.group(1)))
    return pairs


def _is_contract_test_task(section: str, task: str) -> bool:
    name = task.split(":")[-1]
    lowered = name.lower()
    if lowered in _ALREADY_RUN:
        return False
    if lowered.startswith(_NOT_A_TEST_PREFIXES) or lowered.endswith(_NOT_A_TEST_SUFFIXES):
        return False
    # Name only, with no fallback to "anything under verification that says test" — that
    # fallback would pull in integrationTest and smokeTest, which is exactly what this is
    # not for.
    return any(marker in lowered for marker in _CONTRACT_TEST_MARKERS)


def discover_contract_test_tasks(
    root: Path, env: dict[str, str], timeout_seconds: int
) -> list[str]:
    """Ask Gradle which contract-test tasks this repo defines.

    A repo registers these as standalone tasks wired into neither `test` nor `check`, so
    nothing in a normal verify run executes them and a bump that breaks a consumer
    contract still reports a clean result. `tasks --all` is the only listing that shows
    them: an ungrouped task appears under "Other tasks", where both `check --dry-run` and
    `tasks --group verification` miss it.

    Returns [] on any failure. This is an enhancement to verification, so it must never
    be the reason a run cannot proceed.
    """
    result = run_command(
        [_gradle_executable(root), "tasks", "--all", "--quiet"], root, env, timeout_seconds
    )
    if not result.success:
        log.warning(
            "could not list Gradle tasks, so this repo's contract tests will not be run: "
            "exit %s", result.returncode,
        )
        return []
    tasks = [
        task for section, task in parse_gradle_tasks(result.stdout)
        if _is_contract_test_task(section, task)
    ]
    # Deterministic order, and de-duplicated: a multi-project build lists the same task
    # name under each subproject.
    return sorted(dict.fromkeys(tasks))


TEST_COMMANDS: dict[str, Callable[[Path], list[str]]] = {
    "gradle": lambda root: [_gradle_executable(root), "test"],
    "maven": lambda root: [_maven_executable(root), "test"],
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
    "gradle": lambda root: [_gradle_executable(root), "dependencies", "--configuration", "runtimeClasspath"],
    "maven": lambda root: [_maven_executable(root), "dependency:tree", "-Dverbose"],
}


def _as_text(stream: str | bytes | None) -> str:
    """TimeoutExpired's captured output is str or bytes depending on how the child
    was configured and how far it got; normalize both."""
    if stream is None:
        return ""
    if isinstance(stream, str):
        return stream
    return stream.decode("utf-8", errors="replace")


def run_command(args: list[str], cwd: Path, env: dict[str, str], timeout_seconds: int) -> CommandResult:
    # Resolve the program against PATH (and PATHEXT on Windows) so `.cmd` shims like
    # npm/yarn/pnpm are found; a no-op for the wrapper paths, which are already absolute.
    args = [resolve_program(args[0], env), *args[1:]] if args else args
    # The resolved argv, not the requested one: on Windows this is where a bare
    # `gradlew`/`npm` becomes an absolute .bat/.cmd path, and a wrong resolution is
    # otherwise invisible until the command mysteriously fails.
    log.info("exec: %s (cwd=%s)", " ".join(args), cwd)
    # The child's output is captured, not streamed — `tail()` feeds the retry prompt and the
    # verdict, so it has to be held rather than passed through. That means a long install or
    # test run prints nothing for minutes and looks hung, so say so before going quiet.
    log.info(
        "  (output is captured, so nothing appears until this finishes — up to %ds. "
        "Re-run with -v to see it.)", timeout_seconds,
    )
    started = time.monotonic()
    # A missing executable or an over-long build is a normal, retryable build
    # failure -- the retry-prompt machinery can act on it. Letting either escape as
    # an exception would instead tear down the whole run.
    try:
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
    except FileNotFoundError as exc:
        log.error("command not found: %s. PATH resolution failed for %r.", exc, args[0] if args else "")
        return CommandResult(returncode=127, stdout="", stderr=f"command not found: {exc}")
    except subprocess.TimeoutExpired as exc:
        log.error("command timed out after %ss: %s", exc.timeout, " ".join(args))
        return CommandResult(
            returncode=124,
            stdout=_as_text(exc.stdout),
            stderr=_as_text(exc.stderr) + f"\n[TIMEOUT after {exc.timeout}s]",
        )
    log.info("exit %s in %.1fs", proc.returncode, time.monotonic() - started)
    log.debug("stdout:\n%s\nstderr:\n%s", proc.stdout or "", proc.stderr or "")
    return CommandResult(returncode=proc.returncode, stdout=proc.stdout or "", stderr=proc.stderr or "")
