"""Resolve the JDK / Node toolchain a target repo declares in .trident/build.yaml.

Two ways to get a toolchain, in order:

1. An explicit path in ``config.yml``'s ``toolchains:`` map, keyed by major version.
   Use this when you need a specific JDK per repo, or in CI where several are installed.
2. **Fallback: whatever is already on the machine** — ``JAVA_HOME`` (or ``java`` on ``PATH``),
   and ``node`` on ``PATH``. This is the common case when running locally against one repo:
   you already have the right toolchain active, so there is nothing to configure.

The fallback still *checks* the version it found against what the repo declared and warns on a
mismatch, because building with the wrong JDK produces compilation errors that look like the
agent's fault. It warns rather than fails: you may knowingly be running a newer JDK than the
repo declares, which usually works. A hard failure only happens when no toolchain can be found
at all — in which case nothing could have built anyway.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_VERSION_DETECT_TIMEOUT_SECONDS = 30

# Windows JDK/Node binaries carry a .exe suffix; probing for a bare "java" there
# reports a perfectly good JDK as missing.
_EXE = ".exe" if platform.system() == "Windows" else ""


def _java_binary(java_home: Path) -> Path:
    return java_home / "bin" / f"java{_EXE}"


def _node_binary(node_dir: Path) -> Path:
    return node_dir / f"node{_EXE}"


class MissingToolchainError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolchainEnv:
    env: dict[str, str]


def _major(version: str) -> str:
    return version.split(".")[0]


def _detect_java_major(java_home: Path) -> str | None:
    """Best-effort major version of a JDK, via `java -version`. None if undetectable."""
    try:
        proc = subprocess.run(
            [str(_java_binary(java_home)), "-version"],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=_VERSION_DETECT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("could not run java -version in %s: %s", java_home, exc)
        return None
    # `java -version` writes to stderr on most JDKs.
    output = (proc.stderr or "") + (proc.stdout or "")
    match = re.search(r'version "(\d+)(?:\.(\d+))?', output)
    if not match:
        return None
    first, second = match.group(1), match.group(2)
    # Java 8 and earlier report as 1.8.x — the meaningful major is the second component.
    return second if first == "1" and second else first


def _detect_node_major(node_dir: Path) -> str | None:
    try:
        proc = subprocess.run(
            [str(_node_binary(node_dir)), "--version"],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=_VERSION_DETECT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("could not run node --version in %s: %s", node_dir, exc)
        return None
    match = re.match(r"v?(\d+)", (proc.stdout or "").strip())
    return match.group(1) if match else None


def _warn_on_version_mismatch(tool: str, declared_major: str, found_major: str | None, home: Path) -> None:
    if found_major is None:
        log.warning(
            "using ambient %s at %s but could not determine its version; the repo declares %s",
            tool, home, declared_major,
        )
    elif found_major != declared_major:
        log.warning(
            "the repo declares %s %s but the %s on this machine is %s (%s). Proceeding — but if "
            "the build fails to compile, this mismatch is the first thing to check. Pin an exact "
            "path in config.yml's toolchains.%s map to silence this.",
            tool, declared_major, tool, found_major, home, tool.lower(),
        )
    else:
        log.info("using ambient %s %s at %s (matches the repo's declared version)", tool, found_major, home)


def _ambient_java_home(env: dict[str, str]) -> Path | None:
    """JAVA_HOME if usable, else derive it from `java` on PATH."""
    java_home = env.get("JAVA_HOME")
    if java_home and _java_binary(Path(java_home)).exists():
        return Path(java_home)
    java_on_path = shutil.which("java", path=env.get("PATH"))
    if java_on_path:
        # .../<home>/bin/java -> <home>. resolve() follows the symlink shims some
        # platforms put on PATH, so we land on the real JDK rather than /usr/bin.
        resolved = Path(java_on_path).resolve()
        candidate = resolved.parent.parent
        if _java_binary(candidate).exists():
            return candidate
        return resolved.parent.parent
    return None


def resolve_java_env(
    declared_version: str, java_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    env = dict(base_env if base_env is not None else os.environ)
    home = java_map.get(major)

    if home:
        # A configured-but-wrong path (typo, moved install) must fail here, at the
        # pre-agent safety gate, not later as a confusing build error.
        if not Path(home).is_dir():
            raise MissingToolchainError(
                f"configured Java {major} path does not exist: {home} "
                f"(declared {declared_version}). Fix config.yml's toolchains.java map."
            )
        if not _java_binary(Path(home)).exists():
            raise MissingToolchainError(
                f"configured Java {major} path is not a JDK: {home} has no bin/java "
                f"(declared {declared_version}). Fix config.yml's toolchains.java map."
            )
        java_home = Path(home)
        log.info("using configured Java %s toolchain at %s", major, java_home)
    else:
        java_home = _ambient_java_home(env)
        if java_home is None:
            raise MissingToolchainError(
                f"the repo declares Java {declared_version} but no JDK could be found: "
                f"JAVA_HOME is unset (or invalid) and there is no 'java' on PATH. "
                f"Install a JDK, set JAVA_HOME, or add a path to config.yml's "
                f"toolchains.java map under the key \"{major}\"."
            )
        _warn_on_version_mismatch("Java", major, _detect_java_major(java_home), java_home)

    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)


def resolve_node_env(
    declared_version: str, node_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    env = dict(base_env if base_env is not None else os.environ)
    configured = node_map.get(major)

    if configured:
        if not Path(configured).is_dir():
            raise MissingToolchainError(
                f"configured Node {major} path does not exist: {configured} "
                f"(declared {declared_version}). Fix config.yml's toolchains.node map."
            )
        node_dir = Path(configured)
        log.info("using configured Node %s toolchain at %s", major, node_dir)
    else:
        node_on_path = shutil.which("node", path=env.get("PATH"))
        if not node_on_path:
            raise MissingToolchainError(
                f"the repo declares Node {declared_version} but no 'node' was found on PATH. "
                f"Install Node, or add a path to config.yml's toolchains.node map under the "
                f"key \"{major}\"."
            )
        node_dir = Path(node_on_path).resolve().parent
        _warn_on_version_mismatch("Node", major, _detect_node_major(node_dir), node_dir)

    env["PATH"] = str(node_dir) + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)
