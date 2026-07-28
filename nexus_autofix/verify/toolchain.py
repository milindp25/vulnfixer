from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class MissingToolchainError(RuntimeError):
    pass


@dataclass(frozen=True)
class ToolchainEnv:
    env: dict[str, str]


def _major(version: str) -> str:
    return version.split(".")[0]


def resolve_java_env(
    declared_version: str, java_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    home = java_map.get(major)
    if not home:
        raise MissingToolchainError(
            f"no Java {major} toolchain configured (declared {declared_version}); "
            f"configured majors: {sorted(java_map)}. This is a hard failure before the "
            f"agent is invoked — add the path to config.yml's toolchains.java map."
        )
    env = dict(base_env if base_env is not None else os.environ)
    java_home = str(Path(home))
    env["JAVA_HOME"] = java_home
    env["PATH"] = str(Path(java_home) / "bin") + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)


def resolve_node_env(
    declared_version: str, node_map: dict[str, str], base_env: dict[str, str] | None = None
) -> ToolchainEnv:
    major = _major(declared_version)
    node_dir = node_map.get(major)
    if not node_dir:
        raise MissingToolchainError(
            f"no Node {major} toolchain configured (declared {declared_version}); "
            f"configured majors: {sorted(node_map)}. This is a hard failure before the "
            f"agent is invoked — add the path to config.yml's toolchains.node map."
        )
    env = dict(base_env if base_env is not None else os.environ)
    env["PATH"] = str(Path(node_dir)) + os.pathsep + env.get("PATH", "")
    return ToolchainEnv(env=env)
