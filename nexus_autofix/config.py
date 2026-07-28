from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv


@dataclass(frozen=True)
class Secrets:
    iq_url: str
    iq_username: str
    iq_password: str
    github_token: str
    github_api_url: str
    workspace_root: Path
    agent_backend: str | None


@dataclass(frozen=True)
class ProjectConfig:
    subprocess_timeout_seconds: int
    max_attempts: int
    poll_timeout_seconds: int
    default_stage_id: str
    default_gate: str
    java_toolchains: dict[str, str]
    node_toolchains: dict[str, str]
    repos: dict[str, str]


def load_secrets(env_file: Path | None = None) -> Secrets:
    load_dotenv(dotenv_path=env_file)
    workspace_root = os.environ.get("NEXUSFIX_WORKSPACE_ROOT", str(Path.home() / "nfx"))
    return Secrets(
        iq_url=os.environ.get("NEXUSFIX_IQ_URL", ""),
        iq_username=os.environ.get("NEXUSFIX_IQ_USERNAME", ""),
        iq_password=os.environ.get("NEXUSFIX_IQ_PASSWORD", ""),
        github_token=os.environ.get("NEXUSFIX_GITHUB_TOKEN", ""),
        github_api_url=os.environ.get("NEXUSFIX_GITHUB_API_URL", "https://api.github.com"),
        workspace_root=Path(workspace_root),
        agent_backend=os.environ.get("NEXUSFIX_AGENT_BACKEND"),
    )


def load_project_config(path: Path) -> ProjectConfig:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    toolchains = data.get("toolchains") or {}
    return ProjectConfig(
        subprocess_timeout_seconds=data.get("subprocess_timeout_seconds", 1800),
        max_attempts=data.get("max_attempts", 2),
        poll_timeout_seconds=data.get("poll_timeout_seconds", 900),
        default_stage_id=data.get("default_stage_id", "build"),
        default_gate=data.get("default_gate", "pre-pr"),
        java_toolchains={str(k): v for k, v in (toolchains.get("java") or {}).items()},
        node_toolchains={str(k): v for k, v in (toolchains.get("node") or {}).items()},
        repos=data.get("repos") or {},
    )
