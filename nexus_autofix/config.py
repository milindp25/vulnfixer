from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv

from nexus_autofix.iq.filter import DEFAULT_MIN_THREAT_LEVEL


@dataclass(frozen=True)
class Secrets:
    """Everything read from the environment (.env), secret or not.

    `default_app_id` / `default_branch` are not secrets — they live here because this is
    the single place environment variables are read. They let you put the app and branch
    you usually work on in .env instead of retyping them on every invocation; an explicit
    CLI flag still wins.
    """

    iq_url: str
    iq_username: str
    iq_password: str
    github_token: str
    github_api_url: str
    workspace_root: Path
    agent_backend: str | None
    default_app_id: str | None
    default_branch: str | None


@dataclass(frozen=True)
class ProjectConfig:
    subprocess_timeout_seconds: int
    max_attempts: int
    poll_timeout_seconds: int
    default_stage_id: str
    default_gate: str
    min_threat_level: int
    java_toolchains: dict[str, str]
    node_toolchains: dict[str, str]
    repos: dict[str, str]


#: Loaded in this order, from the current working directory only. Earlier entries win,
#: because python-dotenv is told not to overwrite an already-set variable.
ENV_FILENAMES = (".env.local", ".env")


def load_secrets(env_file: Path | None = None) -> Secrets:
    """Read configuration from the environment, seeded from `.env.local` then `.env`.

    Precedence, highest first: a variable already exported in your shell, then
    `.env.local`, then `.env`. `.env.local` is the place for machine-specific overrides
    you don't want to disturb `.env` for.

    Only the current working directory is searched — deliberately not python-dotenv's
    default, which walks up parent directories and can silently pick up a `.env` from
    somewhere above the repo. `config.yml` is read from the CWD too, so both now behave
    the same way. Pass `env_file` to load one specific file instead.
    """
    if env_file is not None:
        load_dotenv(dotenv_path=env_file)
    else:
        for filename in ENV_FILENAMES:
            candidate = Path.cwd() / filename
            if candidate.is_file():
                load_dotenv(dotenv_path=candidate, override=False)

    workspace_root = os.environ.get("NEXUSFIX_WORKSPACE_ROOT", str(Path.home() / "nfx"))
    return Secrets(
        iq_url=os.environ.get("NEXUSFIX_IQ_URL", ""),
        iq_username=os.environ.get("NEXUSFIX_IQ_USERNAME", ""),
        iq_password=os.environ.get("NEXUSFIX_IQ_PASSWORD", ""),
        github_token=os.environ.get("NEXUSFIX_GITHUB_TOKEN", ""),
        github_api_url=os.environ.get("NEXUSFIX_GITHUB_API_URL", "https://api.github.com"),
        workspace_root=Path(workspace_root),
        agent_backend=os.environ.get("NEXUSFIX_AGENT_BACKEND"),
        default_app_id=os.environ.get("NEXUSFIX_APP_ID") or None,
        default_branch=os.environ.get("NEXUSFIX_BRANCH") or None,
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
        min_threat_level=int(data.get("min_threat_level", DEFAULT_MIN_THREAT_LEVEL)),
        java_toolchains={str(k): v for k, v in (toolchains.get("java") or {}).items()},
        node_toolchains={str(k): v for k, v in (toolchains.get("node") or {}).items()},
        repos=data.get("repos") or {},
    )
