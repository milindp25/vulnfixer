import os

from nexus_autofix.config import load_project_config, load_secrets


def test_load_project_config_reads_toolchains_and_defaults(tmp_path):
    config_path = tmp_path / "config.yml"
    config_path.write_text(
        "max_attempts: 3\n"
        "toolchains:\n  java:\n    '17': /opt/jdk17\n  node:\n    '20': /opt/node20\n"
        "repos:\n  payments-core: https://example.com/org/payments-core.git\n",
        encoding="utf-8",
    )
    config = load_project_config(config_path)
    assert config.max_attempts == 3
    assert config.subprocess_timeout_seconds == 1800  # default
    assert config.java_toolchains == {"17": "/opt/jdk17"}
    assert config.repos["payments-core"].endswith("payments-core.git")


def test_load_secrets_reads_env_vars_with_empty_string_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("NEXUSFIX_IQ_URL", raising=False)
    monkeypatch.setenv("NEXUSFIX_IQ_URL", "https://iq.example.com")
    monkeypatch.setenv("NEXUSFIX_AGENT_BACKEND", "mock")
    secrets = load_secrets(env_file=tmp_path / "does-not-exist.env")
    assert secrets.iq_url == "https://iq.example.com"
    assert secrets.agent_backend == "mock"
    assert secrets.github_api_url == "https://api.github.com"
