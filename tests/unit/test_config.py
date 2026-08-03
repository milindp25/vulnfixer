
import pytest

from nexus_autofix.config import load_project_config, load_secrets
from nexus_autofix.http import tls_verify


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


# --- .env / .env.local discovery -------------------------------------------


def _clear_env(monkeypatch):
    for name in ("NEXUSFIX_IQ_URL", "NEXUSFIX_IQ_USERNAME", "NEXUSFIX_APP_ID"):
        monkeypatch.delenv(name, raising=False)


def test_loads_dot_env_from_the_current_directory(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    (tmp_path / ".env").write_text("NEXUSFIX_IQ_URL=https://from-env.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert load_secrets().iq_url == "https://from-env.example.com"


def test_dot_env_local_overrides_dot_env_per_variable(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    (tmp_path / ".env").write_text(
        "NEXUSFIX_IQ_URL=https://base.example.com\nNEXUSFIX_APP_ID=base-app\n", encoding="utf-8"
    )
    (tmp_path / ".env.local").write_text("NEXUSFIX_IQ_URL=https://local.example.com\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    secrets = load_secrets()
    assert secrets.iq_url == "https://local.example.com"
    # Merged, not wholesale replaced: values only in .env survive.
    assert secrets.default_app_id == "base-app"


def test_a_real_environment_variable_beats_both_files(monkeypatch, tmp_path):
    _clear_env(monkeypatch)
    (tmp_path / ".env").write_text("NEXUSFIX_IQ_URL=https://from-env.example.com\n", encoding="utf-8")
    (tmp_path / ".env.local").write_text("NEXUSFIX_IQ_URL=https://from-local.example.com\n", encoding="utf-8")
    monkeypatch.setenv("NEXUSFIX_IQ_URL", "https://from-shell.example.com")
    monkeypatch.chdir(tmp_path)
    assert load_secrets().iq_url == "https://from-shell.example.com"


def test_does_not_walk_up_to_a_parent_directory_dot_env(monkeypatch, tmp_path):
    # python-dotenv's default search walks up the tree, which can silently pick up
    # credentials from a .env above the repo. Only the CWD should be consulted.
    _clear_env(monkeypatch)
    (tmp_path / ".env").write_text("NEXUSFIX_IQ_URL=https://parent.example.com\n", encoding="utf-8")
    child = tmp_path / "child"
    child.mkdir()
    monkeypatch.chdir(child)
    assert load_secrets().iq_url == ""


# --- TLS settings -----------------------------------------------------------


def test_tls_verify_defaults_to_on(monkeypatch):
    monkeypatch.delenv("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.delenv("NEXUSFIX_CA_BUNDLE", raising=False)
    assert tls_verify() is True


def test_ca_bundle_is_used_when_set(monkeypatch):
    monkeypatch.delenv("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", raising=False)
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", "/etc/ssl/corp-ca.pem")
    assert tls_verify() == "/etc/ssl/corp-ca.pem"


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
def test_insecure_flag_disables_verification(monkeypatch, value):
    monkeypatch.setenv("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", value)
    assert tls_verify() is False


def test_insecure_flag_beats_a_ca_bundle(monkeypatch):
    monkeypatch.setenv("NEXUSFIX_CA_BUNDLE", "/etc/ssl/corp-ca.pem")
    monkeypatch.setenv("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", "true")
    assert tls_verify() is False


def test_a_non_truthy_value_does_not_disable_verification(monkeypatch):
    monkeypatch.delenv("NEXUSFIX_CA_BUNDLE", raising=False)
    monkeypatch.setenv("NEXUSFIX_INSECURE_SKIP_TLS_VERIFY", "false")
    assert tls_verify() is True


def _write_config(tmp_path, body="repos: {}\n"):
    path = tmp_path / "config.yml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_scan_method_defaults_to_source_control(tmp_path, monkeypatch):
    from nexus_autofix.config import load_project_config

    for var in ("NEXUSFIX_IQ_CLI_JAR", "NEXUSFIX_IQ_CLI_URL", "NEXUSFIX_SCAN_METHOD"):
        monkeypatch.delenv(var, raising=False)

    assert load_project_config(_write_config(tmp_path)).uses_iq_cli is False


def test_configuring_a_jar_selects_the_cli_scan(tmp_path, monkeypatch):
    from nexus_autofix.config import load_project_config

    monkeypatch.delenv("NEXUSFIX_SCAN_METHOD", raising=False)
    config = load_project_config(_write_config(tmp_path, "iq_cli_jar: /opt/iq.jar\n"))

    assert config.uses_iq_cli is True


def test_a_download_url_alone_selects_the_cli_scan(tmp_path, monkeypatch):
    """So setting only the URL is enough — there is then no path to keep in step."""
    from nexus_autofix.config import load_project_config

    monkeypatch.delenv("NEXUSFIX_SCAN_METHOD", raising=False)
    monkeypatch.delenv("NEXUSFIX_IQ_CLI_JAR", raising=False)
    config = load_project_config(
        _write_config(tmp_path, "iq_cli_download_url: https://x/iq.jar\n")
    )

    assert config.uses_iq_cli is True


def test_the_environment_overrides_config_yml(tmp_path, monkeypatch):
    """config.yml is committed and shared; the jar's location is per-machine."""
    from nexus_autofix.config import load_project_config

    monkeypatch.setenv("NEXUSFIX_IQ_CLI_JAR", "/machine/local/iq.jar")
    config = load_project_config(_write_config(tmp_path, "iq_cli_jar: /from/config.jar\n"))

    assert config.iq_cli_jar == "/machine/local/iq.jar"


def test_scan_method_can_force_source_control_with_a_jar_still_configured(tmp_path, monkeypatch):
    """Useful when a build is broken and findings are still wanted."""
    from nexus_autofix.config import load_project_config

    monkeypatch.setenv("NEXUSFIX_SCAN_METHOD", "source-control")
    config = load_project_config(_write_config(tmp_path, "iq_cli_jar: /opt/iq.jar\n"))

    assert config.uses_iq_cli is False


def test_scan_method_can_force_the_cli(tmp_path, monkeypatch):
    from nexus_autofix.config import load_project_config

    monkeypatch.setenv("NEXUSFIX_SCAN_METHOD", "iq-cli")
    assert load_project_config(_write_config(tmp_path)).uses_iq_cli is True


def test_env_file_settings_reach_the_project_config_without_loading_secrets_first(
    tmp_path, monkeypatch
):
    """The live failure: NEXUSFIX_SCAN_METHOD=iq-cli in .env was ignored and discover kept
    calling the source-control API.

    Every command reads config.yml first and secrets second, and the dotenv load lived in
    `load_secrets` alone — so `load_project_config` read a process environment that .env
    had not been applied to yet, and silently used its config.yml default. Exporting the
    variable in the shell worked, which made it look like the setting itself was fine.
    """
    from nexus_autofix.config import load_project_config

    monkeypatch.delenv("NEXUSFIX_SCAN_METHOD", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("NEXUSFIX_SCAN_METHOD=iq-cli\n", encoding="utf-8")
    (tmp_path / "config.yml").write_text("repos: {}\n", encoding="utf-8")

    config = load_project_config(tmp_path / "config.yml")

    assert config.scan_method == "iq-cli"
    assert config.uses_iq_cli is True


def test_every_env_backed_project_setting_is_readable_from_a_dotenv_file(tmp_path, monkeypatch):
    """Introspective, so a setting added later is covered without editing this test."""
    from nexus_autofix.config import load_project_config

    env_to_field = {
        "NEXUSFIX_IQ_CLI_JAR": ("iq_cli_jar", "/from/env.jar"),
        "NEXUSFIX_IQ_CLI_URL": ("iq_cli_download_url", "https://env/iq.jar"),
        "NEXUSFIX_IQ_CLI_SHA256": ("iq_cli_sha256", "abc123"),
        # Normalised to a tuple: the CLI takes several targets, and an env var can
        # only express that as a comma-separated string.
        "NEXUSFIX_IQ_CLI_SCAN_TARGET": ("iq_cli_scan_target", "build", ("build",)),
        "NEXUSFIX_SCAN_METHOD": ("scan_method", "iq-cli"),
    }
    for var in env_to_field:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text(
        "".join(f"{var}={spec[1]}\n" for var, spec in env_to_field.items()),
        encoding="utf-8",
    )
    (tmp_path / "config.yml").write_text("repos: {}\n", encoding="utf-8")

    config = load_project_config(tmp_path / "config.yml")

    for var, spec in env_to_field.items():
        field, written = spec[0], spec[1]
        expected = spec[2] if len(spec) > 2 else written
        assert getattr(config, field) == expected, f"{var} did not reach {field}"


def test_a_shell_variable_still_beats_the_env_file(tmp_path, monkeypatch):
    from nexus_autofix.config import load_project_config

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NEXUSFIX_SCAN_METHOD", "source-control")
    (tmp_path / ".env").write_text("NEXUSFIX_SCAN_METHOD=iq-cli\n", encoding="utf-8")
    (tmp_path / "config.yml").write_text("repos: {}\n", encoding="utf-8")

    assert load_project_config(tmp_path / "config.yml").scan_method == "source-control"


def test_a_comma_separated_scan_target_becomes_several_targets(tmp_path, monkeypatch):
    """The usual Node invocation passes the lockfile AND package.json, and an environment
    variable can only express a list as a delimited string."""
    from nexus_autofix.config import load_project_config

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("NEXUSFIX_IQ_CLI_SCAN_TARGET", "yarn.lock, package.json")
    (tmp_path / "config.yml").write_text("repos: {}\n", encoding="utf-8")

    config = load_project_config(tmp_path / "config.yml")

    assert config.iq_cli_scan_target == ("yarn.lock", "package.json")


def test_a_yaml_list_scan_target_is_read_as_a_list(tmp_path, monkeypatch):
    from nexus_autofix.config import load_project_config

    monkeypatch.delenv("NEXUSFIX_IQ_CLI_SCAN_TARGET", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yml").write_text(
        "repos: {}\niq_cli_scan_target:\n  - yarn.lock\n  - package.json\n", encoding="utf-8"
    )

    config = load_project_config(tmp_path / "config.yml")

    assert config.iq_cli_scan_target == ("yarn.lock", "package.json")


def test_an_unset_scan_target_defers_to_the_ecosystem(tmp_path, monkeypatch):
    """No single path is right for both Java and Node, so the default is 'work it out'."""
    from nexus_autofix.config import load_project_config

    monkeypatch.delenv("NEXUSFIX_IQ_CLI_SCAN_TARGET", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yml").write_text("repos: {}\n", encoding="utf-8")

    assert load_project_config(tmp_path / "config.yml").iq_cli_scan_target == ()
