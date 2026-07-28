import pytest

from nexus_autofix.verify.toolchain import MissingToolchainError, resolve_java_env, resolve_node_env


def test_resolves_java_by_major_version():
    result = resolve_java_env("17.0.1", {"17": "/opt/jdk17", "21": "/opt/jdk21"}, base_env={"PATH": "/usr/bin"})
    assert result.env["JAVA_HOME"] == "/opt/jdk17"
    assert result.env["PATH"].startswith("/opt/jdk17/bin")
    assert result.env["PATH"].endswith("/usr/bin")


def test_missing_java_major_raises_naming_declared_and_configured():
    with pytest.raises(MissingToolchainError, match="17"):
        resolve_java_env("17.0.1", {"21": "/opt/jdk21"}, base_env={"PATH": ""})


def test_resolves_node_by_major_version():
    result = resolve_node_env("20.11.0", {"20": "/opt/node20"}, base_env={"PATH": "/usr/bin"})
    assert result.env["PATH"].startswith("/opt/node20")


def test_missing_node_major_raises():
    with pytest.raises(MissingToolchainError):
        resolve_node_env("18.0.0", {"20": "/opt/node20"}, base_env={"PATH": ""})
