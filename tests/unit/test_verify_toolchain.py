import pytest

from nexus_autofix.verify.toolchain import MissingToolchainError, resolve_java_env, resolve_node_env


def _fake_jdk(root, name: str) -> str:
    home = root / name
    (home / "bin").mkdir(parents=True)
    (home / "bin" / "java").write_text("#!/bin/sh\n", encoding="utf-8")
    return str(home)


def _fake_node_dir(root, name: str) -> str:
    node_dir = root / name
    node_dir.mkdir(parents=True)
    return str(node_dir)


def test_resolves_java_by_major_version(tmp_path):
    jdk17 = _fake_jdk(tmp_path, "jdk17")
    jdk21 = _fake_jdk(tmp_path, "jdk21")
    result = resolve_java_env("17.0.1", {"17": jdk17, "21": jdk21}, base_env={"PATH": "/usr/bin"})
    assert result.env["JAVA_HOME"] == jdk17
    assert result.env["PATH"].startswith(f"{jdk17}/bin")
    assert result.env["PATH"].endswith("/usr/bin")


def test_missing_java_major_raises_naming_declared_and_configured(tmp_path):
    with pytest.raises(MissingToolchainError, match="17"):
        resolve_java_env("17.0.1", {"21": _fake_jdk(tmp_path, "jdk21")}, base_env={"PATH": ""})


def test_configured_java_path_that_does_not_exist_raises(tmp_path):
    missing = str(tmp_path / "definitely-not-here")
    with pytest.raises(MissingToolchainError, match="does not exist"):
        resolve_java_env("17.0.1", {"17": missing}, base_env={"PATH": ""})


def test_configured_java_path_without_bin_java_raises(tmp_path):
    not_a_jdk = tmp_path / "not-a-jdk"
    not_a_jdk.mkdir()
    with pytest.raises(MissingToolchainError, match="no bin/java"):
        resolve_java_env("17.0.1", {"17": str(not_a_jdk)}, base_env={"PATH": ""})


def test_resolves_node_by_major_version(tmp_path):
    node20 = _fake_node_dir(tmp_path, "node20")
    result = resolve_node_env("20.11.0", {"20": node20}, base_env={"PATH": "/usr/bin"})
    assert result.env["PATH"].startswith(node20)


def test_missing_node_major_raises(tmp_path):
    with pytest.raises(MissingToolchainError):
        resolve_node_env("18.0.0", {"20": _fake_node_dir(tmp_path, "node20")}, base_env={"PATH": ""})


def test_configured_node_path_that_does_not_exist_raises(tmp_path):
    missing = str(tmp_path / "gone")
    with pytest.raises(MissingToolchainError, match="does not exist"):
        resolve_node_env("20.11.0", {"20": missing}, base_env={"PATH": ""})
