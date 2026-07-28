import pytest

from nexus_autofix.verify.toolchain import MissingToolchainError, resolve_java_env, resolve_node_env


def _fake_jdk(root, name: str, version: str = "17.0.1") -> str:
    home = root / name
    (home / "bin").mkdir(parents=True)
    java = home / "bin" / "java"
    # Executable, and answering `java -version` on stderr the way a real JDK does,
    # so both shutil.which() discovery and version detection behave realistically.
    java.write_text(f'#!/bin/sh\necho \'openjdk version "{version}"\' >&2\n', encoding="utf-8")
    java.chmod(0o755)
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


def test_unconfigured_major_falls_back_to_java_home(tmp_path):
    # Nothing configured for 17: use the ambient JDK rather than demanding config.
    ambient = _fake_jdk(tmp_path, "ambient-jdk")
    result = resolve_java_env(
        "17.0.1", {}, base_env={"PATH": "/usr/bin", "JAVA_HOME": ambient}
    )
    assert result.env["JAVA_HOME"] == ambient
    assert result.env["PATH"].startswith(f"{ambient}/bin")


def test_unconfigured_major_falls_back_to_java_on_path(tmp_path):
    ambient = _fake_jdk(tmp_path, "ambient-jdk")
    result = resolve_java_env("17.0.1", {}, base_env={"PATH": f"{ambient}/bin"})
    assert result.env["JAVA_HOME"] == ambient


def test_configured_major_wins_over_ambient_java_home(tmp_path):
    configured = _fake_jdk(tmp_path, "configured-jdk")
    ambient = _fake_jdk(tmp_path, "ambient-jdk")
    result = resolve_java_env(
        "17.0.1", {"17": configured}, base_env={"PATH": "/usr/bin", "JAVA_HOME": ambient}
    )
    assert result.env["JAVA_HOME"] == configured


def test_raises_only_when_no_jdk_can_be_found_at_all():
    with pytest.raises(MissingToolchainError, match="no JDK could be found"):
        resolve_java_env("17.0.1", {}, base_env={"PATH": ""})


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


def test_unconfigured_node_major_falls_back_to_node_on_path(tmp_path):
    ambient = tmp_path / "ambient-node"
    ambient.mkdir()
    node_bin = ambient / "node"
    node_bin.write_text("#!/bin/sh\necho v20.0.0\n", encoding="utf-8")
    node_bin.chmod(0o755)
    result = resolve_node_env("20.11.0", {}, base_env={"PATH": str(ambient)})
    assert result.env["PATH"].startswith(str(ambient))


def test_node_raises_only_when_node_is_nowhere_on_path():
    with pytest.raises(MissingToolchainError, match="no 'node' was found"):
        resolve_node_env("20.11.0", {}, base_env={"PATH": ""})


def test_configured_node_path_that_does_not_exist_raises(tmp_path):
    missing = str(tmp_path / "gone")
    with pytest.raises(MissingToolchainError, match="does not exist"):
        resolve_node_env("20.11.0", {"20": missing}, base_env={"PATH": ""})
