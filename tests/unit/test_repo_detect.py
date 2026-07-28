import pytest

from nexus_autofix.repo.detect import RepoHygieneError, detect_ecosystems, detect_java_build, detect_js_manager


def test_detects_npm_from_package_lock(tmp_path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result.ecosystem == "npm"


def test_detects_yarn_berry_when_yarnrc_present(tmp_path):
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    (tmp_path / ".yarnrc.yml").write_text("", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result.ecosystem == "yarn"


def test_two_lockfiles_raises_hygiene_error(tmp_path):
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    (tmp_path / "yarn.lock").write_text("", encoding="utf-8")
    with pytest.raises(RepoHygieneError):
        detect_js_manager(tmp_path)


def test_detects_maven_over_gradle_when_both_absent_prefers_pom(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    result = detect_java_build(tmp_path)
    assert result.ecosystem == "maven"


def test_skips_node_modules_and_build_dirs(tmp_path):
    nested = tmp_path / "node_modules" / "pkg"
    nested.mkdir(parents=True)
    (nested / "package-lock.json").write_text("{}", encoding="utf-8")
    result = detect_js_manager(tmp_path)
    assert result is None


def test_detect_ecosystems_returns_all_found(tmp_path):
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
    results = detect_ecosystems(tmp_path)
    assert {r.ecosystem for r in results} == {"gradle", "npm"}
