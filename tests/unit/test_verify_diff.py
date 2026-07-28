import os
import subprocess
from pathlib import Path

import pytest

from nexus_autofix.verify import diff as diff_module
from nexus_autofix.verify.diff import (
    DiffClass,
    _emptied_state,
    _looks_like_test_file,
    _unquote_git_path,
    classify_diff,
)


def _git(args, cwd):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True, encoding="utf-8")


def _init_repo(tmp_path: Path) -> Path:
    _git(["init"], tmp_path)
    _git(["config", "user.email", "t@example.com"], tmp_path)
    _git(["config", "user.name", "t"], tmp_path)
    (tmp_path / "build.gradle").write_text("dependencies {}\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "test").mkdir()
    (tmp_path / "src" / "test" / "FooTest.java").write_text("class FooTest { void t() {} }\n", encoding="utf-8")
    _git(["add", "-A"], tmp_path)
    _git(["commit", "-m", "init"], tmp_path)
    return tmp_path


def test_manifest_only_change_classified_manifest_only(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text("dependencies { implementation 'x:y:2.0' }\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.MANIFEST_ONLY


def test_source_file_change_classified_source_touched(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SOURCE_TOUCHED


def test_deleted_test_file_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").unlink()
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("deleted" in reason for reason in result.suspicious_reasons)


def test_disabled_annotation_added_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        "class FooTest { @Disabled void t() {} }\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


def test_trident_build_yaml_modification_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".trident").mkdir()
    (repo / ".trident" / "build.yaml").write_text("strategy:\n  uses: gradle\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "add trident"], repo)
    (repo / ".trident" / "build.yaml").write_text("strategy:\n  uses: maven\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(".trident" in reason for reason in result.suspicious_reasons)


def test_legacy_peer_deps_flag_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".npmrc").write_text("legacy-peer-deps=true\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


# --- extra false-negative checks beyond the 6 required cases ---


def test_pytest_mark_skip_with_reason_argument_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "test_foo.py").write_text(
        '@pytest.mark.skip(reason="flaky")\ndef test_foo():\n    pass\n', encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


def test_disabled_annotation_with_argument_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        'class FooTest { @Disabled("flaky") void t() {} }\n', encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


def test_disabled_with_other_args_before_enabled_false_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        'class FooTest { @Test(groups = "flaky", enabled = false) void t() {} }\n', encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS


def test_test_file_emptied_to_whitespace_only_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text("   \n\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("deleted" in reason for reason in result.suspicious_reasons)


def test_test_file_renamed_away_from_test_shape_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    # Moved out of the test/ directory *and* off the Test.java naming
    # convention -- neither TEST_PATH_HINT nor TEST_FILENAME_PATTERN would
    # recognize the new path as a test file, which is exactly how a rename
    # could quietly remove a file from test discovery.
    _git(["mv", "src/test/FooTest.java", "src/FooOld.txt"], repo)
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("deleted" in reason for reason in result.suspicious_reasons)


# ---------------------------------------------------------------------------
# Regression tests for the adversarial-review fix pass.
# Each block below maps to one numbered gap the reviewer reproduced.
# ---------------------------------------------------------------------------


# --- (1) test-file recognition beyond Java/Python/JS ---


def test_go_test_file_deletion_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "pkg").mkdir()
    (repo / "pkg" / "foo_test.go").write_text("package pkg\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "add go test"], repo)
    (repo / "pkg" / "foo_test.go").unlink()
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("foo_test.go" in reason for reason in result.suspicious_reasons)


@pytest.mark.parametrize(
    "path",
    [
        "pkg/foo_test.go",
        "app/FooTest.kt",
        "app/FooSpec.scala",
        "app/FooIT.java",
        "app/FooITCase.java",
        "app/FooSpec.groovy",
        "src/integrationTest/java/Foo.java",
        "src/androidTest/java/Foo.java",
        "src/testFixtures/java/Foo.java",
    ],
)
def test_looks_like_test_file_recognizes_extended_shapes(path):
    assert _looks_like_test_file(path)


@pytest.mark.parametrize("path", ["src/main/java/Foo.java", "pkg/foo.go", "app/Main.kt"])
def test_looks_like_test_file_rejects_ordinary_source(path):
    assert not _looks_like_test_file(path)


# --- (2) @Test(enabled=false) with nested parens ---


def test_test_annotation_with_nested_call_and_enabled_false_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        "class FooTest {\n  @Test(timeOut = getTimeout(), enabled = false)\n  void t() {}\n}\n",
        encoding="utf-8",
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("enabled=false" in reason for reason in result.suspicious_reasons)


def test_fully_qualified_test_annotation_with_enabled_false_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        "class FooTest {\n"
        "  @org.testng.annotations.Test(dataProvider = provider(), enabled = false)\n"
        "  void t() {}\n}\n",
        encoding="utf-8",
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("enabled=false" in reason for reason in result.suspicious_reasons)


# --- (3) untracked test files reach the structural deleted/emptied check ---


def test_untracked_whitespace_only_test_file_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "BarTest.java").write_text("   \n\n\t\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(
        "BarTest.java" in reason and "whitespace-only" in reason
        for reason in result.suspicious_reasons
    )


# --- (4) non-ASCII / quoted paths ---


def test_unquote_git_path_decodes_c_style_octal_escapes():
    assert _unquote_git_path(r'"Caf\303\251Test.java"') == "CaféTest.java"
    assert _unquote_git_path("plain/path.java") == "plain/path.java"


def test_non_ascii_test_file_emptied_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    target = repo / "src" / "test" / "CaféTest.java"
    target.write_text("class CafeTest { void t() {} }\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "add non-ascii test"], repo)
    target.write_text("   \n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("whitespace-only" in r or "could not be resolved" in r for r in result.suspicious_reasons)


def test_path_resolution_failure_is_not_treated_as_clean(tmp_path):
    # A path git reports as changed but that cannot be resolved on disk must be
    # flagged, never silently read as "not emptied".
    emptied, error = _emptied_state(tmp_path / "does" / "not" / "exist.java")
    assert emptied is False
    assert error is not None


# --- (5) config / CI file coverage ---


@pytest.mark.parametrize(
    "rel_path",
    [
        "src/.gitignore",
        ".gitlab-ci.yml",
        "Jenkinsfile",
        "ci/Jenkinsfile.groovy",
        "azure-pipelines.yml",
        "azure-pipelines-nightly.yml",
        ".circleci/config.yml",
    ],
)
def test_ci_and_gitignore_files_at_any_depth_are_suspicious(tmp_path, rel_path):
    repo = _init_repo(tmp_path)
    target = repo / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("stages: []\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("CI config" in reason for reason in result.suspicious_reasons)


def test_any_file_under_trident_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / ".trident").mkdir()
    (repo / ".trident" / "extra.yaml").write_text("k: v\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(".trident/" in reason for reason in result.suspicious_reasons)


# --- (6) resolutionStrategy block form ---


def test_resolution_strategy_force_block_form_is_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text(
        "dependencies {}\n"
        "configurations.all {\n"
        "    resolutionStrategy {\n"
        "        force 'com.example:lib:1.2.3'\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("resolutionStrategy" in reason for reason in result.suspicious_reasons)


def test_resolution_strategy_dotted_form_still_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text(
        "configurations.all.resolutionStrategy.force 'com.example:lib:1.2.3'\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("resolutionStrategy" in reason for reason in result.suspicious_reasons)


# --- (7) version ranges: real hits, and the critical negative control ---


@pytest.mark.parametrize(
    ("filename", "content", "expected"),
    [
        ("build.gradle", "dependencies { implementation 'com.example:lib:1.2.+' }\n", "1.2.+"),
        ("build.gradle", "dependencies { implementation 'com.example:lib:+' }\n", "+"),
        ("build.gradle", "dependencies { implementation 'com.example:lib:latest.release' }\n", "latest.release"),
        ("pom.xml", "<dependency><version>[1.0,2.0)</version></dependency>\n", "[1.0,2.0)"),
        ("pom.xml", "<dependency><version>(1.0,2.0]</version></dependency>\n", "(1.0,2.0]"),
        ("pom.xml", "<dependency><version>LATEST</version></dependency>\n", "LATEST"),
        ("pom.xml", "<dependency><version>RELEASE</version></dependency>\n", "RELEASE"),
        ("package.json", '{ "dependencies": { "lodash": "*" } }\n', "*"),
        ("package.json", '{ "dependencies": { "lodash": "latest" } }\n', "latest"),
        ("package.json", '{ "dependencies": { "lodash": "x" } }\n', "x"),
    ],
)
def test_open_version_ranges_are_suspicious(tmp_path, filename, content, expected):
    repo = _init_repo(tmp_path)
    (repo / filename).write_text(content, encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(
        f"open/dynamic version range: {expected}" in reason for reason in result.suspicious_reasons
    ), result.suspicious_reasons


@pytest.mark.parametrize(
    "snippet",
    [
        "    return calc(arr[0], 2);\n",
        "    int total = sum(values[1], other[2]);\n",
        "    foo(bar[0], baz);\n",
        "    const x = items[0], y = 2;\n",
    ],
)
def test_ordinary_array_index_code_is_not_a_version_range(tmp_path, snippet):
    # The old pattern fired on any `[digit...,...)` shape, which would make the
    # SUSPICIOUS gate cry wolf on nearly every real Java/JS diff.
    repo = _init_repo(tmp_path)
    (repo / "src" / "Main.java").write_text("class Main {\n" + snippet + "}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert not any("version range" in reason for reason in result.suspicious_reasons), (
        result.suspicious_reasons
    )
    assert result.classification == DiffClass.SOURCE_TOUCHED


def test_pinned_versions_in_manifests_are_not_flagged(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text(
        "dependencies { implementation 'com.example:lib:1.2.3' }\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.MANIFEST_ONLY


# --- (8) additional test-disabling idioms ---


@pytest.mark.parametrize(
    ("filename", "content", "label"),
    [
        ("src/test/foo.test.js", "it.only('a', () => {});\n", ".only("),
        ("src/test/foo.test.js", "describe.only('a', () => {});\n", ".only("),
        ("src/test/foo.test.js", "test.skip('a', () => {});\n", "test.skip("),
        ("src/test/foo.test.js", "xdescribe('a', () => {});\n", "xdescribe("),
        ("src/test/test_foo.py", "@unittest.skip('x')\ndef test_a():\n    pass\n", "@unittest.skip"),
        ("src/test/test_foo.py", "def test_a():\n    pytest.skip('x')\n", "pytest.skip("),
        ("pkg/foo_test.go", "func TestA(t *testing.T) {\n\tt.SkipNow()\n}\n", "t.Skip("),
        ("pkg/foo_test.go", "func TestA(t *testing.T) {\n\tt.Skipf(\"x\")\n}\n", "t.Skip("),
        ("build.gradle", "test {\n    enabled = false\n}\n", "gradle test"),
        ("build.gradle", "task foo {\n    onlyIf { false }\n}\n", "onlyIf"),
        ("pom.xml", "<configuration><skipTests>true</skipTests></configuration>\n", "skipTests"),
        ("pom.xml", "<configuration><skip>true</skip></configuration>\n", "<skip>"),
    ],
)
def test_additional_test_disabling_idioms_are_suspicious(tmp_path, filename, content, label):
    repo = _init_repo(tmp_path)
    target = repo / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(label in reason for reason in result.suspicious_reasons), result.suspicious_reasons


# --- (9) unreadable / oversized / binary files ---


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read chmod 000 files")
def test_unreadable_untracked_file_is_suspicious_not_a_crash(tmp_path):
    repo = _init_repo(tmp_path)
    blocked = repo / "src" / "secret.java"
    blocked.write_text("class Secret {}\n", encoding="utf-8")
    blocked.chmod(0o000)
    try:
        result = classify_diff(repo)
    finally:
        blocked.chmod(0o644)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any(
        "secret.java" in reason and "could not be read" in reason
        for reason in result.suspicious_reasons
    ), result.suspicious_reasons


def test_oversized_untracked_file_is_flagged_for_manual_review(tmp_path, monkeypatch):
    monkeypatch.setattr(diff_module, "MAX_SCAN_BYTES", 16)
    repo = _init_repo(tmp_path)
    (repo / "src" / "Big.java").write_text("x" * 512, encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("review manually" in reason for reason in result.suspicious_reasons)


def test_binary_untracked_file_is_not_text_scanned(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "blob.bin").write_bytes(b"\x00\x01@Disabled it.only( \x00")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SOURCE_TOUCHED
    assert result.suspicious_reasons == []


# --- (10) only added (+) lines are scanned ---


def test_removing_disabled_annotation_is_not_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    target = repo / "src" / "test" / "FooTest.java"
    target.write_text("class FooTest {\n  @Disabled\n  void t() {}\n}\n", encoding="utf-8")
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "disable"], repo)
    # Re-enabling the test removes the annotation -- a `-@Disabled` line.
    target.write_text("class FooTest {\n  void t() {}\n}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SOURCE_TOUCHED
    assert result.suspicious_reasons == []


def test_removing_open_version_range_is_not_suspicious(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "build.gradle").write_text(
        "dependencies { implementation 'com.example:lib:1.2.+' }\n", encoding="utf-8"
    )
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "loose version"], repo)
    (repo / "build.gradle").write_text(
        "dependencies { implementation 'com.example:lib:1.2.3' }\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.MANIFEST_ONLY
    assert result.suspicious_reasons == []


def test_context_lines_are_not_scanned(tmp_path):
    # `@Disabled` is untouched context around a real edit; it must not be
    # reported as a newly added marker.
    repo = _init_repo(tmp_path)
    target = repo / "src" / "test" / "FooTest.java"
    target.write_text(
        "class FooTest {\n  @Disabled\n  void t() {}\n  // tail\n}\n", encoding="utf-8"
    )
    _git(["add", "-A"], repo)
    _git(["commit", "-m", "base"], repo)
    target.write_text(
        "class FooTest {\n  @Disabled\n  void t() {}\n  // changed tail\n}\n", encoding="utf-8"
    )
    result = classify_diff(repo)
    assert result.classification == DiffClass.SOURCE_TOUCHED
    assert result.suspicious_reasons == []


# --- (11) reasons name the offending file ---


def test_reasons_are_attributed_to_the_offending_file(tmp_path):
    repo = _init_repo(tmp_path)
    (repo / "src" / "test" / "FooTest.java").write_text(
        "class FooTest { @Disabled void t() {} }\n", encoding="utf-8"
    )
    (repo / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    marker_reasons = [r for r in result.suspicious_reasons if "@Disabled" in r]
    assert marker_reasons
    assert all(r.startswith("src/test/FooTest.java:") for r in marker_reasons), marker_reasons


# --- (12) waiver / suppression filename hints ---


@pytest.mark.parametrize(
    "rel_path",
    [
        "policy/waivers.json",
        "policy/suppressions.xml",
        "policy/allowlist.json",
        "policy/whitelist.json",
        "policy/false-positive.json",
        "policy/false_positives.yml",
        "policy/nexus-iq-config.yml",
        "policy/nexusiq.json",
        "policy/clm-policy.json",
    ],
)
def test_waiver_style_filenames_are_suspicious(tmp_path, rel_path):
    repo = _init_repo(tmp_path)
    target = repo / rel_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{}\n", encoding="utf-8")
    result = classify_diff(repo)
    assert result.classification == DiffClass.SUSPICIOUS
    assert any("waiver/suppression" in reason for reason in result.suspicious_reasons)
