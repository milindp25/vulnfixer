import subprocess
from pathlib import Path

from nexus_autofix.verify.diff import DiffClass, classify_diff


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
