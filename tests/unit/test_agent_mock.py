from pathlib import Path

from nexus_autofix.agent.mock import MockAgent, MockMode


def test_applies_fix_writes_file_and_reports_it(tmp_path):
    agent = MockAgent(mode=MockMode.APPLIES_FIX, fix_file="build.gradle", fix_content="dependencies { x }")
    result = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert (tmp_path / "build.gradle").read_text(encoding="utf-8") == "dependencies { x }"
    assert result.changed_files == ["build.gradle"]


def test_no_changes_mode_touches_nothing(tmp_path):
    agent = MockAgent(mode=MockMode.NO_CHANGES)
    result = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert result.changed_files == []
    assert list(tmp_path.iterdir()) == []


def test_deletes_test_mode_removes_the_named_file(tmp_path):
    test_file = tmp_path / "FooTest.java"
    test_file.write_text("class FooTest {}", encoding="utf-8")
    agent = MockAgent(mode=MockMode.DELETES_TEST, test_file_to_delete="FooTest.java")
    agent.run(prompt="irrelevant", worktree=tmp_path)
    assert not test_file.exists()


def test_fails_then_fixes_mode_writes_nothing_on_first_call_and_fix_on_second(tmp_path):
    agent = MockAgent(mode=MockMode.FAILS_THEN_FIXES, fix_file="build.gradle", fix_content="fixed")
    first = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert first.changed_files == []
    second = agent.run(prompt="irrelevant", worktree=tmp_path)
    assert second.changed_files == ["build.gradle"]
    assert (tmp_path / "build.gradle").read_text(encoding="utf-8") == "fixed"
