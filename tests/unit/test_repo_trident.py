from pathlib import Path

import pytest

from nexus_autofix.repo.trident import parse_trident_build_yaml


def test_parses_gradle_strategy_with_nested_with_block(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: gradle\n  with:\n    java-version: 17.0.1\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert len(strategies) == 1
    assert strategies[0].ecosystem == "gradle"
    assert strategies[0].toolchain == {"java": "17.0.1"}


def test_parses_yarn_strategy_and_strips_version_suffix(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: yarn@v2\n  with:\n    node-version: 20.11.0\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert strategies[0].ecosystem == "yarn"
    assert strategies[0].toolchain == {"node": "20.11.0"}


def test_multiple_strategy_entries_produce_one_per_entry(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n"
        "  - uses: gradle\n    with:\n      java-version: 17.0.1\n"
        "  - uses: yarn\n    with:\n      node-version: 20.11.0\n",
        encoding="utf-8",
    )
    strategies = parse_trident_build_yaml(path)
    assert [s.ecosystem for s in strategies] == ["gradle", "yarn"]


def test_unknown_uses_value_raises_naming_the_value(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text("strategy:\n  uses: bazel\n", encoding="utf-8")
    with pytest.raises(ValueError, match="bazel"):
        parse_trident_build_yaml(path)


def test_tolerates_top_level_version_keys_alongside_with_block(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text(
        "strategy:\n  uses: gradle\n  java-version: 17.0.1\n", encoding="utf-8"
    )
    strategies = parse_trident_build_yaml(path)
    assert strategies[0].toolchain == {"java": "17.0.1"}
