
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


def test_missing_strategy_key_raises_value_error_not_key_error(tmp_path):
    path = tmp_path / "build.yaml"
    path.write_text("not_strategy: true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="strategy"):
        parse_trident_build_yaml(path)


# --- strategy.uses is written by hand, so match it forgivingly ---------------
# Reported live: a repo declared `uses: Gradle` and the run refused to start with
# "unrecognized ... strategy.uses value: 'Gradle'". Capitalising a build system's name is
# not a mistake worth failing a run over.


def _strategy(tmp_path, yaml_text):
    path = tmp_path / "build.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return parse_trident_build_yaml(path)


def test_a_capitalised_ecosystem_is_accepted(tmp_path):
    assert _strategy(tmp_path, "strategy:\n  uses: Gradle\n")[0].ecosystem == "gradle"


def test_an_uppercase_ecosystem_is_accepted(tmp_path):
    assert _strategy(tmp_path, "strategy:\n  uses: MAVEN\n")[0].ecosystem == "maven"


def test_surrounding_whitespace_is_ignored(tmp_path):
    assert _strategy(tmp_path, 'strategy:\n  uses: "  npm  "\n')[0].ecosystem == "npm"


def test_a_version_suffix_still_resolves_when_capitalised(tmp_path):
    assert _strategy(tmp_path, "strategy:\n  uses: Gradle@v2\n")[0].ecosystem == "gradle"


def test_the_normalised_ecosystem_matches_the_build_command_tables(tmp_path):
    # The point of normalising: BUILD_COMMANDS/TEST_COMMANDS are keyed on the lowercase
    # name, so anything else would resolve here and then KeyError later.
    from nexus_autofix.verify.commands import BUILD_COMMANDS, TEST_COMMANDS

    ecosystem = _strategy(tmp_path, "strategy:\n  uses: Gradle\n")[0].ecosystem
    assert ecosystem in BUILD_COMMANDS
    assert ecosystem in TEST_COMMANDS


def test_a_capitalised_toolchain_key_is_read(tmp_path):
    strategy = _strategy(
        tmp_path, "strategy:\n  uses: Gradle\n  with:\n    Java-Version: '17'\n"
    )[0]
    assert strategy.toolchain == {"java": "17"}


def test_an_empty_with_block_is_not_an_error(tmp_path):
    # `with:` present but empty parses to None, not {} — the same nulls-vs-missing trap.
    strategy = _strategy(tmp_path, "strategy:\n  uses: Gradle\n  with:\n")[0]
    assert strategy.toolchain == {}


def test_a_genuinely_unknown_ecosystem_still_fails_and_says_case_is_ignored(tmp_path):
    with pytest.raises(ValueError, match="case-insensitively"):
        _strategy(tmp_path, "strategy:\n  uses: Cargo\n")
