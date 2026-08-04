"""Discovery of the contract-test tasks a plain `gradlew test` does not run."""

from pathlib import Path
from unittest.mock import patch

from nexus_autofix.verify.commands import (
    CommandResult,
    _is_contract_test_task,
    discover_contract_test_tasks,
    parse_gradle_tasks,
)

# Captured from a real `gradlew tasks --all`, trimmed. The Build-tasks entries are the
# trap: `contractTestConsumerClasses` COMPILES the contract tests and reports success
# without running anything.
REAL_OUTPUT = """
Build tasks
-----------
assemble - Assembles the outputs of this project.
build - Assembles and tests this project.
classes - Assembles main classes.
contractTestConsumerClasses - Assembles contract test consumer classes.
contractTestProviderClasses - Assembles contract test provider classes.
testClasses - Assembles test classes.

Documentation tasks
-------------------
javadoc - Generates Javadoc API documentation.

Publishing tasks
----------------
publish - Publishes all publications.

Verification tasks
------------------
check - Runs all checks.
contractTestConsumer - Runs the consumer contract tests
contractTestProvider - Runs the provider contract tests
test - Runs the test suite.

Other tasks
-----------
compileContractTestConsumerJava - Compiles contract test consumer Java source.
"""


def test_both_the_consumer_and_the_provider_contract_tests_are_selected():
    pairs = parse_gradle_tasks(REAL_OUTPUT)
    selected = [task for section, task in pairs if _is_contract_test_task(section, task)]

    assert selected == ["contractTestConsumer", "contractTestProvider"]


def test_the_classes_tasks_are_never_selected():
    """They compile the contract tests. Running one proves nothing and passes, which
    turns "we now run your contract tests" into a no-op that looks like coverage."""
    for task in ("contractTestConsumerClasses", "contractTestProviderClasses", "testClasses"):
        assert _is_contract_test_task("build", task) is False


def test_compile_tasks_are_never_selected():
    assert _is_contract_test_task("other", "compileContractTestConsumerJava") is False


def test_test_and_check_are_not_re_run():
    """`test` is the main command; `check` would re-run it plus everything else."""
    for task in ("test", "check", "build"):
        assert _is_contract_test_task("verification", task) is False


def test_linters_under_verification_are_not_run_as_tests():
    """checkstyle and jacoco are the repo's own build policy, not this tool's business."""
    for task in ("checkstyleMain", "jacocoTestReport", "spotbugsMain", "pmdMain"):
        assert _is_contract_test_task("verification", task) is False


def test_an_ungrouped_contract_task_is_still_found():
    """A task wired into neither `test` nor `check` and given no group lands under
    "Other tasks" — invisible to `check --dry-run` and to `tasks --group verification`."""
    output = """
Other tasks
-----------
contractTest - Consumer-driven contract tests
"""
    pairs = parse_gradle_tasks(output)
    assert [t for s, t in pairs if _is_contract_test_task(s, t)] == ["contractTest"]


def test_integration_and_other_broad_tests_are_NOT_run():
    """Contract tests are self-contained; these need the other systems up, so running
    them from a developer machine fails for reasons unrelated to the dependency change.
    A red check nobody believes is worse than no check."""
    for task in ("integrationTest", "componentTest", "e2eTest", "acceptanceTest",
                 "smokeTest", "apiTest", "systemTest"):
        assert _is_contract_test_task("verification", task) is False, task


def test_a_non_test_task_under_verification_is_left_alone():
    output = """
Verification tasks
------------------
dependencyCheckAnalyze - Scans dependencies
"""
    pairs = parse_gradle_tasks(output)
    assert [t for s, t in pairs if _is_contract_test_task(s, t)] == []


def test_section_headings_and_rules_are_not_read_as_tasks():
    assert ("verification", "------------------") not in parse_gradle_tasks(REAL_OUTPUT)
    assert all(not set(task) <= {"-"} for _, task in parse_gradle_tasks(REAL_OUTPUT))


def test_a_multi_project_build_does_not_run_the_same_task_twice():
    output = """
Verification tasks
------------------
app:contractTestConsumer - Runs them
lib:contractTestConsumer - Runs them
"""
    with patch("nexus_autofix.verify.commands.run_command",
               return_value=CommandResult(0, output, "")):
        tasks = discover_contract_test_tasks(Path("/repo"), {}, 60)

    assert tasks == ["app:contractTestConsumer", "lib:contractTestConsumer"]


def test_a_failed_task_listing_degrades_to_running_nothing_extra(caplog):
    """An enhancement to verification must never be the reason a run cannot proceed."""
    import logging

    with caplog.at_level(logging.WARNING, logger="nexus_autofix.verify.commands"), \
            patch("nexus_autofix.verify.commands.run_command",
                  return_value=CommandResult(1, "", "boom")):
        tasks = discover_contract_test_tasks(Path("/repo"), {}, 60)

    assert tasks == []
    assert "will not be run" in caplog.text
