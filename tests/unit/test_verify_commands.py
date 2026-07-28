import os
import platform
from pathlib import Path

from nexus_autofix.verify.commands import (
    BUILD_COMMANDS, TEST_COMMANDS, INSTALL_COMMANDS, CommandResult, resolve_program, run_command,
)


def test_gradle_build_command_uses_frozen_x_test(tmp_path):
    cmd = BUILD_COMMANDS["gradle"](tmp_path)
    assert cmd[1:] == ["clean", "build", "-x", "test"]
    # Wrapper is addressed by full path inside the repo, with the platform's suffix —
    # a bare/relative name is resolved against the wrong directory on Windows.
    expected = "gradlew.bat" if platform.system() == "Windows" else "gradlew"
    assert cmd[0] == str(tmp_path / expected)


def test_maven_build_command_uses_the_repo_local_wrapper(tmp_path):
    cmd = BUILD_COMMANDS["maven"](tmp_path)
    expected = "mvnw.cmd" if platform.system() == "Windows" else "mvnw"
    assert cmd[0] == str(tmp_path / expected)


def test_resolve_program_leaves_explicit_paths_untouched(tmp_path):
    explicit = str(tmp_path / "gradlew")
    assert resolve_program(explicit) == explicit


def test_resolve_program_finds_a_bare_name_on_path(tmp_path):
    tool = tmp_path / "faketool"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    assert resolve_program("faketool", {"PATH": str(tmp_path)}) == str(tool)


def test_resolve_program_returns_the_name_unchanged_when_not_found():
    assert resolve_program("definitely-not-installed-xyz", {"PATH": ""}) == "definitely-not-installed-xyz"


def test_npm_verify_uses_ci_never_install():
    assert BUILD_COMMANDS["npm"](Path(".")) == ["npm", "ci"]
    assert INSTALL_COMMANDS["npm"](Path(".")) == ["npm", "install"]


def test_yarn_test_command():
    assert TEST_COMMANDS["yarn"](Path(".")) == ["yarn", "test"]


def test_run_command_captures_output_and_success(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    result = run_command(["python3", "-c", "print('hello'); import sys; sys.exit(0)"], tmp_path, env, 10)
    assert isinstance(result, CommandResult)
    assert result.success is True
    assert "hello" in result.stdout


def test_run_command_captures_failure(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    result = run_command(["python3", "-c", "import sys; sys.exit(1)"], tmp_path, env, 10)
    assert result.success is False
    assert result.returncode == 1


def test_missing_executable_becomes_a_normal_failure_not_an_exception(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    result = run_command(["definitely-not-a-real-command-xyz"], tmp_path, env, 10)
    assert result.success is False
    assert result.returncode == 127
    assert "command not found" in result.stderr


def test_timeout_becomes_a_normal_failure_not_an_exception(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    result = run_command(["python3", "-c", "import time; time.sleep(30)"], tmp_path, env, 1)
    assert result.success is False
    assert result.returncode == 124
    assert "[TIMEOUT after 1s]" in result.stderr


def test_tail_returns_last_n_lines(tmp_path):
    env = {"PATH": os.environ.get("PATH", "")}
    script = "for i in range(300): print(i)"
    result = run_command(["python3", "-c", script], tmp_path, env, 10)
    tail = result.tail(lines=5)
    assert tail.splitlines()[-1] == "299"
    assert len(tail.splitlines()) == 5
