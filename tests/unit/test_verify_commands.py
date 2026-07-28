import os
import platform
from pathlib import Path

from nexus_autofix.verify.commands import (
    BUILD_COMMANDS, TEST_COMMANDS, INSTALL_COMMANDS, CommandResult, run_command,
)


def test_gradle_build_command_uses_frozen_x_test():
    cmd = BUILD_COMMANDS["gradle"](Path("."))
    assert cmd[1:] == ["clean", "build", "-x", "test"]
    assert cmd[0] in {"./gradlew", "gradlew.bat"}


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
