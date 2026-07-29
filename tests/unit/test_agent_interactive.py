import logging
import subprocess

import pytest

from nexus_autofix.agent.interactive import (
    PROMPT_FILENAME,
    AgentAbortedError,
    InteractiveAgent,
)


def _repo(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    for args in (["init"], ["config", "user.email", "t@e.com"], ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "package.json").write_text('{"name":"d"}', encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=tmp_path, check=True, capture_output=True)
    return tmp_path


def _agent(answer="", on_wait=None):
    agent = InteractiveAgent()

    def fake_input(_prompt):
        if on_wait is not None:
            on_wait()
        return answer

    agent.input_fn = fake_input
    return agent


def test_changed_files_come_from_git_after_the_human_step(tmp_path):
    repo = _repo(tmp_path)
    agent = _agent(on_wait=lambda: (repo / "package.json").write_text('{"name":"e"}', encoding="utf-8"))

    result = agent.run(prompt="bump postcss", worktree=repo)

    assert result.changed_files == ["package.json"]


def test_the_prompt_file_is_removed_so_it_never_lands_in_the_diff(tmp_path):
    # git status --porcelain reports untracked files, so a leftover PROMPT.md would be
    # classified as part of the fix and committed onto the branch.
    repo = _repo(tmp_path)
    seen = {}
    agent = _agent(on_wait=lambda: seen.update(existed_during=(repo / PROMPT_FILENAME).exists()))

    result = agent.run(prompt="bump postcss", worktree=repo)

    assert seen["existed_during"] is True, "it must be there while the human works"
    assert not (repo / PROMPT_FILENAME).exists(), "and gone before git is consulted"
    assert PROMPT_FILENAME not in result.changed_files


def test_the_prompt_file_is_removed_even_when_the_step_is_aborted(tmp_path):
    repo = _repo(tmp_path)
    agent = _agent(answer="q")

    with pytest.raises(AgentAbortedError):
        agent.run(prompt="bump postcss", worktree=repo)

    assert not (repo / PROMPT_FILENAME).exists()


def test_aborting_raises_rather_than_reporting_no_changes(tmp_path):
    # Returning normally would surface as NO_CHANGES — "the agent ran and found nothing
    # to do" — which is not what happened.
    repo = _repo(tmp_path)
    with pytest.raises(AgentAbortedError, match="aborted"):
        _agent(answer="q").run(prompt="p", worktree=repo)


def test_no_terminal_raises_instead_of_silently_succeeding(tmp_path):
    repo = _repo(tmp_path)
    agent = InteractiveAgent()

    def no_tty(_prompt):
        raise EOFError()

    agent.input_fn = no_tty
    with pytest.raises(AgentAbortedError, match="needs a terminal"):
        agent.run(prompt="p", worktree=repo)


def test_the_prompt_is_logged_in_full_since_the_file_does_not_survive(tmp_path, caplog):
    repo = _repo(tmp_path)
    with caplog.at_level(logging.INFO):
        _agent().run(prompt="bump postcss to 8.5.18", worktree=repo)

    assert "bump postcss to 8.5.18" in caplog.text


def test_the_instructions_do_not_tell_you_to_use_the_blocked_flag(tmp_path, capsys):
    # --allow-all-tools is precisely what the org policy rejects; the whole point of this
    # mode is approving each action.
    repo = _repo(tmp_path)
    _agent().run(prompt="p", worktree=repo)

    printed = capsys.readouterr().out
    assert "copilot" in printed
    assert "--allow-all-tools" not in printed
    assert str(repo) in printed, "the cd target must be shown"
    assert "do NOT commit" in printed


def test_a_worktree_path_with_spaces_is_quoted_in_the_cd_instruction(tmp_path, capsys):
    repo = _repo(tmp_path / "my repo")
    _agent().run(prompt="p", worktree=repo)

    assert f'cd "{repo}"' in capsys.readouterr().out
