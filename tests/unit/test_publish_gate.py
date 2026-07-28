from nexus_autofix.publish.gate import GateMode, present_pre_pr_gate


def test_approve_returns_true_on_y(capsys):
    approved = present_pre_pr_gate("summary text", prompt_fn=lambda _: "y")
    assert approved is True
    assert "summary text" in capsys.readouterr().out


def test_reject_returns_false_on_anything_else():
    assert present_pre_pr_gate("summary", prompt_fn=lambda _: "n") is False
    assert present_pre_pr_gate("summary", prompt_fn=lambda _: "") is False


def test_gate_mode_values():
    assert {m.value for m in GateMode} == {"none", "pre-pr", "pre-push"}
