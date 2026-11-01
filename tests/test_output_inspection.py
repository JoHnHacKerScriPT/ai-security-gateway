from __future__ import annotations

from app.guardrails.output_inspection import inspect_output


def test_clean_anthropic_style_response_passes():
    payload = {"content": [{"type": "text", "text": "The capital of France is Paris."}]}
    finding = inspect_output(payload)
    assert not finding.blocked


def test_aws_access_key_is_blocked():
    payload = {"choices": [{"message": {"content": "Here is a key: AKIAABCDEFGHIJKLMNOP"}}]}
    finding = inspect_output(payload)
    assert finding.blocked
    assert any("aws_access_key_id" in r for r in finding.reasons)


def test_anthropic_style_api_key_leak_is_blocked():
    payload = {"content": [{"type": "text", "text": "Use sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}]}
    finding = inspect_output(payload)
    assert finding.blocked


def test_ssh_private_key_is_blocked():
    payload = {"content": [{"type": "text", "text": "-----BEGIN RSA PRIVATE KEY-----\nMIIB..."}]}
    finding = inspect_output(payload)
    assert finding.blocked
    assert any("ssh_private_key" in r for r in finding.reasons)


def test_insecure_eval_code_is_blocked_by_default():
    payload = {"choices": [{"message": {"content": "You can run it with eval(user_input) in Python."}}]}
    finding = inspect_output(payload)
    assert finding.blocked
    assert any("python_eval" in r for r in finding.reasons)


def test_subprocess_shell_true_is_blocked():
    payload = {"content": [{"type": "text", "text": "subprocess.run(cmd, shell=True)"}]}
    finding = inspect_output(payload)
    assert finding.blocked
