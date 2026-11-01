"""Output inspection (Layer 4): scans whatever the upstream AI model
returned, BEFORE it reaches the caller, for two OWASP LLM06-style risks.

  * Secret & credential leak detection — API keys, AWS credentials, SSH
    private keys, hardcoded passwords the model may have echoed back
    (from its training data, from a prior turn, or hallucinated-but-real-
    looking).
  * Insecure code guard — dangerous constructs (`eval`, `exec`, shell-outs
    with `shell=True`, etc.) that would introduce a vulnerability if the
    caller pastes the response straight into their own application.

Works against the raw upstream JSON payload by recursively collecting every
string value in it, so it doesn't need to know each provider's exact
response schema (Anthropic's `content` blocks vs. OpenAI's `choices`).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.core.config import get_settings

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("generic_api_key_assignment", re.compile(r"(?i)\b(api[_-]?key|secret)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")),
    ("openai_api_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("ssh_private_key", re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
    (
        "hardcoded_password_assignment",
        re.compile(r"(?i)\bpassword\b\s*[:=]\s*['\"][^'\"\n]{6,}['\"]"),
    ),
]

_INSECURE_CODE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("python_eval", re.compile(r"\beval\s*\(")),
    ("python_exec", re.compile(r"\bexec\s*\(")),
    ("os_system", re.compile(r"\bos\.system\s*\(")),
    ("os_popen", re.compile(r"\bos\.popen\s*\(")),
    ("subprocess_shell_true", re.compile(r"\bsubprocess\.(run|call|Popen)\([^)]*shell\s*=\s*True")),
    ("js_child_process_exec", re.compile(r"\bchild_process\.exec(Sync)?\s*\(")),
    ("js_eval", re.compile(r"(?<![\w.])eval\s*\(")),
    ("sql_string_concat_format", re.compile(r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}%s")),
]


@dataclass
class OutputInspectionFinding:
    blocked: bool
    reasons: list[str] = field(default_factory=list)


def _collect_strings(obj, out: list[str]) -> None:
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for value in obj.values():
            _collect_strings(value, out)
    elif isinstance(obj, list):
        for item in obj:
            _collect_strings(item, out)


def inspect_output(payload: dict) -> OutputInspectionFinding:
    settings = get_settings()
    strings: list[str] = []
    _collect_strings(payload, strings)
    combined = "\n".join(strings)

    reasons: list[str] = []

    for label, pattern in _SECRET_PATTERNS:
        if pattern.search(combined):
            reasons.append(f"secret_leak:{label}")

    insecure_code_hits = [label for label, pattern in _INSECURE_CODE_PATTERNS if pattern.search(combined)]
    if insecure_code_hits:
        reasons.extend(f"insecure_code:{label}" for label in insecure_code_hits)

    secret_hit = any(r.startswith("secret_leak:") for r in reasons)
    code_hit = any(r.startswith("insecure_code:") for r in reasons)
    blocked = secret_hit or (code_hit and settings.block_insecure_code_output)

    return OutputInspectionFinding(blocked=blocked, reasons=reasons)
