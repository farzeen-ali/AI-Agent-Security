"""
Layer 3: Output Guardrail.

Intercepts raw LLM (or simulated LLM) output as the final checkpoint
before anything reaches the end user. Even if an injection slipped past
Layer 1 and a tool abuse slipped past Layer 2, this layer stops sensitive
data -- API keys, secret tokens, credentials, emails, SSNs, private keys,
etc. -- from ever leaving the system by redacting it with pattern-based
masking.
"""

from dataclasses import dataclass, field
from typing import List

from config import PII_MASKING_RULES, compile_masking_rules


@dataclass
class OutputCheckResult:
    """Structured result of a single output sanitization pass."""
    raw_output: str
    sanitized_output: str
    redactions: List[str] = field(default_factory=list)

    @property
    def was_modified(self) -> bool:
        return self.raw_output != self.sanitized_output

    def summary(self) -> str:
        if not self.was_modified:
            return "No sensitive data detected. Output passed through unchanged."
        return f"Redacted {len(self.redactions)} sensitive item(s): {', '.join(sorted(set(self.redactions)))}."


class OutputGuardrail:
    """
    Sanitizes raw LLM output before it is shown to the user.

    Applies an ordered list of regex-based masking rules covering:
      - Cloud/vendor API keys (OpenAI-style, Anthropic-style, AWS)
      - Generic secret/token/password key=value patterns
      - Bearer tokens and PEM private key blocks
      - Email addresses
      - Credit card numbers and US Social Security numbers
      - IPv4 addresses (internal infra leakage)

    Each match is replaced with a clearly-labeled redaction placeholder
    so a security reviewer can see WHAT was caught without the actual
    sensitive value ever appearing in logs or on screen.
    """

    def __init__(self):
        self._rules = compile_masking_rules(PII_MASKING_RULES)

    def sanitize(self, raw_output: str) -> OutputCheckResult:
        """Run all masking rules against raw_output and return the sanitized result."""
        text = raw_output or ""
        redactions: List[str] = []

        for label, pattern, replacement in self._rules:
            if pattern.search(text):
                redactions.append(label)
                text = pattern.sub(replacement, text)

        return OutputCheckResult(raw_output=raw_output or "", sanitized_output=text, redactions=redactions)
