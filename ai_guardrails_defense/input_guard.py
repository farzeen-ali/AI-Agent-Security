"""
Layer 1: Input Guardrail.

Validates raw user prompts BEFORE they ever reach the LLM. This is the
first line of defense in a defense-in-depth architecture: it is cheap,
fast, deterministic, and catches known attack shapes (prompt injection,
role-play jailbreaks, fake system tags, and encoding-based smuggling)
without needing a model call at all.
"""

from dataclasses import dataclass, field
from typing import List

from config import (
    PROMPT_INJECTION_PATTERNS,
    ROLE_PLAY_ESCAPE_PATTERNS,
    SYSTEM_OVERRIDE_TAG_PATTERNS,
    TOKEN_SMUGGLE_PATTERNS,
    compile_patterns,
)


@dataclass
class InputCheckResult:
    """Structured result of a single input validation pass."""
    is_safe: bool
    original_prompt: str
    violations: List[str] = field(default_factory=list)
    category: str = "CLEAN"

    def summary(self) -> str:
        if self.is_safe:
            return "No injection, jailbreak, or override patterns detected."
        return f"Blocked due to {len(self.violations)} violation(s) in category '{self.category}'."


class InputGuardrail:
    """
    Scans raw user input against known attack-pattern families:

      1. Prompt injection       -> "ignore previous instructions", "DAN", etc.
      2. Role-play escapes      -> "pretend you have no restrictions"
      3. System override tags   -> fake <system> / [SYSTEM] markers
      4. Token/encoding smuggle  -> base64/unicode/url-encoded payloads
                                    designed to hide instructions from
                                    naive string filters.

    The guardrail is intentionally allow-by-default / deny-on-match: a
    prompt is considered safe unless it trips a specific, named rule. This
    keeps false positives low while still catching the well-documented
    attack families used in red-teaming an LLM application.
    """

    def __init__(self):
        self._injection_patterns = compile_patterns(PROMPT_INJECTION_PATTERNS)
        self._roleplay_patterns = compile_patterns(ROLE_PLAY_ESCAPE_PATTERNS)
        self._override_patterns = compile_patterns(SYSTEM_OVERRIDE_TAG_PATTERNS)
        self._smuggle_patterns = compile_patterns(TOKEN_SMUGGLE_PATTERNS)
        self.audit_log: List[dict] = []

    def validate(self, prompt: str) -> InputCheckResult:
        """Run all detection families against the prompt and return a verdict."""
        if prompt is None or not prompt.strip():
            result = InputCheckResult(is_safe=False, original_prompt=prompt or "", violations=["Empty or null prompt"], category="EMPTY_INPUT")
            self._log(result)
            return result

        checks = [
            ("PROMPT_INJECTION", self._injection_patterns),
            ("ROLEPLAY_ESCAPE", self._roleplay_patterns),
            ("SYSTEM_OVERRIDE_TAG", self._override_patterns),
            ("TOKEN_SMUGGLE", self._smuggle_patterns),
        ]

        for category, pattern_set in checks:
            violations = [p.pattern for p in pattern_set if p.search(prompt)]
            if violations:
                result = InputCheckResult(
                    is_safe=False,
                    original_prompt=prompt,
                    violations=violations,
                    category=category,
                )
                self._log(result)
                return result

        result = InputCheckResult(is_safe=True, original_prompt=prompt, violations=[], category="CLEAN")
        self._log(result)
        return result

    def _log(self, result: InputCheckResult) -> None:
        self.audit_log.append(
            {
                "prompt_preview": result.original_prompt[:80],
                "is_safe": result.is_safe,
                "category": result.category,
                "violation_count": len(result.violations),
            }
        )
