"""
Central configuration for the AI Guardrails Defense-in-Depth demo.

This module holds every regex pattern, whitelist, and masking rule used by
the three defense layers (input_guard, sandbox, output_guard). Keeping all
detection rules in one place makes the security posture auditable at a
glance, which is the point of a defense-in-depth design.
"""

import re

# ---------------------------------------------------------------------------
# LAYER 1 — INPUT GUARDRAIL CONFIG
# Patterns that indicate prompt injection, jailbreak attempts, role-play
# escapes, system-prompt override attempts, or token/encoding smuggling.
# ---------------------------------------------------------------------------

PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)",
    r"forget\s+(everything|all)\s+(you\s+)?(were\s+)?told",
    r"override\s+(your\s+)?(system|safety|security)\s+(prompt|instructions|rules)",
    r"you\s+are\s+now\s+(in\s+)?(developer|debug|admin|root|god)\s+mode",
    r"act\s+as\s+(if\s+you\s+(are|were)\s+)?(an?\s+)?(unfiltered|unrestricted|jailbroken|uncensored)",
    r"pretend\s+(you\s+)?(have\s+no|there\s+are\s+no)\s+(restrictions|rules|filters|guardrails)",
    r"from\s+now\s+on\s+you\s+(will|must|shall)\s+(respond|act|behave)",
    r"reveal\s+(your\s+)?(system\s+prompt|instructions|hidden\s+prompt)",
    r"what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions)",
    r"do\s+anything\s+now",
    r"\bDAN\b",
    r"jailbreak",
]

ROLE_PLAY_ESCAPE_PATTERNS = [
    r"let'?s\s+play\s+a\s+game\s+where\s+you\s+(are|become|pretend)",
    r"roleplay\s+as\s+an?\s+AI\s+(with\s+no|without)\s+(restrictions|filters|guardrails)",
    r"you\s+are\s+no\s+longer\s+(an?\s+)?AI\s+(assistant|model)",
    r"simulate\s+(a|an)\s+(AI|assistant)\s+that\s+has\s+no\s+(rules|restrictions|ethics)",
    r"for\s+this\s+(conversation|session|chat)\s*,?\s*you\s+(have|are)\s+no\s+(restrictions|limits|filters)",
    r"stay\s+in\s+character\s+no\s+matter\s+what",
]

SYSTEM_OVERRIDE_TAG_PATTERNS = [
    r"<\s*system\s*>",
    r"<\s*/?\s*(admin|root|override|instructions?)\s*>",
    r"\[\s*system\s*\]",
    r"\[\s*/?\s*(end\s+of\s+)?(system\s+prompt|instructions)\s*\]",
    r"###\s*system\s*###",
    r"---\s*BEGIN\s+SYSTEM\s+OVERRIDE\s*---",
    r"\{\{\s*system\s*\}\}",
]

TOKEN_SMUGGLE_PATTERNS = [
    r"(?:[A-Za-z0-9+/]{4}){8,}={0,2}",          # long base64-looking blob
    r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}",  # chained unicode escapes
    r"&#x?[0-9a-fA-F]{2,4};(?:&#x?[0-9a-fA-F]{2,4};){3,}",  # chained HTML entities
    r"(?:%[0-9a-fA-F]{2}){6,}",                  # chained URL-encoding
    r"(?:[A-Za-z]\s+){10,}[A-Za-z]",             # letters split by spaces (zero-width/spacing smuggle)
]

# ---------------------------------------------------------------------------
# LAYER 2 — SANDBOX / TOOL-CALLING CONFIG
# ---------------------------------------------------------------------------

# Only these tool names may ever be invoked by the agent. Anything else is
# denied by default (allow-list, not a block-list).
TOOL_WHITELIST = {
    "calculate_metric",
    "safe_query",
    "lookup_knowledge_base",
    "get_current_time",
    "convert_units",
}

# Explicit patterns that identify dangerous shell / OS-level execution
# attempts hiding inside a tool call's arguments (defense even if a
# malicious or compromised tool name slipped past the whitelist check).
DENIED_SHELL_PATTERNS = [
    r"\bbash\b",
    r"\bsh\b\s+-c",
    r"\bzsh\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"\brm\s+-rf\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"__import__\s*\(",
    r"\bos\.system\b",
    r"\bsubprocess\b",
    r"\bsocket\.\w+\(",
    r"\bnc\s+-e\b",
    r"/etc/passwd",
    r"\bchmod\s+\+x\b",
    r"\bsudo\b",
    r"\bpowershell\b",
    r"\bbase64\s+-d\b",
    r"\bscp\b",
    r"\bssh\b",
]

# ---------------------------------------------------------------------------
# LAYER 3 — OUTPUT GUARDRAIL CONFIG
# PII / secret masking rules. Each entry is (label, compiled-ready pattern,
# replacement). Order matters: more specific patterns run first.
# ---------------------------------------------------------------------------

PII_MASKING_RULES = [
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-_]{15,}", "[REDACTED_API_KEY]"),
    ("OpenAI API Key", r"sk-[A-Za-z0-9\-_]{20,}", "[REDACTED_API_KEY]"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{12,}", "[REDACTED_AWS_KEY]"),
    ("Generic Secret/Token", r"(?i)\b(secret|token|api[_-]?key|password|passwd|pwd)\s*[:=]\s*['\"]?[A-Za-z0-9\-_\.!@#$%^&*]{8,}['\"]?", "[REDACTED_CREDENTIAL]"),
    ("Bearer Token", r"(?i)Bearer\s+[A-Za-z0-9\-_\.]{10,}", "Bearer [REDACTED_TOKEN]"),
    ("Private Key Block", r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ("Email Address", r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", "[REDACTED_EMAIL]"),
    ("Credit Card Number", r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CC_NUMBER]"),
    ("US SSN", r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]"),
    ("IPv4 Address", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]"),
]

# Compiled regex cache helper so other modules don't repeat re.compile calls.
def compile_patterns(pattern_list):
    """Compile a flat list of regex strings with case-insensitive matching."""
    return [re.compile(p, re.IGNORECASE) for p in pattern_list]


def compile_masking_rules(rules):
    """Compile (label, pattern, replacement) tuples into (label, compiled, replacement)."""
    return [(label, re.compile(pattern, re.IGNORECASE), repl) for label, pattern, repl in rules]
