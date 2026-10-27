"""
Layer 2: Agent Sandbox.

Provides an isolated execution layer for agent function/tool calling. The
sandbox enforces a strict allow-list of safe tools and never executes
arbitrary code directly -- every "tool" is a pre-defined Python function
with no access to the shell, filesystem, or network. Even if a request
somehow asks for a dangerous OS-level action, the sandbox denies it by
name (not on the whitelist) AND by content (denied shell patterns found
in the arguments), logging every violation for later security review.
"""

import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List

from config import TOOL_WHITELIST, DENIED_SHELL_PATTERNS, compile_patterns


@dataclass
class SandboxResult:
    """Structured result of a single sandboxed tool-call attempt."""
    allowed: bool
    tool_name: str
    arguments: str
    output: Any = None
    reason: str = ""


# --- Simulated "safe" tool implementations -------------------------------
# These are the ONLY functions the sandbox is able to dispatch to. They
# are pure, side-effect-free, and never touch the OS, network, or disk.

def _tool_calculate_metric(arguments: str) -> str:
    return f"[simulated] Metric calculated from input '{arguments}': result=42.0"


def _tool_safe_query(arguments: str) -> str:
    return f"[simulated] Safe read-only query executed: '{arguments}' -> 3 rows returned."


def _tool_lookup_knowledge_base(arguments: str) -> str:
    return f"[simulated] Knowledge base lookup for '{arguments}' -> 1 article found."


def _tool_get_current_time(arguments: str) -> str:
    return f"[simulated] Current server time: {datetime.datetime.now().isoformat()}"


def _tool_convert_units(arguments: str) -> str:
    return f"[simulated] Unit conversion executed on '{arguments}' -> 1.0 -> 2.20462 lbs."


class AgentSandbox:
    """
    Isolated execution layer for agent tool/function calling.

    Security model (defense in depth within this single layer):
      1. ALLOW-LIST FIRST  -> the requested tool name must be one of a
         small, explicit set of safe, simulated tools. Unknown tool
         names are denied outright, regardless of their arguments.
      2. CONTENT INSPECTION -> even for whitelisted tools, the arguments
         passed in are scanned for shell/OS-command injection patterns
         (bash, curl, rm -rf, eval, os.system, subprocess, etc.) since a
         compromised or confused agent could still try to smuggle a
         dangerous payload through a legitimate-looking tool call.
      3. NO REAL EXECUTION -> every dispatched tool is a simulated,
         side-effect-free Python function. There is no `eval`, no
         `subprocess`, no filesystem or network access anywhere in this
         class, so there is no real-world escape hatch even if checks
         1 and 2 were somehow bypassed.
      4. VIOLATION LOGGING -> every denial is recorded with a timestamp,
         tool name, arguments, and reason so it can be reviewed as a
         security event.
    """

    _DISPATCH = {
        "calculate_metric": _tool_calculate_metric,
        "safe_query": _tool_safe_query,
        "lookup_knowledge_base": _tool_lookup_knowledge_base,
        "get_current_time": _tool_get_current_time,
        "convert_units": _tool_convert_units,
    }

    def __init__(self):
        self.whitelist = set(TOOL_WHITELIST)
        self._denied_shell_patterns = compile_patterns(DENIED_SHELL_PATTERNS)
        self.violation_log: List[Dict[str, Any]] = []

    def execute_tool(self, tool_name: str, arguments: str) -> SandboxResult:
        """Attempt to run a tool call inside the sandbox, enforcing all guardrails."""
        tool_name_clean = (tool_name or "").strip()

        # Check 1: allow-list enforcement
        if tool_name_clean not in self.whitelist:
            reason = f"Tool '{tool_name_clean}' is not in the sandbox whitelist."
            self._log_violation(tool_name_clean, arguments, reason)
            return SandboxResult(allowed=False, tool_name=tool_name_clean, arguments=arguments, reason=reason)

        # Check 2: content inspection for shell/OS injection inside arguments
        matched = [p.pattern for p in self._denied_shell_patterns if p.search(arguments or "")]
        if matched:
            reason = f"Denied shell/OS execution pattern(s) detected in arguments: {matched}"
            self._log_violation(tool_name_clean, arguments, reason)
            return SandboxResult(allowed=False, tool_name=tool_name_clean, arguments=arguments, reason=reason)

        # Check 3: dispatch to the simulated, side-effect-free tool only
        handler = self._DISPATCH[tool_name_clean]
        output = handler(arguments)
        return SandboxResult(allowed=True, tool_name=tool_name_clean, arguments=arguments, output=output, reason="Tool call permitted and executed in sandbox.")

    def _log_violation(self, tool_name: str, arguments: str, reason: str) -> None:
        self.violation_log.append(
            {
                "timestamp": datetime.datetime.now().isoformat(),
                "tool_name": tool_name,
                "arguments_preview": (arguments or "")[:120],
                "reason": reason,
            }
        )
