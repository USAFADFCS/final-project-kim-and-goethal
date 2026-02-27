"""
Logging wrapper for CTF Solver tools.

Wraps any FAIR-compatible tool to provide:
- Logging of tool calls with truncated input
- Scanning for candidate flags in tool output
- Stuck detection (warns when agent repeats same tool+input)
- Self-reflection (contextual analysis when agent is stuck)
"""

import hashlib
import json
import re
from collections import Counter, defaultdict
from typing import Callable, Dict, List, Optional, Tuple

from ctf_solver.config import DEFAULT_FLAG_REGEX

# Error patterns to extract from tool outputs
_ERROR_PATTERNS = [
    re.compile(r"Error:", re.IGNORECASE),
    re.compile(r"blocked|filtered|forbidden|denied", re.IGNORECASE),
    re.compile(r"timeout|timed out|connection refused", re.IGNORECASE),
    re.compile(r"not found|404|403|500", re.IGNORECASE),
    re.compile(r"invalid|syntax error|parse error", re.IGNORECASE),
]

# HTTP status codes that indicate the tool may be sending the wrong request format
_FORMAT_ERROR_STATUS_RE = re.compile(r"\bStatus:\s*(400|405|415|422)\b")

# Pattern to extract the target URL from tool output
_URL_IN_OUTPUT_RE = re.compile(r"URL:\s*(https?://[^\s]+)")

# Map tool names to broad attack categories for reflection suggestions
_TOOL_CATEGORIES = {
    "sqli_probe": "sql_injection",
    "sqli_column_counter": "sql_injection",
    "blind_sqli_boolean": "sql_injection",
    "blind_sqli_time": "sql_injection",
    "sqli_data_dumper": "sql_injection",
    "sql_pattern_hint": "sql_injection",
    "xpath_probe": "xpath_injection",
    "xpath_blind_boolean": "xpath_injection",
    "xpath_payload_generator": "xpath_injection",
    "ssti_probe": "ssti",
    "ssti_exploit_suggester": "ssti",
    "xxe_probe": "xxe",
    "xxe_payload_generator": "xxe",
    "xxe_doctype_builder": "xxe",
    "jwt_tool": "jwt",
    "file_upload": "file_upload",
    "upload_location_finder": "file_upload",
    "filter_enumerator": "filter_bypass",
    "payload_mutator": "filter_bypass",
    "lfi_probe": "file_inclusion",
    "lfi_payload_generator": "file_inclusion",
    "nosql_probe": "nosql_injection",
    "nosql_payload_generator": "nosql_injection",
    "cmdi_probe": "command_injection",
    "cmdi_payload_generator": "command_injection",
    "ssrf_probe": "ssrf",
    "ssrf_payload_generator": "ssrf",
    "crypto_probe": "crypto",
    "crypto_analyzer": "crypto",
    "crypto_payload_generator": "crypto",
    "deserialization_probe": "deserialization",
    "deserialization_payload_generator": "deserialization",
    "http_fetch": "recon",
    "html_inspector": "recon",
    "robots_txt": "recon",
    "path_enumerator": "recon",
    "backup_file_finder": "recon",
    "attack_planner": "planning",
}

# Human-readable category names for reflection messages
_CATEGORY_NAMES = {
    "sql_injection": "SQL Injection",
    "xpath_injection": "XPath Injection",
    "ssti": "Server-Side Template Injection",
    "xxe": "XML External Entity (XXE)",
    "jwt": "JWT Attacks",
    "file_upload": "File Upload",
    "filter_bypass": "Filter/WAF Bypass",
    "file_inclusion": "Local/Remote File Inclusion",
    "nosql_injection": "NoSQL Injection",
    "command_injection": "Command Injection",
    "ssrf": "Server-Side Request Forgery",
    "crypto": "Cryptographic Attacks",
    "deserialization": "Insecure Deserialization",
    "recon": "Reconnaissance",
    "planning": "Attack Planning",
}

# All known attack categories for suggesting alternatives
_ALL_ATTACK_CATEGORIES = [
    "sql_injection", "xpath_injection", "ssti", "xxe", "jwt",
    "file_upload", "filter_bypass", "file_inclusion", "nosql_injection",
    "command_injection", "ssrf", "crypto", "deserialization",
]


class ReflectionEngine:
    """
    Generates contextual self-reflection messages when the agent is stuck.

    Analyzes the RunTracker's tool_call_log to understand what the agent
    has tried, what errors occurred, and suggests alternative approaches.
    """

    def __init__(self, tracker) -> None:
        self.tracker = tracker

    def _extract_errors(self, recent_logs: List[Dict]) -> List[str]:
        """Extract error patterns from recent tool outputs."""
        errors = []
        for entry in recent_logs:
            output = entry.get("output", "")
            for pattern in _ERROR_PATTERNS:
                match = pattern.search(output)
                if match:
                    # Extract a snippet around the match
                    start = max(0, match.start() - 20)
                    end = min(len(output), match.end() + 60)
                    snippet = output[start:end].strip()
                    if snippet and snippet not in errors:
                        errors.append(snippet)
                    break  # One error per log entry
        return errors[:5]  # Limit to 5 most recent

    def _get_categories_tried(self, recent_logs: List[Dict]) -> List[str]:
        """Identify which attack categories have been tried."""
        categories = set()
        for entry in recent_logs:
            tool = entry.get("tool", "")
            cat = _TOOL_CATEGORIES.get(tool)
            if cat and cat != "recon" and cat != "planning":
                categories.add(cat)
        return list(categories)

    def _suggest_alternatives(self, categories_tried: List[str]) -> List[str]:
        """Suggest attack categories NOT yet tried."""
        untried = [
            _CATEGORY_NAMES.get(cat, cat)
            for cat in _ALL_ATTACK_CATEGORIES
            if cat not in categories_tried
        ]
        return untried[:5]  # Limit to top 5

    def _detect_format_mismatch(self, recent_logs: List[Dict]) -> Optional[str]:
        """
        Detect when the agent is hitting the same endpoint with different data
        formats but consistently getting HTTP 400/405/415/422 errors.

        This pattern indicates the tool itself may not support the required
        request format (e.g., FormSubmitTool sending form-encoded data when
        the server expects JSON).

        Returns a diagnostic message if the pattern is detected, or None.
        """
        # Find recent entries that target the same URL with format errors
        url_errors: Dict[str, int] = defaultdict(int)
        url_tools: Dict[str, set] = defaultdict(set)

        for entry in recent_logs:
            output = entry.get("output", "")
            tool = entry.get("tool", "")
            status_match = _FORMAT_ERROR_STATUS_RE.search(output)
            url_match = _URL_IN_OUTPUT_RE.search(output)
            if status_match and url_match:
                url = url_match.group(1)
                url_errors[url] += 1
                url_tools[url].add(tool)

        # If 3+ format errors hitting the same endpoint, flag it
        for url, count in url_errors.items():
            if count >= 3:
                tools_used = ", ".join(url_tools[url])
                return (
                    f"\n\nTOOL FORMAT ISSUE DETECTED: {count} requests to {url} "
                    f"returned HTTP 400/415/422 errors using tool(s): {tools_used}.\n"
                    f"This likely means the tool is NOT sending the request in the "
                    f"format the server expects. Common causes:\n"
                    f"  - Server expects a JSON body but 'form_submit' sends form-encoded data\n"
                    f"  - Server expects a specific Content-Type that the tool doesn't set\n"
                    f"FIX: Use 'http_fetch' with method 'POST' and a 'body' parameter to "
                    f"send a JSON request body directly. Example:\n"
                    f'  {{"url": "{url}", "method": "POST", "body": {{"key": "value"}}}}'
                )
        return None

    def generate_reflection(
        self, current_tool: str, current_input: str, repeat_count: int
    ) -> str:
        """
        Analyze tool_call_log and generate an actionable reflection message.

        Args:
            current_tool: The tool that triggered the stuck detection
            current_input: The repeated input
            repeat_count: How many times this exact call has been made

        Returns:
            A structured reflection message to inject into tool output
        """
        log = getattr(self.tracker, "tool_call_log", [])
        recent = log[-10:] if len(log) > 10 else log

        # Count tools used
        tool_counts = Counter(entry.get("tool", "") for entry in recent)
        tool_summary = ", ".join(
            f"{name} ({count}x)" for name, count in tool_counts.most_common(5)
        )

        # Extract errors
        errors = self._extract_errors(recent)
        error_section = ""
        if errors:
            error_lines = "\n".join(f"  - {e}" for e in errors)
            error_section = f"\nErrors observed:\n{error_lines}"

        # Identify what's been tried and what hasn't
        categories_tried = self._get_categories_tried(log)  # Use full log
        tried_names = [_CATEGORY_NAMES.get(c, c) for c in categories_tried]
        alternatives = self._suggest_alternatives(categories_tried)

        tried_section = ""
        if tried_names:
            tried_section = f"\nAttack categories already tried: {', '.join(tried_names)}"

        alt_section = ""
        if alternatives:
            alt_lines = "\n".join(f"  - {a}" for a in alternatives)
            alt_section = (
                f"\nUntried attack categories to consider:\n{alt_lines}"
            )

        # Check for tool-level format mismatch (e.g. form-encoded vs JSON)
        format_warning = self._detect_format_mismatch(recent)
        format_section = ""
        if format_warning:
            format_section = format_warning

        return (
            f"\n\n[SELF-REFLECTION] You have called '{current_tool}' with the "
            f"same input {repeat_count} times. You are stuck in a loop.\n"
            f"\n"
            f"Tools used recently: {tool_summary}"
            f"{error_section}"
            f"{format_section}"
            f"{tried_section}"
            f"{alt_section}\n"
            f"\n"
            f"MANDATORY: You MUST change your approach. Options:\n"
            f"  1. Use 'attack_planner' to get a structured multi-step plan\n"
            f"  2. Use 'ctf_knowledge_query' to research alternative techniques\n"
            f"  3. Try a completely different vulnerability class\n"
            f"  4. Use 'filter_enumerator' to understand what's being blocked\n"
            f"  5. Re-examine the challenge from scratch with 'http_fetch'\n"
            f"\n"
            f"Do NOT repeat the same tool with the same or similar input."
        )


class StuckDetector:
    """
    Detects when the agent is repeating the same tool+input pattern.

    Tracks recent tool calls by hashing (tool_name, tool_input). When
    the same hash appears >= threshold times, a warning message is
    generated to append to the tool result.
    """

    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold
        self._call_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    def _hash_input(self, tool_input: str) -> str:
        """Hash tool input for comparison. Normalize whitespace first."""
        normalized = tool_input.strip()
        return hashlib.md5(normalized.encode("utf-8", errors="replace")).hexdigest()

    def check(
        self,
        tool_name: str,
        tool_input: str,
        reflection_engine: Optional["ReflectionEngine"] = None,
    ) -> Optional[str]:
        """
        Record a tool call and return a warning if stuck.

        Args:
            tool_name: Name of the tool being called
            tool_input: The tool input string
            reflection_engine: Optional ReflectionEngine for contextual analysis

        Returns:
            Warning/reflection string to append to result, or None.
        """
        input_hash = self._hash_input(tool_input)
        key = (tool_name, input_hash)
        self._call_counts[key] += 1

        count = self._call_counts[key]
        if count >= self.threshold:
            # Use contextual reflection if engine is available
            if reflection_engine is not None:
                return reflection_engine.generate_reflection(
                    tool_name, tool_input, count
                )
            # Fall back to generic warning
            return (
                f"\n\n[WARNING] You have called '{tool_name}' with the same "
                f"input {count} times. This suggests you are stuck in a loop. "
                f"Try a DIFFERENT tool, a different payload, or a fundamentally "
                f"different approach."
            )
        return None

    def reset(self) -> None:
        """Reset all counts."""
        self._call_counts.clear()


class LoggingToolWrapper:
    """
    Wrapper for any FAIR tool that:

    - Logs tool calls (tool name + truncated input).
    - Runs the underlying tool.
    - Scans the result for flags matching the configured pattern and logs any matches.
    - Detects stuck patterns (same tool+input repeated) and provides contextual
      self-reflection to guide the agent toward different approaches.
    """

    def __init__(
        self,
        inner,
        flag_regex: str = DEFAULT_FLAG_REGEX,
        log_callback: Optional[Callable[[str], None]] = None,
        tracker=None,
    ) -> None:
        """
        Initialize the logging wrapper.

        Args:
            inner: The wrapped tool instance
            flag_regex: Regex pattern for detecting flags in output
            log_callback: Optional callback for log messages (defaults to print)
            tracker: Optional RunTracker instance for recording tool usage
        """
        self.inner = inner
        self.flag_regex = flag_regex
        self.log_callback = log_callback or print
        self.tracker = tracker

        # Mirror the wrapped tool's public identity
        self.name = getattr(inner, "name", inner.__class__.__name__)
        self.description = getattr(inner, "description", "")

        # Stuck detection (only active when tracker is present)
        self._stuck_detector = StuckDetector() if tracker is not None else None

        # Contextual reflection engine (only active when tracker is present)
        self._reflection_engine = ReflectionEngine(tracker) if tracker is not None else None

    def _log(self, message: str) -> None:
        """Log a message using the configured callback."""
        self.log_callback(message)

    def use(self, tool_input: str) -> str:
        """Execute the wrapped tool and log the call and any flag matches."""
        # Normalize: if the framework passed a dict/list instead of a JSON
        # string, convert it so downstream tools always receive a str.
        if isinstance(tool_input, (dict, list)):
            tool_input = json.dumps(tool_input)
        elif tool_input is None:
            tool_input = ""

        preview = tool_input
        if len(preview) > 200:
            preview = preview[:200] + "...[truncated]..."

        self._log(f"[LOG] Tool call -> {self.name}: {preview}")

        # Record in tracker if available
        if self.tracker is not None:
            self.tracker.record_tool_call(self.name)

        result = self.inner.use(tool_input)

        # Record detailed tool call for failure analysis
        if self.tracker is not None and hasattr(self.tracker, "record_detailed_tool_call"):
            self.tracker.record_detailed_tool_call(self.name, tool_input, result if isinstance(result, str) else str(result))

        # Stuck detection: warn if repeating same tool+input
        if self._stuck_detector is not None and isinstance(result, str):
            warning = self._stuck_detector.check(
                self.name, tool_input, self._reflection_engine
            )
            if warning:
                result = result + warning
                self._log(f"[LOG] STUCK DETECTED: {self.name} called with same input multiple times")

        # Log potential flags in tool output
        if isinstance(result, str):
            try:
                matches = re.findall(self.flag_regex, result)
                for m in matches:
                    self._log(f"[LOG] Potential flag seen in {self.name} output: {m}")
            except re.error:
                pass  # Invalid regex, skip flag detection

        return result

    def set_flag_regex(self, pattern: str) -> None:
        """Update the flag detection regex pattern."""
        self.flag_regex = pattern
