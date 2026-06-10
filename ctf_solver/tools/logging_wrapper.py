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
import time
from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Optional, Tuple

from ctf_solver.config import DEFAULT_FLAG_REGEX
from ctf_solver.tools.core import apply_hash_hints

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

# Map tool names to broad attack categories for reflection suggestions.
# The canonical tool→category source is ``ctf_solver.taxonomy.TOOL_TO_CATEGORY``.
# This dict intentionally diverges for logging-suggestion display:
#   - ``jwt_attacks`` → ``jwt`` (shorter label in the suggestion text)
#   - ``attack_planner`` → ``planning`` (separate from ``recon`` so the
#     filter at the call-site can skip both planning and recon calls when
#     enumerating "categories tried so far")
#   - ``html_inspector`` → ``recon`` (kept lightweight — the agent is still
#     in discovery mode when using it)
# ``tests/test_taxonomy.py`` verifies that every key here is either in
# taxonomy.TOOL_TO_CATEGORY or explicitly listed as a display-only override
# so adding a new tool in one place flags the other.
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
    "xss_probe": "xss",
    "xss_payload_generator": "xss",
    "csp_analyzer": "xss",
    "graphql_introspection": "graphql",
    "graphql_query": "graphql",
    "race_condition": "race_condition",
    "request_repeater": "recon",
    "crlf_probe": "crlf_injection",
    "php_type_juggling": "php_type_juggling",
    "prototype_pollution_probe": "prototype_pollution",
    "idor_enumerator": "idor",
    "open_redirect_probe": "open_redirect",
    "css_injection_payload_generator": "css_injection",
    "css_exfiltration_builder": "css_injection",
    "http_smuggling_probe": "http_smuggling",
    "flask_session_forge": "flask_session",
    "dom_clobbering_payload_generator": "dom_clobbering",
    "oauth_probe": "oauth_oidc",
    "oauth_payload_generator": "oauth_oidc",
    "php_filter_chain": "php_filter",
    "parser_differential_probe": "parser_differential",
    "websocket_probe": "websocket",
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
    "xss": "Cross-Site Scripting (XSS)",
    "graphql": "GraphQL Exploitation",
    "race_condition": "Race Condition",
    "crlf_injection": "CRLF / Header Injection",
    "php_type_juggling": "PHP Type Juggling",
    "prototype_pollution": "Prototype / Class Pollution",
    "idor": "Insecure Direct Object Reference (IDOR)",
    "open_redirect": "Open Redirect",
    "css_injection": "CSS Injection / Exfiltration",
    "http_smuggling": "HTTP Request Smuggling",
    "flask_session": "Flask Session Cookie Forgery",
    "dom_clobbering": "DOM Clobbering",
    "oauth_oidc": "OAuth / OpenID Connect",
    "php_filter": "PHP Filter Chain",
    "parser_differential": "Parser Differential",
    "websocket": "WebSocket Exploitation",
    "recon": "Reconnaissance",
    "planning": "Attack Planning",
}

# All known attack categories for suggesting alternatives
_ALL_ATTACK_CATEGORIES = [
    "sql_injection",
    "xpath_injection",
    "ssti",
    "xxe",
    "jwt",
    "file_upload",
    "filter_bypass",
    "file_inclusion",
    "nosql_injection",
    "command_injection",
    "ssrf",
    "crypto",
    "deserialization",
    "xss",
    "graphql",
    "race_condition",
    "crlf_injection",
    "php_type_juggling",
    "prototype_pollution",
    "idor",
    "open_redirect",
    "css_injection",
    "http_smuggling",
    "flask_session",
    "dom_clobbering",
    "oauth_oidc",
    "php_filter",
    "parser_differential",
    "websocket",
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
            tried_section = (
                f"\nAttack categories already tried: {', '.join(tried_names)}"
            )

        alt_section = ""
        if alternatives:
            alt_lines = "\n".join(f"  - {a}" for a in alternatives)
            alt_section = f"\nUntried attack categories to consider:\n{alt_lines}"

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


#: Sentinel string the agent loop greps for to force a stall-nudge tier bump
#: when the same (tool, input) pair has been hit more times than the soft
#: ``WARNING`` threshold.  Kept as a module constant so agent.py can match it
#: without re-importing the wrapper.
STUCK_HARD_STOP_TAG = "[STUCK-HARD-STOP]"


# v3.8 P1: structured observation header.  Every tool result emitted by
# LoggingToolWrapper begins with a ``[<tool>] result=<class>; signal=<key>;``
# header so a 26B local model can grep one line to learn outcome instead
# of parsing free-form prose.
_RESULT_ERROR_RE = re.compile(r"^\s*(?:\[[^\]]+\]\s*)?Error[: ]", re.IGNORECASE)
_RESULT_PARTIAL_TAGS = (
    "[WARNING]",
    STUCK_HARD_STOP_TAG,
    "[SELF-REFLECTION]",
    "[PHASE-GATE]",
    "[ModerationBlocked]",
)
_RESULT_VULN_RE = re.compile(
    r"\b(detected|confirmed|vulnerable|injection.+detected|exploit\s+succeeded)\b",
    re.IGNORECASE,
)


def classify_result(text: str, has_flag: bool) -> Tuple[str, str]:
    """Return ``(result, signal)`` from a tool observation string.

    ``result`` is one of: ``success``, ``partial``, ``failure``,
    ``error``, ``info``.  ``signal`` is a short keyword the model can
    pattern-match.  Pure heuristic — kept simple on purpose so the same
    rule applies to all 75 tools.
    """
    if not isinstance(text, str):
        return "info", ""
    if has_flag:
        return "success", "flag_match"
    if _RESULT_ERROR_RE.search(text):
        return "error", "tool_error"
    for tag in _RESULT_PARTIAL_TAGS:
        if tag in text:
            return "partial", tag.strip("[]").lower()
    if _RESULT_VULN_RE.search(text):
        return "partial", "vuln_signal"
    return "info", ""


class StuckDetector:
    """
    Detects when the agent is repeating the same tool+input pattern.

    Tracks recent tool calls by hashing (tool_name, tool_input).

    Two thresholds:
      - ``threshold`` (default 3): emits a soft ``[WARNING]``/contextual
        reflection appended to the tool result.
      - ``hard_stop_threshold`` (default 5): emits a stronger
        ``[STUCK-HARD-STOP]``-tagged message that the agent loop intercepts
        to force a stall-nudge tier bump (effectively kicking the agent out
        of the loop on the next turn instead of waiting for the soft stall
        clock to fire).

    Set ``hard_stop_threshold`` to ``None`` to disable the hard stop.
    """

    def __init__(
        self,
        threshold: int = 3,
        hard_stop_threshold: Optional[int] = 5,
    ) -> None:
        self.threshold = threshold
        self.hard_stop_threshold = hard_stop_threshold
        self._call_counts: Dict[Tuple[str, str], int] = defaultdict(int)

    def _hash_input(self, tool_input: str) -> str:
        """Hash tool input for comparison.

        Canonicalize JSON (sort keys, drop whitespace) before hashing so
        that semantically-identical calls with reordered keys or
        cosmetic whitespace differences collapse to the same bucket.
        Non-JSON input falls back to a stripped-string hash.
        """
        normalized = tool_input.strip()
        try:
            parsed = json.loads(normalized)
            normalized = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        except (json.JSONDecodeError, ValueError):
            pass
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
            Warning/reflection string to append to result, or None.  When the
            ``hard_stop_threshold`` is hit, the returned string is prefixed
            with ``STUCK_HARD_STOP_TAG`` and contains a directive forbidding
            another invocation of the same tool+input.
        """
        input_hash = self._hash_input(tool_input)
        key = (tool_name, input_hash)
        self._call_counts[key] += 1
        count = self._call_counts[key]

        # Hard stop: emit a tagged message the agent loop greps for.
        if self.hard_stop_threshold is not None and count >= self.hard_stop_threshold:
            return (
                f"\n\n{STUCK_HARD_STOP_TAG} You have called '{tool_name}' "
                f"with the same input {count} times. This is a hard stop: "
                "you MUST switch to a different tool AND a different "
                "approach on your next turn — repeating this tool+input "
                "again will not advance the run.  Consult "
                "'ctf_knowledge_query', call 'attack_planner', or pivot to "
                "an entirely different vulnerability category."
            )

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
        event_writer: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """
        Initialize the logging wrapper.

        Args:
            inner: The wrapped tool instance
            flag_regex: Regex pattern for detecting flags in output
            log_callback: Optional callback for log messages (defaults to print)
            tracker: Optional RunTracker instance for recording tool usage
            event_writer: Optional Phase-C structured event sink. Called with
                a JSON-serializable dict per tool call. Use for the
                ``events.jsonl`` per-step record without modifying every tool.
        """
        self.inner = inner
        self.flag_regex = flag_regex
        # Perf-audit fix #4: compile once. re.findall(pattern_string, ...)
        # internally compiles on every call; precompiling here saves 2-5ms
        # per tool call × 30+ tool calls per run = 60-150ms.
        try:
            self._flag_pattern: Optional[re.Pattern] = re.compile(flag_regex)
        except re.error:
            self._flag_pattern = None
        self.log_callback = log_callback or print
        self.tracker = tracker
        self.event_writer = event_writer

        # Mirror the wrapped tool's public identity
        self.name = getattr(inner, "name", inner.__class__.__name__)
        self.description = getattr(inner, "description", "")

        # Stuck detection (only active when tracker is present)
        self._stuck_detector = StuckDetector() if tracker is not None else None

        # Contextual reflection engine (only active when tracker is present)
        self._reflection_engine = (
            ReflectionEngine(tracker) if tracker is not None else None
        )

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

        # Phase C: capture wall-clock duration around the inner call so
        # the events.jsonl record can show per-tool latency.
        t0 = time.monotonic()
        result = self.inner.use(tool_input)
        duration_ms = int((time.monotonic() - t0) * 1000)

        # Record detailed tool call for failure analysis
        if self.tracker is not None and hasattr(
            self.tracker, "record_detailed_tool_call"
        ):
            self.tracker.record_detailed_tool_call(
                self.name,
                tool_input,
                result if isinstance(result, str) else str(result),
            )

        # Stuck detection: warn if repeating same tool+input
        if self._stuck_detector is not None and isinstance(result, str):
            warning = self._stuck_detector.check(
                self.name, tool_input, self._reflection_engine
            )
            if warning:
                result = result + warning
                self._log(
                    f"[LOG] STUCK DETECTED: {self.name} called with same input multiple times"
                )

        # Log potential flags in tool output and record in tracker
        flag_seen = False
        if isinstance(result, str) and self._flag_pattern is not None:
            matches = self._flag_pattern.findall(result)
            for m in matches:
                self._log(f"[LOG] Potential flag seen in {self.name} output: {m}")
                flag_seen = True
                # Record in tracker so agent._has_flag() can detect it
                if (
                    self.tracker is not None
                    and hasattr(self.tracker, "candidate_flags_found")
                    and m not in self.tracker.candidate_flags_found
                ):
                    self.tracker.candidate_flags_found.append(m)

        # v3.8 P1: prepend a structured header so the model can grep one
        # line for outcome.  Existing prose follows verbatim.  Only adds
        # the header when the result is a string and doesn't already
        # carry one (idempotent for tools that opt in to emitting it
        # themselves later).
        if isinstance(result, str) and not result.startswith(f"[{self.name}] result="):
            cls, signal = classify_result(result, has_flag=flag_seen)
            sig_field = f"signal={signal}; " if signal else ""
            result = f"[{self.name}] result={cls}; {sig_field}{result}"

        # v3.10 P5a: apply hash-pattern hints to the FULL assembled output
        # so URL fields (which are concatenated outside the per-tool
        # summarize_for_llm body pass) also surface md5/sha256 hints.
        # Idempotent — apply_hash_hints short-circuits on existing hints.
        if isinstance(result, str):
            result = apply_hash_hints(result)

        # TODO: optional LM-summarizer tier (borrowed from EnIGMA v0.7
        # sweagent/agent/summarizer.py::LMSummarizer).  Gate behind
        # SolverConfig.use_lm_summarizer (default False); fire when
        # `len(result.splitlines()) > lm_summarizer_threshold` (default 150).
        # Use SolverConfig.lm_summarizer_model (default "gpt-4o-mini").
        # Always preserve the raw output: store keyed by step-id in
        # RunTracker.raw_outputs so an LM call to a new show_raw_output(step_id)
        # tool can retrieve it.  Skip-list mirrors EnIGMA's block_list_input —
        # never summarize outputs from already-structured probes (e.g.
        # http_fetch results, JSON tool outputs).  Track cost separately in
        # tracker metrics for A/B testing.
        # See memory/comparative_long_output_handling.md for the full plan
        # and trigger ladder (200K-char fallback, xxd/hexdump bypass, etc.).

        # Phase C: emit a structured per-call event for events.jsonl. Done
        # last so output_len reflects the post-hint, final string the agent
        # actually receives. Wrapped in try/except so a sink failure can
        # never break the run.
        if self.event_writer is not None:
            try:
                output_str = result if isinstance(result, str) else str(result)
                input_hash = (
                    self._stuck_detector._hash_input(tool_input)
                    if self._stuck_detector is not None
                    else hashlib.md5(
                        tool_input.encode("utf-8", errors="replace")
                    ).hexdigest()
                )
                self.event_writer(
                    {
                        "event": "tool_call",
                        "step": (
                            self.tracker.steps if self.tracker is not None else None
                        ),
                        "tool": self.name,
                        "input_hash": input_hash,
                        "input_preview": tool_input[:200],
                        "output_len": len(output_str),
                        "truncated": len(output_str) >= 2000,
                        "duration_ms": duration_ms,
                        "flag_seen": flag_seen,
                        "ts": time.time(),
                    }
                )
            except Exception:
                pass  # Tracing must never crash the run.

        return result

    def set_flag_regex(self, pattern: str) -> None:
        """Update the flag detection regex pattern."""
        self.flag_regex = pattern
        # Recompile the cached pattern so subsequent .use() calls pick up
        # the new regex without paying the per-call compile cost.
        try:
            self._flag_pattern = re.compile(pattern)
        except re.error:
            self._flag_pattern = None
