"""
Lessons-learned pipeline for the CTF Solver (module name kept for import stability).

Drives the post-run analysis flow that produces atomic rule docs (ExpeL-style)
and optional gpt-4o-mini enrichment.  After Batch B the module is specifically:

- Flag scrubbing + category taxonomy (shared infra near the top)
- Deterministic signal extraction (missed signals, partial successes,
  winning inputs, failed approaches, template engine, causal patterns)
- ``analyze_run`` — pulls all of the above into a ``LessonsLearnedDoc``
- ``run_lessons_learned_pipeline`` — dedupe + atomic rule docs + optional LLM
- ``find_and_compress_prior_lesson`` — Reflexion-style retrieval for injection

History: the pre-v2.3 monolithic ``FailureAnalysis`` / ``detect_failure`` /
``analyze_failure`` / ``generate_failure_knowledge_doc`` /
``run_failure_analysis_pipeline`` path was removed in Batch B along with
``RAGMode.AUGMENTED``; everything here now serves a single ExpeL-style flow.
The file name is preserved because ``runner.py``, ``streamlit_app.py``, and
the test suite import from it by that path — a rename would be churn.
"""

import hashlib
import os
import re
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Default flag regex (mirrors config.py — avoid circular import)
_DEFAULT_FLAG_REGEX = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}"


def _scrub_flags(text: str, flag_regex: str = _DEFAULT_FLAG_REGEX) -> str:
    """Replace flag values with [FLAG_REDACTED] before storing in knowledge docs.

    Prevents the agent from finding the actual flag value by querying the
    knowledge base rather than solving the challenge. Applies the caller-supplied
    regex first, then falls back to the default generic pattern.
    """
    text = re.sub(flag_regex, "[FLAG_REDACTED]", text, flags=re.IGNORECASE)
    if flag_regex != _DEFAULT_FLAG_REGEX:
        text = re.sub(_DEFAULT_FLAG_REGEX, "[FLAG_REDACTED]", text, flags=re.IGNORECASE)
    return text


# ---------------------------------------------------------------------------
# Category inference from tool usage
# ---------------------------------------------------------------------------
# Canonical source lives in ``ctf_solver.taxonomy``; the underscore-prefixed
# aliases below preserve the original module-level import sites used across
# tests and helper code (``tests/test_v2_prompt_analyzer.py``,
# ``failure_analyzer.analyze_run``, ``_find_similar_rule_doc``, etc.).
from ctf_solver.taxonomy import CATEGORY_LABELS as _CATEGORY_LABELS
from ctf_solver.taxonomy import TOOL_TO_CATEGORY as _TOOL_TO_CATEGORY

# Patterns indicating the agent admitted failure
_FAILURE_ADMISSION_PATTERNS = [
    r"(?i)i was unable to",
    r"(?i)i could not (find|solve|extract|retrieve)",
    r"(?i)i('m| am) stuck",
    r"(?i)unable to (find|solve|determine|extract)",
    r"(?i)no flag (found|identified|extracted)",
    r"(?i)i cannot (determine|find|solve)",
    r"(?i)all attempts? (failed|exhausted)",
    r"(?i)none of the .* worked",
]

# Patterns for extracting errors from tool output
_ERROR_PATTERNS = [
    r"(?i)(error|exception|traceback|failed|timeout|refused|denied|blocked|forbidden|not found|404|500|503)",
    r"(?i)(connection refused|connection reset|connection timed out)",
    r"(?i)(access denied|unauthorized|403)",
    r"(?i)(syntax error|parse error|invalid)",
]

# ---------------------------------------------------------------------------
# Actionable signal detection (v2.1 — missed signal & partial success)
# ---------------------------------------------------------------------------

# Each entry: (output_regex, label, tools_filter_or_None, required_follow_up_tools)
# tools_filter: only trigger when the emitting tool is in this set (None = any tool)
# required_follow_up_tools: the intersection with the NEXT 5 tool calls must be non-empty
_ACTIONABLE_PATTERNS: List[Tuple[str, str, Optional[frozenset], frozenset]] = [
    (
        r"(?i)(?:password|passwd)\s*[:=]\s*\S+",
        "credential_found",
        None,
        frozenset(["form_submit", "http_fetch"]),
    ),
    (
        r"(?i)api[_-]?key\s*[:=]\s*\S+",
        "api_key_found",
        None,
        frozenset(["http_fetch"]),
    ),
    (
        r"eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        "jwt_token_found",
        None,
        frozenset(["jwt_tool"]),
    ),
    (
        r"(?i)(?:you have an error in your sql|sql.*syntax.*error)",
        "sqli_error_confirmed",
        frozenset(
            [
                "sqli_probe",
                "blind_sqli_boolean",
                "blind_sqli_time",
                "http_fetch",
                "form_submit",
            ]
        ),
        frozenset(["sqli_column_counter", "sqli_data_dumper", "blind_sqli_boolean"]),
    ),
    (
        r"\b49\b",
        "ssti_calculation_confirmed",
        frozenset(["ssti_probe"]),
        frozenset(["ssti_exploit_suggester"]),
    ),
    (
        r"(?i)(?:admin.*panel|/admin[/\s]|administration.*page)",
        "admin_endpoint_found",
        None,
        frozenset(["http_fetch", "form_submit", "cookie_set"]),
    ),
]

# Patterns indicating sub-goal achievement within a failed run
_PARTIAL_SUCCESS_INDICATORS: Dict[str, str] = {
    "sqli_confirmed": r"(?i)(?:you have an error in your sql|sql.*syntax.*error)",
    "ssti_confirmed": r"\b(?:49|36|64|81|7777777)\b",  # 7*7, 6*6, 8*8, 9*9, 7*'7'
    "credential_found": r"(?i)(?:password|passwd)\s*[:=]\s*\S+",
    "auth_bypassed": r"(?i)(?:welcome.*admin|logged in as admin|admin.*dashboard|admin.*panel.*access)",
    "source_disclosed": r"(?i)(?:<\?php|def\s+check_flag|def\s+\w+.*flag)",
    "schema_extracted": r"(?i)(?:information_schema|\.tables|column.*table)",
    "recon_complete": r"(?:Status: 200|Found \d+ (?:endpoint|path|link|page))",
}

# Partial success signals that are definitive category overrides.
# A confirmed exploitation signal trumps tool-frequency heuristics because
# generic tools (http_fetch, form_submit) always outnumber specialist tools.
_PARTIAL_SUCCESS_CATEGORY_OVERRIDE: Dict[str, str] = {
    "sqli_confirmed": "sql_injection",
    "ssti_confirmed": "ssti",
    "schema_extracted": "sql_injection",
    "source_disclosed": "file_inclusion",
    "auth_bypassed": "cookies_auth",
}

# For each signal, at least ONE of these keys must appear in the (possibly augmented)
# tool_counts before the override is applied.  This prevents broad output patterns
# (e.g. \b49\b) from mislabeling unrelated challenges.
# "_ssti_template_probe" is a virtual key added by _augment_tool_counts when any
# tool input contained an SSTI arithmetic probe like {{7*7}}.
# Signals without an entry here have no tool guard (auth_bypassed is observable
# from HTTP alone).
_PARTIAL_SUCCESS_REQUIRED_TOOLS: Dict[str, Set[str]] = {
    "ssti_confirmed": {"ssti_probe", "ssti_exploit_suggester", "_ssti_template_probe"},
    "sqli_confirmed": {
        "sqli_probe",
        "blind_sqli_boolean",
        "blind_sqli_time",
        "sqli_column_counter",
        "sqli_data_dumper",
    },
    "schema_extracted": {
        "sqli_probe",
        "blind_sqli_boolean",
        "blind_sqli_time",
        "sqli_column_counter",
        "sqli_data_dumper",
    },
    "source_disclosed": {"lfi_probe", "lfi_payload_generator"},
}

# Matches SSTI arithmetic probes submitted in tool inputs: {{7*7}}, {{7*'7'}}, etc.
# Used to detect intentional SSTI testing even when generic tools (form_submit) are used.
_SSTI_ARITHMETIC_PROBE_RE = re.compile(r"\{\{[0-9]+\*'?[0-9]+'?\}\}")


def _augment_tool_counts(
    tool_counts: Dict[str, int],
    tool_call_log: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Return a copy of tool_counts augmented with virtual probe-evidence keys.

    Adds "_ssti_template_probe" if any tool input contained an SSTI arithmetic
    probe (e.g. {{7*7}}).  This lets _guarded_category_override distinguish
    intentional SSTI testing via form_submit from innocuous "49" in output.
    """
    augmented = dict(tool_counts)
    for entry in tool_call_log:
        raw_input = entry.get("input", "") or ""
        if _SSTI_ARITHMETIC_PROBE_RE.search(raw_input):
            augmented["_ssti_template_probe"] = 1
            break
    return augmented


def _guarded_category_override(
    partial_successes: List[str],
    tool_counts: Dict[str, int],
    current_category: str,
) -> str:
    """Return the override category only when the required specialist evidence is present.

    Prevents broad output patterns (e.g. \\b49\\b for ssti_confirmed) from
    mislabeling challenges that happen to produce the same numeric output via
    unrelated tools (path_enumerator finding 49 paths, HTTP body sizes, etc.).

    tool_counts should already be augmented via _augment_tool_counts so that
    virtual keys like "_ssti_template_probe" are present when applicable.
    """
    for ps in partial_successes:
        if ps not in _PARTIAL_SUCCESS_CATEGORY_OVERRIDE:
            continue
        required = _PARTIAL_SUCCESS_REQUIRED_TOOLS.get(ps)
        if required is not None and not required.intersection(tool_counts):
            # Signal fired but no confirming evidence — ignore the override
            continue
        return _PARTIAL_SUCCESS_CATEGORY_OVERRIDE[ps]
    return current_category


# Specialized attack tools — distinct from generic recon tools.
# Used by _detect_failed_approaches to identify meaningful failed probes.
_SPECIALIZED_ATTACK_TOOLS: Set[str] = {
    "sqli_probe",
    "sqli_column_counter",
    "blind_sqli_boolean",
    "blind_sqli_time",
    "sqli_data_dumper",
    "ssti_probe",
    "ssti_exploit_suggester",
    "xss_probe",
    "xss_payload_generator",
    "xxe_probe",
    "xxe_payload_generator",
    "lfi_probe",
    "lfi_payload_generator",
    "nosql_probe",
    "nosql_payload_generator",
    "cmdi_probe",
    "cmdi_payload_generator",
    "ssrf_probe",
    "ssrf_payload_generator",
    "jwt_tool",
    "xpath_probe",
    "crypto_probe",
    "deserialization_probe",
    "crlf_probe",
    "php_type_juggling",
    "prototype_pollution_probe",
    "idor_enumerator",
    "race_condition",
}

# Patterns in tool outputs that indicate the approach failed / got no traction.
_FAILED_OUTPUT_PATTERNS: List[Tuple[str, str]] = [
    (
        r"(?i)no (?:injection|vulnerability|template|sql|error) (?:found|detected|identified)",
        "found no vulnerability indicator",
    ),
    (
        r"(?i)(?:not vulnerable|not injectable|parameter.*not.*injectable)",
        "parameter not injectable",
    ),
    (r"(?i)(?:access denied|forbidden|unauthorized)", "access denied"),
    (
        r"(?i)(?:invalid syntax|malformed payload|parse error)",
        "payload rejected/malformed",
    ),
    (r"(?i)(?:no results|empty response|no output found)", "empty/no-results response"),
]

# Patterns to detect which template engine is in use from the winning input or output.
# Order matters — check more specific patterns first.
_TEMPLATE_ENGINE_INPUT_PATTERNS: List[Tuple[str, str]] = [
    (r"\{\{7\*7\}\}", "Jinja2/Twig"),
    (r"\$\{7\*7\}", "FreeMarker/Velocity"),
    (r"#\{7\*7\}", "Thymeleaf/EL"),
    (r"<%=\s*7\s*\*\s*7", "ERB/JSP"),
    (r"\{\{", "Jinja2/Twig (partial)"),
    (r"\$\{", "FreeMarker/Velocity (partial)"),
]

_TEMPLATE_ENGINE_OUTPUT_MARKERS: List[Tuple[str, str]] = [
    (r"<class\s+'", "Jinja2"),  # Python class repr leaks
    (r"url_for\b|config\.items\(\)|request\.cookies", "Flask/Jinja2"),
    (r"FreeMarker template error", "FreeMarker"),
    # Require full Thymeleaf attribute names to avoid false positives
    # (bare "th:" matches too broadly — e.g. CSS class names, "width:", "with:")
    (
        r"Thymeleaf template|th:(?:text|href|action|value|if|each|field|object|method|inline)\b",
        "Thymeleaf",
    ),
]

# Short human-readable description for each tool — used in Quick Exploitation Path.
_TOOL_STEP_DESCRIPTION: Dict[str, str] = {
    "http_fetch": "Fetch the target URL to map the application and identify input forms",
    "javascript_source": "Inspect JS for injection points, credentials, or API endpoints",
    "form_submit": "Submit a payload via the identified form or API endpoint",
    "html_inspector": "Inspect HTML source for hidden fields, comments, or clues",
    "robots_txt": "Check robots.txt for hidden paths",
    "path_enumerator": "Enumerate hidden paths and directories",
    "backup_file_finder": "Look for exposed backup or config files",
    "cookie_inspector": "Inspect session cookie structure",
    "cookie_set": "Override or forge a session cookie",
    "ssti_probe": "Test for Server-Side Template Injection with {{7*7}}",
    "ssti_exploit_suggester": "Get escalation payloads for the detected template engine",
    "sqli_probe": "Probe URL/form parameters for SQL injection",
    "sqli_data_dumper": "Extract database contents via confirmed SQLi",
    "jwt_tool": "Decode and attack the JWT token",
    "wasm_analyzer": "Parse and reverse-engineer the WASM binary",
}


# ---------------------------------------------------------------------------
# Shared helpers used by the lessons-learned pipeline
# (the monolithic FailureAnalysis dataclass + detect_failure + analyze_failure
# path was removed when AUGMENTED mode was retired; only the helpers below
# still serve the new ExpeL-style atomic-rule pipeline at the bottom of this
# file and the outcome-inference logic in runner.py / streamlit_app.py.)
# ---------------------------------------------------------------------------


#: Per-category success strategy text appended to reflexion summaries when a
#: run solved the challenge.  Consumed by ``_compress_to_reflexion_summary``
#: and ``generate_atomic_rule_doc``.  Originally lived inside the legacy
#: success-doc generator; preserved here because the new pipeline still uses it.
_SUCCESS_TAKEAWAYS: Dict[str, str] = {
    "sql_injection": (
        "Use `sqli_probe` on every parameter first, then `sqli_column_counter`, "
        "then `sqli_data_dumper` for extraction. Check for JSON body endpoints."
    ),
    "wasm_re": (
        "Deobfuscate the JS loader with `javascript_source` to find the WASM URL, "
        "then `wasm_analyzer (analyze)`. If data is binary, follow with `wasm_analyzer (xor_decode)`."
    ),
    "ssti": (
        "Test every input with `{{7*7}}` first. On success, use `ssti_exploit_suggester` "
        "for RCE payloads targeting the detected engine."
    ),
    "jwt_attacks": (
        "Decode with `jwt_tool analyze`, then try `alg:none`, "
        "algorithm confusion (RS256→HS256), and `kid_inject`."
    ),
    "client_side": (
        "Run `javascript_source` on every JS file linked from the page. "
        "Credentials and tokens are often hard-coded or in local storage."
    ),
    "xxe": (
        "Inject a DOCTYPE with an external entity into every XML input. "
        "Try both `file:///etc/passwd` and `http://` SSRF variants."
    ),
    "file_upload": (
        "Test double extensions (.php.jpg), content-type spoofing, "
        "and `.htaccess` upload to enable execution."
    ),
    "lfi_rfi": (
        "Try `../` path traversal on all URL parameters. "
        "Combine with PHP wrappers (`php://filter/convert.base64-encode/resource=`) for source disclosure."
    ),
    "nosql_injection": (
        'Inject `{"$gt": ""}` into JSON body fields. '
        "Use `nosql_probe` on login endpoints first."
    ),
    "command_injection": (
        "Test `;id`, `|id`, `` `id` `` in all parameters. "
        "If filtered, try `$(id)` or encoded variants."
    ),
}


def _detect_missed_signals(tool_call_log: List[Dict[str, Any]]) -> List[str]:
    """
    Detect tool outputs containing actionable findings the agent never exploited.

    For each call whose output matches an actionable pattern, checks whether a
    relevant follow-up tool was called within the next 5 steps.  If not, the
    finding is flagged as a "missed signal".

    Returns at most 5 missed-signal strings.
    """
    missed: List[str] = []
    for i, entry in enumerate(tool_call_log):
        output = entry.get("output", "") or ""
        tool_name = entry.get("tool", "")

        for pattern, label, tools_filter, follow_up_tools in _ACTIONABLE_PATTERNS:
            if tools_filter is not None and tool_name not in tools_filter:
                continue
            if not re.search(pattern, output, re.IGNORECASE):
                continue

            subsequent_tools = frozenset(
                e.get("tool", "") for e in tool_call_log[i + 1 : i + 6]
            )
            if not (follow_up_tools & subsequent_tools):
                follow_up_str = ", ".join(sorted(follow_up_tools))
                missed.append(
                    f"`{tool_name}` found {label} but no follow-up exploitation "
                    f"({follow_up_str}) was attempted"
                )
                break  # one signal per tool-call entry

    return missed[:5]


def _detect_partial_successes(tool_call_log: List[Dict[str, Any]]) -> List[str]:
    """
    Detect sub-goals achieved within an overall-failed run (hindsight value).

    Returns a list of achieved goal labels from _PARTIAL_SUCCESS_INDICATORS.
    """
    all_outputs = " ".join(e.get("output", "") or "" for e in tool_call_log)
    return [
        goal
        for goal, pattern in _PARTIAL_SUCCESS_INDICATORS.items()
        if re.search(pattern, all_outputs)
    ]


# ===========================================================================
# v2.3 — Unified Lessons-Learned Pipeline
# ===========================================================================
# Replaces the separate failure/success pipelines with a single pipeline that
# always runs after every attempt and produces atomic rule documents optimised
# for RAG retrieval (ExpeL, Zhao et al. AAAI 2024).
# ---------------------------------------------------------------------------


@dataclass
class AtomicRule:
    """A single transferable lesson extracted from one agent run.

    Kept small (≤400 words when rendered) so each doc has a tight, focused
    embedding — the core ExpeL insight for high-precision retrieval.
    """

    triggering_condition: str  # "When you see X"
    agent_takeaway: str  # Imperative: "Do Y because Z"
    rule_type: str  # "do" or "do_not"
    tool_context: List[str]  # which tools this rule relates to
    confidence: str = "low"  # "low" | "medium" | "high"
    causal_explanation: str = ""  # why the rule holds


@dataclass
class LessonsLearnedDoc:
    """Unified result from analyzing any run — success, failure, or partial."""

    challenge_name: str = ""
    challenge_url: str = ""
    challenge_description: str = ""
    outcome: str = "failure"  # "success" | "failure" | "partial"
    category: str = "unknown"
    timestamp: str = ""
    total_steps: int = 0
    duration_seconds: float = 0.0

    # What happened
    tool_sequence: List[str] = field(default_factory=list)  # ordered
    tool_frequency: Dict[str, int] = field(default_factory=dict)
    causal_diagnosis: str = ""  # why the run went how it did
    partial_successes: List[str] = field(default_factory=list)
    missed_signals: List[str] = field(default_factory=list)

    # Extracted atomic rules (2–5 per run)
    atomic_rules: List[AtomicRule] = field(default_factory=list)

    # Compressed verbal reflection for Reflexion-style injection (100–200 words)
    reflexion_summary: str = ""

    # Exact tool inputs that produced flag-bearing outputs (scrubbed of flag values)
    winning_inputs: List[str] = field(default_factory=list)

    # Specialized attack tools that failed BEFORE the winning exploit (negative knowledge)
    failed_approaches: List[str] = field(default_factory=list)

    # Detected template engine (Jinja2, FreeMarker, etc.) — "" if not applicable
    template_engine: str = ""


# ---------------------------------------------------------------------------
# Causal pattern library — maps response observations to diagnoses
# ---------------------------------------------------------------------------

_CAUSAL_PATTERNS: List[Tuple[str, str, str]] = [
    # (response_pattern_regex, triggering_condition_template, diagnosis)
    (
        r"(?i)same.{0,20}response|identical.{0,20}length",
        "When tool outputs are identical across different payloads on the same parameter",
        "Backend likely uses parameterized queries or a WAF strips injection chars — SQLi on this parameter is ineffective; pivot to auth-bypass logic or NoSQL operators",
    ),
    (
        r"(?i)(400|bad request).{0,60}(quote|'|\"|special)",
        "When the server returns 400 for payloads containing quote characters",
        "WAF or strict input validation blocks special chars — use filter_enumerator with bypass_waf:true or try URL/hex/unicode encoding",
    ),
    (
        r"(?i)redirect.{0,40}(login|auth|403)",
        "When injection payloads trigger a redirect to login or a 403",
        "Input is reflected server-side before the DB query; authentication is required before injection is reachable — authenticate first or try unauthenticated endpoints",
    ),
    (
        r"(?i)no.{0,20}(table|column|result|row).{0,40}found",
        "When UNION/data-dump queries return empty result sets",
        "Schema enumeration incomplete — use sqli_column_counter to determine column count, then enumerate table names via information_schema before dumping data",
    ),
    (
        r"(?i)(connection refused|timeout|reset)",
        "When tools repeatedly encounter connection errors",
        "Service may be rate-limiting or the challenge URL has changed — reduce request rate, verify URL, and try http_fetch before specialised tools",
    ),
]


def _infer_outcome(candidate_flags: List[str], partial_successes: List[str]) -> str:
    """Determine outcome string from run results.

    Precedence (high to low): ``success`` > ``partial`` > ``failure``.
    A run that found a flag is always ``success``, even if it hit the step
    limit or had other partial signals along the way — the flag is the ground
    truth and the lessons pipeline is driven off it.
    """
    if candidate_flags:
        return "success"
    if partial_successes:
        return "partial"
    return "failure"


def _challenge_name_to_slug(name: str) -> str:
    """Convert a challenge name to a filesystem-safe slug."""
    slug = re.sub(r"[^\w\s-]", "", name.lower())
    slug = re.sub(r"[\s_]+", "-", slug).strip("-")
    return slug or "unknown"


def _extract_tool_sequence(tool_call_log: List[Dict[str, Any]]) -> List[str]:
    """Return an ordered deduplicated list of tools from the call log."""
    seen: List[str] = []
    seen_set: set = set()
    for entry in tool_call_log:
        t = entry.get("tool", "")
        if t and t not in seen_set:
            seen.append(t)
            seen_set.add(t)
    return seen


def _extract_winning_inputs(
    tool_call_log: List[Dict[str, Any]],
    candidate_flags: List[str],
    flag_regex: str = _DEFAULT_FLAG_REGEX,
) -> List[str]:
    """Extract inputs from tool calls whose output contained the flag.

    Returns a list of short strings like '`form_submit` input: {"url": "/submit",
    "data": {"name": "{{7*7}}"}}' capped at 3 entries and scrubbed of flag values.
    These are the exact requests that found the flag — the single most reusable
    piece of knowledge for future runs on the same or similar challenges.
    """
    pattern = re.compile(flag_regex, re.IGNORECASE)
    winning: List[str] = []
    for entry in tool_call_log:
        out = entry.get("output", "") or ""
        inp = entry.get("input", "") or ""
        if not out:
            continue
        # Match: output contains a known flag OR matches the flag regex
        matched = (candidate_flags and any(f in out for f in candidate_flags)) or bool(
            pattern.search(out)
        )
        if matched and inp:
            tool = entry.get("tool", "tool")
            # Scrub KNOWN flag values from the input by exact string replacement.
            # We deliberately avoid the broad flag_regex here because it also
            # matches template injection payloads like {{7*7}} (the inner {7*7}
            # matches the flag pattern), which would destroy the most valuable
            # piece of knowledge — the exact exploit payload submitted.
            clean_inp = inp[:400]
            for known_flag in candidate_flags:
                clean_inp = clean_inp.replace(known_flag, "[FLAG_REDACTED]")
            winning.append(f"`{tool}` input: {clean_inp}")
    return winning[:3]


def _detect_failed_approaches(
    tool_call_log: List[Dict[str, Any]],
    flag_regex: str = _DEFAULT_FLAG_REGEX,
) -> List[str]:
    """Find specialized attack tools that failed BEFORE the flag was found.

    Returns strings like "`ssti_probe` failed: found no vulnerability indicator"
    for use in "do_not" rules and the reflexion summary. Only fires for tools in
    _SPECIALIZED_ATTACK_TOOLS — generic recon tools (http_fetch, form_submit) are
    excluded because a 'failed' http_fetch is often just recon, not a dead end.
    """
    flag_pattern = re.compile(flag_regex, re.IGNORECASE)
    # Find the index of the first tool call whose output contains the flag
    winning_idx: Optional[int] = None
    for i, entry in enumerate(tool_call_log):
        if flag_pattern.search(entry.get("output", "") or ""):
            winning_idx = i
            break
    if winning_idx is None:
        return []  # No flag found — can't determine what "failed before the win"

    failed: List[str] = []
    for entry in tool_call_log[:winning_idx]:
        tool = entry.get("tool", "")
        if tool not in _SPECIALIZED_ATTACK_TOOLS:
            continue
        out = (entry.get("output", "") or "").strip()
        if not out:
            continue
        for pattern, description in _FAILED_OUTPUT_PATTERNS:
            if re.search(pattern, out):
                failed.append(f"`{tool}` failed: {description}")
                break
    return failed[:4]  # Cap at 4 to keep doc size manageable


def _detect_template_engine(
    winning_inputs: List[str],
    tool_call_log: List[Dict[str, Any]],
) -> str:
    """Detect which template engine was exploited from inputs and outputs.

    Scans (in order):
    1. Raw tool_call_log inputs from flag-bearing calls — most reliable because
       the scrubbed winning_inputs strings may have had template syntax like
       {{7*7}} partially replaced by the flag regex (since {7*7} matches the
       generic flag pattern).
    2. The formatted winning_inputs strings (in case raw scan misses something).
    3. All tool outputs for engine-specific markers (fallback).

    Returns "" if no engine is identified.
    """
    flag_pattern = re.compile(_DEFAULT_FLAG_REGEX, re.IGNORECASE)
    # SSTI arithmetic probes: 7*7=49, 6*6=36, 9*9=81 — confirmation calls whose
    # outputs don't contain a flag but do confirm template execution
    _SSTI_CONFIRM_PATTERN = re.compile(r"\b(?:49|36|81)\b")

    # Step 1: raw inputs from tool calls whose OUTPUT contained a flag OR whose
    # output matches a known SSTI arithmetic confirmation (e.g. "Hello 49!")
    for entry in tool_call_log:
        out = entry.get("output", "") or ""
        if not (flag_pattern.search(out) or _SSTI_CONFIRM_PATTERN.search(out)):
            continue
        raw_inp = entry.get("input", "") or ""
        for pattern, engine in _TEMPLATE_ENGINE_INPUT_PATTERNS:
            if re.search(pattern, raw_inp):
                return engine

    # Step 2: formatted (scrubbed) winning_inputs as fallback
    combined_inputs = " ".join(winning_inputs)
    for pattern, engine in _TEMPLATE_ENGINE_INPUT_PATTERNS:
        if re.search(pattern, combined_inputs):
            return engine

    # Step 3: engine-specific markers in tool outputs
    all_outputs = " ".join(e.get("output", "") or "" for e in tool_call_log)
    for pattern, engine in _TEMPLATE_ENGINE_OUTPUT_MARKERS:
        if re.search(pattern, all_outputs):
            return engine
    return ""


def _apply_causal_patterns(tool_call_log: List[Dict[str, Any]]) -> str:
    """Scan tool outputs against _CAUSAL_PATTERNS and return the first match."""
    all_outputs = " ".join(e.get("output", "") or "" for e in tool_call_log)
    for pattern, _condition, diagnosis in _CAUSAL_PATTERNS:
        if re.search(pattern, all_outputs):
            return diagnosis
    return ""


# System prompt for LLM-based lesson enhancement (static — no flag risk)
_LLM_LESSONS_SYSTEM_PROMPT = (
    "You are a CTF security analyst reviewing an automated challenge attempt. "
    "Write clear, transferable security lessons based ONLY on the data provided — "
    "do not invent tools or techniques that are not present. "
    "Output valid JSON only with no markdown wrapping or extra text."
)


def _llm_enhance_doc(
    doc: "LessonsLearnedDoc",
    tool_call_log: List[Dict[str, Any]],
    openai_api_key: str,
    lessons_llm_model: str = "gpt-4o-mini",
    flag_regex: str = _DEFAULT_FLAG_REGEX,
) -> "LessonsLearnedDoc":
    """Replace causal_diagnosis, per-rule causal_explanation, and reflexion_summary
    with gpt-4o-mini output for richer, more actionable lesson text.

    All text is pre-scrubbed before sending and post-scrubbed after receiving.
    Falls back to the existing deterministic values on any error (network,
    quota, JSON parse, missing dependency) — the pipeline never blocks.
    """
    import json
    import sys

    try:
        from fairlib import Message

        from ctf_solver.llm import LLMProvider, create_adapter
    except ImportError as exc:
        print(f"[lessons-llm] skipping LLM enhancement: {exc}", file=sys.stderr)
        return doc

    # --- Build pre-scrubbed context for the prompt --------------------------
    scrubbed_outputs = _scrub_flags(
        " | ".join(
            (entry.get("output") or "")[:300]
            for entry in tool_call_log
            if entry.get("output")
        )[:2500],
        flag_regex,
    )

    winning_inputs_text = (
        "\n".join(f"  - {w}" for w in doc.winning_inputs)
        if doc.winning_inputs
        else "  (none)"
    )

    rule_count = len(doc.atomic_rules)
    user_prompt = (
        f"Challenge category: {doc.category}\n"
        f"Challenge name: {doc.challenge_name or 'unknown'}\n"
        f"Outcome: {doc.outcome} after {doc.total_steps} steps\n"
        f"Tools used (ordered): {', '.join(doc.tool_sequence) or 'none'}\n"
        f"Partial successes: {', '.join(doc.partial_successes) or 'none'}\n"
        f"Missed signals: {', '.join(doc.missed_signals) or 'none'}\n"
        f"Failed approaches: {', '.join(doc.failed_approaches) or 'none'}\n"
        f"Template engine detected: {doc.template_engine or 'unknown'}\n"
        f"Winning inputs (flag values redacted):\n{winning_inputs_text}\n\n"
        f"Scrubbed tool outputs (truncated):\n{scrubbed_outputs}\n\n"
        "---\n"
        "Respond with JSON containing exactly these keys:\n"
        "{\n"
        '  "reflexion_summary": "120-160 word narrative: what happened, why it worked/failed, what to try next time",\n'
        '  "causal_explanation": "1-2 sentences: WHY the outcome happened mechanistically",\n'
        f'  "rule_causal_explanations": [/* {rule_count} short explanations, one per rule in order */]\n'
        "}"
    )

    # --- Call gpt-4o-mini ---------------------------------------------------
    try:
        adapter = create_adapter(
            provider=LLMProvider.OPENAI,
            model_name=lessons_llm_model,
            api_key=openai_api_key,
        )
        response: Message = adapter.invoke(
            [
                Message(role="system", content=_LLM_LESSONS_SYSTEM_PROMPT),
                Message(role="user", content=user_prompt),
            ]
        )
        raw_content = response.content or ""
        # Strip potential markdown code fences (gpt-4o-mini sometimes adds them)
        raw_content = raw_content.strip()
        if raw_content.startswith("```"):
            # Drop the opening fence line (e.g. "```json")
            first_nl = raw_content.find("\n")
            if first_nl != -1:
                raw_content = raw_content[first_nl + 1 :].strip()
            # Drop the closing fence if present
            if raw_content.endswith("```"):
                raw_content = raw_content[:-3].strip()
        result: Dict[str, Any] = json.loads(raw_content)
    except Exception as exc:
        print(
            f"[lessons-llm] LLM call failed, using deterministic fallback: {exc}",
            file=sys.stderr,
        )
        return doc

    # --- Post-scrub into locals first, then apply atomically ----------------
    # Compute every scrubbed value BEFORE mutating ``doc``.  If anything fails
    # part-way through (KeyError on a malformed response, regex blow-up in
    # _scrub_flags, etc.) we bail without leaving the doc in a half-enriched
    # state that is indistinguishable from a fully deterministic one.
    try:
        reflexion_src = result.get("reflexion_summary", "")
        new_reflexion: Optional[str] = (
            _scrub_flags(reflexion_src, flag_regex)
            if isinstance(reflexion_src, str) and reflexion_src
            else None
        )

        causal_src = result.get("causal_explanation", "")
        new_causal: Optional[str] = (
            _scrub_flags(causal_src, flag_regex)
            if isinstance(causal_src, str) and causal_src
            else None
        )

        new_rule_explanations: Dict[int, str] = {}
        rule_explanations = result.get("rule_causal_explanations", [])
        if isinstance(rule_explanations, list):
            for idx in range(len(doc.atomic_rules)):
                if idx < len(rule_explanations) and isinstance(
                    rule_explanations[idx], str
                ):
                    new_rule_explanations[idx] = _scrub_flags(
                        rule_explanations[idx], flag_regex
                    )
    except Exception as exc:
        print(
            f"[lessons-llm] failed to scrub LLM results, keeping deterministic: {exc}",
            file=sys.stderr,
        )
        return doc

    if new_reflexion is not None:
        doc.reflexion_summary = new_reflexion
    if new_causal is not None:
        doc.causal_diagnosis = new_causal
    for idx, text in new_rule_explanations.items():
        doc.atomic_rules[idx].causal_explanation = text

    return doc


def analyze_run(
    config_data: Dict[str, Any],
    tracker_data: Dict[str, Any],
    tool_call_log: List[Dict[str, Any]],
    agent_response: Optional[str],
    candidate_flags: List[str],
    flag_regex: str = _DEFAULT_FLAG_REGEX,
    use_llm: bool = False,
    openai_api_key: str = "",
    lessons_llm_model: str = "gpt-4o-mini",
) -> LessonsLearnedDoc:
    """
    Analyze any run (success, failure, or partial) and produce a LessonsLearnedDoc.

    Deterministic by default. When use_llm=True and openai_api_key is provided,
    replaces causal_diagnosis, causal_explanation per rule, and reflexion_summary
    with gpt-4o-mini output for richer, more actionable lessons.

    Args:
        config_data: Dict with challenge_url, challenge_description, challenge_name.
        tracker_data: Dict from RunTracker.to_dict()
        tool_call_log: List of detailed tool call records
        agent_response: The agent's final response text
        candidate_flags: Flags found during the run
        flag_regex: Pattern used for flag scrubbing in generated docs
        use_llm: If True, enhance causal fields with gpt-4o-mini
        openai_api_key: OpenAI API key (required when use_llm=True)
        lessons_llm_model: Model name to use for lesson generation

    Returns:
        LessonsLearnedDoc with extracted insights and atomic rules
    """
    # Determine partial successes and outcome
    partial_successes = _detect_partial_successes(tool_call_log)
    missed_signals = _detect_missed_signals(tool_call_log)
    outcome = _infer_outcome(candidate_flags, partial_successes)

    # Category inference: partial success signals first (strongest), then tool frequency
    tool_counts: Dict[str, int] = tracker_data.get("tool_calls", {})
    category_scores: Counter = Counter()
    for tool_name, count in tool_counts.items():
        cat = _TOOL_TO_CATEGORY.get(tool_name)
        if cat:
            category_scores[cat] += count
    category = category_scores.most_common(1)[0][0] if category_scores else "unknown"
    # Override with confirmed exploitation signal — only when specialist evidence is present.
    # Guard prevents broad patterns (e.g. \b49\b) from mislabeling unrelated challenges.
    augmented_counts = _augment_tool_counts(tool_counts, tool_call_log)
    category = _guarded_category_override(partial_successes, augmented_counts, category)

    # Causal diagnosis from response patterns
    causal_diagnosis = _apply_causal_patterns(tool_call_log)
    if not causal_diagnosis and outcome == "failure":
        causal_diagnosis = f"The run exhausted its budget without finding the flag after {tracker_data.get('steps', 0)} steps in category '{_CATEGORY_LABELS.get(category, category)}'"

    doc = LessonsLearnedDoc(
        challenge_name=config_data.get("challenge_name", ""),
        challenge_url=config_data.get("challenge_url", ""),
        challenge_description=config_data.get("challenge_description", ""),
        outcome=outcome,
        category=category,
        timestamp=time.strftime("%Y-%m-%d", time.gmtime()),
        total_steps=tracker_data.get("steps", 0),
        duration_seconds=tracker_data.get("duration_seconds", 0.0),
        tool_sequence=_extract_tool_sequence(tool_call_log),
        tool_frequency=dict(tool_counts),
        causal_diagnosis=causal_diagnosis,
        partial_successes=partial_successes,
        missed_signals=missed_signals,
    )

    doc.winning_inputs = _extract_winning_inputs(tool_call_log, candidate_flags)
    doc.failed_approaches = _detect_failed_approaches(tool_call_log)
    doc.template_engine = _detect_template_engine(doc.winning_inputs, tool_call_log)
    doc.atomic_rules = _extract_atomic_rules(doc)
    doc.reflexion_summary = _compress_to_reflexion_summary(doc)

    # Optional LLM enhancement: replace causal fields with richer prose
    if use_llm and openai_api_key:
        doc = _llm_enhance_doc(
            doc, tool_call_log, openai_api_key, lessons_llm_model, flag_regex
        )

    return doc


def _extract_atomic_rules(doc: LessonsLearnedDoc) -> List[AtomicRule]:
    """
    Extract 2–5 atomic rules from a LessonsLearnedDoc.

    For failure/partial runs: missed-signal rules + causal-diagnosis rule.
    For success runs: winning tool chain rule + key decision-point rules.
    """
    rules: List[AtomicRule] = []
    category_label = _CATEGORY_LABELS.get(doc.category, "web exploitation")

    if doc.outcome == "success":
        # Confidence: "medium" if we have a confirmed exploit input, else "low".
        # Matches importance-scoring from Park et al. (2023) — higher confidence
        # for experience-backed rules that include specific exploit evidence.
        base_confidence = "medium" if doc.winning_inputs else "low"

        # Rule 1: winning tool chain (include template engine if detected)
        chain = " → ".join(doc.tool_sequence[:6]) if doc.tool_sequence else "unknown"
        engine_suffix = (
            f" (engine: {doc.template_engine})" if doc.template_engine else ""
        )
        rules.append(
            AtomicRule(
                triggering_condition=f"When facing a {category_label}{engine_suffix} challenge with these tools available",
                agent_takeaway=f"Follow this winning tool sequence: {chain}",
                rule_type="do",
                tool_context=doc.tool_sequence[:6],
                confidence=base_confidence,
                causal_explanation=f"This sequence successfully found the flag in {doc.total_steps} steps",
            )
        )
        # Rule 2: partial successes — these are decision-point rules
        for ps in doc.partial_successes[:2]:
            rules.append(
                AtomicRule(
                    triggering_condition=f"When you achieve '{ps}' during a {category_label} challenge",
                    agent_takeaway=f"Continue exploitation after confirming '{ps}' — do not stop at reconnaissance",
                    rule_type="do",
                    tool_context=doc.tool_sequence[:3],
                    confidence=base_confidence,
                    causal_explanation="Partial successes are exploitation footholds, not endpoints",
                )
            )
        # Rule 3: negative knowledge — approaches that failed BEFORE the win.
        # From ExpeL (Zhao 2024): cross-episode negative knowledge prevents the
        # agent from repeating dead-end approaches on similar challenges.
        for failed in doc.failed_approaches[:2]:
            # Parse: "`tool` failed: description"
            tool_match = re.match(r"`(.+?)` failed: (.+)", failed)
            if not tool_match:
                continue
            failed_tool, failure_desc = tool_match.group(1), tool_match.group(2)
            rules.append(
                AtomicRule(
                    triggering_condition=f"When attempting {category_label} and {failed_tool} returns non-useful output",
                    agent_takeaway=f"Do NOT continue with `{failed_tool}` — it {failure_desc}. Switch to direct payload injection via form_submit or http_fetch instead.",
                    rule_type="do_not",
                    tool_context=[failed_tool],
                    confidence="low",
                    causal_explanation=f"On this challenge, `{failed_tool}` {failure_desc} while direct payload injection succeeded",
                )
            )

    else:
        # Rule from causal diagnosis
        if doc.causal_diagnosis:
            # Find matching triggering condition from _CAUSAL_PATTERNS
            triggering = f"When {category_label} probes return no useful output after multiple payloads"
            for _pattern, condition, diagnosis in _CAUSAL_PATTERNS:
                if diagnosis == doc.causal_diagnosis:
                    triggering = condition
                    break
            rules.append(
                AtomicRule(
                    triggering_condition=triggering,
                    agent_takeaway=doc.causal_diagnosis,
                    rule_type="do_not",
                    tool_context=doc.tool_sequence[:3],
                    confidence="low",
                    causal_explanation="Observed from response patterns in this run",
                )
            )

        # Rules from missed signals
        for signal in doc.missed_signals[:3]:
            # Parse signal format: "`tool` found X but no follow-up (Y) was attempted"
            label_match = re.search(r"found\s+(\w+)", signal)
            label = label_match.group(1) if label_match else "an actionable finding"
            follow_match = re.search(r"\(([^)]+)\)", signal)
            follow_up = (
                follow_match.group(1)
                if follow_match
                else "follow-up exploitation tools"
            )
            rules.append(
                AtomicRule(
                    triggering_condition=f"When a tool output contains {label} during a {category_label} challenge",
                    agent_takeaway=f"Immediately call {follow_up} before exploring other vectors — do not miss this signal",
                    rule_type="do",
                    tool_context=[follow_up.split(",")[0].strip()],
                    confidence="low",
                    causal_explanation=f"Signal was detected but not exploited: {signal}",
                )
            )

        # Generic rule if nothing else was extracted
        if not rules:
            top_tools = [
                t
                for t, _ in sorted(doc.tool_frequency.items(), key=lambda x: -x[1])[:3]
            ]
            rules.append(
                AtomicRule(
                    triggering_condition=f"When a {category_label} challenge resists standard payloads",
                    agent_takeaway="Pivot to a different attack vector early rather than repeating the same approach with minor variations",
                    rule_type="do_not",
                    tool_context=top_tools,
                    confidence="low",
                    causal_explanation=f"Run exhausted {doc.total_steps} steps without progress",
                )
            )

    return rules[:5]  # cap at 5 per run


def _compress_to_reflexion_summary(doc: LessonsLearnedDoc) -> str:
    """
    Produce a 100–200 word verbal reflection for Reflexion-style injection.

    Much more useful than the raw 2000-char failure doc because it's causally
    structured and scoped to the key lesson (Shinn et al. NeurIPS 2023).
    """
    category_label = _CATEGORY_LABELS.get(doc.category, "web exploitation")
    outcome_verb = "succeeded" if doc.outcome == "success" else "failed"
    # Sort by count descending (not insertion order) to show most-used tools first
    top_tools = [
        t for t, _ in sorted(doc.tool_frequency.items(), key=lambda x: -x[1])[:3]
    ]
    tools_str = ", ".join(f"`{t}`" for t in top_tools) if top_tools else "no tools"

    lines = [
        f"In a prior attempt on a {category_label} challenge, the agent {outcome_verb} "
        f"after {doc.total_steps} steps.",
        f"Primary tools used: {tools_str}.",
    ]

    if doc.causal_diagnosis:
        lines.append(f"Diagnosis: {doc.causal_diagnosis}.")

    if doc.partial_successes:
        ps_str = ", ".join(doc.partial_successes[:2])
        lines.append(f"Partial progress confirmed: {ps_str}.")

    if doc.missed_signals:
        ms_str = "; ".join(doc.missed_signals[:2])
        lines.append(f"Missed signals not exploited: {ms_str}.")

    # Content to append AFTER scrubbing — attack payloads and curated text that
    # would be incorrectly destroyed by the broad flag regex (e.g. {{7*7}} →
    # {[FLAG_REDACTED]} because {7*7} matches (?:[A-Za-z0-9_]+)?\{...\}).
    post_scrub: List[str] = []

    if doc.outcome == "success" and doc.tool_sequence:
        chain = " → ".join(doc.tool_sequence[:5])
        engine_note = f" ({doc.template_engine})" if doc.template_engine else ""
        lines.append(f"Winning sequence{engine_note}: {chain}.")
        # Negative knowledge — prevent repeating dead-end approaches (ExpeL).
        # This goes in lines (scrubbed) because it's derived from tool names,
        # not from payloads.
        if doc.failed_approaches:
            failed_note = "; ".join(doc.failed_approaches[:2])
            lines.append(f"What did NOT work: {failed_note}.")
        # Winning inputs and strategy go POST-scrub: they contain template syntax
        # and curated payloads that the flag regex would destroy.
        if doc.winning_inputs:
            post_scrub.append(
                f"Key winning input(s): {' | '.join(doc.winning_inputs[:2])}"
            )
        strategy = _SUCCESS_TAKEAWAYS.get(doc.category, "")
        if strategy:
            post_scrub.append(f"Strategy for next time: {strategy}")
    elif doc.outcome != "success" and doc.atomic_rules:
        rule = doc.atomic_rules[0]
        lines.append(f"Key lesson: {rule.agent_takeaway}.")

    scrubbed = _scrub_flags(" ".join(lines))
    if post_scrub:
        scrubbed += " " + " ".join(post_scrub)
    return scrubbed


def generate_atomic_rule_doc(
    rule: AtomicRule,
    doc: LessonsLearnedDoc,
    rule_index: int,
    site_fingerprint: str = "",
    flag_regex: str = _DEFAULT_FLAG_REGEX,
) -> str:
    """
    Generate a single atomic-rule markdown document for one extracted rule.

    The template places the most retrieval-relevant content (triggering condition
    + agent takeaway) in the first ~200 tokens, matching best practices from
    RAFT (Zhang 2024) and Self-RAG (Asai 2023).

    Flag values are scrubbed via _scrub_flags() to prevent leakage into RAG.
    The site_fingerprint (page title/h1/form) is stored for content-based
    contamination filtering rather than URL matching.
    """
    category_label = _CATEGORY_LABELS.get(doc.category, "General Web Exploitation")
    date_str = doc.timestamp or time.strftime("%Y-%m-%d", time.gmtime())
    challenge_slug = _challenge_name_to_slug(
        doc.challenge_name or doc.challenge_url or "unknown"
    )
    tags = ", ".join(
        filter(None, [doc.category, doc.outcome, "experience", rule.rule_type])
    )
    # Scrub flag values from rule text before storing
    clean_triggering = _scrub_flags(rule.triggering_condition, flag_regex)
    clean_takeaway = _scrub_flags(rule.agent_takeaway, flag_regex)
    clean_causal = _scrub_flags(rule.causal_explanation, flag_regex)
    # reflexion_summary is already scrubbed at generation time; do not re-scrub
    # (re-scrubbing would destroy template payloads like {{7*7}} in winning_inputs
    # that were intentionally appended post-scrub in _compress_to_reflexion_summary)
    clean_summary = (
        doc.reflexion_summary
        or f"Run outcome: {doc.outcome} after {doc.total_steps} steps."
    )
    lines = [
        f"# {category_label}: {clean_triggering[:70]}",
        "",
        f"**Type:** experience_{doc.outcome}",
        f"**Category:** {category_label}",
        f"**Challenge:** {doc.challenge_name or challenge_slug}",
        f"**Challenge URL:** {doc.challenge_url or 'unknown'}",
        f"**Auto-generated:** {date_str}",
        f"**Tags:** {tags}",
        f"**Confidence:** {rule.confidence}",
    ]
    if doc.template_engine:
        lines.append(f"**Template engine:** {doc.template_engine}")
    if site_fingerprint:
        lines.append(f"**Site fingerprint:** {site_fingerprint}")
    lines += [
        "",
        f"**Applies when:** {clean_triggering}",
        "",
        f"**Agent takeaway:** {clean_takeaway}",
        "",
        "---",
        "",
        "## What Happened",
        "",
        clean_summary,
        "",
        "## Transferable Rule",
        "",
        f"{'Do' if rule.rule_type == 'do' else 'Avoid this'}: {clean_takeaway}",
        "",
        f"Reason: {clean_causal}" if clean_causal else "",
        "",
        "## Tools Involved",
        "",
    ]

    for t in rule.tool_context[:4]:
        lines.append(f"- `{t}`")

    if doc.outcome == "success" and doc.tool_sequence:
        chain = " → ".join(doc.tool_sequence[:6])
        lines.append("")
        lines.append(f"**Full sequence:** {chain}")

    # Quick Exploitation Path — episodic exemplar (ExpeL / Park et al.).
    # Only rendered for Rule 1 (the tool-sequence rule) so each doc stays focused.
    # Gives the agent a numbered, step-by-step action plan instead of a bare list.
    if doc.outcome == "success" and doc.tool_sequence and rule_index == 1:
        lines += ["", "## Quick Exploitation Path", ""]
        lines.append(
            "> **Note:** Replace `<TARGET_URL>` with the current challenge URL."
        )
        lines.append("")
        for step_num, tool in enumerate(doc.tool_sequence[:6], 1):
            desc = _TOOL_STEP_DESCRIPTION.get(tool, f"Use `{tool}`")
            # Inject the exact winning parameters at the step that found the flag.
            # Generalize the challenge URL so agents don't copy stale hostnames.
            winning_step = next(
                (wi for wi in doc.winning_inputs if f"`{tool}`" in wi), None
            )
            if winning_step:
                params = winning_step.split("input:", 1)[-1].strip()
                if doc.challenge_url:
                    params = params.replace(doc.challenge_url, "<TARGET_URL>")
                lines.append(
                    f"{step_num}. **`{tool}`**: {desc} — use: `{params[:600]}`"
                )
            else:
                lines.append(f"{step_num}. **`{tool}`**: {desc}")
        # Append escalation advice from SUCCESS_TAKEAWAYS if available
        strategy = _SUCCESS_TAKEAWAYS.get(doc.category, "")
        if strategy:
            lines += ["", f"> **Next-step strategy:** {strategy}"]

    if doc.outcome == "success" and doc.winning_inputs:
        lines.append("")
        lines.append("## Key Exploit Inputs")
        lines.append("")
        lines.append("The following request(s) produced the flag:")
        lines.append("")
        for wi in doc.winning_inputs[:3]:
            lines.append(f"- {wi}")

    if doc.outcome == "success" and doc.failed_approaches and rule_index == 1:
        lines += ["", "## What Did NOT Work (Before the Win)", ""]
        lines.append("Avoid these approaches — they failed on this challenge:")
        lines.append("")
        for fa in doc.failed_approaches[:4]:
            lines.append(f"- {fa}")

    lines.append("")
    return "\n".join(lines)


def _tool_sequence_hash(tool_call_log: List[Dict[str, Any]]) -> int:
    """Return a stable hash of the first 5 tool names in the log.

    Used to distinguish runs that took different approaches on the same
    challenge: same URL+category+outcome but different tool sequence is NOT
    a duplicate and should produce a new lessons doc.

    Must be stable across Python processes so duplicate detection works when
    comparing the current run's seq_hash against hashes written to prior docs.
    Python's built-in ``hash()`` is salted per-process (PEP 456); md5-derived
    integers are not.
    """
    first_five = tuple(entry.get("tool", "") for entry in tool_call_log[:5])
    digest = hashlib.md5("|".join(first_five).encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, "big", signed=True)


def _is_lessons_duplicate(
    challenge_url: str,
    category: str,
    outcome: str,
    seq_hash: int,
    lessons_dir: Path,
) -> bool:
    """Return True if an identical run (same URL + category + outcome + tool approach) exists.

    A different tool sequence (even with same URL + category + outcome) is
    NOT a duplicate — the agent tried a new approach and we want that captured.
    """
    if not lessons_dir.exists():
        return False
    expected_label = _CATEGORY_LABELS.get(category, "")
    for doc_path in lessons_dir.glob("lessons_*.md"):
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        url_match = re.search(r"\*\*Challenge URL:\*\*\s*(\S+)", content)
        doc_url = url_match.group(1) if url_match else ""
        if challenge_url and doc_url != challenge_url:
            continue
        type_match = re.search(r"\*\*Type:\*\*\s*experience_(\w+)", content)
        doc_outcome = type_match.group(1) if type_match else ""
        cat_match = re.search(r"\*\*Category:\*\*\s*(.+)", content)
        doc_cat = cat_match.group(1).strip() if cat_match else ""
        # Check stored sequence hash (written as **Seq hash:** <int>)
        hash_match = re.search(r"\*\*Seq hash:\*\*\s*(-?\d+)", content)
        doc_hash = int(hash_match.group(1)) if hash_match else None
        if (
            doc_outcome == outcome
            and doc_cat == expected_label
            and doc_hash is not None
            and doc_hash == seq_hash
        ):
            return True
    return False


def _jaccard_word_overlap(a: str, b: str) -> float:
    """Return Jaccard similarity between word sets of two strings.

    Empty or malformed inputs return 0.0. Two empty strings being "100% similar"
    would silently suppress new lesson docs whose triggering conditions failed
    to parse into any word tokens — better to treat those as non-matches so a
    real lesson lands in the corpus instead of bumping confidence on a malformed one.
    """
    wa: Set[str] = set(re.findall(r"\w+", a.lower()))
    wb: Set[str] = set(re.findall(r"\w+", b.lower()))
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def _find_similar_rule_doc(
    triggering_condition: str,
    category: str,
    lessons_dir: Path,
) -> Optional[Path]:
    """Find an existing lessons doc with a similar triggering condition.

    Returns the path to the most similar doc (Jaccard ≥ 0.60 on word tokens),
    or None if no sufficiently similar doc exists.  Used to bump confidence of
    recurring patterns rather than writing redundant docs.
    """
    if not lessons_dir.exists():
        return None
    expected_label = _CATEGORY_LABELS.get(category, "")
    best_path: Optional[Path] = None
    best_score = 0.0
    for doc_path in lessons_dir.glob("lessons_*.md"):
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        cat_match = re.search(r"\*\*Category:\*\*\s*(.+)", content)
        doc_cat = cat_match.group(1).strip() if cat_match else ""
        if doc_cat != expected_label:
            continue
        applies_match = re.search(r"\*\*Applies when:\*\*\s*(.+)", content)
        if not applies_match:
            continue
        score = _jaccard_word_overlap(triggering_condition, applies_match.group(1))
        if score >= 0.60 and score > best_score:
            best_score = score
            best_path = doc_path
    return best_path


_CONFIDENCE_LADDER = {"low": "medium", "medium": "high", "high": "high"}


def _bump_confidence(doc_path: Path) -> None:
    """Promote the confidence level of an existing rule doc by one step.

    Confidence ladder: low → medium → high.  Called when a new run produces a
    rule that is semantically similar to an existing one, indicating the pattern
    is recurring and should be trusted more by the reranker.
    """
    try:
        content = doc_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    current_match = re.search(r"(\*\*Confidence:\*\*\s*)(\w+)", content)
    if not current_match:
        return
    current = current_match.group(2)
    new_level = _CONFIDENCE_LADDER.get(current, current)
    if new_level == current:
        return  # Already at max
    updated = (
        content[: current_match.start(2)] + new_level + content[current_match.end(2) :]
    )
    doc_path.write_text(updated, encoding="utf-8")


def run_lessons_learned_pipeline(
    config_data: Dict[str, Any],
    tracker_data: Dict[str, Any],
    tool_call_log: List[Dict[str, Any]],
    agent_response: Optional[str],
    candidate_flags: List[str],
    lessons_docs_dir: str = "out/lessons_knowledge",
    max_steps: int = 20,
    actual_steps: int = 0,
    flag_regex: str = _DEFAULT_FLAG_REGEX,
    site_fingerprint: str = "",
    use_llm: bool = False,
    openai_api_key: str = "",
    lessons_llm_model: str = "gpt-4o-mini",
) -> List[str]:
    """
    Unified post-run pipeline that always runs (success or failure).

    Generates atomic rule documents inspired by ExpeL (Zhao et al. AAAI 2024):
    one small, focused markdown file per extracted rule, optimised for RAG
    retrieval.

    Dedup is approach-aware: same URL+category+outcome with a DIFFERENT tool
    sequence is NOT a duplicate — the agent tried a new approach and we want
    that captured.  When a new rule's triggering condition is semantically
    similar to an existing one (Jaccard ≥ 0.60), we bump the existing doc's
    confidence (low→medium→high) instead of writing a redundant file.

    When use_llm=True and openai_api_key is provided, causal fields are
    enriched with gpt-4o-mini output (~$0.0003/run, falls back silently).

    Args:
        config_data: Dict with challenge_url, challenge_description, challenge_name.
        tracker_data: Dict from RunTracker.to_dict()
        tool_call_log: List of tool call records
        agent_response: The agent's final response text
        candidate_flags: Flags found during the run
        lessons_docs_dir: Directory to save lesson docs
        max_steps: Maximum steps configured
        actual_steps: Actual steps taken
        flag_regex: Flag regex for scrubbing
        site_fingerprint: Content fingerprint from RunTracker (title/h1/form)
        use_llm: If True, enrich causal fields with gpt-4o-mini
        openai_api_key: OpenAI API key (required when use_llm=True)
        lessons_llm_model: Model name to use for lesson generation

    Returns:
        List of paths to generated doc files (empty if all skipped/merged).
    """
    docs_dir = Path(lessons_docs_dir)
    docs_dir.mkdir(parents=True, exist_ok=True)

    doc = analyze_run(
        config_data=config_data,
        tracker_data=tracker_data,
        tool_call_log=tool_call_log,
        agent_response=agent_response,
        candidate_flags=candidate_flags,
        flag_regex=flag_regex,
        use_llm=use_llm,
        openai_api_key=openai_api_key,
        lessons_llm_model=lessons_llm_model,
    )

    # Quality gate: single/two-step runs have no transferable signal.
    # A fluke success (agent guessed on step 1) is not a lesson worth storing.
    if doc.total_steps < 3:
        return []

    # Dedup: skip if same URL+category+outcome+tool_approach already stored
    seq_hash = _tool_sequence_hash(tool_call_log)
    if _is_lessons_duplicate(
        doc.challenge_url, doc.category, doc.outcome, seq_hash, docs_dir
    ):
        return []

    challenge_slug = _challenge_name_to_slug(
        doc.challenge_name or doc.challenge_url or "unknown"
    )
    timestamp_slug = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    written: List[str] = []

    # Per-category cap: prevent one overrepresented category from flooding RAG.
    # Count existing atomic rule docs for this category (not consolidations).
    _MAX_LESSONS_PER_CATEGORY = 12
    target_label = f"**Category:** {_CATEGORY_LABELS.get(doc.category, doc.category)}"
    category_doc_count = sum(
        1
        for p in docs_dir.glob("lessons_*.md")
        if any(
            line.strip() == target_label
            for line in p.read_text(encoding="utf-8", errors="ignore").split("\n")
        )
    )
    category_full = category_doc_count >= _MAX_LESSONS_PER_CATEGORY

    for i, rule in enumerate(doc.atomic_rules, 1):
        # Cross-run confidence merging: bump similar existing rule instead of writing new
        similar = _find_similar_rule_doc(
            rule.triggering_condition, doc.category, docs_dir
        )
        if similar is not None:
            _bump_confidence(similar)
            continue

        # Skip writing new docs when the category is at capacity — confidence
        # merging above still fires, but we stop adding more noise to RAG.
        if category_full:
            continue

        rule_content = generate_atomic_rule_doc(
            rule,
            doc,
            i,
            site_fingerprint=site_fingerprint,
            flag_regex=flag_regex,
        )
        # Embed sequence hash so dedup can identify identical approaches
        rule_content += f"\n**Seq hash:** {seq_hash}\n"
        existing = list(docs_dir.glob("lessons_*.md"))
        next_index = len(existing) + 1
        filename = f"lessons_{next_index:03d}_{challenge_slug}_r{i}_{timestamp_slug}.md"
        doc_path = docs_dir / filename
        # Atomic write: temp file + rename to prevent partial reads
        fd, tmp_path = tempfile.mkstemp(dir=str(docs_dir), suffix=".md.tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(rule_content)
            os.rename(tmp_path, str(doc_path))
        except Exception:
            os.unlink(tmp_path)
            raise
        written.append(str(doc_path))

    return written


def find_and_compress_prior_lesson(
    challenge_name: Optional[str],
    challenge_url: Optional[str],
    lessons_docs_dir: str = "out/lessons_knowledge",
    fallback_failure_docs_dir: str = "out/failure_knowledge",
    challenge_description: Optional[str] = None,
) -> Optional[str]:
    """Backward-compatible wrapper — returns only the compressed text.

    For callers that need the list of source filenames the compression drew
    from (Phase A1 injection tracing), use
    ``find_and_compress_prior_lesson_with_sources``.
    """
    text, _ = find_and_compress_prior_lesson_with_sources(
        challenge_name=challenge_name,
        challenge_url=challenge_url,
        lessons_docs_dir=lessons_docs_dir,
        fallback_failure_docs_dir=fallback_failure_docs_dir,
        challenge_description=challenge_description,
    )
    return text


def find_and_compress_prior_lesson_with_sources(
    challenge_name: Optional[str],
    challenge_url: Optional[str],
    lessons_docs_dir: str = "out/lessons_knowledge",
    fallback_failure_docs_dir: str = "out/failure_knowledge",
    challenge_description: Optional[str] = None,
) -> Tuple[Optional[str], List[str]]:
    """
    Aggregate ALL prior lesson docs for this challenge into a structured
    multi-run reflection for Reflexion-style injection. Returns both the
    compressed text and the list of source filenames it was distilled from
    (so downstream tracing can show "lesson X drove this prompt").

    Improvements over the previous single-doc extraction:
    - Shows ALL prior outcomes (e.g. "2 success, 1 failure runs") so the agent
      knows how reliable the knowledge is (confidence signal from run count).
    - Surfaces the most recent SUCCESS details (winning sequence + exploit input)
      as the primary action guide.
    - Appends the most recent FAILURE lesson as negative knowledge to avoid
      repeating dead-end approaches.
    - Caps total output at ~800 chars to stay within the context budget.

    Based on: Park et al. (2023) episodic memory aggregation; ExpeL (Zhao 2024)
    cross-episode insight merging; Shinn et al. (2023) Reflexion.

    Returns:
        ``(text, sources)`` — ``text`` is the structured reflection string or
        None if no prior doc exists; ``sources`` is the list of basename
        filenames (e.g. ``lessons_019_open-application_r1_*.md``) that
        contributed to the compression. Empty list when ``text`` is None.
    """
    name_slug = _challenge_name_to_slug(challenge_name) if challenge_name else ""

    def _collect_matching(
        directory: str, pattern: str
    ) -> List[Tuple[float, str, str, str]]:
        """Return list of (mtime, outcome, content, filename) for matches."""
        if not challenge_name:
            return []
        d = Path(directory)
        if not d.exists():
            return []
        results: List[Tuple[float, str, str, str]] = []
        for doc_path in d.glob(pattern):
            try:
                content = doc_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            if name_slug in doc_path.name or challenge_name.lower() in content.lower():
                outcome_match = re.search(r"\*\*Type:\*\*\s*experience_(\w+)", content)
                outcome = outcome_match.group(1) if outcome_match else "unknown"
                results.append(
                    (doc_path.stat().st_mtime, outcome, content, doc_path.name)
                )
        return results

    # 1. Gather all matching lessons_*.md docs
    all_docs = _collect_matching(lessons_docs_dir, "lessons_*.md")

    if all_docs:
        # Sort: success first (highest priority for Reflexion), then by recency
        _OUTCOME_PRIORITY = {"success": 0, "partial": 1, "failure": 2, "unknown": 3}
        all_docs.sort(key=lambda x: (_OUTCOME_PRIORITY.get(x[1], 3), -x[0]))

        # Count outcomes for the run summary header
        outcome_counts: Dict[str, int] = {}
        for _, outcome, _, _ in all_docs:
            outcome_counts[outcome] = outcome_counts.get(outcome, 0) + 1
        count_str = ", ".join(
            f"{v} {k}"
            for k, v in sorted(
                outcome_counts.items(), key=lambda kv: _OUTCOME_PRIORITY.get(kv[0], 3)
            )
        )

        parts: List[str] = [
            f"Prior runs on '{challenge_name}' ({len(all_docs)} total: {count_str}):"
        ]
        # Track only the docs whose content actually contributed to the
        # compressed output (one success + one failure at most).
        contributing: List[str] = []

        # Most recent success — primary action guide
        success_docs = [
            (mtime, c, fname) for mtime, o, c, fname in all_docs if o == "success"
        ]
        if success_docs:
            _, best_success, best_fname = success_docs[
                0
            ]  # already sorted by recency DESC within outcome
            contributing.append(best_fname)
            summary_m = re.search(
                r"## What Happened\n\n(.+?)(?:\n\n##|\Z)", best_success, re.DOTALL
            )
            summary = (
                summary_m.group(1).strip()[:500] if summary_m else best_success[:300]
            )
            exploit_m = re.search(
                r"## Key Exploit Inputs\n\n.+?\n\n((?:- .+\n?)+)",
                best_success,
                re.DOTALL,
            )
            exploit_note = ""
            if exploit_m:
                exploit_note = " Exploit: " + exploit_m.group(1).strip()[:200]
            parts.append(f"✓ MOST RECENT SUCCESS: {summary}{exploit_note}")

        # Most recent failure/partial — negative knowledge
        fail_docs = [
            (mtime, c, fname)
            for mtime, o, c, fname in all_docs
            if o in ("failure", "partial")
        ]
        if fail_docs:
            _, best_fail, best_fail_fname = fail_docs[0]
            contributing.append(best_fail_fname)
            summary_m = re.search(
                r"## What Happened\n\n(.+?)(?:\n\n##|\Z)", best_fail, re.DOTALL
            )
            fail_summary = (
                summary_m.group(1).strip()[:300] if summary_m else best_fail[:200]
            )
            parts.append(f"✗ PRIOR FAILURE: {fail_summary}")

        return "\n\n".join(parts)[:1500], contributing

    # 2. Category fallback (v3.8 P2): no per-challenge match, but the
    # classifier may still infer a category from name / URL / description,
    # in which case we surface successful runs from that category as
    # negative-or-positive prior knowledge. This is what makes lessons
    # *generalize* across CTF platforms instead of only firing on
    # previously-seen challenges.
    category_text, category_sources = _collect_lessons_by_category_with_sources(
        challenge_name=challenge_name,
        challenge_url=challenge_url,
        challenge_description=challenge_description,
        lessons_docs_dir=lessons_docs_dir,
    )
    if category_text is not None:
        return category_text, category_sources

    # 3. Fallback: failure_*.md legacy docs (compress on-the-fly).
    # Per-challenge only — the legacy format predates category metadata.
    if not challenge_name:
        return None, []
    legacy_docs = _collect_matching(fallback_failure_docs_dir, "failure_*.md")
    if not legacy_docs:
        return None, []

    legacy_docs.sort(key=lambda x: -x[0])  # most recent first
    _, _, raw, legacy_fname = legacy_docs[0]

    lines: List[str] = [f"Prior attempt on '{challenge_name}' (legacy failure doc):"]
    cat_m = re.search(r"\*\*Category:\*\*\s*(.+)", raw)
    if cat_m:
        lines.append(f"Category: {cat_m.group(1).strip()}.")
    reason_m = re.search(r"\*\*Failure Reason:\*\*\s*(.+)", raw)
    if reason_m:
        lines.append(f"Failure reason: {reason_m.group(1).strip()}.")
    sugg_m = re.search(
        r"##\s*\d*\.?\s*Suggestions.*?\n(.*?)(?:\n## |\Z)", raw, re.DOTALL
    )
    if sugg_m:
        lines.append(f"Suggestions: {sugg_m.group(1).strip()[:400]}")
    return " ".join(lines)[:1500], [legacy_fname]


def _collect_lessons_by_category(
    *,
    challenge_name: Optional[str],
    challenge_url: Optional[str],
    challenge_description: Optional[str],
    lessons_docs_dir: str,
) -> Optional[str]:
    """Backward-compatible wrapper — returns only the compressed text."""
    text, _ = _collect_lessons_by_category_with_sources(
        challenge_name=challenge_name,
        challenge_url=challenge_url,
        challenge_description=challenge_description,
        lessons_docs_dir=lessons_docs_dir,
    )
    return text


def _collect_lessons_by_category_with_sources(
    *,
    challenge_name: Optional[str],
    challenge_url: Optional[str],
    challenge_description: Optional[str],
    lessons_docs_dir: str,
) -> Tuple[Optional[str], List[str]]:
    """Category-fallback Reflexion injection (v3.8 P2).

    When ``find_and_compress_prior_lesson`` finds no per-challenge match,
    classify the challenge from name + URL + description and surface
    successful runs from the same category as a Reflexion summary.

    Returns ``(None, [])`` when:
      - The classifier returns ``UNKNOWN`` or yields no signal at all.
      - The lessons dir contains no docs in the inferred category.

    Otherwise returns ``(text, source_filenames)`` with text capped at ~1500
    chars and source_filenames listing the basenames that contributed.
    """
    # Lazy import: avoids a hard dependency on the classifier when this
    # module is imported by code that doesn't need lesson injection.
    try:
        from ctf_solver.classifier.challenge_classifier import (
            ChallengeCategory,
            create_classifier,
        )
    except Exception:
        return None, []

    description = " ".join(
        s for s in (challenge_name, challenge_description) if s and isinstance(s, str)
    ).strip()
    if not description and not challenge_url:
        return None, []

    classifier = create_classifier()
    try:
        result = classifier.classify(
            description=description or None,
            url=challenge_url,
        )
    except Exception:
        return None, []
    if result.primary_category == ChallengeCategory.UNKNOWN:
        return None, []

    category_key = result.primary_category.value
    target_label = _CATEGORY_LABELS.get(category_key)
    if not target_label:
        return None, []

    d = Path(lessons_docs_dir)
    if not d.exists():
        return None, []

    matches: List[Tuple[float, str, str, str]] = []
    label_line = f"**Category:** {target_label}"
    for doc_path in d.glob("lessons_*.md"):
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if label_line not in content:
            continue
        outcome_match = re.search(r"\*\*Type:\*\*\s*experience_(\w+)", content)
        outcome = outcome_match.group(1) if outcome_match else "unknown"
        matches.append((doc_path.stat().st_mtime, outcome, content, doc_path.name))

    if not matches:
        return None, []

    _OUTCOME_PRIORITY = {"success": 0, "partial": 1, "failure": 2, "unknown": 3}
    matches.sort(key=lambda x: (_OUTCOME_PRIORITY.get(x[1], 3), -x[0]))

    parts: List[str] = [
        (
            f"No prior runs match this challenge by name; falling back to "
            f"category lessons. Inferred category: '{target_label}' "
            f"(confidence={result.confidence:.2f}). "
            f"{len(matches)} relevant prior run(s) in this category."
        )
    ]
    contributing: List[str] = []
    success_docs = [
        (mtime, c, fname) for mtime, o, c, fname in matches if o == "success"
    ]
    if success_docs:
        _, best_success, best_fname = success_docs[0]
        contributing.append(best_fname)
        summary_m = re.search(
            r"## What Happened\n\n(.+?)(?:\n\n##|\Z)", best_success, re.DOTALL
        )
        summary = summary_m.group(1).strip()[:400] if summary_m else best_success[:300]
        parts.append(f"✓ A success in this category: {summary}")
    fail_docs = [
        (mtime, c, fname)
        for mtime, o, c, fname in matches
        if o in ("failure", "partial")
    ]
    if fail_docs:
        _, best_fail, best_fail_fname = fail_docs[0]
        contributing.append(best_fail_fname)
        summary_m = re.search(
            r"## What Happened\n\n(.+?)(?:\n\n##|\Z)", best_fail, re.DOTALL
        )
        fail_summary = (
            summary_m.group(1).strip()[:300] if summary_m else best_fail[:200]
        )
        parts.append(f"✗ A failure in this category: {fail_summary}")
    return "\n\n".join(parts)[:1500], contributing
