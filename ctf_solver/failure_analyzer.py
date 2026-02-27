"""
Failure analysis engine for the CTF Solver.

Provides deterministic (no LLM) failure detection, analysis, and knowledge
document generation. When a run fails, this module:

1. Detects that the run failed (no flag found, max steps, agent admission)
2. Analyzes what was tried and what went wrong from tool call logs
3. Generates a structured markdown knowledge document
4. Saves it to the failure knowledge directory for RAG augmentation

Design decision: analysis is purely deterministic to avoid confounding
variables in the academic study and to keep costs at zero.
"""

import os
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Category inference from tool usage
# ---------------------------------------------------------------------------

_TOOL_TO_CATEGORY = {
    "sqli_probe": "sql_injection",
    "sqli_column_counter": "sql_injection",
    "blind_sqli_boolean": "sql_injection",
    "blind_sqli_time": "sql_injection",
    "sqli_data_dumper": "sql_injection",
    "sql_pattern_hint": "sql_injection",
    "jwt_tool": "jwt_attacks",
    "ssti_probe": "ssti",
    "ssti_exploit_suggester": "ssti",
    "file_upload": "file_upload",
    "upload_location_finder": "file_upload",
    "xxe_probe": "xxe",
    "xxe_payload_generator": "xxe",
    "xxe_doctype_builder": "xxe",
    "cookie_inspector": "cookies_auth",
    "cookie_set": "cookies_auth",
    "robots_txt": "recon",
    "path_enumerator": "recon",
    "backup_file_finder": "recon",
    "html_inspector": "client_side",
    "javascript_source": "client_side",
    "timing_compare": "recon",
    "response_diff": "recon",
    "xpath_probe": "xpath_injection",
    "xpath_blind_boolean": "xpath_injection",
    "xpath_payload_generator": "xpath_injection",
    "filter_enumerator": "filter_bypass",
    "payload_mutator": "filter_bypass",
    "ssrf_probe": "ssrf",
    "ssrf_payload_generator": "ssrf",
    "attack_planner": "recon",
    "lfi_probe": "file_inclusion",
    "lfi_payload_generator": "file_inclusion",
    "nosql_probe": "nosql_injection",
    "nosql_payload_generator": "nosql_injection",
    "cmdi_probe": "command_injection",
    "cmdi_payload_generator": "command_injection",
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
}

_CATEGORY_LABELS = {
    "sql_injection": "SQL Injection",
    "jwt_attacks": "JWT Attacks",
    "ssti": "Server-Side Template Injection",
    "file_upload": "File Upload Vulnerabilities",
    "xxe": "XML External Entity (XXE)",
    "cookies_auth": "Cookies / Session / Auth Bypass",
    "recon": "Reconnaissance & Hidden Paths",
    "client_side": "Client-Side (HTML/JS) Analysis",
    "command_injection": "Command Injection",
    "xpath_injection": "XPath Injection",
    "filter_bypass": "Filter/WAF Bypass",
    "file_inclusion": "Local/Remote File Inclusion",
    "nosql_injection": "NoSQL Injection",
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
    "unknown": "General Web Exploitation",
}

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
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FailureAnalysis:
    """Structured result of analyzing a failed run."""

    challenge_url: str = ""
    challenge_description: str = ""
    failure_reason: str = ""
    inferred_category: str = "unknown"
    total_steps: int = 0
    duration_seconds: float = 0.0

    # What was tried
    tools_used: List[str] = field(default_factory=list)
    tool_frequency: Dict[str, int] = field(default_factory=dict)
    payloads_tried: List[str] = field(default_factory=list)
    urls_accessed: List[str] = field(default_factory=list)

    # What went wrong
    errors_encountered: List[str] = field(default_factory=list)
    repeated_failures: List[str] = field(default_factory=list)

    # Suggestions (deterministic)
    suggestions: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Failure detection
# ---------------------------------------------------------------------------

def detect_failure(
    agent_response: Optional[str],
    candidate_flags: List[str],
    max_steps: int,
    actual_steps: int,
    flag_regex: str = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}",
) -> Tuple[bool, str]:
    """
    Determine whether the run failed and why.

    Returns:
        (is_failure, reason) — True if the run failed, with a human-readable reason.
    """
    # No response at all
    if not agent_response or not agent_response.strip():
        return True, "Agent produced no response"

    # No flags found anywhere
    if not candidate_flags:
        return True, "No candidate flags found in any tool output"

    # Max steps exhausted (likely stuck in a loop)
    if actual_steps >= max_steps:
        return True, f"Max steps exhausted ({actual_steps}/{max_steps})"

    # Agent explicitly admits failure
    for pattern in _FAILURE_ADMISSION_PATTERNS:
        if re.search(pattern, agent_response):
            return True, "Agent admitted failure in final response"

    # If we have candidate flags, assume success
    return False, "Run appears successful"


# ---------------------------------------------------------------------------
# 2. Failure analysis (deterministic)
# ---------------------------------------------------------------------------

def analyze_failure(
    config_data: Dict[str, Any],
    tracker_data: Dict[str, Any],
    tool_call_log: List[Dict[str, Any]],
    agent_response: Optional[str],
    failure_reason: str,
) -> FailureAnalysis:
    """
    Analyze a failed run using tool call logs and tracker data.

    All analysis is deterministic — no LLM calls.

    Args:
        config_data: Dict with challenge_url, challenge_description, etc.
        tracker_data: Dict from RunTracker.to_dict()
        tool_call_log: List of detailed tool call records
        agent_response: The agent's final response text
        failure_reason: Reason string from detect_failure()

    Returns:
        FailureAnalysis with extracted insights
    """
    analysis = FailureAnalysis(
        challenge_url=config_data.get("challenge_url", ""),
        challenge_description=config_data.get("challenge_description", ""),
        failure_reason=failure_reason,
        total_steps=tracker_data.get("steps", 0),
        duration_seconds=tracker_data.get("duration_seconds", 0.0),
    )

    # Tool usage stats
    tool_counts = tracker_data.get("tool_calls", {})
    analysis.tool_frequency = dict(tool_counts)
    analysis.tools_used = list(tool_counts.keys())

    # Infer challenge category from which tools were used most
    category_scores: Counter = Counter()
    for tool_name, count in tool_counts.items():
        cat = _TOOL_TO_CATEGORY.get(tool_name)
        if cat:
            category_scores[cat] += count
    if category_scores:
        analysis.inferred_category = category_scores.most_common(1)[0][0]

    # Extract payloads, URLs, and errors from tool call log
    seen_payloads = set()
    seen_urls = set()
    seen_errors = set()
    repeated_inputs: Counter = Counter()

    for entry in tool_call_log:
        tool_input = entry.get("input", "")
        tool_output = entry.get("output", "")
        tool_name = entry.get("tool", "")

        # Extract URLs from input
        url_matches = re.findall(r'https?://[^\s"\'}\]]+', tool_input)
        for url in url_matches:
            seen_urls.add(url)

        # Extract payloads (SQL-related inputs)
        if tool_name in ("sqli_probe", "blind_sqli_boolean", "blind_sqli_time",
                         "sqli_data_dumper", "form_submit", "http_fetch"):
            # Track repeated identical inputs (sign of being stuck)
            input_key = f"{tool_name}:{tool_input[:200]}"
            repeated_inputs[input_key] += 1

            # Extract SQL-like payloads
            sql_matches = re.findall(
                r"""['"]?\s*(?:OR|AND|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|'|"|--|/\*|#|;).*?(?=['"\s}]|$)""",
                tool_input, re.IGNORECASE
            )
            for p in sql_matches:
                p_clean = p.strip()[:200]
                if p_clean and p_clean not in seen_payloads:
                    seen_payloads.add(p_clean)

        # Extract errors from output
        for err_pattern in _ERROR_PATTERNS:
            err_matches = re.findall(err_pattern, tool_output)
            for err in err_matches:
                if isinstance(err, str) and err.strip():
                    seen_errors.add(err.strip().lower())

    analysis.payloads_tried = sorted(seen_payloads)[:50]
    analysis.urls_accessed = sorted(seen_urls)[:20]
    analysis.errors_encountered = sorted(seen_errors)[:30]

    # Identify repeated failures (same input tried 3+ times)
    analysis.repeated_failures = [
        inp.split(":", 1)[1] if ":" in inp else inp
        for inp, count in repeated_inputs.items()
        if count >= 3
    ][:10]

    # Generate deterministic suggestions
    analysis.suggestions = _generate_suggestions(analysis, tool_call_log)

    return analysis


def _generate_suggestions(
    analysis: FailureAnalysis,
    tool_call_log: List[Dict[str, Any]],
) -> List[str]:
    """Generate deterministic suggestions based on what was tried."""
    suggestions = []

    cat = analysis.inferred_category

    # Category-specific suggestions
    if cat == "sql_injection":
        if not any("blind" in t for t in analysis.tools_used):
            suggestions.append(
                "Try blind SQL injection (boolean-based or time-based) if error-based SQLi failed"
            )
        if not any("column" in t for t in analysis.tools_used):
            suggestions.append(
                "Try determining column count with sqli_column_counter before UNION attacks"
            )
        # Check if filter bypass might be needed
        if any("blocked" in e or "filtered" in e or "forbidden" in e
               for e in analysis.errors_encountered):
            suggestions.append(
                "Input appears filtered — try alternative operators: "
                "GLOB instead of LIKE/=, IS instead of =, || for concatenation, "
                "BETWEEN for range comparisons"
            )

    elif cat == "jwt_attacks":
        suggestions.append(
            "Try algorithm confusion (none, HS256↔RS256), weak secrets, "
            "and kid header injection"
        )

    elif cat == "ssti":
        suggestions.append(
            "Try multiple template engines: {{7*7}} for Jinja2/Twig, "
            "${7*7} for Freemarker, #{7*7} for Ruby ERB"
        )

    elif cat == "file_upload":
        suggestions.append(
            "Try double extensions (.php.jpg), content-type spoofing, "
            "null byte injection, and .htaccess upload"
        )

    elif cat == "cookies_auth":
        suggestions.append(
            "Check for predictable session tokens, JWT in cookies, "
            "or base64-encoded role fields"
        )

    # General suggestions based on failure patterns
    if analysis.repeated_failures:
        suggestions.append(
            f"Agent was stuck repeating the same input {len(analysis.repeated_failures)} time(s) — "
            "vary the approach or try a different attack vector"
        )

    if analysis.total_steps >= 15:
        suggestions.append(
            "Run used most of its step budget — prioritize the most promising "
            "attack vector early rather than trying everything"
        )

    if not any(t in analysis.tools_used for t in ("robots_txt", "path_enumerator", "backup_file_finder")):
        suggestions.append(
            "No reconnaissance was performed — try robots.txt, path enumeration, "
            "or backup file discovery first"
        )

    if not any(t in analysis.tools_used for t in ("javascript_source", "html_inspector")):
        suggestions.append(
            "No client-side analysis done — check HTML source and JavaScript "
            "for hints, hidden fields, or client-side validation"
        )

    return suggestions[:8]  # Cap at 8 suggestions


# ---------------------------------------------------------------------------
# 3. Knowledge document generation
# ---------------------------------------------------------------------------

def generate_failure_knowledge_doc(
    analysis: FailureAnalysis,
    doc_index: int,
) -> str:
    """
    Generate a markdown knowledge document from the failure analysis.

    The format matches the existing docs/ convention with sections, Tags,
    and actionable content for RAG retrieval.

    Args:
        analysis: FailureAnalysis from analyze_failure()
        doc_index: Numeric index for the doc filename (e.g., 100)

    Returns:
        Markdown string ready to be saved
    """
    category_label = _CATEGORY_LABELS.get(analysis.inferred_category, "General Web Exploitation")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    lines = [
        f"# Failure Analysis: {category_label}",
        "",
        f"> **Auto-generated:** {timestamp}",
        f"> **Category:** {category_label}",
        f"> **Failure Reason:** {analysis.failure_reason}",
        "",
        "---",
        "",
    ]

    # Section 1: Challenge context
    lines.append("## 1. Challenge Context")
    lines.append("")
    lines.append(f"**Tags:** `failure-analysis, {analysis.inferred_category}, lessons-learned`")
    lines.append("")
    if analysis.challenge_url:
        lines.append(f"- **URL:** `{analysis.challenge_url}`")
    if analysis.challenge_description:
        lines.append(f"- **Description:** {analysis.challenge_description}")
    lines.append(f"- **Steps used:** {analysis.total_steps}")
    lines.append(f"- **Duration:** {analysis.duration_seconds:.1f}s")
    lines.append("")

    # Section 2: What was tried (negative knowledge)
    lines.append("## 2. What Was Tried (Negative Knowledge)")
    lines.append("")
    lines.append(f"**Tags:** `negative-knowledge, {analysis.inferred_category}, tools-used`")
    lines.append("")
    lines.append("The following tools and techniques were attempted but did **not** lead to a solution:")
    lines.append("")

    if analysis.tool_frequency:
        lines.append("### Tools Used")
        lines.append("")
        for tool, count in sorted(analysis.tool_frequency.items(), key=lambda x: -x[1]):
            lines.append(f"- `{tool}`: {count} call(s)")
        lines.append("")

    if analysis.payloads_tried:
        lines.append("### Payloads Attempted")
        lines.append("")
        lines.append("```")
        for p in analysis.payloads_tried[:15]:
            lines.append(p)
        lines.append("```")
        lines.append("")

    if analysis.urls_accessed:
        lines.append("### URLs Accessed")
        lines.append("")
        for url in analysis.urls_accessed[:10]:
            lines.append(f"- `{url}`")
        lines.append("")

    # Section 3: Errors encountered
    if analysis.errors_encountered:
        lines.append("## 3. Errors Encountered")
        lines.append("")
        lines.append(f"**Tags:** `errors, {analysis.inferred_category}, debugging`")
        lines.append("")
        for err in analysis.errors_encountered[:15]:
            lines.append(f"- {err}")
        lines.append("")

    # Section 4: Repeated failures (stuck patterns)
    if analysis.repeated_failures:
        lines.append("## 4. Stuck Patterns (Repeated Failures)")
        lines.append("")
        lines.append(f"**Tags:** `stuck-patterns, loop-detection, {analysis.inferred_category}`")
        lines.append("")
        lines.append("The agent repeated the following inputs 3+ times, indicating it was stuck:")
        lines.append("")
        lines.append("```")
        for rf in analysis.repeated_failures[:5]:
            lines.append(rf[:200])
        lines.append("```")
        lines.append("")

    # Section 5: Suggestions for next attempt
    lines.append("## 5. Suggestions for Next Attempt")
    lines.append("")
    lines.append(f"**Tags:** `suggestions, {analysis.inferred_category}, strategy`")
    lines.append("")
    lines.append("> **Agent Takeaway:** When encountering a similar challenge, avoid the approaches "
                 "listed in Section 2 and try the suggestions below instead.")
    lines.append("")
    if analysis.suggestions:
        for i, suggestion in enumerate(analysis.suggestions, 1):
            lines.append(f"{i}. {suggestion}")
    else:
        lines.append("- Try a fundamentally different attack vector")
        lines.append("- Consult the knowledge base for alternative techniques")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 3b. Deduplication
# ---------------------------------------------------------------------------

def _is_duplicate(analysis: FailureAnalysis, docs_dir: Path) -> bool:
    """
    Check if a similar failure doc already exists in the directory.

    Similarity criteria (all must match):
      1. Same challenge_url (exact)
      2. Same inferred_category (exact, via label)
      3. Jaccard similarity of tool sets > 0.7

    Returns True if a duplicate exists.
    """
    if not docs_dir.exists():
        return False

    existing_docs = list(docs_dir.glob("failure_*.md"))
    if not existing_docs:
        return False

    new_tools = set(analysis.tools_used)
    expected_label = _CATEGORY_LABELS.get(analysis.inferred_category, "")

    for doc_path in existing_docs:
        try:
            content = doc_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        # Extract challenge URL from doc
        url_match = re.search(r"\*\*URL:\*\*\s*`([^`]+)`", content)
        doc_url = url_match.group(1) if url_match else ""

        # Must have a matching URL (and URL must be non-empty)
        if not analysis.challenge_url or doc_url != analysis.challenge_url:
            continue

        # Extract category from doc
        cat_match = re.search(r"\*\*Category:\*\*\s*(.+)", content)
        doc_category = cat_match.group(1).strip() if cat_match else ""

        if doc_category != expected_label:
            continue

        # Extract tool names from doc for Jaccard similarity
        doc_tools: set = set()
        tool_pattern = re.compile(r"^- `([^`]+)`: \d+ call", re.MULTILINE)
        for m in tool_pattern.finditer(content):
            doc_tools.add(m.group(1))

        # Jaccard similarity
        if not new_tools and not doc_tools:
            return True  # Both empty → identical

        union = new_tools | doc_tools
        if not union:
            continue

        jaccard = len(new_tools & doc_tools) / len(union)
        if jaccard > 0.7:
            return True

    return False


# ---------------------------------------------------------------------------
# 4. Pipeline entry point
# ---------------------------------------------------------------------------

def run_failure_analysis_pipeline(
    config_data: Dict[str, Any],
    tracker_data: Dict[str, Any],
    tool_call_log: List[Dict[str, Any]],
    agent_response: Optional[str],
    candidate_flags: List[str],
    failure_docs_dir: str = "out/failure_knowledge",
    max_steps: int = 20,
    actual_steps: int = 0,
    flag_regex: str = r"(?:[A-Za-z0-9_]+)?\{[^\n\r{}]{1,200}\}",
) -> Optional[str]:
    """
    Main entry point: detect failure → analyze → generate doc → save.

    Args:
        config_data: Dict with challenge_url, challenge_description, etc.
        tracker_data: Dict from RunTracker.to_dict()
        tool_call_log: List of detailed tool call records
        agent_response: The agent's final response text
        candidate_flags: List of candidate flags found during the run
        failure_docs_dir: Directory to save failure knowledge docs
        max_steps: Maximum steps configured for the run
        actual_steps: Actual steps taken
        flag_regex: Flag regex pattern

    Returns:
        Path to the generated doc file, or None if the run succeeded.
    """
    # Step 1: Detect failure
    is_failure, reason = detect_failure(
        agent_response=agent_response,
        candidate_flags=candidate_flags,
        max_steps=max_steps,
        actual_steps=actual_steps,
        flag_regex=flag_regex,
    )

    if not is_failure:
        return None

    # Step 2: Analyze
    analysis = analyze_failure(
        config_data=config_data,
        tracker_data=tracker_data,
        tool_call_log=tool_call_log,
        agent_response=agent_response,
        failure_reason=reason,
    )

    # Step 2.5: Deduplication check
    docs_dir = Path(failure_docs_dir)
    docs_dir.mkdir(parents=True, exist_ok=True)

    if _is_duplicate(analysis, docs_dir):
        return None  # Similar doc already exists

    # Step 3: Generate document

    existing = list(docs_dir.glob("failure_*.md"))
    next_index = len(existing) + 1

    doc_content = generate_failure_knowledge_doc(analysis, next_index)

    # Step 4: Save
    timestamp_slug = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    category_slug = analysis.inferred_category.replace(" ", "_")
    filename = f"failure_{next_index:03d}_{category_slug}_{timestamp_slug}.md"
    doc_path = docs_dir / filename

    doc_path.write_text(doc_content, encoding="utf-8")

    return str(doc_path)
