"""
Search and pattern matching tools for CTF solving.

Provides regex search, response analysis, and SQL pattern detection.
"""

import json
import re
from typing import List


class RegexSearchTool:
    """
    RegexSearchTool: find regex matches within a text.

    Inputs (JSON via `.use`):

        {
          "text": "some long text ...",
          "pattern": "FLAG\\{.*?\\}",
          "max_matches": 50        # optional
        }

    Behavior:
      - Compiles the given regex pattern using Python's `re` module (DOTALL).
      - Finds all matches in `text`.
      - Returns up to max_matches results, numbered, and notes if truncated.
    """

    name: str = "regex_search"
    description: str = (
        "Search a text for occurrences of a regular expression. Input JSON keys: "
        "'text' (string), 'pattern' (string regex), and 'max_matches' (optional int, "
        "default 50). Returns up to max_matches matches and notes if truncated. "
        "Use this tool to find flags, secrets, or patterns in HTTP responses, "
        "JavaScript code, or any text content."
    )

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[RegexSearchTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        pattern = data.get("pattern")
        max_matches = data.get("max_matches", 50)

        if not isinstance(text, str):
            return "[RegexSearchTool] Error: 'text' must be a string."
        if not isinstance(pattern, str):
            return "[RegexSearchTool] Error: 'pattern' must be a string."

        try:
            max_matches_int = int(max_matches)
        except Exception:
            max_matches_int = 50

        try:
            regex = re.compile(pattern, re.DOTALL)
        except re.error as exc:
            return f"[RegexSearchTool] Error: invalid regex pattern: {exc}"

        matches = regex.findall(text)

        if not matches:
            return "[RegexSearchTool] No matches found."

        lines: List[str] = ["[RegexSearchTool] Matches:"]
        count = 0
        for idx, m in enumerate(matches, start=1):
            if count >= max_matches_int:
                break
            if isinstance(m, tuple):
                m_str = ", ".join(repr(x) for x in m)
            else:
                m_str = repr(m)
            lines.append(f"{idx}. {m_str}")
            count += 1

        if len(matches) > max_matches_int:
            lines.append(
                f"...[truncated: {len(matches) - max_matches_int} additional matches]"
            )

        return "\n".join(lines)


class ResponseSearchTool:
    """
    ResponseSearchTool: highlight lines in a response that contain given keywords.

    Inputs (JSON via `.use`):

        {
          "text": "<full HTTP response body as string>",
          "keywords": ["error", "sql", "warning"],  # optional list of strings
          "context_lines": 2                        # optional int, default 2
        }

    Behavior:
      - Splits 'text' into lines.
      - For each line that contains any keyword (case-insensitive), captures
        that line plus a small context window before and after it.
      - Returns a readable result with line numbers and context, so the LLM
        can quickly focus on interesting parts (errors, hints, mentions of SQL, etc.).
    """

    name: str = "response_search"
    description: str = (
        "Search an HTTP response body for lines containing certain keywords, "
        "and return those lines with surrounding context. Input JSON keys: "
        "'text' (string), 'keywords' (optional list of strings), and "
        "'context_lines' (optional int, default 2). Use this tool to find "
        "error messages, hints, or indicators of vulnerabilities in responses."
    )

    # Default keywords for general CTF/web exploitation
    DEFAULT_KEYWORDS = [
        "error",
        "warning",
        "sql",
        "exception",
        "flag",
        "invalid",
        "denied",
        "forbidden",
        "secret",
        "admin",
    ]

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[ResponseSearchTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        keywords = data.get("keywords", [])
        context_lines = data.get("context_lines", 2)

        if not isinstance(text, str):
            return "[ResponseSearchTool] Error: 'text' must be a string."

        # Normalize keywords
        if keywords is None:
            keywords = []
        if not isinstance(keywords, list):
            return "[ResponseSearchTool] Error: 'keywords' must be a list of strings if provided."

        normalized_keywords: List[str] = []
        for kw in keywords:
            if isinstance(kw, str) and kw.strip():
                normalized_keywords.append(kw.lower())

        # If no keywords given, use a sensible default set
        if not normalized_keywords:
            normalized_keywords = [kw.lower() for kw in self.DEFAULT_KEYWORDS]

        try:
            ctx = int(context_lines)
        except Exception:
            ctx = 2

        lines = text.splitlines()
        n = len(lines)

        # Collect line indices that match
        matched_indices: List[int] = []
        for i, line in enumerate(lines):
            lower_line = line.lower()
            if any(kw in lower_line for kw in normalized_keywords):
                matched_indices.append(i)

        if not matched_indices:
            return "[ResponseSearchTool] No lines matched the given keywords."

        # Collect context line indices
        context_indices = set()
        for i in matched_indices:
            start = max(0, i - ctx)
            end = min(n - 1, i + ctx)
            for j in range(start, end + 1):
                context_indices.add(j)

        sorted_indices = sorted(context_indices)

        # Build output
        out_lines: List[str] = [
            "[ResponseSearchTool] Matching lines with context:",
            f"Keywords (case-insensitive): {normalized_keywords}",
            f"Context lines before/after each match: {ctx}",
            "",
        ]

        for idx in sorted_indices:
            prefix = ">>" if idx in matched_indices else "  "
            # 1-based line numbers for readability
            out_lines.append(f"{prefix} [line {idx+1}] {lines[idx]}")

        return "\n".join(out_lines)


class SqlPatternHintTool:
    """
    SqlPatternHintTool: scan a response body for common SQL/logging hints.

    Inputs (JSON via `.use`):

        {
          "text": "<full HTTP response body as string>"
        }

    Behavior:
      - Splits 'text' into lines.
      - Checks each line (case-insensitive) for common SQL-related substrings,
        such as: SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, ' or 1=1, --, etc.
      - Returns lines that contain these patterns, along with a short explanation
        that such lines may indicate echoed SQL queries or error messages relevant
        to SQL injection reasoning.
      - Does NOT hard-code any specific SQL injection payloads; it only highlights hints.
    """

    name: str = "sql_pattern_hint"
    description: str = (
        "Highlight response lines that contain SQL-related patterns, to help "
        "reason about possible SQL injection behavior. Input JSON key: 'text' "
        "(string). Scans for substrings like 'SELECT', 'FROM', 'WHERE', "
        "'INSERT', 'UPDATE', 'DELETE', \"' or 1=1\", and '--', and returns "
        "matching lines with a short explanatory note. Use this tool when "
        "investigating potential SQL injection vulnerabilities."
    )

    # Common SQL/logging hints (lowercase for comparison)
    SQL_PATTERNS = [
        "select ",
        " from ",
        " where ",
        " insert ",
        " update ",
        " delete ",
        " union ",
        "group by",
        "order by",
        "' or 1=1",
        '" or 1=1',
        "--",
        "/*",
        "*/",
        "sql",
        "syntax error",
        "database error",
        "mysql",
        "sqlite",
        "postgresql",
        "oracle",
    ]

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[SqlPatternHintTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        if not isinstance(text, str):
            return "[SqlPatternHintTool] Error: 'text' must be a string."

        lines = text.splitlines()

        matches: List[str] = []
        for idx, line in enumerate(lines):
            lower_line = line.lower()
            if any(p in lower_line for p in self.SQL_PATTERNS):
                matches.append(f"[line {idx+1}] {line}")

        if not matches:
            return (
                "[SqlPatternHintTool] No obvious SQL-related patterns were found in "
                "the provided text. This does not rule out SQL injection, but there "
                "are no clear error messages or echoed queries to highlight."
            )

        out_lines: List[str] = [
            "[SqlPatternHintTool] Potential SQL-related hints found in response:",
            "These lines contain substrings commonly associated with SQL queries or "
            "database error messages. They might indicate:",
            "- Echoed or logged SQL statements.",
            "- SQL syntax or database errors.",
            "- Input being directly inserted into queries.",
            "",
        ]
        out_lines.extend(matches)

        return "\n".join(out_lines)
