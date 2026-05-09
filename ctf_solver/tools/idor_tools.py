"""IDOR enumeration probe (split from misc_probe_tools.py)."""

import hashlib
import re
from typing import Dict, List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class IdorEnumeratorTool:
    """
    IdorEnumeratorTool: enumerate resources to detect IDOR vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/user/1",
          "param": "1",
          "param_type": "path",
          "param_name": "id",
          "range_start": 0,
          "range_end": 20,
          "id_type": "sequential",
          "method": "GET",
          "headers": {},
          "data": {},
          "timeout": 10
        }

    Enumerates IDs in the specified range and detects anomalies indicating
    Insecure Direct Object Reference vulnerabilities.
    """

    name: str = "idor_enumerator"
    description: str = (
        "Enumerate resources to detect IDOR (Insecure Direct Object Reference) "
        "vulnerabilities. Input must be JSON with 'url' (URL containing the ID) and "
        "'param' (the CURRENT ID VALUE present in the URL/param — e.g. '1', "
        "'e93028bdc1aa…', the literal string the server identifies the resource by). "
        "Optionally: 'param_type' (path/query/body, default path); 'param_name' "
        "(QUERY/BODY FIELD NAME, e.g. 'id'; ignored for path-IDOR); 'range_start' "
        "(default 0); 'range_end' (default 100, capped at MAX_RANGE=100); 'id_type' "
        "('sequential' tries 0,1,2…; 'md5' tries md5(0), md5(1), … — use 'md5' when "
        "the current ID is a 32-char hex token); 'method' (default GET), 'headers', "
        "'data', 'timeout' (default 10). Returns enumeration results with anomaly "
        "detection. Range capped at 100 IDs."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "param": {"type": "string"},
            "param_type": {
                "type": "string",
                "enum": ["path", "query", "body"],
                "default": "path",
            },
            "param_name": {"type": "string", "default": "id"},
            "range_start": {"type": "integer", "default": 0},
            "range_end": {"type": "integer", "default": 100},
            "id_type": {
                "type": "string",
                "enum": ["sequential", "md5"],
                "default": "sequential",
            },
            "method": {"type": "string", "enum": ["GET", "POST"], "default": "GET"},
            "headers": {"type": "object"},
            "data": {"type": "object"},
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url", "param"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/api/user/1",
            "param": "1",
            "param_type": "path",
            "range_end": 50,
        },
        {
            "url": "http://example.com/profile/user/e93028bdc1aacdfb3687181f2031765d",
            "param": "e93028bdc1aacdfb3687181f2031765d",
            "param_type": "path",
            "id_type": "md5",
            "range_end": 50,
        },
    ]

    # Flag patterns
    FLAG_PATTERNS: List[str] = [
        r"(picoCTF\{[^}]+\})",
        r"(HTB\{[^}]+\})",
        r"(THM\{[^}]+\})",
        r"(FLAG\{[^}]+\})",
        r"(flag\{[^}]+\})",
        r"(CTF\{[^}]+\})",
        r"(ctf\{[^}]+\})",
    ]

    # Interesting content patterns
    INTERESTING_PATTERNS: List[Tuple[str, str]] = [
        (r"admin", "Contains 'admin'"),
        (r"password", "Contains 'password'"),
        (r"secret", "Contains 'secret'"),
        (r"token", "Contains 'token'"),
        (r"api[_-]?key", "Contains API key reference"),
        (r"private", "Contains 'private'"),
        (r"root", "Contains 'root'"),
        (r"flag", "Contains 'flag'"),
    ]

    MAX_RANGE = 100

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _extract_flag(self, text: str) -> Optional[str]:
        """Try to extract a CTF flag from response text."""
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, text)
            if match:
                return match.group(1)
        return None

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "IdorEnumeratorTool")
        if err:
            return err
        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = str(data.get("param", "")).strip()
        param_type = data.get("param_type", "path").strip().lower()
        param_name = data.get("param_name", "id").strip()
        range_start = data.get("range_start", 0)
        # v3.10 P5b: default range_end raised from 20 to 100 (== MAX_RANGE).
        # On the live Crystal Peak run gemma called IDOR with the default,
        # tried md5(0..20), all 404'd, and abandoned the path. The
        # privileged user_id was outside that window. 100 covers more
        # ground without exceeding the existing safety cap.
        range_end = data.get("range_end", 100)
        id_type = data.get("id_type", "sequential").strip().lower()
        method = (data.get("method") or "GET").upper()
        headers = data.get("headers") or {}
        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        if not url:
            return "[IdorEnumeratorTool] Error: 'url' is required."
        if not param:
            return "[IdorEnumeratorTool] Error: 'param' (current ID value) is required."
        if param_type not in ("path", "query", "body"):
            return f"[IdorEnumeratorTool] Error: 'param_type' must be path, query, or body, got '{param_type}'."
        if id_type not in ("sequential", "md5"):
            return f"[IdorEnumeratorTool] Error: 'id_type' must be sequential or md5, got '{id_type}'."
        if method not in ("GET", "POST"):
            return f"[IdorEnumeratorTool] Error: 'method' must be GET or POST, got '{method}'."

        # Cap range at MAX_RANGE
        if range_end - range_start > self.MAX_RANGE:
            range_end = range_start + self.MAX_RANGE

        # Generate ID values
        id_values = []
        for i in range(range_start, range_end + 1):
            if id_type == "sequential":
                id_values.append(str(i))
            elif id_type == "md5":
                id_values.append(hashlib.md5(str(i).encode()).hexdigest())

        # Enumerate IDs
        results_table = []
        flags_found = []
        interesting_findings = []
        response_lengths = []

        for id_value in id_values:
            try:
                resp = self._make_request(
                    url,
                    method,
                    param,
                    param_type,
                    param_name,
                    id_value,
                    headers,
                    form_data,
                    timeout,
                )

                resp_text = resp.text
                resp_status = resp.status_code
                resp_length = len(resp_text)
                preview = resp_text[:150].replace("\n", " ").replace("\r", "")

                results_table.append(
                    {
                        "id": (
                            id_value
                            if id_type == "sequential"
                            else f"{id_value[:8]}... (md5 of {id_values.index(id_value) + range_start})"
                        ),
                        "status": resp_status,
                        "length": resp_length,
                        "preview": preview,
                    }
                )
                response_lengths.append(resp_length)

                # Check for flags
                flag = self._extract_flag(resp_text)
                if flag:
                    flags_found.append((id_value, flag))
                    interesting_findings.append(
                        f"ID {id_value}: Contains potential flag pattern: {flag}"
                    )

                # Check for interesting content
                for pattern, desc in self.INTERESTING_PATTERNS:
                    if re.search(pattern, resp_text, re.IGNORECASE):
                        interesting_findings.append(f"ID {id_value}: {desc}")
                        break  # Only report first match per ID

            except requests.exceptions.Timeout:
                results_table.append(
                    {
                        "id": id_value,
                        "status": "TIMEOUT",
                        "length": 0,
                        "preview": "(request timed out)",
                    }
                )
            except Exception as exc:
                results_table.append(
                    {
                        "id": id_value,
                        "status": "ERROR",
                        "length": 0,
                        "preview": str(exc)[:100],
                    }
                )

        # Detect anomalies (responses that differ significantly from average)
        if response_lengths:
            avg_length = sum(response_lengths) / len(response_lengths)
            for entry in results_table:
                if isinstance(entry["status"], int) and entry["status"] not in (
                    404,
                    403,
                ):
                    length_diff = abs(entry["length"] - avg_length)
                    if (
                        length_diff > avg_length * 0.5
                        and avg_length > 0
                        and entry["length"] > 0
                    ):
                        interesting_findings.append(
                            f"ID {entry['id']}: Response differs significantly "
                            f"({entry['length']} bytes vs ~{avg_length:.0f} avg)"
                        )

        # Build output report
        id_display = f"{range_start}-{range_end}"
        url_display = url.replace(param, "{id}") if param_type == "path" else url

        output_lines = [
            "[IdorEnumeratorTool] IDOR Enumeration Results",
            "=" * 50,
            f"URL: {url_display}",
            f"ID Range: {id_display}",
            f"Type: {id_type}",
            f"Param Type: {param_type}",
            f"Method: {method}",
            "",
        ]

        if flags_found:
            output_lines.append("!!! FLAGS FOUND !!!")
            for id_val, flag in flags_found:
                output_lines.append(f"  ID {id_val}: {flag}")
            output_lines.append("")

        output_lines.append("=== Results ===")
        output_lines.append(f"{'ID':<12} {'Status':<8} {'Length':<8} Response Preview")
        output_lines.append("-" * 70)

        for entry in results_table:
            id_str = str(entry["id"])[:10]
            status_str = str(entry["status"])
            length_str = str(entry["length"])
            preview_str = entry["preview"][:60]
            output_lines.append(
                f"{id_str:<12} {status_str:<8} {length_str:<8} {preview_str}"
            )

        output_lines.append("")

        # Interesting findings
        if interesting_findings:
            # Deduplicate
            unique_findings = list(dict.fromkeys(interesting_findings))
            output_lines.append("=== Interesting Findings ===")
            for finding in unique_findings:
                if "flag" in finding.lower():
                    output_lines.append(f"[!] {finding}")
                else:
                    output_lines.append(f"[+] {finding}")
            output_lines.append("")
        else:
            output_lines.append("=== No anomalies detected ===")
            output_lines.append("")

        # Summary
        output_lines.append("SUMMARY:")
        status_counts: Dict[str, int] = {}
        for entry in results_table:
            s = str(entry["status"])
            status_counts[s] = status_counts.get(s, 0) + 1
        for status, count in sorted(status_counts.items()):
            output_lines.append(f"  Status {status}: {count} responses")

        # v3.10 P5b: when no anomaly and no flag and every response was an
        # error/404, the agent on the live Crystal Peak run abandoned IDOR
        # after one narrow window. Surface a deterministic next-step
        # hint so the model knows to expand the search rather than pivot
        # to an unrelated tool.
        only_misses = (
            not flags_found
            and not interesting_findings
            and bool(response_lengths)
            and all(
                isinstance(entry["status"], int) and entry["status"] in (404, 403, 401)
                for entry in results_table
                if isinstance(entry["status"], int)
            )
        )
        if only_misses:
            next_start = range_end + 1
            next_end = min(next_start + self.MAX_RANGE - 1, next_start + 99)
            output_lines.append("")
            output_lines.append(
                "[NEXT STEP] All responses were 401/403/404 in this window. "
                f"Expand search: retry with range_start={next_start}, "
                f"range_end={next_end}. For CTF challenges where user IDs "
                "are 4-digit (e.g. guest=3000 hint), also try "
                "range_start=1000, range_end=1099 or other realistic "
                "windows. Do NOT pivot to a different tool until the "
                "IDOR search has covered plausible ID ranges."
            )

        return "\n".join(output_lines)

    def _make_request(
        self,
        url: str,
        method: str,
        param: str,
        param_type: str,
        param_name: str,
        id_value: str,
        headers: dict,
        form_data: dict,
        timeout: int,
    ) -> requests.Response:
        """Make request with the given ID value substituted."""
        if param_type == "path":
            # Replace the param value in the URL path
            test_url = url.replace(param, id_value, 1)
            if method == "GET":
                return self.session.get(test_url, headers=headers, timeout=timeout)
            else:
                return self.session.post(
                    test_url, data=form_data, headers=headers, timeout=timeout
                )
        elif param_type == "query":
            request_params = {**form_data, param_name: id_value}
            if method == "GET":
                return self.session.get(
                    url, params=request_params, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_params, headers=headers, timeout=timeout
                )
        else:  # body
            # Detect JSON content type
            content_type = ""
            for k, v in headers.items():
                if k.lower() == "content-type":
                    content_type = v.lower()
                    break
            use_json = "application/json" in content_type

            request_data = {**form_data, param_name: id_value}
            if method == "GET":
                return self.session.get(
                    url, params=request_data, headers=headers, timeout=timeout
                )
            elif use_json:
                return self.session.post(
                    url, json=request_data, headers=headers, timeout=timeout
                )
            else:
                return self.session.post(
                    url, data=request_data, headers=headers, timeout=timeout
                )
