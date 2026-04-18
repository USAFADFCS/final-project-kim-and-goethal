"""IDOR enumeration probe (split from misc_probe_tools.py)."""

import hashlib
import json
import re
from typing import Dict, List, Optional, Tuple

import requests


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
        "'param' (current ID value in URL or parameter). Optionally provide 'param_type' "
        "(path/query/body, default path), 'param_name' (for query/body), 'range_start' "
        "(default 0), 'range_end' (default 20), 'id_type' (sequential/md5, default "
        "sequential), 'method' (default GET), 'headers', 'data', 'timeout' (default 10). "
        "Returns enumeration results with anomaly detection. Range capped at 100 IDs."
    )

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
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[IdorEnumeratorTool] Error: Invalid JSON input. {exc}"

        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        param = str(data.get("param", "")).strip()
        param_type = data.get("param_type", "path").strip().lower()
        param_name = data.get("param_name", "id").strip()
        range_start = data.get("range_start", 0)
        range_end = data.get("range_end", 20)
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
