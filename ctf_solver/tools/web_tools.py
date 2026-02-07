"""
Web-specific tools for CTF solving.

Provides robots.txt parsing and cookie manipulation capabilities.
"""

import json
from typing import List, Optional
from urllib.parse import urlparse

import requests


class RobotsTxtTool:
    """
    RobotsTxtTool: fetch and parse robots.txt for a base URL.

    Inputs (JSON via `.use`):

        {
          "base_url": "https://example.com"
        }

    Behavior:
      - Fetches {base_url}/robots.txt using the shared session.
      - Parses lines starting with 'Disallow' or 'Allow' (case-insensitive).
      - Returns a readable summary of rules and suggested paths to explore.
    """

    name: str = "robots_txt"
    description: str = (
        "Fetch and parse robots.txt for a given base URL. Input JSON key: "
        "'base_url' (string, e.g., 'https://example.com'). The tool fetches "
        "base_url + '/robots.txt', parses Allow/Disallow rules, and returns a "
        "readable summary and suggested paths to explore. Use this tool to "
        "discover hidden or restricted paths on the web server."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[RobotsTxtTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        base_url = data.get("base_url")
        if not isinstance(base_url, str) or not base_url:
            return "[RobotsTxtTool] Error: 'base_url' (string) is required."

        robots_url = base_url.rstrip("/") + "/robots.txt"

        try:
            resp = self.session.get(robots_url, timeout=10)
        except Exception as exc:
            return (
                f"[RobotsTxtTool] Error fetching robots.txt at {robots_url!r}: {exc!r}"
            )

        if resp.status_code == 404:
            return (
                f"[RobotsTxtTool] robots.txt not found at {robots_url}. "
                "There may be no explicit crawling rules."
            )

        text = resp.text or ""
        lines = text.splitlines()

        allow_rules: List[str] = []
        disallow_rules: List[str] = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if lower.startswith("allow:"):
                allow_rules.append(stripped)
            elif lower.startswith("disallow:"):
                disallow_rules.append(stripped)

        summary: List[str] = [
            f"[RobotsTxtTool] robots.txt for {base_url}",
            f"Fetched from: {robots_url}",
            "",
            "[RAW CONTENT]",
            text,
            "",
            "[PARSED RULES]",
        ]

        summary.append("Allow rules:")
        summary.extend(allow_rules or ["- (none)"])
        summary.append("")
        summary.append("Disallow rules:")
        summary.extend(disallow_rules or ["- (none)"])
        summary.append("")

        # Suggest paths to explore based on Disallow rules.
        suggested_paths: List[str] = []
        for rule in disallow_rules:
            parts = rule.split(":", 1)
            if len(parts) == 2:
                path = parts[1].strip()
                if path and path != "/":
                    suggested_paths.append(path)

        summary.append("[SUGGESTED PATHS TO EXPLORE]")
        if suggested_paths:
            for p in suggested_paths:
                full = base_url.rstrip("/") + p
                summary.append(f"- {full}")
        else:
            summary.append("- (no specific Disallow paths found to suggest)")

        return "\n".join(summary)


class CookieInspectorTool:
    """
    CookieInspectorTool: inspect cookies stored in the shared session.

    Inputs (JSON via `.use`):

        {
          "base_url": "https://example.com"   # or
          "domain": "example.com"
        }

    Behavior:
      - Determines a domain from base_url or domain.
      - Filters cookies from the shared session for that domain.
      - Returns key/value pairs and attributes in a human-friendly format.
    """

    name: str = "cookie_inspector"
    description: str = (
        "Inspect cookies stored in the shared HTTP session for a given domain. "
        "Input JSON keys: 'base_url' (e.g., 'https://example.com') or 'domain' "
        "(e.g., 'example.com'). Returns cookie names, values, and basic attributes. "
        "Use this tool to examine session cookies, authentication tokens, or "
        "any other cookies that might be relevant to the challenge."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[CookieInspectorTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        base_url = data.get("base_url")
        domain = data.get("domain")

        if base_url and not isinstance(base_url, str):
            return "[CookieInspectorTool] Error: 'base_url' must be a string if provided."
        if domain and not isinstance(domain, str):
            return "[CookieInspectorTool] Error: 'domain' must be a string if provided."

        if not domain and base_url:
            parsed = urlparse(base_url)
            domain = parsed.hostname or ""
        if not domain:
            return (
                "[CookieInspectorTool] Error: You must provide either 'base_url' "
                "or 'domain' in the JSON input."
            )

        domain = domain.lstrip(".")
        jar = self.session.cookies

        lines: List[str] = [
            f"[CookieInspectorTool] Cookies for domain matching {domain!r}:"
        ]
        found = False
        for c in jar:
            c_domain = (c.domain or "").lstrip(".")
            if c_domain.endswith(domain):
                found = True
                lines.append(
                    f"- name={c.name!r}, value={c.value!r}, "
                    f"domain={c.domain!r}, path={c.path!r}, secure={c.secure}, "
                    f"expires={c.expires}"
                )

        if not found:
            lines.append("- (no cookies found for this domain)")

        return "\n".join(lines)


class CookieSetTool:
    """
    CookieSetTool: set or update a cookie in the shared session.

    Inputs (JSON via `.use`):

        {
          "domain": "example.com",
          "name": "admin",
          "value": "true",
          "path": "/"                 # optional, defaults to "/"
        }

    Behavior:
      - Sets/updates the cookie in the shared session. Subsequent HTTP calls
        using that session will include this cookie when appropriate.
    """

    name: str = "cookie_set"
    description: str = (
        "Set or update a cookie in the shared HTTP session. Input JSON keys: "
        "'domain' (string, required), 'name' (string, required), 'value' "
        "(string, required), and 'path' (optional, default '/'). Use this tool "
        "to manipulate session state, bypass authentication checks, or test "
        "cookie-based vulnerabilities."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[CookieSetTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        domain = data.get("domain")
        name = data.get("name")
        value = data.get("value")
        path = data.get("path", "/")

        if not all(isinstance(x, str) and x for x in (domain, name, value)):
            return (
                "[CookieSetTool] Error: 'domain', 'name', and 'value' must all be "
                "non-empty strings."
            )

        if not isinstance(path, str):
            return "[CookieSetTool] Error: 'path' must be a string."

        try:
            self.session.cookies.set(name=name, value=value, domain=domain, path=path)
        except Exception as exc:
            return f"[CookieSetTool] Error setting cookie: {exc!r}"

        return (
            f"[CookieSetTool] Set cookie: name={name!r}, value={value!r}, "
            f"domain={domain!r}, path={path!r}"
        )
