"""
Reconnaissance meta-tools for CTF solving.

Provides:
- SecurityHeaderAnalyzerTool: analyzes HTTP response headers for security
  misconfigurations, server leaks, debug headers, and CTF-relevant hints.
- DeepReconTool: orchestrates multiple recon tools in a single call to save
  4-5 ReAct cycles at the start of every challenge.
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from ctf_solver.tools.html_tools import HtmlInspectorTool, JavaScriptSourceTool
from ctf_solver.tools.http_tools import HttpFetchTool
from ctf_solver.tools.web_tools import CookieInspectorTool, RobotsTxtTool

# ── SecurityHeaderAnalyzerTool ──────────────────────────────────────────


# Headers that should be present for security
_SECURITY_HEADERS: Dict[str, str] = {
    "content-security-policy": (
        "Content-Security-Policy: MISSING — XSS payloads may execute freely"
    ),
    "strict-transport-security": (
        "Strict-Transport-Security: MISSING — no HSTS, downgrade attacks possible"
    ),
    "x-frame-options": ("X-Frame-Options: MISSING — clickjacking possible"),
    "x-content-type-options": (
        "X-Content-Type-Options: MISSING — MIME-sniffing attacks possible"
    ),
    "referrer-policy": (
        "Referrer-Policy: MISSING — referrer may leak sensitive URL params"
    ),
    "permissions-policy": ("Permissions-Policy: MISSING (non-critical)"),
}

# Headers that leak server/technology info
_TECH_HEADERS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
]

# Patterns in header names/values that hint at debug or sensitive info
_DEBUG_PATTERNS = re.compile(
    r"(debug|trace|dev|test|token|secret|key|flag|internal|x-request-id"
    r"|x-trace-id|x-correlation-id|x-response-time)",
    re.IGNORECASE,
)

# Technology hints for CTF recommendations
_TECH_HINTS: Dict[str, str] = {
    "php": "PHP detected — consider type juggling, deserialization, filter chains, LFI",
    "express": "Express/Node.js detected — consider prototype pollution, SSTI (Pug/EJS/Nunjucks), NoSQL injection",
    "flask": "Flask detected — consider SSTI (Jinja2), Flask session forgery, pickle deserialization",
    "django": "Django detected — consider SSTI, ORM injection, debug mode endpoints (/admin)",
    "werkzeug": "Werkzeug detected — check for debug console at /console",
    "apache": "Apache detected — check for .htaccess, mod_status, server-info",
    "nginx": "Nginx detected — check for off-by-slash path traversal, alias misconfiguration",
    "tomcat": "Tomcat detected — check /manager, /host-manager, JSP file upload",
    "iis": "IIS detected — check for short filename disclosure, web.config exposure",
    "ruby": "Ruby detected — consider ERB SSTI, deserialization, mass assignment",
    "aspnet": "ASP.NET detected — consider ViewState deserialization, padding oracle",
}


class SecurityHeaderAnalyzerTool:
    """
    SecurityHeaderAnalyzerTool: analyze HTTP response headers for security
    misconfigurations and attack surface hints.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://example.com",
          "headers": {"Authorization": "Bearer ..."},  // optional
          "timeout": 10                                // optional
        }
    """

    name: str = "security_header_analyzer"
    description: str = (
        "Analyze HTTP response headers for security misconfigurations and "
        "attack surface hints. Input must be JSON with keys: 'url' (required), "
        "optional 'headers' (dict of request headers), optional 'timeout' (int, "
        "default 10). Checks for: missing security headers (CSP, HSTS, "
        "X-Frame-Options, X-Content-Type-Options), server/technology version "
        "leaks (Server, X-Powered-By), debug/custom headers, CORS "
        "misconfigurations, cookie security flags (HttpOnly, Secure, SameSite), "
        "and cache control issues. Returns a categorized security assessment "
        "with CTF-relevant exploitation hints."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[SecurityHeaderAnalyzerTool] Error: tool_input must be JSON: {exc}"

        url = data.get("url", "")
        if not url:
            return "[SecurityHeaderAnalyzerTool] Error: 'url' is required."

        req_headers = data.get("headers", {})
        timeout = data.get("timeout", 10)

        try:
            resp = self.session.get(
                url,
                headers=req_headers,
                timeout=timeout,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException as exc:
            return f"[SecurityHeaderAnalyzerTool] Error fetching {url}: {exc}"

        return self._analyze(url, resp)

    def _analyze(self, url: str, resp: requests.Response) -> str:
        """Build the full analysis report from a response."""
        hdrs = resp.headers
        lines: List[str] = [
            "[SecurityHeaderAnalyzerTool] Header Analysis Results",
            "",
            f"URL: {url}",
            f"Status: {resp.status_code}",
        ]

        # 1 — Missing security headers
        missing = self._check_missing_headers(hdrs)
        if missing:
            lines.append("")
            lines.append("=== MISSING SECURITY HEADERS ===")
            for msg in missing:
                lines.append(f"[!] {msg}")

        # 2 — Server / technology leaks
        leaks = self._check_tech_leaks(hdrs)
        if leaks:
            lines.append("")
            lines.append("=== SERVER / TECHNOLOGY LEAKS ===")
            for name, value in leaks:
                lines.append(f"[*] {name}: {value}")

        # 3 — Debug / custom headers
        debug = self._check_debug_headers(hdrs)
        if debug:
            lines.append("")
            lines.append("=== DEBUG / CUSTOM HEADERS ===")
            for name, value in debug:
                lines.append(f"[!!] {name}: {value}")

        # 4 — CORS
        cors = self._check_cors(hdrs)
        if cors:
            lines.append("")
            lines.append("=== CORS CONFIGURATION ===")
            for msg in cors:
                lines.append(f"[!] {msg}")

        # 5 — Cookie security
        cookie_issues = self._check_cookies(resp)
        if cookie_issues:
            lines.append("")
            lines.append("=== COOKIE SECURITY ===")
            for msg in cookie_issues:
                lines.append(f"[!] {msg}")

        # 6 — Cache headers
        cache = self._check_cache(hdrs)
        if cache:
            lines.append("")
            lines.append("=== CACHE CONTROL ===")
            for msg in cache:
                lines.append(f"[!] {msg}")

        # 7 — CTF hints (synthesized)
        hints = self._ctf_hints(hdrs, missing, leaks, cookie_issues)
        if hints:
            lines.append("")
            lines.append("=== CTF HINTS ===")
            for hint in hints:
                lines.append(f"[*] {hint}")

        # 8 — All response headers (raw listing)
        lines.append("")
        lines.append("=== ALL RESPONSE HEADERS ===")
        for name, value in hdrs.items():
            lines.append(f"  {name}: {value}")

        return "\n".join(lines)

    # ── Analysis helpers ────────────────────────────────────────────────

    def _check_missing_headers(
        self, hdrs: requests.structures.CaseInsensitiveDict
    ) -> List[str]:
        missing = []
        for header_lower, message in _SECURITY_HEADERS.items():
            if header_lower not in hdrs:
                # Also check X- prefixed variants
                alt = "x-" + header_lower if not header_lower.startswith("x-") else None
                if alt and alt in hdrs:
                    continue
                missing.append(message)
        return missing

    def _check_tech_leaks(
        self, hdrs: requests.structures.CaseInsensitiveDict
    ) -> List[Tuple[str, str]]:
        leaks = []
        for h in _TECH_HEADERS:
            val = hdrs.get(h)
            if val:
                leaks.append((h, val))
        return leaks

    def _check_debug_headers(
        self, hdrs: requests.structures.CaseInsensitiveDict
    ) -> List[Tuple[str, str]]:
        debug = []
        # Skip well-known headers that match debug patterns but aren't debug
        skip = {
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "x-xss-protection",
            "server",
            "x-powered-by",
            "set-cookie",
            "content-type",
            "content-length",
            "cache-control",
            "access-control-allow-origin",
            "access-control-allow-credentials",
        }
        for name, value in hdrs.items():
            name_lower = name.lower()
            if name_lower in skip:
                continue
            if name_lower in {h.lower() for h in _TECH_HEADERS}:
                continue
            # Check name or value for debug-like patterns
            if _DEBUG_PATTERNS.search(name) or _DEBUG_PATTERNS.search(value):
                debug.append((name, value))
        return debug

    def _check_cors(self, hdrs: requests.structures.CaseInsensitiveDict) -> List[str]:
        issues = []
        acao = hdrs.get("access-control-allow-origin", "")
        acac = hdrs.get("access-control-allow-credentials", "")
        if acao == "*":
            issues.append("Access-Control-Allow-Origin: * (overly permissive)")
            if acac.lower() == "true":
                issues.append(
                    "Access-Control-Allow-Credentials: true WITH wildcard origin — "
                    "credentials may be stolen cross-origin"
                )
        elif acao and acao != "*":
            issues.append(f"Access-Control-Allow-Origin: {acao}")
        return issues

    def _check_cookies(self, resp: requests.Response) -> List[str]:
        issues = []
        raw_cookies = resp.headers.get("set-cookie", "")
        if not raw_cookies:
            return issues

        # requests merges Set-Cookie headers; get raw from response
        raw_headers = resp.raw.headers if hasattr(resp.raw, "headers") else {}
        cookie_strings = (
            raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
        )
        if not cookie_strings:
            # Fallback: parse the merged header
            cookie_strings = [raw_cookies]

        interesting_names = {
            "session",
            "token",
            "auth",
            "admin",
            "role",
            "user",
            "jwt",
            "sid",
        }

        for cs in cookie_strings:
            cs_lower = cs.lower()
            # Extract cookie name and value
            name_val = cs.split(";")[0].strip()
            cookie_name = (
                name_val.split("=")[0].strip().lower() if "=" in name_val else ""
            )

            flags_missing = []
            if "httponly" not in cs_lower:
                flags_missing.append("missing HttpOnly")
            if "secure" not in cs_lower:
                flags_missing.append("missing Secure")
            if "samesite" not in cs_lower:
                flags_missing.append("missing SameSite")

            detail = ""
            if cookie_name in interesting_names:
                val = name_val.split("=", 1)[1] if "=" in name_val else ""
                if val:
                    detail = f" — value='{val[:60]}'"

            if flags_missing or cookie_name in interesting_names:
                flag_str = ", ".join(flags_missing) if flags_missing else "flags OK"
                issues.append(
                    f"Cookie '{name_val.split('=')[0].strip()}': {flag_str}{detail}"
                )

        return issues

    def _check_cache(self, hdrs: requests.structures.CaseInsensitiveDict) -> List[str]:
        issues = []
        cc = hdrs.get("cache-control", "").lower()
        if not cc:
            issues.append("No Cache-Control header — sensitive responses may be cached")
        elif "no-store" not in cc and "private" not in cc:
            issues.append(
                f"Cache-Control: {hdrs.get('cache-control', '')} — "
                "sensitive data may be cached by proxies"
            )
        return issues

    def _ctf_hints(
        self,
        hdrs: requests.structures.CaseInsensitiveDict,
        missing: List[str],
        leaks: List[Tuple[str, str]],
        cookie_issues: List[str],
    ) -> List[str]:
        hints = []

        # Technology-based hints
        combined = " ".join(v for _, v in leaks).lower()
        for tech_key, hint in _TECH_HINTS.items():
            if tech_key in combined:
                hints.append(hint)

        # Missing CSP → XSS hint
        if any("Content-Security-Policy" in m for m in missing):
            hints.append("No CSP — XSS payloads will execute without restriction")

        # Cookie manipulation hints
        for ci in cookie_issues:
            ci_lower = ci.lower()
            if "role" in ci_lower or "admin" in ci_lower:
                hints.append(
                    "Access-control cookie detected — try modifying with cookie_set "
                    "(e.g., role=admin, admin=true)"
                )
                break

        # Werkzeug debug console
        server = hdrs.get("server", "").lower()
        if "werkzeug" in server:
            hints.append("Werkzeug server — try accessing /console for debug shell")

        return hints


# ── DeepReconTool ───────────────────────────────────────────────────────


# Maximum combined output size to prevent context window flooding
_MAX_COMBINED_OUTPUT = 8000

# CDN hostnames whose scripts are framework code, not challenge logic.
# deep_recon skips fetching these to avoid context window flooding.
_CDN_SKIP_HOSTS = frozenset(
    {
        "cdn.tailwindcss.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
        "code.jquery.com",
        "stackpath.bootstrapcdn.com",
        "maxcdn.bootstrapcdn.com",
        "ajax.googleapis.com",
        "fonts.googleapis.com",
        "cdn.bootcdn.net",
    }
)


class DeepReconTool:
    """
    DeepReconTool: run comprehensive reconnaissance on a target URL in a
    single tool call, combining http_fetch + html_inspector +
    javascript_source + robots_txt + cookie_inspector + header analysis.

    Saves 4-5 ReAct cycles by performing all initial recon at once.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "http://example.com/challenge",
          "base_url": "http://example.com",  // optional, derived from url
          "skip": ["robots_txt"],            // optional, steps to skip
          "max_body": 4000                   // optional, body truncation limit
        }
    """

    name: str = "deep_recon"
    description: str = (
        "Run comprehensive reconnaissance on a target URL in a single call. "
        "Combines: HTTP fetch, HTML inspection, JavaScript extraction, "
        "robots.txt, cookie inspection, and security header analysis. "
        "Input must be JSON with keys: 'url' (required), optional 'base_url' "
        "(for robots.txt, defaults to scheme+host of url), optional 'skip' "
        "(list of steps to skip: 'http_fetch', 'html_inspector', "
        "'javascript_source', 'robots_txt', 'cookie_inspector', "
        "'security_headers'), optional 'max_body' (int, default 4000 chars "
        "for HTTP body preview). Saves 4-5 ReAct cycles compared to calling "
        "each tool individually. Returns a combined recon report with a "
        "summary of actionable findings."
    )

    # Steps in execution order
    STEPS = [
        "http_fetch",
        "html_inspector",
        "javascript_source",
        "robots_txt",
        "cookie_inspector",
        "security_headers",
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()
        self._http_tool = HttpFetchTool(session=self.session)
        self._html_tool = HtmlInspectorTool(session=self.session)
        self._js_tool = JavaScriptSourceTool(session=self.session)
        self._robots_tool = RobotsTxtTool(session=self.session)
        self._cookie_tool = CookieInspectorTool(session=self.session)
        self._header_tool = SecurityHeaderAnalyzerTool(session=self.session)

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return f"[DeepReconTool] Error: tool_input must be JSON: {exc}"

        url = data.get("url", "")
        if not url:
            return "[DeepReconTool] Error: 'url' is required."

        skip = set(data.get("skip", []))
        max_body = data.get("max_body", 4000)

        # Derive base_url for robots.txt
        parsed = urlparse(url)
        base_url = data.get("base_url", f"{parsed.scheme}://{parsed.netloc}")

        sections: List[str] = [
            "[DeepReconTool] Comprehensive Reconnaissance Report",
            f"Target: {url}",
        ]

        # Track findings for summary
        findings: List[str] = []

        # Step 1: HTTP Fetch
        http_output = ""
        if "http_fetch" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 1: HTTP RESPONSE")
            sections.append("=" * 50)
            try:
                http_input = json.dumps(
                    {
                        "url": url,
                        "method": "GET",
                        "max_body": max_body,
                    }
                )
                http_output = self._http_tool.use(http_input)
                sections.append(http_output)
            except Exception as exc:
                sections.append(f"[Error] http_fetch failed: {exc}")

        # Step 2: HTML Inspector
        if "html_inspector" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 2: HTML STRUCTURE")
            sections.append("=" * 50)
            try:
                html_input = json.dumps({"url": url})
                html_output = self._html_tool.use(html_input)
                sections.append(html_output)
                # Extract finding counts
                if "FORMS" in html_output:
                    findings.append("Forms detected in HTML")
                if "COMMENTS" in html_output:
                    findings.append("HTML comments found (may contain hints)")
            except Exception as exc:
                sections.append(f"[Error] html_inspector failed: {exc}")

        # Step 3: JavaScript Source (cap per-script size, skip CDN frameworks)
        if "javascript_source" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 3: JAVASCRIPT ANALYSIS")
            sections.append("=" * 50)
            try:
                js_input = json.dumps(
                    {
                        "url": url,
                        "base_url": base_url,
                        "max_chars_per_script": 2000,
                        "max_scripts": 10,
                    }
                )
                js_output = self._js_tool.use(js_input)
                # Strip CDN framework scripts from the output to save context
                filtered_lines: List[str] = []
                skip_until_next = False
                for line in js_output.split("\n"):
                    if line.startswith("[EXTERNAL SCRIPT"):
                        # Check if the URL is a known CDN
                        cdn_hit = False
                        for host in _CDN_SKIP_HOSTS:
                            if host in line:
                                cdn_hit = True
                                break
                        if cdn_hit:
                            filtered_lines.append(
                                line.split("]")[0]
                                + "] (CDN framework — skipped to save context)"
                            )
                            skip_until_next = True
                            continue
                        skip_until_next = False
                    elif skip_until_next:
                        if line.startswith("[") and "SCRIPT" in line:
                            skip_until_next = False
                        else:
                            continue
                    filtered_lines.append(line)
                js_output = "\n".join(filtered_lines)
                sections.append(js_output)
                if "EXTERNAL SCRIPT" in js_output or "INLINE SCRIPT" in js_output:
                    findings.append(
                        "JavaScript code found — check for credentials/logic"
                    )
            except Exception as exc:
                sections.append(f"[Error] javascript_source failed: {exc}")

        # Step 4: Robots.txt
        if "robots_txt" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 4: ROBOTS.TXT")
            sections.append("=" * 50)
            try:
                robots_input = json.dumps({"base_url": base_url})
                robots_output = self._robots_tool.use(robots_input)
                sections.append(robots_output)
                if "Disallow" in robots_output:
                    findings.append("robots.txt has disallowed paths — explore them")
            except Exception as exc:
                sections.append(f"[Error] robots_txt failed: {exc}")

        # Step 5: Cookie Inspector
        if "cookie_inspector" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 5: COOKIES")
            sections.append("=" * 50)
            try:
                cookie_input = json.dumps(
                    {"base_url": base_url, "domain": parsed.netloc}
                )
                cookie_output = self._cookie_tool.use(cookie_input)
                sections.append(cookie_output)
                if "=" in cookie_output and "No cookies" not in cookie_output:
                    findings.append("Cookies set — check for access control cookies")
            except Exception as exc:
                sections.append(f"[Error] cookie_inspector failed: {exc}")

        # Step 6: Security Header Analysis
        if "security_headers" not in skip:
            sections.append("")
            sections.append("=" * 50)
            sections.append("SECTION 6: SECURITY HEADERS")
            sections.append("=" * 50)
            try:
                header_input = json.dumps({"url": url})
                header_output = self._header_tool.use(header_input)
                sections.append(header_output)
                if "CTF HINTS" in header_output:
                    findings.append("Security header analysis found CTF hints")
            except Exception as exc:
                sections.append(f"[Error] security_header_analyzer failed: {exc}")

        # Summary
        sections.append("")
        sections.append("=" * 50)
        sections.append("RECON SUMMARY")
        sections.append("=" * 50)
        if findings:
            for f in findings:
                sections.append(f"- {f}")
        else:
            sections.append("- No notable findings from automated recon")
        sections.append("")
        sections.append(
            "Next steps: Review the sections above. Follow up on any "
            "credentials, hidden paths, access-control cookies, or "
            "vulnerability hints with targeted tools."
        )

        result = "\n".join(sections)

        # Truncate if output is too large
        if len(result) > _MAX_COMBINED_OUTPUT:
            truncated = result[:_MAX_COMBINED_OUTPUT]
            truncated += (
                f"\n\n... [Output truncated at {_MAX_COMBINED_OUTPUT} chars. "
                f"Total was {len(result)} chars. Use individual tools for "
                f"full output on specific sections.]"
            )
            return truncated

        return result
