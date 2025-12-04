#!/usr/bin/env python3
"""
pico_agentic_solver.py - FAIR agent for PicoCTF-style web challenges

Current capabilities:
- LLM "brain": OpenAIAdapter (configured via fairlib.settings / OPENAI_API_KEY)
- Planner: ReActPlanner (Reason-Act loop) with custom PromptBuilder role + examples
- Memory: WorkingMemory (short-term conversation history)
- Tools (FAIR AbstractTool interface):
    * HttpFetchTool         - HTTP GET/HEAD with shared session
    * HtmlInspectorTool     - Summarize structure of HTML pages or strings
    * RegexSearchTool       - Generic regex matcher (e.g., search for picoCTF{.*})
    * RobotsTxtTool         - Fetch and parse robots.txt rules
    * CookieInspectorTool   - Inspect cookies stored in the shared session
    * CookieSetTool         - Set/modify cookies in the shared session
    * FormSubmitTool        - Submit GET/POST forms using the shared session
    * JavaScriptSourceTool  - Extract inline and external JavaScript from pages
    * ResponseSearchTool    - Highlight lines around given keywords in a response body
    * SqlPatternHintTool    - Scan responses for SQL / injection hints
    * CTFKnowledgeQueryTool - RAG over PicoCTF Web Exploitation + docs/

The agent is designed to solve picoCTF-style web challenges, including:
- where are the robots
- insp3ct0r
- dont-use-client-side
- logon
- SQLiLite

The script uses the FAIR agentic framework (fairlib) and is structured to
allow the LLM to autonomously decide:
- which tools to invoke,
- in what order,
- based on the evolving ReAct conversation.

It does *not* hard-code a specific fixed sequence of tool calls. Instead, the
Planner (ReActPlanner) + PromptBuilder describe tools and capabilities, and the
LLM chooses how to explore the challenge.
"""

import os
import json
import argparse
import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

import re
import requests
from bs4 import BeautifulSoup, Comment
from dotenv import load_dotenv
from urllib.parse import urlparse, urljoin
from pathlib import Path

# Optional JS beautifier (if installed)
try:
    import jsbeautifier  # type: ignore
    HAS_JSBEAUTIFIER = True
except Exception:
    HAS_JSBEAUTIFIER = False

# ---------------------------------------------------------------------------
# FAIR framework imports
# ---------------------------------------------------------------------------

from fairlib import (
    settings,
    OpenAIAdapter,
    SimpleAgent,
    ToolRegistry,
    ToolExecutor,
    ReActPlanner,
    WorkingMemory,
    SentenceTransformerEmbedder,
    SimpleRetriever,
    KnowledgeBaseQueryTool,
    RoleDefinition,
    Example,
)

from fairlib.utils.document_processor import DocumentProcessor
from fairlib.modules.memory.vector_faiss import FaissVectorStore

# FAIR AbstractTool base class
from core.interfaces.tools import AbstractTool

# ---------------------------------------------------------------------------
# Global logger
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared HTTP session factory
# ---------------------------------------------------------------------------

def create_shared_session() -> requests.Session:
    """
    Create and configure a shared requests.Session.

    This session will be passed to all HTTP-related tools so cookies and
    headers persist across requests. You can customize default headers,
    timeouts, etc. here.
    """
    session = requests.Session()
    # Set a more realistic User-Agent for some CTF challenges:
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
    )
    return session


# ---------------------------------------------------------------------------
# Utility: safe text truncation
# ---------------------------------------------------------------------------

def truncate(text: str, max_len: int = 4000) -> str:
    """
    Truncate a string to at most max_len characters, appending a note if truncated.
    """
    if len(text) <= max_len:
        return text
    return text[:max_len] + f"\n\n[Truncated to {max_len} characters...]"


# ---------------------------------------------------------------------------
# HttpFetchTool
# ---------------------------------------------------------------------------

class HttpFetchTool(AbstractTool):
    """
    HTTP fetch tool using a shared requests.Session.

    Input (dict), e.g.:
    {
      "url": "https://example.com",
      "method": "GET",              # optional, "GET" or "HEAD" (default GET)
      "params": {"q": "test"},      # optional, dict
      "headers": {"User-Agent": "..."}, # optional
      "max_body": 4000              # optional, int
    }

    Behavior:
      - Uses a shared requests.Session to perform the HTTP request.
      - Supports "GET" and "HEAD".
      - Returns a human-readable summary including:
          * Method + final URL
          * Status code
          * Headers
          * Truncated body (for GET; HEAD has no body)
    """

    name: str = "http_fetch"
    description: str = (
        "Perform an HTTP GET or HEAD request. Input JSON keys: 'url' "
        "(required), 'method' (optional, 'GET' or 'HEAD'), 'params' "
        "(optional dict), 'headers' (optional dict), and 'max_body' "
        "(optional int). Returns status code, headers, and truncated body."
    )

    def __init__(self, session: requests.Session):
        self.session = session

    async def use(self, input_data: Dict[str, Any]) -> str:
        url = input_data.get("url")
        if not url:
            return "Error: 'url' is required in http_fetch input."

        method = str(input_data.get("method", "GET")).upper()
        params = input_data.get("params") or {}
        extra_headers = input_data.get("headers") or {}
        max_body = int(input_data.get("max_body", 4000))

        headers = dict(self.session.headers)
        headers.update(extra_headers)

        try:
            if method == "HEAD":
                resp = self.session.head(url, headers=headers, params=params, timeout=10)
            else:
                resp = self.session.get(url, headers=headers, params=params, timeout=10)
        except Exception as e:
            return f"HTTP error while fetching {url!r}: {e}"

        body = ""
        if method != "HEAD":
            try:
                body = resp.text
            except Exception:
                body = "<non-text body>"

        summary = []
        summary.append(f"[HTTP FETCH] {method} {resp.url}")
        summary.append(f"Status: {resp.status_code}")
        summary.append("Headers:")
        for k, v in resp.headers.items():
            summary.append(f"  {k}: {v}")

        if method != "HEAD":
            summary.append("\nBody (truncated):")
            summary.append(truncate(body, max_body))

        return "\n".join(summary)


# ---------------------------------------------------------------------------
# HtmlInspectorTool
# ---------------------------------------------------------------------------

class HtmlInspectorTool(AbstractTool):
    """
    HTML inspection tool.

    Input (dict), e.g.:
    {
      "html": "<!doctype html>...",
      "url": "https://example.com",  # optional, if you want it to fetch instead
      "base_url": "https://example.com",  # optional, used for link resolution
      "max_items": 50                 # optional limit on links/scripts/styles/comments
    }

    Behavior:
      - If 'html' is provided, parse that directly.
      - Else if 'url' is provided, fetch the HTML using the shared session.
      - Extract:
          * all <a href="..."> links,
          * all <script src="..."> external JS references,
          * all <link rel="stylesheet" href="..."> CSS references,
          * all HTML comments.
      - Return a human-readable summary grouping these categories.
    """

    name: str = "html_inspector"
    description: str = (
        "Inspect HTML structure: links, JS, CSS, and comments. Input JSON keys: "
        "'html' (optional string), 'url' (optional string), 'base_url' (optional "
        "string), and 'max_items' (optional int). Returns a text summary."
    )

    def __init__(self, session: requests.Session, http_tool: HttpFetchTool):
        self.session = session
        self.http_tool = http_tool

    async def use(self, input_data: Dict[str, Any]) -> str:
        html = input_data.get("html")
        url = input_data.get("url")
        base_url = input_data.get("base_url")
        max_items = int(input_data.get("max_items", 50))

        if not html and not url:
            return "Error: HtmlInspectorTool requires either 'html' or 'url' in input."

        if html is None and url:
            # Fetch the page to get HTML
            fetch_input = {"url": url, "method": "GET", "max_body": 100000}
            fetch_result = await self.http_tool.use(fetch_input)
            # Attempt to extract the body portion after "Body (truncated):"
            body_index = fetch_result.find("Body (truncated):")
            if body_index != -1:
                html = fetch_result[body_index + len("Body (truncated):") :].strip()
            else:
                html = fetch_result

        if not html:
            return "Error: failed to obtain HTML for inspection."

        soup = BeautifulSoup(html, "html.parser")

        if not base_url and url:
            base_url = url

        def resolve_href(href: str) -> str:
            if not base_url:
                return href
            return urljoin(base_url, href)

        links = []
        scripts = []
        styles = []
        comments = []

        for a in soup.find_all("a", href=True):
            links.append(resolve_href(a["href"]))
        for s in soup.find_all("script", src=True):
            scripts.append(resolve_href(s["src"]))
        for link in soup.find_all("link", rel=True, href=True):
            rel = [r.lower() for r in link.get("rel", [])]
            if "stylesheet" in rel:
                styles.append(resolve_href(link["href"]))
        for c in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comments.append(str(c))

        def format_list(label: str, items: List[str]) -> List[str]:
            out = [f"=== {label} (showing up to {max_items}) ==="]
            for idx, item in enumerate(items[:max_items], start=1):
                out.append(f"{idx}. {item}")
            if len(items) > max_items:
                out.append(f"... ({len(items) - max_items} more not shown)")
            out.append("")
            return out

        summary_lines: List[str] = []
        summary_lines.extend(format_list("Links (href)", links))
        summary_lines.extend(format_list("External JS (script src)", scripts))
        summary_lines.extend(format_list("Stylesheets (link rel=stylesheet)", styles))

        summary_lines.append(f"=== HTML Comments (showing up to {max_items}) ===")
        for idx, c in enumerate(comments[:max_items], start=1):
            summary_lines.append(f"[Comment #{idx}]\n{truncate(c, 500)}\n")
        if len(comments) > max_items:
            summary_lines.append(f"... ({len(comments) - max_items} more comments not shown)")

        return "\n".join(summary_lines)


# ---------------------------------------------------------------------------
# RegexSearchTool
# ---------------------------------------------------------------------------

class RegexSearchTool(AbstractTool):
    """
    Regex-based search tool for text.

    Input (dict), e.g.:
    {
      "text": "full HTTP response body...",
      "pattern": "picoCTF\\{.*?\\}",
      "max_matches": 20
    }

    Behavior:
      - Compiles the given regex pattern.
      - Returns all matches (joined as lines), truncated if too many.
      - Useful for scanning for flags like picoCTF{...}.
    """

    name: str = "regex_search"
    description: str = (
        "Search for regex patterns in text. Input JSON keys: 'text' (string), "
        "'pattern' (string, Python-style regex), and 'max_matches' (optional int). "
        "Returns matching substrings."
    )

    async def use(self, input_data: Dict[str, Any]) -> str:
        text = input_data.get("text", "")
        pattern = input_data.get("pattern")
        max_matches = int(input_data.get("max_matches", 50))

        if not pattern:
            return "Error: 'pattern' is required in regex_search input."
        if not text:
            return "Warning: 'text' is empty or missing; nothing to search."

        try:
            regex = re.compile(pattern)
        except re.error as e:
            return f"Error compiling regex pattern {pattern!r}: {e}"

        matches = regex.findall(text)
        if not matches:
            return f"No matches found for pattern {pattern!r}."

        matches_str = []
        for idx, m in enumerate(matches[:max_matches], start=1):
            matches_str.append(f"{idx}. {m!r}")
        if len(matches) > max_matches:
            matches_str.append(f"... ({len(matches) - max_matches} more matches not shown)")

        return "Regex matches:\n" + "\n".join(matches_str)


# ---------------------------------------------------------------------------
# RobotsTxtTool
# ---------------------------------------------------------------------------

class RobotsTxtTool(AbstractTool):
    """
    Tool to fetch and inspect robots.txt.

    Input (dict), e.g.:
    {
      "base_url": "https://example.com",
      "max_lines": 200
    }

    Behavior:
      - Fetches {base_url}/robots.txt using the shared session.
      - Parses lines starting with Disallow/Allow.
      - Returns a readable summary plus suggested paths to explore.
    """

    name: str = "robots_txt"
    description: str = (
        "Fetch and inspect robots.txt rules from a base URL. Input JSON keys: "
        "'base_url' (string) and 'max_lines' (optional int). Returns disallow/allow "
        "rules and suggested hidden paths to explore."
    )

    def __init__(self, session: requests.Session):
        self.session = session

    async def use(self, input_data: Dict[str, Any]) -> str:
        base_url = input_data.get("base_url")
        max_lines = int(input_data.get("max_lines", 200))

        if not base_url:
            return "Error: 'base_url' is required for robots_txt tool."

        if not base_url.endswith("/"):
            base_url = base_url.rstrip("/")

        robots_url = base_url + "/robots.txt"
        try:
            resp = self.session.get(robots_url, timeout=10)
        except Exception as e:
            return f"Error fetching robots.txt at {robots_url!r}: {e}"

        if resp.status_code != 200:
            return (
                f"robots.txt not accessible at {robots_url!r}. "
                f"Status code: {resp.status_code}"
            )

        content = resp.text
        lines = content.splitlines()[:max_lines]

        disallows = []
        allows = []
        others = []

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            lower = stripped.lower()
            if lower.startswith("disallow:"):
                disallows.append(stripped)
            elif lower.startswith("allow:"):
                allows.append(stripped)
            else:
                others.append(stripped)

        summary = []
        summary.append(f"[robots.txt] URL: {robots_url}")
        summary.append("=== Disallow rules ===")
        summary.extend(disallows or ["(none)"])
        summary.append("")
        summary.append("=== Allow rules ===")
        summary.extend(allows or ["(none)"])
        summary.append("")
        summary.append("=== Other lines ===")
        summary.extend(others or ["(none)"])

        suggested_paths = []
        for line in disallows:
            try:
                _, path = line.split(":", 1)
                path = path.strip()
                if path and path != "/":
                    suggested_paths.append(path)
            except ValueError:
                continue

        if suggested_paths:
            summary.append("")
            summary.append("=== Suggested paths to explore (from Disallow) ===")
            for p in suggested_paths:
                summary.append(f"- {p}")

        return "\n".join(summary)


# ---------------------------------------------------------------------------
# CookieInspectorTool
# ---------------------------------------------------------------------------

class CookieInspectorTool(AbstractTool):
    """
    Tool to inspect cookies stored in the shared session.

    Input (dict), e.g.:
    {
      "base_url": "https://example.com"
    }

    Behavior:
      - Examines the session cookies for the domain of base_url.
      - Returns key/value pairs and simple attributes.
    """

    name: str = "cookie_inspector"
    description: str = (
        "Inspect cookies in the shared HTTP session. Input JSON keys: "
        "'base_url' (string) or 'domain' (string). Returns cookie names, values, "
        "and attributes."
    )

    def __init__(self, session: requests.Session):
        self.session = session

    async def use(self, input_data: Dict[str, Any]) -> str:
        base_url = input_data.get("base_url")
        domain = input_data.get("domain")

        if base_url and not domain:
            try:
                parsed = urlparse(base_url)
                domain = parsed.netloc
            except Exception:
                domain = None

        if not domain:
            return "Error: CookieInspectorTool requires 'base_url' or 'domain'."

        cookies = self.session.cookies
        matching = []
        for c in cookies:
            if domain in c.domain:
                matching.append(c)

        if not matching:
            return f"No cookies found for domain {domain!r}."

        lines = [f"Cookies for domain {domain!r}:"]
        for c in matching:
            lines.append(
                f"- name={c.name!r}, value={c.value!r}, domain={c.domain!r}, "
                f"path={c.path!r}, secure={c.secure}, httponly={getattr(c, 'rest', {}).get('HttpOnly', False)}"
            )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# CookieSetTool
# ---------------------------------------------------------------------------

class CookieSetTool(AbstractTool):
    """
    Tool to set or update a cookie in the shared session.

    Input (dict), e.g.:
    {
      "domain": "example.com",
      "name": "auth",
      "value": "admin",
      "path": "/"
    }

    Behavior:
      - Sets/updates a cookie on the session so subsequent requests use it.
    """

    name: str = "cookie_set"
    description: str = (
        "Set or update a cookie in the shared HTTP session. Input JSON keys: "
        "'domain' (string), 'name' (string), 'value' (string), and optional "
        "'path' (string)."
    )

    def __init__(self, session: requests.Session):
        self.session = session

    async def use(self, input_data: Dict[str, Any]) -> str:
        domain = input_data.get("domain")
        name = input_data.get("name")
        value = input_data.get("value")
        path = input_data.get("path", "/")

        if not domain or not name:
            return "Error: CookieSetTool requires 'domain' and 'name'."

        self.session.cookies.set(name=name, value=value, domain=domain, path=path)
        return (
            f"Cookie set in session: name={name!r}, value={value!r}, "
            f"domain={domain!r}, path={path!r}."
        )


# ---------------------------------------------------------------------------
# FormSubmitTool
# ---------------------------------------------------------------------------

class FormSubmitTool(AbstractTool):
    """
    Tool to submit an HTTP form using the shared session.

    Input (dict), e.g.:
    {
      "url": "https://example.com/login",
      "method": "POST",
      "data": {"username": "admin", "password": "password"},
      "headers": {"Content-Type": "application/x-www-form-urlencoded"},
      "max_body": 4000
    }

    Behavior:
      - Uses shared session to submit the form.
      - Supports GET and POST.
      - Returns status code, headers, and truncated body.
    """

    name: str = "form_submit"
    description: str = (
        "Submit an HTTP form using the shared session. Input JSON keys: 'url' "
        "(string), 'method' ('GET' or 'POST'), 'data' (dict), 'headers' (dict), "
        "and 'max_body' (optional int). Returns status code, headers, body."
    )

    def __init__(self, session: requests.Session):
        self.session = session

    async def use(self, input_data: Dict[str, Any]) -> str:
        url = input_data.get("url")
        if not url:
            return "Error: 'url' is required for form_submit tool."

        method = str(input_data.get("method", "POST")).upper()
        data = input_data.get("data") or {}
        headers = input_data.get("headers") or {}
        max_body = int(input_data.get("max_body", 4000))

        try:
            if method == "GET":
                resp = self.session.get(url, params=data, headers=headers, timeout=10)
            else:
                resp = self.session.post(url, data=data, headers=headers, timeout=10)
        except Exception as e:
            return f"Error submitting form to {url!r} via {method}: {e}"

        try:
            body = resp.text
        except Exception:
            body = "<non-text body>"

        summary = []
        summary.append(f"[FORM SUBMIT] {method} {resp.url}")
        summary.append(f"Status: {resp.status_code}")
        summary.append("Headers:")
        for k, v in resp.headers.items():
            summary.append(f"  {k}: {v}")
        summary.append("\nBody (truncated):")
        summary.append(truncate(body, max_body))

        return "\n".join(summary)


# ---------------------------------------------------------------------------
# JavaScriptSourceTool
# ---------------------------------------------------------------------------

class JavaScriptSourceTool(AbstractTool):
    """
    Tool to extract inline and external JavaScript from an HTML page.

    Input (dict), e.g.:
    {
      "url": "https://example.com/page",   # optional
      "html": "<!doctype html>...",        # optional
      "base_url": "https://example.com",   # optional, for resolving relative src
      "max_scripts": 20,
      "max_chars_per_script": 4000
    }

    Behavior:
      - If 'html' is provided, parse that directly.
      - Else if 'url' is provided, fetch the HTML using the shared session.
      - Parse HTML, locate <script> tags.
      - For each script:
          * If it has a 'src', resolve it against base_url or page URL and fetch JS.
          * If inline, capture its text content.
      - If jsbeautifier is available, pretty-print each script.
      - Return a readable text summary with sections like:
          [INLINE SCRIPT #1]
          ...
          [EXTERNAL SCRIPT: https://example.com/static/app.js]
          ...
    """

    name: str = "javascript_source"
    description: str = (
        "Extract JavaScript code from an HTML page. Input JSON keys: 'url' "
        "(optional), 'html' (optional), 'base_url' (optional), 'max_scripts' "
        "(optional int), and 'max_chars_per_script' (optional int). If 'url' is "
        "given, the tool fetches the page and then all external scripts."
    )

    def __init__(self, session: requests.Session, http_tool: HttpFetchTool):
        self.session = session
        self.http_tool = http_tool

    async def use(self, input_data: Dict[str, Any]) -> str:
        html = input_data.get("html")
        url = input_data.get("url")
        base_url = input_data.get("base_url")
        max_scripts = int(input_data.get("max_scripts", 20))
        max_chars_per_script = int(input_data.get("max_chars_per_script", 4000))

        if not html and not url:
            return "Error: JavaScriptSourceTool requires 'url' or 'html'."

        if html is None and url:
            fetch_input = {"url": url, "method": "GET", "max_body": 200000}
            fetch_result = await self.http_tool.use(fetch_input)
            body_index = fetch_result.find("Body (truncated):")
            if body_index != -1:
                html = fetch_result[body_index + len("Body (truncated):") :].strip()
            else:
                html = fetch_result

        if not html:
            return "Error: failed to obtain HTML for JavaScript extraction."

        soup = BeautifulSoup(html, "html.parser")

        if not base_url:
            if url:
                base_url = url
            else:
                base_url = ""

        scripts = soup.find_all("script")
        summary: List[str] = []
        summary.append("[JavaScriptSourceTool] Extracting scripts...")
        summary.append(f"Total <script> tags found: {len(scripts)}")
        summary.append("")

        idx = 0
        for s in scripts:
            if idx >= max_scripts:
                summary.append(
                    f"... (reached max_scripts={max_scripts}; remaining scripts not shown)"
                )
                break

            src = s.get("src")
            if src:
                full_src = urljoin(base_url, src)
                try:
                    resp = self.session.get(full_src, timeout=10)
                    js_text = resp.text
                except Exception as e:
                    js_text = f"<error fetching external JS {full_src!r}: {e}>"

                if HAS_JSBEAUTIFIER and not js_text.startswith("<error"):
                    js_text = jsbeautifier.beautify(js_text)

                js_text = truncate(js_text, max_chars_per_script)
                summary.append(f"[EXTERNAL SCRIPT: {full_src}]")
                summary.append(js_text)
                summary.append("")
            else:
                js_text = s.string or s.get_text()
                if not js_text or not js_text.strip():
                    continue
                if HAS_JSBEAUTIFIER:
                    js_text = jsbeautifier.beautify(js_text)
                js_text = truncate(js_text, max_chars_per_script)
                summary.append(f"[INLINE SCRIPT #{idx + 1}]")
                summary.append(js_text)
                summary.append("")

            idx += 1

        if idx == 0:
            summary.append("No inline or external JavaScript content found.")

        return "\n".join(summary)


# ---------------------------------------------------------------------------
# ResponseSearchTool
# ---------------------------------------------------------------------------

class ResponseSearchTool(AbstractTool):
    """
    Tool to search a response body for lines containing given keywords, with
    context lines around each match.

    Input (dict), e.g.:
    {
      "text": "full response body...",
      "keywords": ["SQL", "error", "SELECT"],
      "context_lines": 2,
      "max_hits": 40
    }

    Behavior:
      - Splits text into lines.
      - For each line containing any keyword (case-insensitive), captures it
        plus N lines before/after.
      - Returns a summary of interesting sections for debugging / hint-finding.
    """

    name: str = "response_search"
    description: str = (
        "Search response text for lines containing certain keywords and show a "
        "context window around each match. Input JSON keys: 'text' (string), "
        "'keywords' (list of strings), 'context_lines' (optional int), and "
        "'max_hits' (optional int)."
    )

    async def use(self, input_data: Dict[str, Any]) -> str:
        text = input_data.get("text", "")
        keywords = input_data.get("keywords", [])
        context_lines = int(input_data.get("context_lines", 2))
        max_hits = int(input_data.get("max_hits", 40))

        if not text:
            return "Warning: no 'text' provided to response_search."
        if not keywords:
            return "Warning: no 'keywords' provided to response_search."

        lower_keywords = [k.lower() for k in keywords]
        lines = text.splitlines()

        hits: List[Tuple[int, str]] = []
        for i, line in enumerate(lines):
            lower_line = line.lower()
            if any(k in lower_line for k in lower_keywords):
                hits.append((i, line))
                if len(hits) >= max_hits:
                    break

        if not hits:
            return f"No lines found containing keywords: {keywords!r}."

        out: List[str] = []
        out.append(
            f"[ResponseSearchTool] Found {len(hits)} interesting lines (max_hits={max_hits})."
        )
        out.append("")

        for idx, (line_no, line) in enumerate(hits, start=1):
            start = max(0, line_no - context_lines)
            end = min(len(lines), line_no + context_lines + 1)
            out.append(f"--- Hit #{idx} (line {line_no}) ---")
            for j in range(start, end):
                prefix = ">>" if j == line_no else "  "
                out.append(f"{prefix} {j}: {lines[j]}")
            out.append("")

        if len(hits) >= max_hits:
            out.append(f"... (reached max_hits={max_hits}; further hits not shown).")

        return "\n".join(out)


# ---------------------------------------------------------------------------
# SqlPatternHintTool
# ---------------------------------------------------------------------------

class SqlPatternHintTool(AbstractTool):
    """
    Tool to scan text for common SQL / injection-related patterns and highlight
    them with brief hints.

    Input (dict), e.g.:
    {
      "text": "response body...",
      "max_hits": 40
    }

    Behavior:
      - Searches for substrings like SELECT, FROM, WHERE, INSERT, UPDATE,
        ' OR 1=1, '--, etc.
      - Returns lines containing these patterns, with context and short hints.
    """

    name: str = "sql_pattern_hint"
    description: str = (
        "Scan response text for common SQL / injection-related patterns such as "
        "'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', ' OR 1=1', '--', etc. "
        "Input JSON keys: 'text' (string), 'max_hits' (optional int)."
    )

    PATTERNS = [
        "select ",
        " from ",
        " where ",
        " insert ",
        " update ",
        " delete ",
        " or 1=1",
        "' or '1'='1",
        "--",
        "/*",
        "*/",
        "union select",
        "database error",
        "sql syntax",
    ]

    async def use(self, input_data: Dict[str, Any]) -> str:
        text = input_data.get("text", "")
        max_hits = int(input_data.get("max_hits", 40))

        if not text:
            return "Warning: no 'text' provided to sql_pattern_hint."

        lower_text = text.lower()
        lines = text.splitlines()
        hits: List[Tuple[int, str, List[str]]] = []

        for i, line in enumerate(lines):
            lower_line = line.lower()
            matched = [p for p in self.PATTERNS if p in lower_line]
            if matched:
                hits.append((i, line, matched))
                if len(hits) >= max_hits:
                    break

        if not hits:
            return (
                "No obvious SQL-related patterns found in the provided text. "
                "This does not mean the site is not vulnerable, only that "
                "nothing obvious is echoed back."
            )

        out: List[str] = []
        out.append(
            f"[SqlPatternHintTool] Found {len(hits)} lines that may be related "
            f"to SQL queries or errors (max_hits={max_hits})."
        )
        out.append("")

        for idx, (line_no, line, matched) in enumerate(hits, start=1):
            out.append(f"--- Hit #{idx} (line {line_no}) ---")
            out.append(f"Patterns: {matched}")
            out.append(f"Line: {line}")
            out.append(
                "Hint: This line might indicate an echoed SQL query or "
                "database error message that could be relevant for SQL injection."
            )
            out.append("")

        if len(hits) >= max_hits:
            out.append(f"... (reached max_hits={max_hits}; further hits not shown).")

        return "\n".join(out)


# ---------------------------------------------------------------------------
# RAG: CTFKnowledgeQueryTool and initialization
# ---------------------------------------------------------------------------

def split_text(text: str, chunk_size: int = 800, overlap: int = 100) -> List[str]:
    """
    Very simple text splitter: splits on paragraphs, then merges them into
    overlapping chunks of roughly chunk_size characters.
    """
    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: List[str] = []
    current = ""
    for p in paragraphs:
        if len(current) + len(p) + 2 > chunk_size:
            if current:
                chunks.append(current)
            current = p
        else:
            current = (current + "\n\n" + p) if current else p

    if current:
        chunks.append(current)

    # Add overlap by merging chunk n with the last 100 chars of chunk n-1, etc.
    if overlap > 0 and len(chunks) > 1:
        overlapped_chunks = []
        prev = ""
        for c in chunks:
            if prev:
                prefix = prev[-overlap:]
                overlapped_chunks.append((prefix + "\n" + c).strip())
            else:
                overlapped_chunks.append(c)
            prev = c
        return overlapped_chunks

    return chunks


def initialize_ctf_knowledge_base(
    docs_dir: str = "docs",
    pdf_path: str = "Book-3-Web-Exploitation.pdf",
) -> Optional[SimpleRetriever]:
    """
    Initialize a RAG knowledge base for web-exploitation help.

    - Loads the PicoCTF Web Exploitation guide PDF.
    - Also loads *.md and *.txt from docs_dir, if present.
    - Uses SentenceTransformerEmbedder to embed text chunks.
    - Stores vectors in a FaissVectorStore.
    - Returns a SimpleRetriever for the knowledge base, or None if
      initialization fails.

    This is called once at agent startup and reused for all queries.
    """
    logger.info("Initializing CTF RAG knowledge base...")

    docprocessor = DocumentProcessor()

    documents: List[Dict[str, Any]] = []

    # Load PDF if available
    pdf_file = Path(pdf_path)
    if pdf_file.exists():
        try:
            pdf_docs = docprocessor.read_pdf(str(pdf_file))
            documents.extend(pdf_docs)
            logger.info("Loaded PDF for RAG: %s", pdf_file)
        except Exception as e:
            logger.warning("Failed to load PDF %s: %s", pdf_file, e)
    else:
        logger.warning("PDF file for RAG not found: %s", pdf_file)

    # Load *.md and *.txt from docs_dir
    docs_path = Path(docs_dir)
    if docs_path.exists() and docs_path.is_dir():
        for ext in ("*.md", "*.txt"):
            for f in docs_path.glob(ext):
                try:
                    text_docs = docprocessor.read_text(str(f))
                    documents.extend(text_docs)
                    logger.info("Loaded doc for RAG: %s", f)
                except Exception as e:
                    logger.warning("Failed to load doc %s: %s", f, e)
    else:
        logger.info("No docs directory found at %s; skipping extra docs.", docs_path)

    if not documents:
        logger.warning("No documents found for CTF RAG knowledge base.")
        return None

    # Extract raw text content and chunk it
    all_text = "\n\n".join([d.get("text", "") for d in documents if d.get("text")])
    chunks = split_text(all_text, chunk_size=800, overlap=100)
    if not chunks:
        logger.warning("No text chunks produced for CTF RAG knowledge base.")
        return None

    # Create embedder and vector store
    embedder = SentenceTransformerEmbedder(model_name_or_path="all-MiniLM-L6-v2")
    vector_store = FaissVectorStore(embedder_dimension=embedder.dimension)

    # Index chunks
    logger.info("Indexing %d chunks in FaissVectorStore...", len(chunks))
    for idx, chunk in enumerate(chunks):
        vector_store.add_document(
            {
                "id": f"ctf-doc-{idx}",
                "text": chunk,
            }
        )

    retriever = SimpleRetriever(vector_store=vector_store, embedder=embedder)
    logger.info("CTF RAG knowledge base initialized with %d chunks.", len(chunks))
    return retriever


def build_ctf_knowledge_tool(retriever: SimpleRetriever) -> KnowledgeBaseQueryTool:
    """
    Wrap the retriever in a FAIR KnowledgeBaseQueryTool.

    Input (dict), e.g.:
    {
      "query": "How do I exploit SQL injection in a login form?"
    }

    Behavior:
      - Uses retriever to get top-k relevant chunks.
      - Returns a concise text summary with the top passages.
    """
    tool = KnowledgeBaseQueryTool(
        name="ctf_knowledge_query",
        description=(
            "Consult an internal web-exploitation knowledge base built from "
            "the PicoCTF Web Exploitation guide and local docs/. Use this to "
            "refresh your memory on SQL injection, cookies, robots.txt, client-"
            "side validation, etc."
        ),
        retriever=retriever,
        max_docs=5,
    )
    return tool


# ---------------------------------------------------------------------------
# Agent construction: LLM, tools, planner, prompt builder
# ---------------------------------------------------------------------------

def build_agent() -> SimpleAgent:
    """
    Build and return a SimpleAgent configured for PicoCTF-style web exploitation.

    This:
      - Initializes the OpenAIAdapter as the LLM.
      - Creates a shared HTTP session.
      - Registers tools in a ToolRegistry.
      - Builds a ReActPlanner with a custom PromptBuilder role + few-shot examples.
      - Uses a WorkingMemory.
    """
    load_dotenv()

    # Configure OpenAIAdapter via fairlib.settings
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if not openai_api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Please define it in your environment or .env file."
        )

    settings.OPENAI_API_KEY = openai_api_key
    settings.LLM_MODEL_NAME = "gpt-4o-mini"

    llm = OpenAIAdapter()

    # Shared HTTP session
    session = create_shared_session()

    # Tool registry and executor
    tool_registry = ToolRegistry()
    tool_executor = ToolExecutor(tool_registry)

    # ---- HTTP / HTML / JS / regex tools ----
    http_tool = HttpFetchTool(session=session)
    html_inspector_tool = HtmlInspectorTool(session=session, http_tool=http_tool)
    regex_tool = RegexSearchTool()
    js_tool = JavaScriptSourceTool(session=session, http_tool=http_tool)

    # ---- robots.txt, cookies, forms ----
    robots_tool = RobotsTxtTool(session=session)
    cookie_inspector_tool = CookieInspectorTool(session=session)
    cookie_set_tool = CookieSetTool(session=session)
    form_submit_tool = FormSubmitTool(session=session)

    # ---- response search and SQL pattern hints ----
    response_search_tool = ResponseSearchTool()
    sql_hint_tool = SqlPatternHintTool()

    # Register all tools
    tool_registry.register_tool(http_tool)
    tool_registry.register_tool(html_inspector_tool)
    tool_registry.register_tool(regex_tool)
    tool_registry.register_tool(robots_tool)
    tool_registry.register_tool(cookie_inspector_tool)
    tool_registry.register_tool(cookie_set_tool)
    tool_registry.register_tool(form_submit_tool)
    tool_registry.register_tool(js_tool)
    tool_registry.register_tool(response_search_tool)
    tool_registry.register_tool(sql_hint_tool)

    # ---- RAG: CTF knowledge base ----
    rag_retriever = initialize_ctf_knowledge_base()
    ctf_knowledge_tool = build_ctf_knowledge_tool(rag_retriever)
    if ctf_knowledge_tool is not None:
        tool_registry.register_tool(ctf_knowledge_tool)
        logger.info("Registered 'ctf_knowledge_query' RAG tool.")
    else:
        logger.warning(
            "CTF RAG knowledge base not available; 'ctf_knowledge_query' tool disabled."
        )

    # Planner (ReAct) with PromptBuilder customization
    planner = ReActPlanner(llm, tool_registry)

    # === PromptBuilder Tuning: Role + Few-Shot Examples ===
    pb = planner.prompt_builder

    # Role definition
    pb.role_definition = RoleDefinition(
        system_message=(
            "You are a PicoCTF-style web exploitation agent. You are skilled at "
            "solving Capture-The-Flag (CTF) web challenges involving HTTP, HTML, "
            "JavaScript, cookies, robots.txt, login forms, and SQL injection. "
            "You have access to tools that can:\n"
            "- fetch web pages and submit forms,\n"
            "- inspect HTML structure and comments,\n"
            "- extract and read JavaScript (inline and external),\n"
            "- inspect and modify cookies,\n"
            "- inspect robots.txt for hidden or disallowed paths,\n"
            "- search response bodies for interesting patterns or flags,\n"
            "- detect lines that look like SQL queries or database errors,\n"
            "- and consult an internal knowledge base about web exploitation.\n\n"
            "Use the ReAct style: think step-by-step, decide whether to use a tool, "
            "call tools when needed, observe results, and then continue reasoning. "
            "Your goal is to find the PicoCTF flag if it exists, or explain clearly "
            "why you could not find it."
        )
    )

    # Few-shot Example A: robots.txt style challenge
    example_a_user = (
        "I am working on a web challenge where the description says something "
        "about 'robots being too honest.' Maybe the flag is hidden in robots.txt "
        "or a disallowed directory."
    )
    example_a_thought = (
        "The hint about 'robots' suggests robots.txt might hide something. "
        "I should fetch robots.txt and see if there are disallowed paths, "
        "then fetch those paths."
    )
    example_a_action = (
        "Action: robots_txt\n"
        "Input: {\"base_url\": \"https://example.com\"}"
    )
    example_a_observation = (
        "Observation: Disallow: /hidden-flag\n"
        "I should now fetch /hidden-flag."
    )
    example_a_final = (
        "The challenge hint pointed to robots.txt. After fetching robots.txt and "
        "visiting the disallowed path, I found the flag in /hidden-flag/index.html."
    )

    pb.examples.append(
        Example(
            user=example_a_user,
            thought=example_a_thought,
            action=example_a_action,
            observation=example_a_observation,
            answer=example_a_final,
        )
    )

    # Few-shot Example B: client-side JavaScript password check
    example_b_user = (
        "The challenge gives me a login page that says the password check is done "
        "on the client side. I suspect the JavaScript contains the password or some "
        "logic to reconstruct it."
    )
    example_b_thought = (
        "If the password check is client-side, I should look at the JavaScript. "
        "I can fetch the page, then extract inline and external JS, and inspect "
        "the code to see how the password is validated."
    )
    example_b_action = (
        "Action: javascript_source\n"
        "Input: {\"url\": \"https://example.com/login\", \"max_scripts\": 5}"
    )
    example_b_observation = (
        "Observation: The JS code compares the input to a hard-coded string "
        "and prints 'correct' if it matches."
    )
    example_b_final = (
        "By inspecting the client-side JavaScript, I found the hard-coded password "
        "used by the challenge. Using that password in the login form reveals the "
        "flag."
    )

    pb.examples.append(
        Example(
            user=example_b_user,
            thought=example_b_thought,
            action=example_b_action,
            observation=example_b_observation,
            answer=example_b_final,
        )
    )

    # Working memory
    memory = WorkingMemory(max_turns=20)

    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        memory=memory,
        tool_executor=tool_executor,
    )

    return agent


# ---------------------------------------------------------------------------
# Helper: parse natural-language request into (base_url, challenge, task)
# ---------------------------------------------------------------------------

def parse_user_request(user_text: str):
    """
    Parse a free-form user request like:
      "find the PicoCTF flag on the url https://example.com. The challenge is called where are the robots"

    Returns (base_url, challenge, task).

    Heuristics:
      - base_url: first http(s):// URL found via regex.
      - challenge: from any sentence mentioning 'challenge', with boilerplate words stripped.
      - task: defaults to the full user_text.
    """
    if not user_text:
        return None, None, None

    text = user_text.strip()

    # 1. Extract URL
    url_match = re.search(r'https?://\S+', text)
    base_url = url_match.group(0) if url_match else None

    # 2. Extract challenge name
    challenge = None
    sentences = re.split(r'[.!?]', text)
    for sent in sentences:
        sent_clean = sent.strip()
        if not sent_clean:
            continue
        if "challenge" in sent_clean.lower():
            # Remove boilerplate words around the challenge name
            # e.g. "The challenge is called where are the robots"
            # -> "where are the robots"
            tmp = re.sub(
                r'\b(challenge|is|called|named|the|this|that|is called|is named)\b',
                ' ',
                sent_clean,
                flags=re.IGNORECASE,
            )
            tmp = re.sub(r'\s+', ' ', tmp).strip()
            if tmp:
                challenge = tmp
                break

    # 3. Default task = full text
    task = text or None

    return base_url, challenge, task


# ---------------------------------------------------------------------------
# Main / CLI
# ---------------------------------------------------------------------------

async def main() -> None:
    """
    CLI entry point.

    Modes:
      1) Classic CLI:
         python pico_agentic_solver.py \
           --base-url https://example.com \
           --challenge "where-are-the-robots" \
           --task "Find the PicoCTF flag."

      2) Natural-language request:
         python pico_agentic_solver.py
         (then type something like)
         "find the PicoCTF flag on the url https://example.com. "
         "The challenge is called where are the robots."

         or:
         python pico_agentic_solver.py \
           --request "find the PicoCTF flag on the url https://example.com. The challenge is called where are the robots."
    """

    parser = argparse.ArgumentParser(
        description="PicoCTF web challenge agent using the FAIR agentic framework."
    )
    # Make base-url and challenge optional so we can infer them from natural language.
    parser.add_argument(
        "--base-url",
        required=False,
        help=(
            "Base URL for the picoCTF challenge instance "
            "(e.g., https://example.com or https://saturn.picoctf.net:12345). "
            "If omitted, the script will try to infer it from --request or interactive input."
        ),
    )
    parser.add_argument(
        "--challenge",
        required=False,
        help=(
            "Challenge name (e.g., where-are-the-robots, insp3ct0r, logon, SQLiLite). "
            "If omitted, the script will try to infer it from --request or interactive input."
        ),
    )
    parser.add_argument(
        "--task",
        required=False,
        default="Find the PicoCTF flag for this web challenge.",
        help="High-level task description for the agent.",
    )
    parser.add_argument(
        "--request",
        required=False,
        help=(
            "Natural-language description of what you want, e.g.: "
            "\"find the PicoCTF flag on the url https://example.com. "
            "The challenge is called where are the robots.\" "
            "If omitted and base-url/challenge are missing, you will be prompted interactively."
        ),
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    # Determine base_url, challenge, and task, possibly using natural language.
    base_url = args.base_url
    challenge = args.challenge
    task = args.task
    user_request_text: str

    if base_url and challenge:
        # Classic CLI mode – we already have everything we need.
        user_request_text = args.request or (
            f"Find the PicoCTF flag for challenge '{challenge}' at {base_url}."
        )
    else:
        # Need to get and parse a natural-language request.
        if args.request:
            user_request_text = args.request
        else:
            print(
                "No --base-url/--challenge provided. Please describe your goal, e.g.\n"
                "\"find the PicoCTF flag on the url https://example.com. "
                "The challenge is called where are the robots.\""
            )
            user_request_text = input("Your request: ").strip()

        parsed_url, parsed_challenge, parsed_task = parse_user_request(user_request_text)

        # Fill in any missing pieces from parsing
        if not base_url:
            base_url = parsed_url
        if not challenge:
            challenge = parsed_challenge

        # If still missing pieces, ask interactively for clarity
        if not base_url:
            base_url = input("Could not find a URL in your request. Please enter the base URL: ").strip()
        if not challenge:
            challenge = input("Could not determine the challenge name. Please enter the challenge name: ").strip()
        if not task:
            task = input("Briefly describe the task (e.g., 'Find the PicoCTF flag.'): ").strip()

    # Final sanity check
    if not base_url or not challenge:
        print(
            "Error: base URL or challenge name is still missing after parsing. "
            "Please rerun and provide either CLI args or a clearer natural-language request."
        )
        return

    logger.info(
        "Using base_url=%r, challenge=%r, task=%r",
        base_url,
        challenge,
        task,
    )

    logger.info(
        "Building FAIR agent with HTTP, HTML, regex, robots, cookie, form, JS, "
        "response-search, SQL-hint, and CTF RAG tools..."
    )
    agent = build_agent()
    logger.info("Agent built successfully.")

    # Compose initial message for the agent
    initial_message = (
        f"You are a web CTF agent.\n"
        f"Challenge: {challenge}\n"
        f"Base URL: {base_url}\n"
        f"Task: {task}\n\n"
        "User request (natural language):\n"
        f"{user_request_text}\n\n"
        "You have tools to:\n"
        "- fetch pages over HTTP ('http_fetch'),\n"
        "- inspect HTML structure ('html_inspector'),\n"
        "- search for patterns like 'picoCTF{...}' using regex ('regex_search'),\n"
        "- examine robots.txt rules ('robots_txt'),\n"
        "- inspect and modify cookies ('cookie_inspector', 'cookie_set'),\n"
        "- submit forms using GET or POST ('form_submit'),\n"
        "- extract and inspect JavaScript (inline and external) ('javascript_source'),\n"
        "- focus on interesting lines in responses using keywords ('response_search'),\n"
        "- highlight SQL-related hints in responses ('sql_pattern_hint'), and\n"
        "- consult an internal web-exploitation knowledge base "
        "('ctf_knowledge_query') built from the PicoCTF Web Exploitation guide "
        "and your docs/ directory.\n\n"
        "Use your tools via the ReAct process to explore the site, understand login "
        "and database behavior, and try to find the PicoCTF flag. When you believe "
        "you have found the flag, clearly state it in your final answer."
    )

    print("\n=== Agent Input ===")
    print(initial_message)
    print("===================\n")

    try:
        response = await agent.arun(initial_message)
    except Exception as exc:
        logger.exception("Error while running agent:")
        print(f"Agent encountered an error: {exc}")
        return

    print("\n=== Agent Final Answer ===")
    print(response)
    print("==========================\n")


if __name__ == "__main__":
    asyncio.run(main())