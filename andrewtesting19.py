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
    * ResponseSearchTool    - Highlight lines around given keywords in responses
    * SqlPatternHintTool    - Highlight SQL/error-like patterns in responses
    * ctf_knowledge_query   - RAG tool over PicoCTF Web Exploitation + docs/

The RAG tool uses FAIR’s DocumentProcessor + SentenceTransformerEmbedder +
FaissVectorStore + SimpleRetriever to build a reusable knowledge base of
web-exploitation notes for the agent to consult.

This script assumes the following files/directories exist at runtime:
- Book-3-Web-Exploitation.pdf      (PicoCTF Web Exploitation guide)
- docs/                            (optional)
    *.md, *.txt                    (your additional notes)

You can override the docs directory with the CTF_DOCS_DIR environment variable.

Additional behavior:
- CLI is tailored to specific PicoCTF web challenges:
    --challenge ∈ {where-are-the-robots, insp3ct0r, dont-use-client-side, logon, SQLiLite}
- Logging:
    * Logs each tool call (name + truncated input)
    * Logs whenever a tool output or the final answer contains `picoCTF{...}`
"""

import os
import json
import argparse
import asyncio
import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import re
import sys
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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LoggingToolWrapper: log tool calls + picoCTF hits
# ---------------------------------------------------------------------------


class LoggingToolWrapper:
    """
    Wrapper for any FAIR tool that:

    - Logs tool calls (tool name + truncated input).
    - Runs the underlying tool.
    - Scans the result for picoCTF{...} and logs any potential flags.
    """

    def __init__(self, inner) -> None:
        self.inner = inner
        # Mirror the wrapped tool's public identity
        self.name = getattr(inner, "name", inner.__class__.__name__)
        self.description = getattr(inner, "description", "")

    def use(self, tool_input: str) -> str:
        preview = tool_input
        if preview is None:
            preview = ""
        if len(preview) > 200:
            preview = preview[:200] + "...[truncated]..."

        print(f"[LOG] Tool call -> {self.name}: {preview}")

        result = self.inner.use(tool_input)

        # Log potential flags in tool output
        if isinstance(result, str):
            matches = re.findall(r"picoCTF\{.*?\}", result)
            for m in matches:
                print(f"[LOG] Potential flag seen in {self.name} output: {m}")

        return result


# ---------------------------------------------------------------------------
# HttpFetchTool definition
# ---------------------------------------------------------------------------


class HttpFetchTool:
    """
    HttpFetchTool: perform HTTP GET/HEAD requests against a URL.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "https://example.com/path",
          "method": "GET",                  # optional, "GET" (default) or "HEAD"
          "params": {"key": "value"},       # optional
          "headers": {"User-Agent": "..."}, # optional
          "max_body": 4000                  # optional, int
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
        "Perform an HTTP GET or HEAD request to a URL with optional query "
        "parameters and headers. Input must be JSON with keys: 'url' "
        "(required), 'method' (optional: 'GET' or 'HEAD', default 'GET'), "
        "'params' (optional dict), 'headers' (optional dict), and 'max_body' "
        "(optional int, default 4000). Returns status, headers, and a "
        "truncated response body (for GET)."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        # Parse JSON input
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[HttpFetchTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        if not url or not isinstance(url, str):
            return "[HttpFetchTool] Error: 'url' (string) is required in the input JSON."

        method = (data.get("method") or "GET").upper()
        params = data.get("params") or {}
        headers = data.get("headers") or {}
        max_body = data.get("max_body", 4000)

        if not isinstance(params, dict):
            return "[HttpFetchTool] Error: 'params' must be a JSON object (dict)."
        if not isinstance(headers, dict):
            return "[HttpFetchTool] Error: 'headers' must be a JSON object (dict)."

        try:
            if method == "HEAD":
                response = self.session.head(
                    url, params=params, headers=headers, timeout=10
                )
            else:
                # default / fallback to GET
                response = self.session.get(
                    url, params=params, headers=headers, timeout=10
                )
                method = "GET"
        except Exception as exc:
            return f"[HttpFetchTool] Error during {method!r} request to {url!r}: {exc!r}"

        header_lines = [f"{k}: {v}" for k, v in response.headers.items()]
        headers_str = "\n".join(header_lines)

        # HEAD responses typically have no body
        if method == "HEAD":
            body_preview = "[No body for HEAD request]"
            max_body_int = 0
        else:
            text = response.text or ""
            try:
                max_body_int = int(max_body)
            except Exception:
                max_body_int = 4000

            if max_body_int > 0:
                body_preview = text[:max_body_int]
                if len(text) > max_body_int:
                    body_preview += "\n...[truncated]..."
            else:
                body_preview = text

        summary = (
            f"[HttpFetchTool] Method: {method}\n"
            f"URL: {response.url}\n"
            f"Status: {response.status_code}\n"
            f"Headers:\n{headers_str}\n\n"
            f"Body (truncated to {max_body_int} chars):\n{body_preview}"
        )
        return summary


# ---------------------------------------------------------------------------
# HtmlInspectorTool definition
# ---------------------------------------------------------------------------


class HtmlInspectorTool:
    """
    HtmlInspectorTool: inspect and summarize the structure of an HTML page.

    Inputs (JSON via `.use`):

        {
          "url": "https://example.com/path",  # optional
          "html": "<html>...</html>",        # optional
          "max_items": 50                    # optional, maximum items per section
        }

    Behavior:
      - If 'html' is provided, parse that directly.
      - Else if 'url' is provided, fetch the page using the shared session.
      - Extract:
          * <a href=...> links (href + text)
          * <script src=...> external script URLs
          * <link rel="stylesheet" href=...> CSS URLs
          * HTML comments
      - Return a readable text summary grouping LINKS / SCRIPTS / STYLESHEETS / COMMENTS.
    """

    name: str = "html_inspector"
    description: str = (
        "Inspect and summarize the structure of HTML. Input JSON keys: "
        "'url' (optional) or 'html' (optional), and 'max_items' (optional int). "
        "If 'url' is given, fetches that page; otherwise uses the provided 'html'. "
        "Extracts links, external scripts, stylesheets, and comments and returns "
        "a readable summary."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _fetch_html(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=10)
        except Exception as exc:
            return f"[HtmlInspectorTool] Error fetching URL {url!r}: {exc!r}"
        return resp.text or ""

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[HtmlInspectorTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        html = data.get("html")
        max_items = data.get("max_items", 50)

        if html and not isinstance(html, str):
            return "[HtmlInspectorTool] Error: 'html' must be a string if provided."
        if url and not isinstance(url, str):
            return "[HtmlInspectorTool] Error: 'url' must be a string if provided."

        if not html and not url:
            return (
                "[HtmlInspectorTool] Error: You must provide either 'url' or 'html' "
                "in the JSON input."
            )

        if not html and url:
            html = self._fetch_html(url)

        if html.startswith("[HtmlInspectorTool] Error"):
            # Propagate error from _fetch_html
            return html

        soup = BeautifulSoup(html, "html.parser")

        # Extract links
        links: List[str] = []
        for a in soup.find_all("a", href=True):
            text = (a.get_text() or "").strip()
            href = a["href"]
            if text:
                links.append(f"- text={text!r}, href={href!r}")
            else:
                links.append(f"- href={href!r}")

        # Extract external scripts
        scripts: List[str] = []
        for script in soup.find_all("script", src=True):
            src = script["src"]
            scripts.append(f"- src={src!r}")

        # Extract stylesheets
        stylesheets: List[str] = []
        for link in soup.find_all("link", rel=True, href=True):
            rel = " ".join(link.get("rel", []))
            if "stylesheet" in rel.lower():
                href = link["href"]
                stylesheets.append(f"- rel={rel!r}, href={href!r}")

        # Extract comments
        comments: List[str] = []
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            c_text = str(comment).strip()
            if len(c_text) > 200:
                c_text = c_text[:200] + " ...[truncated]..."
            comments.append(f"- {c_text!r}")

        def truncate_list(items: List[str], max_n: int) -> List[str]:
            if len(items) <= max_n:
                return items
            return items[:max_n] + [
                f"...[truncated, {len(items) - max_n} more items]..."
            ]

        try:
            max_items_int = int(max_items)
        except Exception:
            max_items_int = 50

        links = truncate_list(links, max_items_int)
        scripts = truncate_list(scripts, max_items_int)
        stylesheets = truncate_list(stylesheets, max_items_int)
        comments = truncate_list(comments, max_items_int)

        summary_parts = [
            "[HtmlInspectorTool] HTML structure summary:",
            "",
        ]
        if url:
            summary_parts.append(f"Source URL: {url}")
            summary_parts.append("")

        summary_parts.append("[LINKS]")
        summary_parts.extend(links or ["- (none found)"])
        summary_parts.append("")

        summary_parts.append("[SCRIPTS - external src]")
        summary_parts.extend(scripts or ["- (none found)"])
        summary_parts.append("")

        summary_parts.append("[STYLESHEETS]")
        summary_parts.extend(stylesheets or ["- (none found)"])
        summary_parts.append("")

        summary_parts.append("[COMMENTS]")
        summary_parts.extend(comments or ["- (none found)"])
        summary_parts.append("")

        return "\n".join(summary_parts)


# ---------------------------------------------------------------------------
# RegexSearchTool definition
# ---------------------------------------------------------------------------


class RegexSearchTool:
    """
    RegexSearchTool: find regex matches within a text.

    Inputs (JSON via `.use`):

        {
          "text": "some long text ...",
          "pattern": "picoCTF\\{.*?\\}",
          "max_matches": 50        # optional
        }

    Behavior:
      - Compiles the given regex pattern using Python's `re` module (DOTALL).
      - Finds all matches in `text`.
      - Returns up to max_matches results, numbered, and notes if truncated.
    """

    name: str = "regex_search"
    description: str = (
        "Search a text for occurrences of a regular expression. Input JSON keys: "
        "'text' (string), 'pattern' (string regex), and 'max_matches' (optional int, "
        "default 50). Returns up to max_matches matches and notes if truncated. "
        "Useful for finding picoCTF{...} flags in HTTP responses."
    )

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[RegexSearchTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        pattern = data.get("pattern")
        max_matches = data.get("max_matches", 50)

        if not isinstance(text, str):
            return "[RegexSearchTool] Error: 'text' must be a string."
        if not isinstance(pattern, str):
            return "[RegexSearchTool] Error: 'pattern' must be a string."

        try:
            max_matches_int = int(max_matches)
        except Exception:
            max_matches_int = 50

        try:
            regex = re.compile(pattern, re.DOTALL)
        except re.error as exc:
            return f"[RegexSearchTool] Error: invalid regex pattern: {exc}"

        matches = regex.findall(text)

        if not matches:
            return "[RegexSearchTool] No matches found."

        lines: List[str] = ["[RegexSearchTool] Matches:"]
        count = 0
        for idx, m in enumerate(matches, start=1):
            if count >= max_matches_int:
                break
            if isinstance(m, tuple):
                m_str = ", ".join(repr(x) for x in m)
            else:
                m_str = repr(m)
            lines.append(f"{idx}. {m_str}")
            count += 1

        if len(matches) > max_matches_int:
            lines.append(
                f"...[truncated: {len(matches) - max_matches_int} additional matches]"
            )

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# RobotsTxtTool definition
# ---------------------------------------------------------------------------


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
        "readable summary and suggested paths to explore."
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


# ---------------------------------------------------------------------------
# CookieInspectorTool definition
# ---------------------------------------------------------------------------


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
        "(e.g., 'example.com'). Returns cookie names, values, and basic attributes."
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


# ---------------------------------------------------------------------------
# CookieSetTool definition
# ---------------------------------------------------------------------------


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
        "(string, required), and 'path' (optional, default '/')."
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


# ---------------------------------------------------------------------------
# FormSubmitTool definition
# ---------------------------------------------------------------------------


class FormSubmitTool:
    """
    FormSubmitTool: submit GET/POST forms using the shared session.

    Inputs (JSON via `.use`):

        {
          "url": "https://example.com/login",
          "method": "POST",                   # "GET" or "POST"
          "data": {"username": "test", "password": "test"},
          "headers": {"Content-Type": "application/x-www-form-urlencoded"},
          "max_body": 4000
        }

    Behavior:
      - Uses the shared session to submit the request.
      - For GET, `data` is used as query params.
      - For POST, `data` is used as form data.
      - Returns status code, headers, and a truncated body similar to HttpFetchTool.
    """

    name: str = "form_submit"
    description: str = (
        "Submit an HTTP form using GET or POST with the shared session. "
        "Input JSON keys: 'url' (string, required), 'method' (string, 'GET' or "
        "'POST', required), 'data' (optional dict of form fields), "
        "'headers' (optional dict), and 'max_body' (optional int, default 4000). "
        "Returns status, headers, and a truncated body."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[FormSubmitTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        method = data.get("method")
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        max_body = data.get("max_body", 4000)

        if not isinstance(url, str) or not url:
            return "[FormSubmitTool] Error: 'url' (string) is required."
        if not isinstance(method, str) or not method:
            return "[FormSubmitTool] Error: 'method' (string) is required."

        method = method.upper()
        if method not in ("GET", "POST"):
            return "[FormSubmitTool] Error: 'method' must be 'GET' or 'POST'."

        if not isinstance(form_data, dict):
            return "[FormSubmitTool] Error: 'data' must be a JSON object (dict) if provided."
        if not isinstance(headers, dict):
            return "[FormSubmitTool] Error: 'headers' must be a JSON object (dict) if provided."

        try:
            if method == "GET":
                resp = self.session.get(url, params=form_data, headers=headers, timeout=10)
            else:  # POST
                resp = self.session.post(url, data=form_data, headers=headers, timeout=10)
        except Exception as exc:
            return f"[FormSubmitTool] Error during {method!r} request to {url!r}: {exc!r}"

        header_lines = [f"{k}: {v}" for k, v in resp.headers.items()]
        headers_str = "\n".join(header_lines)

        text = resp.text or ""
        try:
            max_body_int = int(max_body)
        except Exception:
            max_body_int = 4000

        if max_body_int > 0:
            body_preview = text[:max_body_int]
            if len(text) > max_body_int:
                body_preview += "\n...[truncated]..."
        else:
            body_preview = text

        summary = (
            f"[FormSubmitTool] Method: {method}\n"
            f"URL: {resp.url}\n"
            f"Status: {resp.status_code}\n"
            f"Headers:\n{headers_str}\n\n"
            f"Body (truncated to {max_body_int} chars):\n{body_preview}"
        )
        return summary


# ---------------------------------------------------------------------------
# JavaScriptSourceTool definition
# ---------------------------------------------------------------------------


class JavaScriptSourceTool:
    """
    JavaScriptSourceTool: extract and (optionally) pretty-print JS from a page.

    Inputs (JSON via `.use`):

        {
          "url": "https://example.com/page",   # optional
          "html": "<html>...</html>",          # optional
          "base_url": "https://example.com",   # optional, for resolving relative src
          "max_scripts": 20,                   # optional
          "max_chars_per_script": 4000         # optional
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
        "provided, fetches the page. Then parses <script> tags: for each tag, "
        "either fetches external JS from 'src' or captures inline JS. Returns a "
        "readable summary labeling each script block. If jsbeautifier is "
        "installed, scripts may be pretty-printed."
    )

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def _fetch_html(self, url: str) -> str:
        try:
            resp = self.session.get(url, timeout=10)
        except Exception as exc:
            return f"[JavaScriptSourceTool] Error fetching URL {url!r}: {exc!r}"
        return resp.text or ""

    def _beautify_js(self, code: str) -> str:
        if HAS_JSBEAUTIFIER:
            try:
                return jsbeautifier.beautify(code)  # type: ignore
            except Exception:
                return code
        return code

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[JavaScriptSourceTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        url = data.get("url")
        html = data.get("html")
        base_url = data.get("base_url")
        max_scripts = data.get("max_scripts", 20)
        max_chars_per_script = data.get("max_chars_per_script", 4000)

        if url and not isinstance(url, str):
            return "[JavaScriptSourceTool] Error: 'url' must be a string if provided."
        if html and not isinstance(html, str):
            return "[JavaScriptSourceTool] Error: 'html' must be a string if provided."
        if base_url and not isinstance(base_url, str):
            return "[JavaScriptSourceTool] Error: 'base_url' must be a string if provided."

        if not html and not url:
            return (
                "[JavaScriptSourceTool] Error: You must provide either 'url' or "
                "'html' in the JSON input."
            )

        if not html and url:
            html = self._fetch_html(url)
        page_url = url

        if html.startswith("[JavaScriptSourceTool] Error"):
            return html

        try:
            max_scripts_int = int(max_scripts)
        except Exception:
            max_scripts_int = 20

        try:
            max_chars_int = int(max_chars_per_script)
        except Exception:
            max_chars_int = 4000

        soup = BeautifulSoup(html, "html.parser")
        script_tags = soup.find_all("script")

        blocks: List[str] = ["[JavaScriptSourceTool] Extracted JavaScript code:"]
        if url:
            blocks.append(f"Source page URL: {url}")
        if base_url:
            blocks.append(f"Base URL for resolving src: {base_url}")
        blocks.append("")

        count = 0
        for idx, script in enumerate(script_tags, start=1):
            if count >= max_scripts_int:
                blocks.append(
                    f"...[truncated: more than {max_scripts_int} <script> tags found]"
                )
                break

            src = script.get("src")
            if src:
                # External script
                if base_url:
                    full_src = urljoin(base_url, src)
                elif page_url:
                    full_src = urljoin(page_url, src)
                else:
                    full_src = src

                blocks.append(f"[EXTERNAL SCRIPT #{idx}: {full_src}]")

                try:
                    resp = self.session.get(full_src, timeout=10)
                    js_code = resp.text or ""
                except Exception as exc:
                    blocks.append(
                        f"Error fetching external script {full_src!r}: {exc!r}\n"
                    )
                    count += 1
                    continue

                js_code = self._beautify_js(js_code)

                if max_chars_int > 0 and len(js_code) > max_chars_int:
                    js_code = js_code[:max_chars_int] + "\n...[truncated]..."

                blocks.append(js_code)
                blocks.append("")  # blank line
            else:
                # Inline script
                js_code = script.string or script.get_text() or ""
                js_code = js_code.strip()
                if not js_code:
                    continue

                blocks.append(f"[INLINE SCRIPT #{idx}]")

                js_code = self._beautify_js(js_code)

                if max_chars_int > 0 and len(js_code) > max_chars_int:
                    js_code = js_code[:max_chars_int] + "\n...[truncated]..."

                blocks.append(js_code)
                blocks.append("")

            count += 1

        if count == 0:
            blocks.append("- (no <script> tags with content or src found)")

        return "\n".join(blocks)


# ---------------------------------------------------------------------------
# ResponseSearchTool definition
# ---------------------------------------------------------------------------


class ResponseSearchTool:
    """
    ResponseSearchTool: highlight lines in a response that contain given keywords.

    Inputs (JSON via `.use`):

        {
          "text": "<full HTTP response body as string>",
          "keywords": ["error", "sql", "warning"],  # optional list of strings
          "context_lines": 2                        # optional int, default 2
        }

    Behavior:
      - Splits 'text' into lines.
      - For each line that contains any keyword (case-insensitive), captures
        that line plus a small context window before and after it.
      - Returns a readable result with line numbers and context, so the LLM
        can quickly focus on interesting parts (errors, hints, mentions of SQL, etc.).
    """

    name: str = "response_search"
    description: str = (
        "Search an HTTP response body for lines containing certain keywords, "
        "and return those lines with surrounding context. Input JSON keys: "
        "'text' (string), 'keywords' (optional list of strings), and "
        "'context_lines' (optional int, default 2). Useful for zooming in on "
        "error messages or hints related to web vulnerabilities."
    )

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[ResponseSearchTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        keywords = data.get("keywords", [])
        context_lines = data.get("context_lines", 2)

        if not isinstance(text, str):
            return "[ResponseSearchTool] Error: 'text' must be a string."

        # Normalize keywords
        if keywords is None:
            keywords = []
        if not isinstance(keywords, list):
            return "[ResponseSearchTool] Error: 'keywords' must be a list of strings if provided."

        normalized_keywords: List[str] = []
        for kw in keywords:
            if isinstance(kw, str) and kw.strip():
                normalized_keywords.append(kw.lower())

        # If no keywords given, use a small default set
        if not normalized_keywords:
            normalized_keywords = [
                "error",
                "warning",
                "sql",
                "exception",
                "picoctf",
                "flag",
                "invalid",
            ]

        try:
            ctx = int(context_lines)
        except Exception:
            ctx = 2

        lines = text.splitlines()
        n = len(lines)

        # Collect line indices that match
        matched_indices: List[int] = []
        for i, line in enumerate(lines):
            lower_line = line.lower()
            if any(kw in lower_line for kw in normalized_keywords):
                matched_indices.append(i)

        if not matched_indices:
            return "[ResponseSearchTool] No lines matched the given keywords."

        # Collect context line indices
        context_indices = set()
        for i in matched_indices:
            start = max(0, i - ctx)
            end = min(n - 1, i + ctx)
            for j in range(start, end + 1):
                context_indices.add(j)

        sorted_indices = sorted(context_indices)

        # Build output
        out_lines: List[str] = [
            "[ResponseSearchTool] Matching lines with context:",
            f"Keywords (case-insensitive): {normalized_keywords}",
            f"Context lines before/after each match: {ctx}",
            "",
        ]

        for idx in sorted_indices:
            prefix = ">>" if idx in matched_indices else "  "
            # 1-based line numbers for readability
            out_lines.append(f"{prefix} [line {idx+1}] {lines[idx]}")

        return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# SqlPatternHintTool definition
# ---------------------------------------------------------------------------


class SqlPatternHintTool:
    """
    SqlPatternHintTool: scan a response body for common SQL/logging hints.

    Inputs (JSON via `.use`):

        {
          "text": "<full HTTP response body as string>"
        }

    Behavior:
      - Splits 'text' into lines.
      - Checks each line (case-insensitive) for common SQL-related substrings,
        such as: SELECT, FROM, WHERE, INSERT, UPDATE, DELETE, ' or 1=1, --, etc.
      - Returns lines that contain these patterns, along with a short explanation
        that such lines may indicate echoed SQL queries or error messages relevant
        to SQL injection reasoning.
      - Does NOT hard-code any specific SQL injection payloads; it only highlights hints.
    """

    name: str = "sql_pattern_hint"
    description: str = (
        "Highlight response lines that contain SQL-related patterns, to help "
        "reason about possible SQL injection behavior. Input JSON key: 'text' "
        "(string). Scans for substrings like 'SELECT', 'FROM', 'WHERE', "
        "'INSERT', 'UPDATE', 'DELETE', \"' or 1=1\", and '--', and returns "
        "matching lines with a short explanatory note."
    )

    def use(self, tool_input: str) -> str:
        try:
            data = json.loads(tool_input) if tool_input else {}
        except json.JSONDecodeError as exc:
            return (
                f"[SqlPatternHintTool] Error: tool_input must be JSON. "
                f"Decoding failed with: {exc}"
            )

        text = data.get("text")
        if not isinstance(text, str):
            return "[SqlPatternHintTool] Error: 'text' must be a string."

        lines = text.splitlines()

        # Common SQL/logging hints (lowercase for comparison)
        patterns = [
            "select ",
            " from ",
            " where ",
            " insert ",
            " update ",
            " delete ",
            " union ",
            "group by",
            "order by",
            "' or 1=1",
            "\" or 1=1",
            "--",
            "/*",
            "*/",
            "sql",
            "syntax error",
            "database error",
        ]

        matches: List[str] = []
        for idx, line in enumerate(lines):
            lower_line = line.lower()
            if any(p in lower_line for p in patterns):
                matches.append(f"[line {idx+1}] {line}")

        if not matches:
            return (
                "[SqlPatternHintTool] No obvious SQL-related patterns were found in "
                "the provided text. This does not rule out SQL injection, but there "
                "are no clear error messages or echoed queries to highlight."
            )

        out_lines: List[str] = [
            "[SqlPatternHintTool] Potential SQL-related hints found in response:",
            "These lines contain substrings commonly associated with SQL queries or "
            "database error messages. They might indicate:",
            "- Echoed or logged SQL statements.",
            "- SQL syntax or database errors.",
            "- Input being directly inserted into queries.",
            "",
        ]
        out_lines.extend(matches)

        return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# RAG helper: simple text splitter
# ---------------------------------------------------------------------------


def split_text(text: str, chunk_size: int = 1000, chunk_overlap: int = 150) -> List[str]:
    """
    Simple text splitter used for RAG.

    Splits a long text into overlapping chunks so that:
      - Each chunk has up to `chunk_size` characters.
      - Consecutive chunks overlap by `chunk_overlap` characters.

    This is intentionally simple and mirrors the demo_rag_from_documents.py
    approach. In a more advanced project, you could switch to a semantic
    splitter.
    """
    if not text:
        return []
    chunks: List[str] = []
    start = 0
    length = len(text)
    while start < length:
        end = start + chunk_size
        chunks.append(text[start:end])
        start += max(1, chunk_size - chunk_overlap)
    return chunks


# ---------------------------------------------------------------------------
# Minimal Document wrapper for FAISS
# ---------------------------------------------------------------------------

@dataclass
class SimpleDocument:
    """
    Minimal document type compatible with FaissVectorStore.

    FaissVectorStore expects each document to have a .page_content attribute.
    We keep metadata optional so we don't disturb any existing functionality.
    """
    page_content: str
    metadata: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# RAG initialization: build CTF knowledge base (PDF + docs/)
# ---------------------------------------------------------------------------

_rag_retriever: Optional[SimpleRetriever] = None


def initialize_ctf_knowledge_base() -> Optional[SimpleRetriever]:
    """
    Build and cache a RAG knowledge base for PicoCTF-style web exploitation.

    Data sources:
      - Book-3-Web-Exploitation.pdf  (PicoCTF Web Exploitation booklet)
      - Any *.md / *.txt files in docs/ (or CTF_DOCS_DIR) alongside this script.

    Pipeline:
      - DocumentProcessor for extraction (PDF/Markdown/Text).
      - SentenceTransformerEmbedder for embeddings.
      - FaissVectorStore as the vector store.
      - SimpleRetriever wrapping the vector store.

    This function is called once at agent construction time and the resulting
    retriever is reused for all ctf_knowledge_query tool calls.
    """
    global _rag_retriever
    if _rag_retriever is not None:
        return _rag_retriever

    logger.info("Initializing CTF RAG knowledge base (PDF + docs/)...")

    rag_cfg = getattr(settings, "rag_system", None)

    # Vector store directory
    index_dir = Path(
        getattr(
            getattr(rag_cfg, "paths", None),
            "vector_store_dir",
            "out/ctf_vector_store",
        )
    ).resolve()
    index_dir.mkdir(parents=True, exist_ok=True)

    # Embedding model / config
    embed_model = getattr(
        getattr(rag_cfg, "embeddings", None),
        "embedding_model",
        "sentence-transformers/all-MiniLM-L6-v2",
    )
    use_gpu = getattr(getattr(rag_cfg, "vector_store", None), "use_gpu", False)
    batch_size = getattr(getattr(rag_cfg, "embeddings", None), "batch_size", 128)

    try:
        embedder = SentenceTransformerEmbedder(model_name=embed_model)
    except Exception as e:
        logger.error(
            "Failed to initialize SentenceTransformerEmbedder for RAG: %s", e, exc_info=True
        )
        return None

    # Build FAISS vector store
    try:
        vector_store = FaissVectorStore(
            embedder=embedder,
            index_dir=str(index_dir),
            use_gpu=use_gpu,
            normalize=True,
            batch_size=batch_size,
        )
        # Load existing index if present (otherwise this is a fresh index)
        try:
            vector_store.load()
            logger.info("Loaded existing FAISS index from %s", index_dir)
        except Exception as e:
            logger.warning(
                "Could not load existing FAISS index at %s (will create new one): %s",
                index_dir,
                e,
            )
    except Exception as e:
        logger.error("Failed to initialize FaissVectorStore: %s", e, exc_info=True)
        return None

    # Use DocumentProcessor to load the PDF and docs
    script_dir = Path(__file__).resolve().parent
    docs_dir_name = os.getenv("CTF_DOCS_DIR", "docs")
    docs_dir = script_dir / docs_dir_name

    doc_proc = DocumentProcessor({"files_directory": str(script_dir)})

    doc_paths: List[Path] = []

    # Primary PicoCTF Web Exploitation booklet
    pdf_path = script_dir / "Book-3-Web-Exploitation.pdf"
    if pdf_path.exists():
        doc_paths.append(pdf_path)
    else:
        logger.warning(
            "PicoCTF Web Exploitation PDF not found at %s. "
            "RAG will rely on docs/ only (if present).",
            pdf_path,
        )

    # Additional notes (Markdown / text) in docs/
    if docs_dir.exists() and docs_dir.is_dir():
        doc_paths.extend(sorted(docs_dir.glob("*.md")))
        doc_paths.extend(sorted(docs_dir.glob("*.txt")))
    else:
        logger.info(
            "Docs directory %s not found. You can create it and add *.md / *.txt "
            "files with your own notes on SQL injection, robots.txt, cookies, etc.",
            docs_dir,
        )

    all_chunks: List[str] = []

    for path in doc_paths:
        try:
            docs = doc_proc.process_file(str(path))
        except Exception as e:
            logger.error("DocumentProcessor failed for %s: %s", path, e, exc_info=True)
            continue

        if not docs:
            logger.warning("DocumentProcessor returned no documents for %s", path)
            continue

        for doc in docs:
            text = getattr(doc, "page_content", None)
            if not isinstance(text, str) or not text.strip():
                continue
            # Chunk the document for retrieval
            chunks = split_text(text, chunk_size=1200, chunk_overlap=200)
            all_chunks.extend(chunks)

    if not all_chunks:
        logger.warning(
            "No document chunks were created; CTF RAG knowledge base will be empty."
        )
    else:
        logger.info("Adding %d chunks to FAISS vector store...", len(all_chunks))
        # ✅ FIX: Wrap raw strings into SimpleDocument so FaissVectorStore can access .page_content
        docs_for_store = [SimpleDocument(page_content=chunk) for chunk in all_chunks]
        try:
            vector_store.add_documents(docs_for_store)
        except Exception as e:
            logger.error(
                "Failed to add chunks to FAISS vector store: %s", e, exc_info=True
            )
            return None

    _rag_retriever = SimpleRetriever(vector_store)
    logger.info(
        "CTF knowledge base initialized with %d chunks (PDF + docs).", len(all_chunks)
    )
    return _rag_retriever


# ---------------------------------------------------------------------------
# CTF RAG Tool: wrap FAIR's KnowledgeBaseQueryTool
# ---------------------------------------------------------------------------


def build_ctf_knowledge_tool(
    retriever: Optional[SimpleRetriever],
) -> Optional[KnowledgeBaseQueryTool]:
    """
    Wrap FAIR's KnowledgeBaseQueryTool as a CTF-specific RAG tool.

    We reuse the underlying KnowledgeBaseQueryTool (which already handles the
    retriever interaction and formatting), but override its name and description
    to make it clear that this tool is for web-exploitation knowledge.

    The tool is exposed to the LLM as 'ctf_knowledge_query'.
    """
    if retriever is None:
        logger.warning(
            "No retriever available; ctf_knowledge_query tool will not be registered."
        )
        return None

    # Instantiate FAIR's generic knowledge-base tool
    ctf_tool = KnowledgeBaseQueryTool(retriever)

    # Override its public identity so the planner sees the right name + description
    ctf_tool.name = "ctf_knowledge_query"
    ctf_tool.description = (
        "Consult an internal web-exploitation knowledge base (PicoCTF Web Exploitation "
        "booklet + your docs/) for help on topics such as SQL injection, robots.txt "
        "abuse, cookies, client-side validation, and other PicoCTF-style web CTF "
        "patterns. Input should be a natural-language question like "
        "'How do I exploit a simple login form with SQL injection?' The tool returns "
        "the most relevant passages, separated and trimmed so they are easy to read."
    )

    return ctf_tool


# ---------------------------------------------------------------------------
# Agent construction (with PromptBuilder tuning + logging wrapper)
# ---------------------------------------------------------------------------


def build_agent() -> SimpleAgent:
    """
    Construct and return a SimpleAgent wired up with:

      - OpenAI LLM (OpenAIAdapter, using fairlib.settings)
      - ReActPlanner + custom PromptBuilder role + examples
      - ToolRegistry with HTTP / HTML / regex / cookies / robots / form / JS / search / SQL / RAG tools
      - LoggingToolWrapper around all tools (for tool-call + picoCTF logging)
      - ToolExecutor
      - WorkingMemory
    """

    # Load environment variables from .env (if present)
    load_dotenv()

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Set it in your environment or a .env file."
        )
    settings.api_keys.openai_api_key = api_key

    llm = OpenAIAdapter(api_key=settings.api_keys.openai_api_key)

    # Single shared HTTP session for ALL HTTP-related tools
    shared_session = requests.Session()

    tool_registry = ToolRegistry()

    # Instantiate actual tools
    http_tool = HttpFetchTool(session=shared_session)
    html_tool = HtmlInspectorTool(session=shared_session)
    regex_tool = RegexSearchTool()
    robots_tool = RobotsTxtTool(session=shared_session)
    cookie_inspector_tool = CookieInspectorTool(session=shared_session)
    cookie_set_tool = CookieSetTool(session=shared_session)
    form_submit_tool = FormSubmitTool(session=shared_session)
    js_source_tool = JavaScriptSourceTool(session=shared_session)
    response_search_tool = ResponseSearchTool()
    sql_pattern_hint_tool = SqlPatternHintTool()

    # Wrap them with LoggingToolWrapper
    tool_registry.register_tool(LoggingToolWrapper(http_tool))
    tool_registry.register_tool(LoggingToolWrapper(html_tool))
    tool_registry.register_tool(LoggingToolWrapper(regex_tool))
    tool_registry.register_tool(LoggingToolWrapper(robots_tool))
    tool_registry.register_tool(LoggingToolWrapper(cookie_inspector_tool))
    tool_registry.register_tool(LoggingToolWrapper(cookie_set_tool))
    tool_registry.register_tool(LoggingToolWrapper(form_submit_tool))
    tool_registry.register_tool(LoggingToolWrapper(js_source_tool))
    tool_registry.register_tool(LoggingToolWrapper(response_search_tool))
    tool_registry.register_tool(LoggingToolWrapper(sql_pattern_hint_tool))

    # ---- RAG: CTF knowledge base ----
    rag_retriever = initialize_ctf_knowledge_base()
    ctf_knowledge_tool = build_ctf_knowledge_tool(rag_retriever)
    if ctf_knowledge_tool is not None:
        tool_registry.register_tool(LoggingToolWrapper(ctf_knowledge_tool))
        logger.info("Registered 'ctf_knowledge_query' RAG tool (with logging wrapper).")
    else:
        logger.warning(
            "CTF RAG knowledge base not available; 'ctf_knowledge_query' tool disabled."
        )

    # Planner (ReAct) with PromptBuilder customization
    planner = ReActPlanner(llm, tool_registry)

    # === PromptBuilder Tuning: Role + Few-Shot Examples ===
    pb = planner.prompt_builder

    # 1. Custom RoleDefinition: PicoCTF-style web exploitation agent
    role_text = (
        "You are a PicoCTF-style web exploitation agent. "
        "Your job is to solve web Capture-The-Flag challenges by exploring the target web "
        "application, understanding how it works, and extracting the final flag.\n"
        "You have tools for:\n"
        "- HTTP fetching and form submission ('http_fetch', 'form_submit'),\n"
        "- HTML inspection and JavaScript inspection ('html_inspector', 'javascript_source'),\n"
        "- working with cookies and robots.txt ('cookie_inspector', 'cookie_set', 'robots_txt'),\n"
        "- searching and analyzing responses ('regex_search', 'response_search', 'sql_pattern_hint'),\n"
        "- and consulting an internal web-exploitation knowledge base ('ctf_knowledge_query').\n"
        "Use a Thought → Action → Tool Observation loop: think step-by-step about what to do next, "
        "choose ONE tool to call, read the observation, then continue reasoning until you can "
        "confidently call the 'final_answer' tool with the flag or a clear explanation."
    )
    pb.role_definition = RoleDefinition(role_text)

    # 2. Few-shot ReAct-style examples (robots.txt + client-side JS)
    pb.examples.clear()

    # Example A: robots.txt based discovery
    robots_example = Example(
        """User Request: The challenge hint mentions 'robots', so robots.txt might be hiding something. Use your tools to find any disallowed path and see if it contains a flag.

Thought: The user's goal is to see if robots.txt lists any disallowed paths that might hide a flag. I should first fetch robots.txt from the base URL.
Action: {"tool_name": "robots_txt", "tool_input": {"base_url": "https://example.com"}}

Tool Observation: [RobotsTxtTool] robots.txt for https://example.com
Disallow: /secret-admin
[SUGGESTED PATHS TO EXPLORE]
- https://example.com/secret-admin

Thought: robots.txt disallows /secret-admin, which is likely a hidden admin page. I should fetch that path to look for a secret or flag.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/secret-admin", "method": "GET"}}

Tool Observation: [HttpFetchTool] Method: GET
URL: https://example.com/secret-admin
Status: 200
Body:
Welcome admin, here is your flag: FLAG{example_robot_flag}

Thought: By checking robots.txt and then visiting the disallowed path /secret-admin, I found the flag. I should now return it with the final_answer tool.
Action: {"tool_name": "final_answer", "tool_input": "The flag is FLAG{example_robot_flag} from the hidden /secret-admin page."}
"""
    )

    # Example B: client-side JavaScript password check + RAG
    js_example = Example(
        """User Request: The challenge says 'Don't trust the client' and shows a simple login form. The password check is probably in JavaScript. Figure out the correct password.

Thought: The hint 'Don't trust the client' suggests the password check is implemented in client-side JavaScript. I'll briefly consult my web-exploitation knowledge base for best practices.
Action: {"tool_name": "ctf_knowledge_query", "tool_input": "How do I solve web CTF challenges where the password check is hidden in client-side JavaScript?"}

Tool Observation: The knowledge base explains that these challenges are typically solved by fetching the page, extracting the JavaScript logic, and reading the condition the password must satisfy.

Thought: Based on that, I should first fetch the login page HTML and then analyze the JavaScript it loads.
Action: {"tool_name": "http_fetch", "tool_input": {"url": "https://example.com/login", "method": "GET"}}

Tool Observation: [HttpFetchTool] Method: GET
URL: https://example.com/login
Status: 200
Body:
<html>...<script src=\"/static/check.js\"></script>...</html>

Thought: The page loads an external script /static/check.js. That file likely contains the password check. I will extract and read the JavaScript source.
Action: {"tool_name": "javascript_source", "tool_input": {"url": "https://example.com/login", "base_url": "https://example.com"}}

Tool Observation: [JavaScriptSourceTool] Extracted JavaScript code:
[EXTERNAL SCRIPT #1: https://example.com/static/check.js]
function checkPassword(input) {
  const secret = 'super-secret-password';
  if (input === secret) {
    // show the flag
  }
}

Thought: The JavaScript compares the user input to the string 'super-secret-password'. That must be the correct password. I should report this as the answer using the final_answer tool.
Action: {"tool_name": "final_answer", "tool_input": "The correct password is 'super-secret-password', recovered from the client-side JavaScript check."}
"""
    )

    pb.examples.append(robots_example)
    pb.examples.append(js_example)

    # === Tool executor, memory, and agent ===
    executor = ToolExecutor(tool_registry)
    memory = WorkingMemory()

    agent = SimpleAgent(
        llm=llm,
        planner=planner,
        tool_executor=executor,
        memory=memory,
        max_steps=15,
    )

    # Optional: short, high-level role description (secondary to PromptBuilder role)
    agent.role_description = (
        "You are a PicoCTF-style web exploitation agent that uses tools to explore "
        "web challenges, reason about HTTP, HTML/JS, cookies, robots.txt, and SQL "
        "behavior, consults an internal CTF knowledge base when needed, and finally "
        "returns the discovered PicoCTF flag using the 'final_answer' tool."
    )

    return agent


# ---------------------------------------------------------------------------
# Main / CLI
# ---------------------------------------------------------------------------


async def main() -> None:
    """
    CLI entry point.

    - Parses command-line flags:
        --base-url
        --challenge ∈ {where-are-the-robots, insp3ct0r, dont-use-client-side, logon, SQLiLite}
        --task (optional)
    - OR, if no flags are provided, prompts for a free-form description like:
        "solve the ctf challenge at https://... it is a web challenge and the title is called XYZ"
      and automatically extracts base_url, challenge, and task.
    - Builds the FAIR agent (including RAG knowledge base).
    - Sends a single high-level instruction describing the challenge and strategy.
    - Prints the agent's final answer, and logs any picoCTF{...} it contains.
    """

    parser = argparse.ArgumentParser(
        description="PicoCTF web challenge agent using the FAIR agentic framework."
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help=(
            "Base URL for the picoCTF challenge instance "
            "(e.g., https://example.com or https://saturn.picoctf.net:12345)."
        ),
    )
    parser.add_argument(
        "--challenge",
        required=True,
        choices=[
            "where-are-the-robots",
            "insp3ct0r",
            "dont-use-client-side",
            "logon",
            "SQLiLite",
        ],
        help="Challenge name: one of {where-are-the-robots, insp3ct0r, dont-use-client-side, logon, SQLiLite}.",
    )
    parser.add_argument(
        "--task",
        required=False,
        default="Find and print the PicoCTF flag for this web challenge.",
        help="High-level task description for the agent.",
    )

    # ----------------------------------------------------------------------
    # Free-form description mode: if no CLI args, auto-derive arguments
    # ----------------------------------------------------------------------
    if len(sys.argv) == 1:
        print(
            "No command-line arguments detected.\n"
            "You can instead describe the web CTF challenge in a single line.\n"
            "Example:\n"
            "  solve the ctf challenge at https://saturn.picoctf.net:12345, "
            "it is a web challenge and the title is called SQLiLite\n"
        )
        description = input(
            "Describe the web CTF challenge (one line): "
        ).strip()

        # Extract base URL with a simple regex
        base_url_match = re.search(r"https?://\S+", description)
        if base_url_match:
            base_url = base_url_match.group(0).rstrip(".,)'\"")
        else:
            base_url = ""
            print(
                "[Note] Could not automatically find a URL in your description. "
                "The agent may fail if base_url is empty."
            )

        # Infer challenge name from the text (best effort)
        desc_lower = description.lower()
        challenge = None

        if "where are the robots" in desc_lower or "where-are-the-robots" in desc_lower:
            challenge = "where-are-the-robots"
        elif "insp3ct0r" in desc_lower:
            challenge = "insp3ct0r"
        elif (
            "dont-use-client-side" in desc_lower
            or "don't use client side" in desc_lower
            or "dont use client side" in desc_lower
        ):
            challenge = "dont-use-client-side"
        elif "logon" in desc_lower:
            challenge = "logon"
        elif (
            "sqlilite" in desc_lower
            or "sqli lite" in desc_lower
            or "sqli" in desc_lower
        ):
            challenge = "SQLiLite"
        else:
            challenge = "insp3ct0r"
            print(
                "[Note] Could not infer a specific challenge name from your description; "
                "defaulting to 'insp3ct0r'. If this is incorrect, rerun with explicit "
                "--challenge and --base-url."
            )

        # Use the full description as part of the task
        task = (
            description
            + " (Your goal is to understand the challenge behavior and find and print the PicoCTF flag.)"
        )

        # ✅ IMPORTANT FIX: do NOT include the script name in this list
        fake_argv = [
            "--base-url",
            base_url,
            "--challenge",
            challenge,
            "--task",
            task,
        ]
        args = parser.parse_args(fake_argv)
    else:
        # Normal CLI path: parse the actual command-line arguments
        args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logger.info(
        "Building FAIR agent with HTTP, HTML, regex, robots, cookie, form, JS, "
        "response-search, SQL-hint, and CTF RAG tools..."
    )
    agent = build_agent()
    logger.info("Agent built successfully.")

    # System-style + user-style initial message:
    # Emphasize recon, RAG usage, no brute force, and explicit flag printing.
    initial_message = (
        "SYSTEM: You are a PicoCTF-style web exploitation agent running in a FAIR ReAct loop.\n"
        "You must solve the given web challenge by reasoning carefully and using tools, "
        "not by brute forcing.\n\n"
        f"USER:\n"
        f"Challenge name: {args.challenge}\n"
        f"Base URL: {args.base_url}\n"
        f"Overall task: {args.task}\n\n"
        "Guidelines for this challenge:\n"
        "- Start with reconnaissance: fetch the main page at the base URL and inspect its HTML, links, and scripts.\n"
        "- As you explore, follow interesting links, inspect robots.txt, and check cookies when relevant.\n"
        "- Inspect client-side JavaScript when you suspect any client-side validation or password checks.\n"
        "- Use the 'ctf_knowledge_query' tool whenever you are uncertain which web exploitation technique to apply,\n"
        "  such as SQL injection, robots.txt enumeration, cookie abuse, client-side JS analysis, etc.\n"
        "- Avoid brute forcing credentials, passwords, or inputs. Instead, rely on logical reasoning, response analysis,\n"
        "  and the internal web-exploitation knowledge base.\n"
        "- At every stage, think step-by-step using the ReAct pattern: Thought → Action (tool call) → Observation.\n"
        "- Whenever you see a string that looks like a PicoCTF flag (picoCTF{...}), note it and verify its context.\n"
        "- When you are confident you have the correct flag, clearly print it in your final answer, in the form: picoCTF{...}.\n\n"
        "Now begin your investigation using these tools and reasoning steps."
    )

    print("\n=== Agent Input (System + User Prompt) ===")
    print(initial_message)
    print("=========================================\n")

    try:
        response = await agent.arun(initial_message)
    except Exception as exc:
        logger.exception("Error while running agent:")
        print(f"Agent encountered an error: {exc}")
        return

    # Log any potential flags in the final answer
    if isinstance(response, str):
        matches = re.findall(r"picoCTF\{.*?\}", response)
        for m in matches:
            print(f"[LOG] Potential flag seen in final answer: {m}")

    print("\n=== Agent Final Answer ===")
    print(response)
    print("================================\n")


if __name__ == "__main__":
    asyncio.run(main())