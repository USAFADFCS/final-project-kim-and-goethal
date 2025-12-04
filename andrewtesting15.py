#!/usr/bin/env python3
"""
pico_agent_solver.py

Agentic picoCTF Web Challenge Solver
====================================

This single-file Python script implements an *agentic* system that uses:

- An OpenAI LLM as the "brain" (via Chat Completions)
- A set of generic, reusable web/CTF tools (HTTP, HTML parsing, JS/CSS inspection, decoding, cookies, forms, SQLi probing)
- A Retrieval-Augmented Generation (RAG) subsystem over a local `kb/` knowledge base

to solve the following picoCTF web challenges:

- where are the robots
- insp3ct0r
- dont-use-client-side
- logon
- SQLiLite

The overall flow is:
- You specify which challenge and base URL to solve via CLI.
- The script builds a ToolCallingAgent with all tools + RAG.
- A ReAct-style loop lets the LLM decide when to call tools or stop.
- The agent explores the webapp, uses the tools and RAG, and then returns a final answer.
- The script extracts and prints any `picoCTF{...}` flag from the final answer.

----------------------------------------------------------------------
SETUP
----------------------------------------------------------------------

1. Install dependencies (in a virtualenv is recommended):

    pip install openai==0.28.0 requests beautifulsoup4 numpy

   (If you're using a newer `openai` library that uses the `OpenAI()` client,
    you'll need to adapt the API calls; this script currently uses the 0.x style.)

2. Set your OpenAI API key in the environment:

    export OPENAI_API_KEY="sk-..."

3. Prepare the `kb/` directory:

   Create a directory named `kb` in the same folder as this script and add
   any text-based files (e.g., `.txt`, `.md`) containing:
   - SQL injection tutorials
   - basic web exploitation notes
   - picoCTF web exploitation guide content
   etc.

   Example:
       mkdir kb
       echo "Basic SQL injection notes..." > kb/sql_notes.txt

   The script will automatically load, chunk, and embed all `.txt` and `.md`
   files in `kb/` at startup of the RAG subsystem.

----------------------------------------------------------------------
EXAMPLE CLI COMMANDS
----------------------------------------------------------------------

Each challenge requires `--challenge` and `--base-url`:

    python pico_agent_solver.py --challenge where_are_the_robots \
        --base-url http://saturn.picoctf.net:12345

    python pico_agent_solver.py --challenge insp3ct0r \
        --base-url http://saturn.picoctf.net:45678

    python pico_agent_solver.py --challenge dont_use_client_side \
        --base-url http://saturn.picoctf.net:23456

    python pico_agent_solver.py --challenge logon \
        --base-url http://saturn.picoctf.net:34567

    python pico_agent_solver.py --challenge sqlilite \
        --base-url http://saturn.picoctf.net:56789

Run `python pico_agent_solver.py --help` for full CLI help.

NOTE: This script is a research/educational project and may need small
adjustments to target specific picoCTF instances (e.g., different paths,
ports, or challenge variations).
"""

import os
import sys
import glob
import json
import argparse
from typing import List, Dict, Any, Optional, Tuple

import openai  # pip install openai==0.28.0
import requests  # pip install requests
from bs4 import BeautifulSoup  # pip install beautifulsoup4
from urllib.parse import urljoin, urlparse, unquote_plus
from pathlib import Path
import base64
import binascii
import re
import numpy as np


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Default chat model (change if desired/available).
DEFAULT_OPENAI_MODEL = "gpt-4.1-mini"

# Embedding model used by the RAG subsystem.
DEFAULT_EMBEDDING_MODEL = "text-embedding-3-small"


def configure_openai_from_env() -> None:
    """
    Configure the OpenAI client from the OPENAI_API_KEY environment variable.

    Raises:
        RuntimeError: If the OPENAI_API_KEY variable is not set.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY environment variable is not set. "
            "Please export your API key before running this script.\n"
            "Example:\n"
            '    export OPENAI_API_KEY="sk-..."'
        )
    openai.api_key = api_key


# ---------------------------------------------------------------------------
# LLM Client
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Simple wrapper around OpenAI Chat Completions API.

    This class does NOT know anything about tools, ReAct, or RAG.
    It just sends a list of messages to the OpenAI model and returns the text.
    """

    def __init__(self, model: str = DEFAULT_OPENAI_MODEL):
        """
        Initialize the LLM client.

        Args:
            model: Name of the OpenAI chat model to use.
        """
        self.model = model

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.0,
        max_tokens: int = 512,
    ) -> str:
        """
        Send a chat completion request to the OpenAI API.

        Args:
            messages: List of messages, each like
                      {"role": "user"/"system"/"assistant", "content": "..."}.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens for the response.

        Returns:
            Assistant message content as a string.

        Raises:
            RuntimeError: If the OpenAI API call fails for any reason.
        """
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
        except Exception as e:
            raise RuntimeError(f"OpenAI ChatCompletion error: {e!r}")
        return response["choices"][0]["message"]["content"]


# ---------------------------------------------------------------------------
# Tool infrastructure
# ---------------------------------------------------------------------------

class Tool:
    """
    Base class for all tools.

    Concrete tools must:
    - Provide a unique `name` (used by the agent / LLM).
    - Provide a human-readable `description`.
    - Implement `run(**kwargs)` which performs the tool's action and returns a dict.
    """

    name: str = "base_tool"
    description: str = "Base tool (should be overridden by subclasses)."

    def run(self, **kwargs) -> Dict[str, Any]:
        """
        Execute the tool with the given keyword arguments.

        Subclasses MUST override this method with actual logic.

        Args:
            **kwargs: Tool-specific keyword arguments.

        Returns:
            Dict with tool-specific results (must be JSON-serializable).
        """
        raise NotImplementedError("Tool subclasses must implement run().")


class ToolRegistry:
    """
    Registry for tools, mapping tool names to instances.

    The agent uses this to look up tools by name when the LLM requests
    a tool call.
    """

    def __init__(self) -> None:
        """Create an empty tool registry."""
        self._tools: Dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """
        Register a tool under its `name`.

        Args:
            tool: Tool instance to register.
        """
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[Tool]:
        """
        Retrieve a tool by name.

        Args:
            name: Name of the tool.

        Returns:
            Tool instance if found, else None.
        """
        return self._tools.get(name)

    def list_descriptions(self) -> List[str]:
        """
        Return a list of short descriptions for all registered tools.

        Useful for constructing the system prompt.
        """
        descs = []
        for t in self._tools.values():
            descs.append(f"- {t.name}: {t.description}")
        return descs


# ---------------------------------------------------------------------------
# Shared HTTP session helper
# ---------------------------------------------------------------------------

def create_shared_session(base_url: Optional[str] = None) -> requests.Session:
    """
    Create a shared requests.Session that will be used by HTTP-related tools.

    Cookies and HTTP settings will be shared across all tools that use this session.

    Args:
        base_url: Optional base URL for logging / configuration (not required).

    Returns:
        A configured requests.Session instance.
    """
    session = requests.Session()
    # You can set a custom User-Agent or other headers here if desired.
    return session


# ---------------------------------------------------------------------------
# Low-level web interaction tools
# ---------------------------------------------------------------------------

class HttpFetchTool(Tool):
    """
    Tool for performing basic HTTP requests (GET or HEAD).

    This is a generic web tool and not specific to any single CTF challenge.

    Expected inputs (kwargs to run):
        - url (str): Full URL to fetch. REQUIRED.
        - method (str): HTTP method, "GET" or "HEAD". Defaults to "GET".
        - params (dict | None): Optional query string parameters.
        - headers (dict | None): Optional request headers.
        - timeout (float | None): Optional timeout in seconds (default set in __init__).

    Output (dict):
        {
            "success": bool,
            "error": str | None,
            "status_code": int | None,
            "headers": dict | None,
            "text": str | None,
            "url": str | None,
        }
    """

    name = "http_fetch"
    description = (
        "Perform a simple HTTP GET or HEAD request to a given URL and return "
        "the status code, headers, and body text."
    )

    def __init__(self, session: Optional[requests.Session] = None, default_timeout: float = 10.0):
        """
        Initialize the HttpFetchTool.

        Args:
            session: Optional shared requests.Session. If None, a new one is created.
            default_timeout: Default timeout in seconds for HTTP requests.
        """
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    def run(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "error": None,
            "status_code": None,
            "headers": None,
            "text": None,
            "url": url,
        }

        method = method.upper()
        if method not in ("GET", "HEAD"):
            result["error"] = f"Unsupported method: {method}"
            return result

        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                timeout=timeout or self.default_timeout,
            )
            result["success"] = True
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["text"] = resp.text
            result["url"] = resp.url  # final URL (after redirects)
        except requests.RequestException as e:
            result["error"] = f"RequestException: {e!r}"

        return result


class HtmlLinkAndFormExtractorTool(Tool):
    """
    Tool for parsing HTML to extract links and forms.

    Expected inputs (kwargs to run):
        - html (str): The HTML content to parse. REQUIRED.
        - base_url (str | None): Optional base URL used to resolve relative URLs.

    Output (dict):
        {
            "links": [
                {
                    "href": str,
                    "text": str,
                },
                ...
            ],
            "forms": [
                {
                    "method": str,
                    "action": str,
                    "inputs": [
                        {"name": str | None, "type": str | None},
                        ...
                    ],
                },
                ...
            ],
        }
    """

    name = "html_link_and_form_extractor"
    description = (
        "Parse an HTML document and return all links and forms, including form methods, "
        "actions, and input field names."
    )

    def run(self, html: str, base_url: Optional[str] = None) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")

        links: List[Dict[str, Any]] = []
        for a in soup.find_all("a", href=True):
            href = a.get("href", "")
            text = (a.get_text() or "").strip()
            if base_url:
                href = urljoin(base_url, href)
            links.append({"href": href, "text": text})

        forms: List[Dict[str, Any]] = []
        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            if base_url:
                action = urljoin(base_url, action)

            inputs: List[Dict[str, Any]] = []
            for inp in form.find_all("input"):
                name = inp.get("name")
                field_type = inp.get("type")
                inputs.append({"name": name, "type": field_type})

            forms.append(
                {
                    "method": method,
                    "action": action,
                    "inputs": inputs,
                }
            )

        return {"links": links, "forms": forms}


class StaticResourceFinderTool(Tool):
    """
    Tool for extracting CSS and JS resource URLs from HTML.

    Expected inputs (kwargs to run):
        - html (str): The HTML content to parse. REQUIRED.
        - base_url (str | None): Optional base URL used to resolve relative URLs.

    Output (dict):
        {
            "css": [ "https://example.com/style.css", ... ],
            "js":  [ "https://example.com/script.js", ... ],
        }
    """

    name = "static_resource_finder"
    description = (
        "Given an HTML document and an optional base URL, extract all referenced CSS and "
        "JavaScript file URLs."
    )

    def run(self, html: str, base_url: Optional[str] = None) -> Dict[str, Any]:
        soup = BeautifulSoup(html, "html.parser")

        css_urls: List[str] = []
        js_urls: List[str] = []

        for link in soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
            href = link.get("href")
            if not href:
                continue
            if base_url:
                href = urljoin(base_url, href)
            css_urls.append(href)

        for script in soup.find_all("script", src=True):
            src = script.get("src")
            if not src:
                continue
            if base_url:
                src = urljoin(base_url, src)
            js_urls.append(src)

        return {"css": css_urls, "js": js_urls}


# ---------------------------------------------------------------------------
# Specialized client-side & cookie tools
# ---------------------------------------------------------------------------

class StaticFileFetchTool(Tool):
    """
    Tool for fetching static resources such as CSS or JS files via HTTP GET.

    Expected inputs (kwargs to run):
        - url (str): Full URL to the static resource. REQUIRED.
        - headers (dict | None): Optional request headers.
        - timeout (float | None): Optional timeout in seconds.

    Output (dict):
        {
            "success": bool,
            "error": str | None,
            "status_code": int | None,
            "headers": dict | None,
            "text": str | None,
            "url": str | None,
        }
    """

    name = "static_file_fetch"
    description = (
        "Fetch a static file (e.g., CSS, JS) via HTTP GET and return its content plus metadata."
    )

    def __init__(self, session: Optional[requests.Session] = None, default_timeout: float = 10.0):
        """
        Initialize the StaticFileFetchTool.

        Args:
            session: Optional shared requests.Session. If None, a new one is created.
            default_timeout: Default timeout in seconds for HTTP requests.
        """
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    def run(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "success": False,
            "error": None,
            "status_code": None,
            "headers": None,
            "text": None,
            "url": url,
        }
        try:
            resp = self.session.get(
                url=url,
                headers=headers,
                timeout=timeout or self.default_timeout,
            )
            result["success"] = True
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["text"] = resp.text
            result["url"] = resp.url
        except requests.RequestException as e:
            result["error"] = f"RequestException: {e!r}"

        return result


class JsAndCssInspectorTool(Tool):
    """
    Tool for inspecting JS or CSS content to find potentially interesting data.

    Heuristics:
        - Summarizes size, number of lines, and a preview snippet.
        - Extracts inline comments (// and /* ... */).
        - Extracts suspicious-looking strings (base64-like, long hex blobs, long quoted strings).

    Expected inputs (kwargs to run):
        - content (str): The raw JS/CSS text. REQUIRED.
        - content_type (str): Either "js" or "css" (used only for labeling).

    Output (dict):
        {
            "summary": {...},
            "comments": [str, ...],
            "suspicious_strings": [str, ...],
        }
    """

    name = "js_css_inspector"
    description = (
        "Inspect JavaScript or CSS content and return a brief summary, inline comments, "
        "and suspicious-looking strings (e.g., long constants, base64/hex-like values)."
    )

    BASE64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){10,}")  # 20+ hex chars in pairs

    def run(self, content: str, content_type: str = "js") -> Dict[str, Any]:
        lines = content.splitlines()
        num_lines = len(lines)
        approx_length = len(content)
        preview = content[:300]

        # Extract comments
        comments: List[str] = []
        for m in re.finditer(r"/\*.*?\*/", content, re.DOTALL):
            comments.append(m.group(0))

        if content_type.lower() == "js":
            for m in re.finditer(r"//.*?$", content, re.MULTILINE):
                comments.append(m.group(0))

        # Suspicious strings
        suspicious: List[str] = []
        for m in self.BASE64_RE.finditer(content):
            suspicious.append(m.group(0))
        for m in self.HEX_RE.finditer(content):
            suspicious.append(m.group(0))
        for m in re.finditer(r"(['\"])(.{20,}?)\1", content, re.DOTALL):
            suspicious.append(m.group(2))

        seen = set()
        uniq_suspicious = []
        for s in suspicious:
            if s not in seen:
                seen.add(s)
                uniq_suspicious.append(s)

        summary = {
            "content_type": content_type.lower(),
            "num_lines": num_lines,
            "approx_length": approx_length,
            "preview": preview,
        }

        return {
            "summary": summary,
            "comments": comments,
            "suspicious_strings": uniq_suspicious,
        }


class DecoderTool(Tool):
    """
    Tool for decoding encoded strings.

    Supported encodings:
        - "base64": base64-encoded strings
        - "hex": hex-encoded strings
        - "url": URL-encoded (percent-encoded) strings

    Expected inputs (kwargs to run):
        - encoding (str): One of "base64", "hex", "url". REQUIRED.
        - value (str): The encoded value. REQUIRED.

    Output (dict):
        {
            "success": bool,
            "encoding": str,
            "decoded": str | None,
            "error": str | None,
        }
    """

    name = "decoder"
    description = (
        "Decode strings in base64, hex, or URL-encoded format. "
        "Useful for uncovering hidden values in web challenges."
    )

    def run(self, encoding: str, value: str) -> Dict[str, Any]:
        encoding = encoding.lower().strip()
        result: Dict[str, Any] = {
            "success": False,
            "encoding": encoding,
            "decoded": None,
            "error": None,
        }

        try:
            if encoding == "base64":
                cleaned = "".join(value.split())
                missing = len(cleaned) % 4
                if missing:
                    cleaned += "=" * (4 - missing)
                decoded_bytes = base64.b64decode(cleaned, validate=False)
                result["decoded"] = decoded_bytes.decode("utf-8", errors="replace")
                result["success"] = True

            elif encoding == "hex":
                cleaned = value.strip().replace(" ", "")
                decoded_bytes = binascii.unhexlify(cleaned)
                result["decoded"] = decoded_bytes.decode("utf-8", errors="replace")
                result["success"] = True

            elif encoding == "url":
                result["decoded"] = unquote_plus(value)
                result["success"] = True

            else:
                result["error"] = f"Unsupported encoding: {encoding}"
        except (binascii.Error, ValueError, UnicodeDecodeError) as e:
            result["error"] = f"Decoding error: {e!r}"

        return result


class CookieManagerTool(Tool):
    """
    Tool for inspecting and manipulating cookies via a shared requests.Session.

    Operations:
        - "list": List cookies for a given base URL / domain.
        - "set":  Set a cookie for a given base URL / domain.
        - "request": Make a GET/POST request with current cookies.

    Expected inputs (kwargs to run):

        Shared:
            - operation (str): "list" | "set" | "request". REQUIRED.
            - base_url (str): Base URL of the target application. REQUIRED.

        For "list":
            - base_url

        For "set":
            - base_url
            - key (str)
            - value (str)

        For "request":
            - base_url
            - path (str): Full URL or path relative to base_url.
            - method (str): "GET" or "POST". Defaults to "GET".
            - params (dict | None)
            - data (dict | None)
            - headers (dict | None)
            - timeout (float | None)

    Outputs:
        For "list":
            {
                "success": bool,
                "error": str | None,
                "cookies": [...],
            }

        For "set":
            {
                "success": bool,
                "error": str | None,
                "cookies": [...],
            }

        For "request":
            {
                "success": bool,
                "error": str | None,
                "status_code": int | None,
                "headers": dict | None,
                "text": str | None,
                "url": str | None,
                "cookies": [...],
            }
    """

    name = "cookie_manager"
    description = (
        "Inspect and manipulate HTTP cookies using a shared session: list cookies, "
        "set cookie values, and make requests with the current cookie jar."
    )

    def __init__(self, session: Optional[requests.Session] = None, default_timeout: float = 10.0):
        """
        Initialize the CookieManagerTool.

        Args:
            session: Optional shared requests.Session. If None, a new one is created.
            default_timeout: Default timeout in seconds for HTTP requests.
        """
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    @staticmethod
    def _extract_domain(base_url: str) -> str:
        """Extract the hostname/domain from a base URL."""
        parsed = urlparse(base_url)
        return parsed.hostname or ""

    def _list_cookies_for_domain(self, domain: str) -> List[Dict[str, Any]]:
        """Return a list of cookies matching a given domain."""
        cookies_info: List[Dict[str, Any]] = []
        for cookie in self.session.cookies:
            if domain and cookie.domain and domain not in cookie.domain:
                continue
            cookies_info.append(
                {
                    "name": cookie.name,
                    "value": cookie.value,
                    "domain": cookie.domain,
                    "path": cookie.path,
                }
            )
        return cookies_info

    def run(self, operation: str, base_url: str, **kwargs) -> Dict[str, Any]:
        op = operation.lower().strip()
        domain = self._extract_domain(base_url)

        if op == "list":
            cookies = self._list_cookies_for_domain(domain)
            return {
                "success": True,
                "error": None,
                "cookies": cookies,
            }

        elif op == "set":
            key = kwargs.get("key")
            value = kwargs.get("value")
            if key is None or value is None:
                return {
                    "success": False,
                    "error": "Missing 'key' or 'value' for set operation.",
                    "cookies": [],
                }
            self.session.cookies.set(name=key, value=value, domain=domain, path="/")
            cookies = self._list_cookies_for_domain(domain)
            return {
                "success": True,
                "error": None,
                "cookies": cookies,
            }

        elif op == "request":
            path = kwargs.get("path", "/")
            method = kwargs.get("method", "GET").upper()
            params = kwargs.get("params")
            data = kwargs.get("data")
            headers = kwargs.get("headers")
            timeout = kwargs.get("timeout") or self.default_timeout

            if path.startswith("http://") or path.startswith("https://"):
                url = path
            else:
                url = urljoin(base_url, path)

            result: Dict[str, Any] = {
                "success": False,
                "error": None,
                "status_code": None,
                "headers": None,
                "text": None,
                "url": url,
                "cookies": [],
            }

            if method not in ("GET", "POST"):
                result["error"] = f"Unsupported method: {method}"
                return result

            try:
                resp = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    data=data,
                    headers=headers,
                    timeout=timeout,
                )
                result["success"] = True
                result["status_code"] = resp.status_code
                result["headers"] = dict(resp.headers)
                result["text"] = resp.text
                result["url"] = resp.url
                result["cookies"] = self._list_cookies_for_domain(domain)
            except requests.RequestException as e:
                result["error"] = f"RequestException: {e!r}"

            return result

        else:
            return {
                "success": False,
                "error": f"Unsupported operation: {operation}",
            }


# ---------------------------------------------------------------------------
# Form & SQL injection tools
# ---------------------------------------------------------------------------

class FormSubmitterTool(Tool):
    """
    Tool for submitting HTML forms using a shared requests.Session.

    This is a generic tool and not tied to one specific challenge.

    Expected inputs (kwargs to run):
        - base_url (str): Base URL of the target application. REQUIRED.
        - method (str): HTTP method, e.g., "GET" or "POST". REQUIRED.
        - action (str): Form action attribute (absolute or relative URL). REQUIRED.
        - fields (dict): Mapping of field name to value for submission. REQUIRED.
        - headers (dict | None): Optional headers.
        - timeout (float | None): Optional timeout in seconds.

    Output (dict):
        {
            "success": bool,
            "error": str | None,
            "status_code": int | None,
            "headers": dict | None,
            "text": str | None,
            "url": str | None,
        }
    """

    name = "form_submitter"
    description = (
        "Submit HTML forms (GET or POST) to a given action URL using provided field values, "
        "preserving cookies via a shared session."
    )

    def __init__(self, session: Optional[requests.Session] = None, default_timeout: float = 10.0):
        """
        Initialize the FormSubmitterTool.

        Args:
            session: Optional shared requests.Session. If None, a new one is created.
            default_timeout: Default timeout in seconds for HTTP submissions.
        """
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    def run(
        self,
        base_url: str,
        method: str,
        action: str,
        fields: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        method = method.upper()
        result: Dict[str, Any] = {
            "success": False,
            "error": None,
            "status_code": None,
            "headers": None,
            "text": None,
            "url": None,
        }

        if method not in ("GET", "POST"):
            result["error"] = f"Unsupported form method: {method}"
            return result

        if action.startswith("http://") or action.startswith("https://"):
            url = action
        else:
            url = urljoin(base_url, action)

        try:
            if method == "GET":
                resp = self.session.get(
                    url=url,
                    params=fields,
                    headers=headers,
                    timeout=timeout or self.default_timeout,
                )
            else:
                resp = self.session.post(
                    url=url,
                    data=fields,
                    headers=headers,
                    timeout=timeout or self.default_timeout,
                )

            result["success"] = True
            result["status_code"] = resp.status_code
            result["headers"] = dict(resp.headers)
            result["text"] = resp.text
            result["url"] = resp.url
        except requests.RequestException as e:
            result["error"] = f"RequestException: {e!r}"

        return result


class SqlInjectionProbeTool(Tool):
    """
    Tool for systematically testing potential SQL injection payloads against a form.

    This is generic and can be used on any login/search form.

    Expected inputs (kwargs to run):

        - base_url (str): Base URL of the target application. REQUIRED.
        - method (str): HTTP method, e.g., "POST". REQUIRED.
        - action (str): Form action URL (absolute or relative). REQUIRED.
        - target_field (str): Name of the field to inject into (e.g., "password"). REQUIRED.
        - static_fields (dict): Other field names/values that remain constant (e.g., username). REQUIRED.
        - payloads (list[str] | None): Optional list of payloads; uses default list if None.
        - headers (dict | None): Optional headers.
        - timeout (float | None): Optional timeout in seconds.
        - success_keywords (list[str] | None): Keywords that hint at success.
        - error_keywords (list[str] | None): Keywords that hint at errors.

    Output (dict):
        {
            "success": bool,
            "error": str | None,
            "baseline": {"status_code": int | None, "length": int | None},
            "results": [
                {
                    "payload": str,
                    "status_code": int | None,
                    "length": int,
                    "length_diff": int,
                    "is_length_anomaly": bool,
                    "is_status_anomaly": bool,
                    "success_keywords_found": [str, ...],
                    "error_keywords_found": [str, ...],
                    "url": str | None,
                },
                ...
            ],
        }
    """

    name = "sqli_probe"
    description = (
        "Test a form for SQL injection by submitting a series of payloads to a target field "
        "and summarizing how the responses differ."
    )

    DEFAULT_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "' OR 1=1/*",
    ]

    def __init__(self, session: Optional[requests.Session] = None, default_timeout: float = 10.0):
        """
        Initialize the SqlInjectionProbeTool.

        Args:
            session: Optional shared requests.Session. If None, a new one is created.
            default_timeout: Default timeout in seconds for HTTP submissions.
        """
        self.session = session or requests.Session()
        self.default_timeout = default_timeout

    def run(
        self,
        base_url: str,
        method: str,
        action: str,
        target_field: str,
        static_fields: Dict[str, Any],
        payloads: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        success_keywords: Optional[List[str]] = None,
        error_keywords: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        method = method.upper()
        if method not in ("GET", "POST"):
            return {
                "success": False,
                "error": f"Unsupported form method: {method}",
                "baseline": {"status_code": None, "length": None},
                "results": [],
            }

        if action.startswith("http://") or action.startswith("https://"):
            url = action
        else:
            url = urljoin(base_url, action)

        if payloads is None:
            payloads = list(self.DEFAULT_PAYLOADS)

        if success_keywords is None:
            success_keywords = ["welcome", "success", "logged in", "flag", "picoctf"]
        if error_keywords is None:
            error_keywords = ["error", "sql", "syntax", "exception"]

        results: List[Dict[str, Any]] = []

        baseline_status: Optional[int] = None
        baseline_length: Optional[int] = None

        def submit_payload(payload: str) -> Dict[str, Any]:
            fields = dict(static_fields)
            fields[target_field] = payload
            try:
                if method == "GET":
                    resp = self.session.get(
                        url=url,
                        params=fields,
                        headers=headers,
                        timeout=timeout or self.default_timeout,
                    )
                else:
                    resp = self.session.post(
                        url=url,
                        data=fields,
                        headers=headers,
                        timeout=timeout or self.default_timeout,
                    )
                text = resp.text or ""
                length = len(text)
                status_code = resp.status_code
                resp_url = resp.url

                lower = text.lower()
                succ_found = [kw for kw in success_keywords if kw.lower() in lower]
                err_found = [kw for kw in error_keywords if kw.lower() in lower]

                return {
                    "payload": payload,
                    "status_code": status_code,
                    "length": length,
                    "url": resp_url,
                    "success_keywords_found": succ_found,
                    "error_keywords_found": err_found,
                }
            except requests.RequestException as e:
                return {
                    "payload": payload,
                    "status_code": None,
                    "length": 0,
                    "url": url,
                    "success_keywords_found": [],
                    "error_keywords_found": [f"RequestException: {e!r}"],
                }

        for idx, payload in enumerate(payloads):
            result = submit_payload(payload)

            if idx == 0:
                baseline_status = result.get("status_code")
                baseline_length = result.get("length")

            length = result.get("length", 0)
            status_code = result.get("status_code")

            if baseline_length is not None:
                length_diff = length - baseline_length
                threshold = max(int(0.1 * baseline_length), 50)
                is_length_anomaly = abs(length_diff) >= threshold
            else:
                length_diff = 0
                is_length_anomaly = False

            if baseline_status is not None and status_code is not None:
                is_status_anomaly = status_code != baseline_status
            else:
                is_status_anomaly = False

            result["length_diff"] = length_diff
            result["is_length_anomaly"] = is_length_anomaly
            result["is_status_anomaly"] = is_status_anomaly

            results.append(result)

        return {
            "success": True,
            "error": None,
            "baseline": {
                "status_code": baseline_status,
                "length": baseline_length,
            },
            "results": results,
        }


# ---------------------------------------------------------------------------
# RAG subsystem
# ---------------------------------------------------------------------------

class RAGKnowledgeBase:
    """
    Retrieval-Augmented Generation (RAG) knowledge base.

    This implementation:
    - Loads text-like files from a `kb/` directory (.txt, .md).
    - Splits them into overlapping chunks.
    - Embeds chunks using OpenAI embeddings (DEFAULT_EMBEDDING_MODEL).
    - Stores embeddings in an in-memory NumPy matrix.
    - Supports cosine-similarity search over the chunks.

    Useful for:
    - SQL injection tutorials
    - Web exploitation notes
    - picoCTF web exploitation guides
    """

    def __init__(
        self,
        kb_path: str = "kb",
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
        chunk_size: int = 800,
        chunk_overlap: int = 200,
    ) -> None:
        """
        Initialize the RAGKnowledgeBase.

        Args:
            kb_path: Path to the directory containing knowledge base files.
            embedding_model: OpenAI embedding model name.
            chunk_size: Target size of text chunks (characters).
            chunk_overlap: Overlap between consecutive chunks (characters).
        """
        self.kb_path = Path(kb_path)
        self.embedding_model = embedding_model
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

        self.chunks: List[Dict[str, Any]] = []
        self.embeddings: Optional[np.ndarray] = None

        self._build_index()

    def _iter_kb_files(self) -> List[Path]:
        """Return a list of text-like files in the kb directory (.txt, .md)."""
        if not self.kb_path.is_dir():
            return []
        exts = (".txt", ".md")
        files: List[Path] = []
        for ext in exts:
            files.extend(self.kb_path.glob(f"*{ext}"))
        return files

    @staticmethod
    def _read_text_file(path: Path) -> str:
        """Read a text file as UTF-8, ignoring errors."""
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _chunk_text(self, text: str, source: str) -> List[Dict[str, Any]]:
        """
        Split a long text into overlapping chunks.

        Args:
            text: Full document text.
            source: Source document name.

        Returns:
            List of chunk dicts with "text", "source", "chunk_id".
        """
        chunks: List[Dict[str, Any]] = []
        if not text:
            return chunks

        start = 0
        chunk_index = 0
        length = len(text)

        while start < length:
            end = min(start + self.chunk_size, length)
            chunk_text = text[start:end]
            chunk_id = f"{source}::chunk_{chunk_index}"
            chunks.append(
                {
                    "text": chunk_text,
                    "source": source,
                    "chunk_id": chunk_id,
                }
            )
            chunk_index += 1
            if end == length:
                break
            start = max(0, end - self.chunk_overlap)

        return chunks

    def _embed_batch(self, texts: List[str]) -> np.ndarray:
        """
        Embed a batch of texts using OpenAI embeddings.

        Args:
            texts: List of text strings.

        Returns:
            NumPy array of shape (len(texts), D).

        Raises:
            RuntimeError: If the OpenAI Embedding API call fails.
        """
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)

        try:
            resp = openai.Embedding.create(
                model=self.embedding_model,
                input=texts,
            )
        except Exception as e:
            raise RuntimeError(f"OpenAI Embedding error: {e!r}")

        vectors = [item["embedding"] for item in resp["data"]]
        return np.array(vectors, dtype=np.float32)

    def _build_index(self) -> None:
        """
        Build the vector index from documents in `kb_path`.

        Notes:
            - If no kb/ directory or no supported files exist, the KB remains empty.
            - If embedding calls fail, an exception will be raised.
        """
        files = self._iter_kb_files()
        if not files:
            print("[RAG] No kb/ directory or no .txt/.md files found. RAG KB will be empty.")
            self.chunks = []
            self.embeddings = None
            return

        all_chunks: List[Dict[str, Any]] = []
        for path in files:
            text = self._read_text_file(path)
            if not text.strip():
                continue
            source_name = path.name
            file_chunks = self._chunk_text(text, source=source_name)
            all_chunks.extend(file_chunks)

        if not all_chunks:
            print("[RAG] KB files are empty. RAG KB will be empty.")
            self.chunks = []
            self.embeddings = None
            return

        print(f"[RAG] Building index from {len(all_chunks)} chunks across {len(files)} file(s)...")
        batch_size = 64
        all_vectors: List[np.ndarray] = []
        for i in range(0, len(all_chunks), batch_size):
            batch_texts = [c["text"] for c in all_chunks[i : i + batch_size]]
            batch_emb = self._embed_batch(batch_texts)
            all_vectors.append(batch_emb)

        self.chunks = all_chunks
        self.embeddings = np.vstack(all_vectors) if all_vectors else None
        print(f"[RAG] Index built: {len(self.chunks)} chunks embedded.")

    def is_ready(self) -> bool:
        """Return True if the KB has any embeddings loaded."""
        return self.embeddings is not None and len(self.chunks) > 0

    def query(self, text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Query the knowledge base using cosine similarity.

        Args:
            text: User or agent query.
            top_k: Number of most relevant chunks to return.

        Returns:
            List of dicts: {"text", "source", "score", "chunk_id"}.
        """
        if not self.is_ready():
            return []

        q_emb = self._embed_batch([text])
        if q_emb.size == 0:
            return []
        q = q_emb[0]

        doc_mat = self.embeddings
        if doc_mat is None or doc_mat.size == 0:
            return []

        doc_norms = np.linalg.norm(doc_mat, axis=1) + 1e-8
        q_norm = np.linalg.norm(q) + 1e-8
        sims = (doc_mat @ q) / (doc_norms * q_norm)

        k = min(top_k, len(self.chunks))
        top_idx = np.argsort(-sims)[:k]

        results: List[Dict[str, Any]] = []
        for idx in top_idx:
            chunk = self.chunks[idx]
            score = float(sims[idx])
            results.append(
                {
                    "text": chunk["text"],
                    "source": chunk["source"],
                    "chunk_id": chunk["chunk_id"],
                    "score": score,
                }
            )
        return results


_GLOBAL_RAG_KB: Optional[RAGKnowledgeBase] = None


def get_rag_kb(kb_path: str = "kb") -> RAGKnowledgeBase:
    """
    Lazy singleton initializer for the RAG knowledge base.

    Ensures KB is built only once per process.

    Args:
        kb_path: Path to the KB directory.

    Returns:
        A RAGKnowledgeBase instance.
    """
    global _GLOBAL_RAG_KB
    if _GLOBAL_RAG_KB is None:
        _GLOBAL_RAG_KB = RAGKnowledgeBase(kb_path=kb_path)
    return _GLOBAL_RAG_KB


class RAGQueryTool(Tool):
    """
    Tool for querying the RAG knowledge base.

    Expected inputs (kwargs to run):
        - query (str): Natural-language question or description. REQUIRED.
        - top_k (int | None): Number of chunks to retrieve (default 5).

    Output (dict):
        {
            "success": bool,
            "error": str | None,
            "query": str,
            "results": [
                {"text": str, "source": str, "chunk_id": str, "score": float},
                ...
            ],
        }
    """

    name = "rag_query"
    description = (
        "Query the knowledge base (SQLi tutorials, web CTF notes, picoCTF web guide, etc.) "
        "and retrieve the most relevant text snippets."
    )

    def __init__(self, kb: RAGKnowledgeBase):
        """
        Initialize the RAGQueryTool.

        Args:
            kb: A RAGKnowledgeBase instance.
        """
        self.kb = kb

    def run(self, query: str, top_k: int = 5) -> Dict[str, Any]:
        if not query or not isinstance(query, str):
            return {
                "success": False,
                "error": "Query must be a non-empty string.",
                "query": query,
                "results": [],
            }

        if not self.kb.is_ready():
            return {
                "success": False,
                "error": "Knowledge base is empty or not initialized (no usable files in kb/).",
                "query": query,
                "results": [],
            }

        results = self.kb.query(query, top_k=top_k)
        return {
            "success": True,
            "error": None,
            "query": query,
            "results": results,
        }


# ---------------------------------------------------------------------------
# Agent / ReAct loop
# ---------------------------------------------------------------------------

class ToolCallingAgent:
    """
    ReAct-style agent that uses an LLM plus a collection of tools.

    Responsibilities:
        - Maintain a conversation history (system + user + assistant + observations).
        - Use a system prompt that lists tools and explains a strict JSON protocol.
        - At each step:
            1. Ask the LLM what to do next.
            2. Parse JSON as either a tool call or a final answer.
            3. If a tool call, run the tool and append an observation.
            4. Repeat until final_answer or max_steps is reached.

    The agent prints logs for each step and tool call for debugging.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tool_registry: ToolRegistry,
        rag_kb: Optional[RAGKnowledgeBase] = None,
        max_steps: int = 10,
    ) -> None:
        """
        Initialize the ToolCallingAgent.

        Args:
            llm_client: LLMClient instance for Chat Completions.
            tool_registry: Registry of available tools.
            rag_kb: Optional RAGKnowledgeBase (for reference only).
            max_steps: Maximum number of tool-calling steps.
        """
        self.llm_client = llm_client
        self.tool_registry = tool_registry
        self.rag_kb = rag_kb
        self.max_steps = max_steps
        self.messages: List[Dict[str, str]] = []

    def build_system_prompt(self) -> str:
        """
        Build a system prompt that explains the tools and the strict JSON protocol.

        Tool names and descriptions are pulled from the registry.
        """
        tool_descriptions = "\n".join(self.tool_registry.list_descriptions())
        return f"""
You are an expert picoCTF web exploitation agent.

You can ONLY interact with the outside world by calling tools. You have access to the following tools:

{tool_descriptions}

Each tool is identified by its `name` (the word after the dash above). You must call tools using a strict JSON-only protocol.

TOOL-CALLING PROTOCOL (very important):
- When you want to call a tool, you MUST respond with a single JSON object, and NOTHING else.
- The JSON must have this form:
  {{
    "tool": "<tool_name>",
    "args": {{ ... }}
  }}
- <tool_name> MUST be exactly one of the tool names listed above (e.g., "http_fetch", "static_file_fetch", "decoder", "rag_query").
- The "args" object must contain all the parameters required by that tool, with JSON-serializable values only
  (strings, numbers, booleans, lists, objects). Do NOT include comments or trailing commas.

FINAL ANSWER PROTOCOL:
- When you have fully solved the challenge and are ready to provide the final result (e.g., picoCTF flag and explanation),
  you MUST respond with a JSON object of the form:
  {{
    "final_answer": "<your final answer here>"
  }}

RULES:
- Never mix "tool" and "final_answer" in the same JSON object.
- Never output plain text or Markdown. Only output a single JSON object for each response.
- Use tools iteratively in a ReAct style: think about what information you need, call tools to get observations,
  then reason again, and so on, until you can confidently return a final answer.
- Flags typically look like picoCTF{{...}}. Explicitly search for that format when you believe you've found the flag.
""".strip()

    def initialize_conversation(self, goal_prompt: str) -> None:
        """
        Initialize the conversation with a system prompt and a user goal.

        Args:
            goal_prompt: Challenge-specific goal description for the agent.
        """
        system_prompt = self.build_system_prompt()
        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": goal_prompt},
        ]

    @staticmethod
    def _parse_json_control(content: str) -> Tuple[str, Dict[str, Any]]:
        """
        Parse the LLM's response content as JSON and classify it.

        Returns:
            (kind, payload) where:
                - kind == "final": payload={"final_answer": "..."}
                - kind == "tool":  payload={"tool": "<name>", "args": {...}}
                - kind == "error": payload={"error": "<error message>"}
        """
        try:
            obj = json.loads(content)
        except json.JSONDecodeError as e:
            return "error", {"error": f"Response was not valid JSON: {e}"}

        if isinstance(obj, dict) and "final_answer" in obj:
            return "final", {"final_answer": obj["final_answer"]}

        if isinstance(obj, dict) and "tool" in obj:
            tool_name = obj.get("tool")
            args = obj.get("args", {})
            if not isinstance(args, dict):
                return "error", {"error": "The 'args' field must be a JSON object."}
            return "tool", {"tool": tool_name, "args": args}

        return "error", {"error": "JSON must contain either 'final_answer' or 'tool'."}

    def run(self) -> str:
        """
        Run the ReAct-style loop until a final answer is produced or max_steps is reached.

        Returns:
            The final answer string (if found), or a fallback string if the loop exits
            without a valid final_answer.

        Raises:
            RuntimeError: If the conversation has not been initialized.
        """
        if not self.messages:
            raise RuntimeError("Agent conversation not initialized. Call initialize_conversation() first.")

        last_response_text = ""

        for step in range(self.max_steps):
            print(f"[AGENT] Step {step+1}/{self.max_steps} - Requesting next action from LLM...")
            try:
                assistant_content = self.llm_client.chat(self.messages, temperature=0.0, max_tokens=800)
            except RuntimeError as e:
                print(f"[AGENT] ERROR: {e}")
                return f"LLM call failed: {e}"

            last_response_text = assistant_content
            print(f"[AGENT] Raw LLM response:\n{assistant_content}\n")
            self.messages.append({"role": "assistant", "content": assistant_content})

            kind, payload = self._parse_json_control(assistant_content)

            if kind == "final":
                print("[AGENT] Received final_answer from LLM.")
                return str(payload.get("final_answer", ""))

            if kind == "error":
                err = payload["error"]
                print(f"[AGENT] Protocol error parsing LLM response: {err}")
                self.messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your last response did not follow the required JSON protocol.\n"
                            f"Error: {err}\n\n"
                            "Remember: you must respond with either:\n"
                            '  {\"tool\": \"<tool_name>\", \"args\": { ... }}\n'
                            'or\n'
                            '  {\"final_answer\": \"<text>\"}\n'
                            "Try again, strictly following this format."
                        ),
                    }
                )
                continue

            if kind == "tool":
                tool_name = payload["tool"]
                args = payload["args"]

                print(f"[AGENT] LLM requested tool call: {tool_name}")
                print(f"[AGENT] Tool arguments (truncated): {json.dumps(args)[:300]}")

                tool = self.tool_registry.get(tool_name)
                if tool is None:
                    print(f"[AGENT] ERROR: Unknown tool '{tool_name}'.")
                    self.messages.append(
                        {
                            "role": "user",
                            "content": (
                                f"The tool name '{tool_name}' does not exist. "
                                "Check the tool list in the system prompt and choose a valid tool.\n"
                                "Try again with a correct JSON tool call."
                            ),
                        }
                    )
                    continue

                try:
                    result = tool.run(**args)
                except Exception as e:
                    print(f"[AGENT] Exception while running tool '{tool_name}': {e!r}")
                    result = {
                        "success": False,
                        "error": f"Exception while running tool '{tool_name}': {e!r}",
                    }

                obs_json = json.dumps(result, indent=2)
                print(f"[AGENT] Observation from tool '{tool_name}' (key fields):")
                # Print a short summary
                if isinstance(result, dict):
                    print(f"  success: {result.get('success')}, error: {result.get('error')}")
                    if "status_code" in result or "length" in result:
                        print(
                            "  status_code:",
                            result.get("status_code"),
                            "| length:",
                            len(result.get("text", "")) if isinstance(result.get("text"), str) else "N/A",
                        )
                print(f"[AGENT] Full observation (truncated):\n{obs_json[:1000]}\n")

                self.messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"Observation from tool '{tool_name}':\n"
                            f"{obs_json}\n\n"
                            "Given this observation, either call another tool or return a "
                            'final answer using {"final_answer": "..."}.\n'
                        ),
                    }
                )
                continue

        print("[AGENT] Reached max_steps without a valid final_answer.")
        return (
            "Agent reached max_steps without producing a valid final_answer. "
            f"Last model response was:\n{last_response_text}"
        )


def create_default_agent(base_url: str) -> ToolCallingAgent:
    """
    Factory function to construct a ToolCallingAgent with default tools and RAG.

    Steps:
        - Creates an LLMClient.
        - Creates a ToolRegistry and registers all core tools.
        - Initializes a shared requests.Session for HTTP-related tools.
        - Initializes a RAGKnowledgeBase (singleton) and RAGQueryTool.
        - Returns a fully wired ToolCallingAgent.

    Args:
        base_url: Base URL of the CTF challenge instance.

    Returns:
        Configured ToolCallingAgent.
    """
    llm_client = LLMClient()

    session = create_shared_session(base_url=base_url)
    tool_registry = ToolRegistry()

    # Core web tools
    http_fetch_tool = HttpFetchTool(session=session)
    html_extractor_tool = HtmlLinkAndFormExtractorTool()
    static_res_finder_tool = StaticResourceFinderTool()
    static_file_fetch_tool = StaticFileFetchTool(session=session)
    js_css_inspector_tool = JsAndCssInspectorTool()
    decoder_tool = DecoderTool()
    cookie_manager_tool = CookieManagerTool(session=session)
    form_submitter_tool = FormSubmitterTool(session=session)
    sqli_probe_tool = SqlInjectionProbeTool(session=session)

    # RAG KB + query tool
    rag_kb = get_rag_kb(kb_path="kb")
    rag_query_tool = RAGQueryTool(kb=rag_kb)

    # Register tools
    tool_registry.register(http_fetch_tool)
    tool_registry.register(html_extractor_tool)
    tool_registry.register(static_res_finder_tool)
    tool_registry.register(static_file_fetch_tool)
    tool_registry.register(js_css_inspector_tool)
    tool_registry.register(decoder_tool)
    tool_registry.register(cookie_manager_tool)
    tool_registry.register(form_submitter_tool)
    tool_registry.register(sqli_probe_tool)
    tool_registry.register(rag_query_tool)

    agent = ToolCallingAgent(
        llm_client=llm_client,
        tool_registry=tool_registry,
        rag_kb=rag_kb,
        max_steps=10,
    )
    return agent


# ---------------------------------------------------------------------------
# Utility: flag extraction
# ---------------------------------------------------------------------------

FLAG_REGEX = re.compile(r"picoCTF\{.*?\}", re.IGNORECASE)


def extract_flag(text: str) -> Optional[str]:
    """
    Extract the first picoCTF{...} substring from text, case-insensitive.

    Args:
        text: Arbitrary text (LLM final answer).

    Returns:
        The matched flag string, or None if not found.
    """
    if not isinstance(text, str):
        return None
    m = FLAG_REGEX.search(text)
    if m:
        return m.group(0)
    return None


# ---------------------------------------------------------------------------
# Challenge-specific solver functions
# ---------------------------------------------------------------------------

def solve_where_are_the_robots(base_url: str, agent: ToolCallingAgent) -> Optional[str]:
    """
    Solve the picoCTF 'where are the robots' challenge using the ToolCallingAgent.

    Strategy:
        - Fetch /robots.txt.
        - Enumerate disallowed paths.
        - Fetch those paths and search for picoCTF{...}.
    """
    print(f"[SOLVER] Starting 'where_are_the_robots' for base URL: {base_url}")

    goal = (
        "You are solving the picoCTF challenge 'where are the robots'.\n"
        f"The base URL of this challenge instance is: {base_url}\n\n"
        "High-level strategy:\n"
        "1. Use http_fetch to request /robots.txt.\n"
        "2. Parse robots.txt and identify any Disallow or other interesting paths.\n"
        "3. Use http_fetch to fetch each interesting path and inspect the responses.\n"
        "4. Use html_link_and_form_extractor and static_resource_finder if needed to follow links.\n"
        "5. Search all responses for a flag in the format picoCTF{...}.\n"
        "6. Once you find the flag, return it as part of a final explanation.\n\n"
        "Remember: when you are done, respond with a JSON object of the form:\n"
        '  {\"final_answer\": \"<your explanation and the picoCTF{...} flag>\"}.\n'
        "Do NOT include any other keys alongside final_answer."
    )

    agent.initialize_conversation(goal_prompt=goal)
    final_answer = agent.run()
    print("[SOLVER] Agent final answer (where_are_the_robots):")
    print(final_answer)

    flag = extract_flag(final_answer)
    if flag is None:
        print("[SOLVER] Could not extract picoCTF flag from final answer.")
    return flag


def solve_insp3ct0r(base_url: str, agent: ToolCallingAgent) -> Optional[str]:
    """
    Solve the picoCTF 'Insp3ct0r' challenge using the ToolCallingAgent.

    Strategy:
        - Fetch main page.
        - Find linked CSS/JS.
        - Inspect JS/CSS for hidden flag pieces or encoded strings.
        - Decode as needed and reconstruct picoCTF{...}.
    """
    print(f"[SOLVER] Starting 'insp3ct0r' for base URL: {base_url}")

    goal = (
        "You are solving the picoCTF challenge 'Insp3ct0r'.\n"
        f"The base URL of this challenge instance is: {base_url}\n\n"
        "High-level strategy:\n"
        "1. Use http_fetch to retrieve the main page.\n"
        "2. Use static_resource_finder to identify linked CSS and JS files.\n"
        "3. Use static_file_fetch to retrieve each CSS and JS file.\n"
        "4. Use js_css_inspector to quickly summarize the JS/CSS and extract comments and suspicious strings.\n"
        "5. If you encounter encoded-looking data (base64, hex, URL-encoded), use the decoder tool.\n"
        "6. Search all content for a flag in the form picoCTF{...}. The flag might be split into parts; if so, "
        "reconstruct the full flag.\n"
        "7. When done, provide a brief explanation of how you found the flag and return the full picoCTF{...} in final_answer.\n\n"
        "Remember to follow the JSON-only protocol for tool calls and final answers."
    )

    agent.initialize_conversation(goal_prompt=goal)
    final_answer = agent.run()
    print("[SOLVER] Agent final answer (insp3ct0r):")
    print(final_answer)

    flag = extract_flag(final_answer)
    if flag is None:
        print("[SOLVER] Could not extract picoCTF flag from final answer.")
    return flag


def solve_dont_use_client_side(base_url: str, agent: ToolCallingAgent) -> Optional[str]:
    """
    Solve the picoCTF 'dont-use-client-side' challenge using the ToolCallingAgent.

    Strategy:
        - Fetch main page.
        - Find JS that performs client-side validation.
        - Reverse the JS logic to derive the correct password or bypass.
        - Submit the correct input and grab the flag.
    """
    print(f"[SOLVER] Starting 'dont_use_client_side' for base URL: {base_url}")

    goal = (
        "You are solving the picoCTF challenge 'dont-use-client-side'.\n"
        f"The base URL of this challenge instance is: {base_url}\n\n"
        "High-level strategy:\n"
        "1. Use http_fetch to load the main challenge page.\n"
        "2. Use static_resource_finder to locate any JavaScript files used for client-side validation.\n"
        "3. Use static_file_fetch and js_css_inspector to read and analyze the JS logic. Determine how the password "
        "or key is validated (e.g., character-by-character checks, hashing, comparisons).\n"
        "4. Use decoder if you see encoded strings.\n"
        "5. Once you understand the validation logic, either:\n"
        "   - compute the correct password and submit it via http_fetch or form_submitter, OR\n"
        "   - bypass validation by sending a direct HTTP request with parameters that indicate success.\n"
        "6. After successful validation, locate the picoCTF{...} flag in the response.\n"
        "7. Return a final_answer JSON with a short explanation and the full picoCTF flag.\n\n"
        "Always use the JSON-only protocol for tool calls and final_answer."
    )

    agent.initialize_conversation(goal_prompt=goal)
    final_answer = agent.run()
    print("[SOLVER] Agent final answer (dont_use_client_side):")
    print(final_answer)

    flag = extract_flag(final_answer)
    if flag is None:
        print("[SOLVER] Could not extract picoCTF flag from final answer.")
    return flag


def solve_logon(base_url: str, agent: ToolCallingAgent) -> Optional[str]:
    """
    Solve the picoCTF 'logon' challenge using the ToolCallingAgent.

    Strategy:
        - Understand login form.
        - Log in as normal user and inspect cookies.
        - Manipulate cookies (e.g., admin flag) to gain privileged access.
        - Grab picoCTF flag from privileged page.
    """
    print(f"[SOLVER] Starting 'logon' for base URL: {base_url}")

    goal = (
        "You are solving the picoCTF challenge 'logon'.\n"
        f"The base URL of this challenge instance is: {base_url}\n\n"
        "High-level strategy:\n"
        "1. Use http_fetch to retrieve the main login page.\n"
        "2. Use html_link_and_form_extractor to identify the login form's method, action, and field names.\n"
        "3. Use form_submitter to attempt a normal login (e.g., with a test username/password) and observe the response.\n"
        "4. Use cookie_manager (operation='list') to see which cookies are set (e.g., session, admin flags, username).\n"
        "5. Experiment with cookie_manager (operation='set' and 'request') to modify cookies such as roles or admin flags, "
        "then re-request the protected area.\n"
        "6. Through cookie manipulation or other subtle behavior, obtain access to a page that reveals the picoCTF{...} flag.\n"
        "7. Return a final_answer JSON with a short explanation and the full picoCTF flag.\n\n"
        "Use tools iteratively and follow the strict JSON protocol for tool calls and final answers."
    )

    agent.initialize_conversation(goal_prompt=goal)
    final_answer = agent.run()
    print("[SOLVER] Agent final answer (logon):")
    print(final_answer)

    flag = extract_flag(final_answer)
    if flag is None:
        print("[SOLVER] Could not extract picoCTF flag from final answer.")
    return flag


def solve_sqlilite(base_url: str, agent: ToolCallingAgent) -> Optional[str]:
    """
    Solve the picoCTF 'SQLiLite' challenge using the ToolCallingAgent.

    Strategy:
        - Identify the relevant form (login/search).
        - Use RAG (rag_query) to recall SQLi patterns.
        - Use sqli_probe to try payloads in a suspected vulnerable field.
        - Use promising payload(s) to extract the picoCTF flag.
    """
    print(f"[SOLVER] Starting 'sqlilite' for base URL: {base_url}")

    goal = (
        "You are solving the picoCTF challenge 'SQLiLite'.\n"
        f"The base URL of this challenge instance is: {base_url}\n\n"
        "High-level strategy:\n"
        "1. Use http_fetch to retrieve the main page and any login/search forms.\n"
        "2. Use html_link_and_form_extractor to identify form methods, actions, and input field names.\n"
        "3. Use rag_query to recall relevant SQL injection techniques (especially for simple login forms).\n"
        "4. Choose a likely target field for injection (e.g., password) and use sqli_probe to test multiple payloads.\n"
        "5. Inspect the sqli_probe results to see which payloads cause anomalous responses "
        "(different status code, longer content, presence of success or error keywords).\n"
        "6. Use the most promising payload with form_submitter or repeated sqli_probe attempts to gain access or reveal the flag.\n"
        "7. Search any resulting pages for the picoCTF{...} flag and, once found, return it with a short explanation "
        "in your final_answer JSON.\n\n"
        "As always, follow the strict JSON-only protocol for all tool calls and final answers."
    )

    agent.initialize_conversation(goal_prompt=goal)
    final_answer = agent.run()
    print("[SOLVER] Agent final answer (sqlilite):")
    print(final_answer)

    flag = extract_flag(final_answer)
    if flag is None:
        print("[SOLVER] Could not extract picoCTF flag from final answer.")
    return flag


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command-line arguments.

    Usage:
        python pico_agent_solver.py --challenge where_are_the_robots \
            --base-url http://example.com

    Args:
        argv: Optional list of arguments (defaults to sys.argv[1:]).

    Returns:
        Parsed argparse.Namespace.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Agentic picoCTF web challenge solver using OpenAI + tools + RAG.\n\n"
            "This script builds a tool-using agent that can solve specific picoCTF "
            "web challenges by exploring the target site, inspecting JS/CSS, "
            "probing for SQL injection, and using a local knowledge base."
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "--challenge",
        required=True,
        choices=[
            "where_are_the_robots",
            "insp3ct0r",
            "dont_use_client_side",
            "logon",
            "sqlilite",
        ],
        help=(
            "Which picoCTF challenge to solve.\n"
            "Choices:\n"
            "  where_are_the_robots\n"
            "  insp3ct0r\n"
            "  dont_use_client_side\n"
            "  logon\n"
            "  sqlilite"
        ),
    )

    parser.add_argument(
        "--base-url",
        required=True,
        help=(
            "Base URL of the picoCTF challenge instance.\n"
            "Example: http://saturn.picoctf.net:12345"
        ),
    )

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    """
    Entry point for the CLI.

    Steps:
        - Configures OpenAI from the environment.
        - Creates a default agent.
        - Dispatches to the appropriate challenge solver.
        - Prints the final flag (or an error message).
    """
    args = parse_args(argv)

    try:
        configure_openai_from_env()
    except RuntimeError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    base_url = args.base_url
    challenge = args.challenge

    print(f"[MAIN] Selected challenge: {challenge}")
    print(f"[MAIN] Base URL: {base_url}")

    agent = create_default_agent(base_url=base_url)

    if challenge == "where_are_the_robots":
        flag = solve_where_are_the_robots(base_url, agent)
    elif challenge == "insp3ct0r":
        flag = solve_insp3ct0r(base_url, agent)
    elif challenge == "dont_use_client_side":
        flag = solve_dont_use_client_side(base_url, agent)
    elif challenge == "logon":
        flag = solve_logon(base_url, agent)
    elif challenge == "sqlilite":
        flag = solve_sqlilite(base_url, agent)
    else:
        print(f"[ERROR] Unknown challenge: {challenge}", file=sys.stderr)
        sys.exit(1)

    if flag:
        print(f"\n[FLAG] {flag}")
    else:
        print("\n[FINAL] No picoCTF flag could be extracted from the agent's final answer.")


if __name__ == "__main__":
    main()