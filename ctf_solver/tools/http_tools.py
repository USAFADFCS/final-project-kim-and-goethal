"""
HTTP-related tools for CTF solving.

Provides HTTP GET/HEAD requests and form submission capabilities.
"""

import json
from typing import Optional

import requests


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
        "truncated response body (for GET). Use this tool to fetch web pages, "
        "API endpoints, or any HTTP resource."
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
        "Returns status, headers, and a truncated body. Use this tool to submit "
        "login forms, search queries, or any form-based interaction."
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
