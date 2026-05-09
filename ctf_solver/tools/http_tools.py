"""
HTTP-related tools for CTF solving.

Provides HTTP GET/HEAD requests and form submission capabilities.

Batch D #6: uses ``ctf_solver.tools.core.parse_json_input`` for input
parsing — proof-of-concept for the broader migration away from per-tool
JSON boilerplate.  Error strings are byte-for-byte identical to the
pre-migration version so existing tests are unaffected.
"""

import re
from typing import List, Optional

import requests

from ctf_solver.tools.core import parse_json_input, summarize_for_llm

# Broad CTF flag pattern: PREFIX{content} — catches most CTF flag formats.
# Used to scan full response bodies before truncation so flags beyond
# the max_body limit are still surfaced to the agent.
# The negative lookbehind prevents "AAAAACTF{...}" from matching the leading
# non-prefix characters, and the prefix is limited to 20 chars max.
_FLAG_SCAN_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"((?:picoCTF|HTB|THM|FLAG|CTF|MetaCTF|[A-Za-z0-9_]{1,20})\{[^}\n\r]{1,200}\})",
    re.IGNORECASE,
)


def _scan_for_flags(full_text: str, truncation_point: int) -> List[str]:
    """Return flags found in text beyond the truncation point."""
    matches = _FLAG_SCAN_RE.findall(full_text)
    # Only return flags that are partially or fully beyond truncation
    result = []
    for flag in matches:
        pos = full_text.find(flag)
        if pos >= truncation_point:
            result.append(flag)
    return list(dict.fromkeys(result))  # deduplicate preserving order


def _scan_binary_for_flags(content: bytes) -> List[str]:
    """
    Scan raw binary content for CTF flag patterns.

    Converts each byte to its printable ASCII character (or a space for
    non-printable bytes) and runs the flag regex over the result.
    This catches flags embedded in plaintext inside binary files (e.g.
    WASM data sections, zip archives, PDF metadata).
    """
    text = "".join(chr(b) if 32 <= b < 127 else " " for b in content)
    return list(dict.fromkeys(_FLAG_SCAN_RE.findall(text)))


class HttpFetchTool:
    """
    HttpFetchTool: perform HTTP requests against a URL.

    Tool interface (FAIR-style):
      - `name` and `description` class attributes.
      - `.use(tool_input: str) -> str`, where tool_input is JSON.

    Expected JSON tool_input format:

        {
          "url": "https://example.com/path",
          "method": "GET",                  # optional, default "GET"
          "params": {"key": "value"},       # optional query parameters
          "headers": {"User-Agent": "..."}, # optional
          "body": {"key": "value"},         # optional, JSON body for POST/PUT/PATCH/DELETE
          "raw_body": "<xml>data</xml>",    # optional, raw string body (mutually exclusive with body)
          "max_body": 4000,                 # optional, int
          "timeout": 10,                    # optional, request timeout in seconds
          "follow_redirects": true,         # optional, default true
          "auth": ["user", "pass"]          # optional, HTTP Basic Auth [username, password]
        }

    Behavior:
      - Uses a shared requests.Session to perform the HTTP request.
      - Supports "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE".
      - For POST/PUT/PATCH/DELETE: sends `body` as JSON, or `raw_body` as raw string.
      - `follow_redirects`: when false, stops at the first redirect and shows Location header.
      - `auth`: HTTP Basic Authentication credentials as [username, password].
      - Returns a human-readable summary including:
          * Method + final URL (and redirect chain if redirects occurred)
          * Status code
          * Set-Cookie headers (highlighted separately)
          * Response headers
          * Truncated body (for non-HEAD; HEAD has no body)
    """

    name: str = "http_fetch"
    description: str = (
        "Perform an HTTP request to a URL. Input must be JSON with keys: 'url' "
        "(required), 'method' (optional: 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', "
        "'DELETE'; default 'GET'), 'params' (optional dict of query params), "
        "'headers' (optional dict), 'body' (optional dict, sent as JSON for "
        "POST/PUT/PATCH/DELETE), 'raw_body' (optional string, sent as raw body "
        "with explicit Content-Type in headers), 'max_body' (optional int, default "
        "4000), 'timeout' (optional int, default 10), 'follow_redirects' (optional "
        "bool, default true — set to false to inspect redirects), and 'auth' "
        "(optional [username, password] for HTTP Basic Auth). Returns status, "
        "headers, Set-Cookie info, and a truncated response body. Use "
        "'insecure' (optional bool, default false) to skip SSL certificate "
        "verification for self-signed or invalid certificates."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Target URL"},
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"],
                "default": "GET",
            },
            "params": {"type": "object", "description": "Query parameters"},
            "headers": {"type": "object", "description": "Request headers"},
            "body": {
                "type": "object",
                "description": "JSON body for POST/PUT/PATCH/DELETE; mutually exclusive with raw_body",
            },
            "raw_body": {
                "type": "string",
                "description": 'Raw string body. Set Content-Type via headers. Inner double quotes must be \\" inside JSON.',
            },
            "max_body": {"type": "integer", "default": 4000},
            "timeout": {"type": "integer", "default": 10},
            "follow_redirects": {"type": "boolean", "default": True},
            "auth": {
                "type": "array",
                "items": {"type": "string"},
                "description": "[username, password] for HTTP Basic Auth",
            },
            "insecure": {
                "type": "boolean",
                "default": False,
                "description": "Skip SSL verification for self-signed certs",
            },
        },
        "required": ["url"],
        "additionalProperties": False,
    }
    samples = [
        {"url": "http://example.com/", "method": "GET"},
        {
            "url": "http://example.com/api/login",
            "method": "POST",
            "body": {"username": "admin", "password": "x"},
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "HttpFetchTool", url_field="url")
        if err:
            return err

        url = data.get("url")
        if not url or not isinstance(url, str):
            return (
                "[HttpFetchTool] Error: 'url' (string) is required in the input JSON."
            )

        method = (data.get("method") or "GET").upper()
        params = data.get("params") or {}
        headers = data.get("headers") or {}
        body = data.get("body")
        raw_body = data.get("raw_body")
        max_body = data.get("max_body", 4000)
        timeout = data.get("timeout", 10)
        follow_redirects = data.get("follow_redirects", True)
        auth = data.get("auth")
        insecure = data.get("insecure", False)

        if not isinstance(params, dict):
            return "[HttpFetchTool] Error: 'params' must be a JSON object (dict)."
        if not isinstance(headers, dict):
            return "[HttpFetchTool] Error: 'headers' must be a JSON object (dict)."
        if body is not None and raw_body is not None:
            return (
                "[HttpFetchTool] Error: 'body' and 'raw_body' are mutually exclusive."
            )

        allowed_methods = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
        if method not in allowed_methods:
            return f"[HttpFetchTool] Error: 'method' must be one of {allowed_methods}."

        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 10

        # Build auth tuple if provided
        auth_tuple = None
        if auth and isinstance(auth, (list, tuple)) and len(auth) == 2:
            auth_tuple = (str(auth[0]), str(auth[1]))

        # Suppress InsecureRequestWarning when using insecure mode
        if insecure:
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        try:
            request_kwargs = {
                "params": params,
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": bool(follow_redirects),
                "verify": not bool(insecure),
            }
            if auth_tuple:
                request_kwargs["auth"] = auth_tuple

            if method == "HEAD":
                response = self.session.head(url, **request_kwargs)
            elif method in ("POST", "PUT", "PATCH", "DELETE"):
                request_fn = getattr(self.session, method.lower())
                if body is not None:
                    request_kwargs["json"] = body
                elif raw_body is not None:
                    request_kwargs["data"] = (
                        raw_body if isinstance(raw_body, str) else str(raw_body)
                    )
                response = request_fn(url, **request_kwargs)
            else:
                response = self.session.get(url, **request_kwargs)
        except Exception as exc:
            return (
                f"[HttpFetchTool] Error during {method!r} request to {url!r}: {exc!r}"
            )

        # Build redirect chain info
        redirect_info = ""
        if response.history:
            chain = []
            for r in response.history:
                loc = r.headers.get("Location", "?")
                chain.append(f"  {r.status_code} {r.url} -> {loc}")
            redirect_info = "\nRedirect chain:\n" + "\n".join(chain) + "\n"

        # Extract Set-Cookie headers
        set_cookies = []
        for r in [*response.history, response]:
            for sc in (
                r.headers.getlist("Set-Cookie")
                if hasattr(r.headers, "getlist")
                else (
                    [v for k, v in r.raw.headers.items() if k.lower() == "set-cookie"]
                    if hasattr(r, "raw") and hasattr(r.raw, "headers")
                    else []
                )
            ):
                set_cookies.append(sc)
        # Fallback: parse from response headers directly
        if not set_cookies:
            for key, val in response.headers.items():
                if key.lower() == "set-cookie":
                    set_cookies.append(val)

        set_cookie_section = ""
        if set_cookies:
            set_cookie_section = (
                "\n[SET-COOKIE HEADERS]\n"
                + "\n".join(f"  {sc}" for sc in set_cookies)
                + "\n"
            )

        header_lines = [f"{k}: {v}" for k, v in response.headers.items()]
        headers_str = "\n".join(header_lines)

        # HEAD responses typically have no body
        if method == "HEAD":
            body_preview = "[No body for HEAD request]"
            max_body_int = 0
        else:
            try:
                max_body_int = int(max_body)
            except Exception:
                max_body_int = 4000

            # Try text first, fall back to hex for binary responses
            try:
                text = response.text or ""
            except Exception:
                text = ""

            # Detect binary content
            content_type = response.headers.get("Content-Type", "")
            is_binary = any(
                t in content_type.lower()
                for t in [
                    "octet-stream",
                    "image/",
                    "audio/",
                    "video/",
                    "application/pdf",
                    "application/zip",
                    "application/gzip",
                    "application/wasm",
                ]
            ) or (
                # Detect by magic bytes: WASM (\x00asm) and common binary formats
                bool(response.content)
                and response.content[:4] in (b"\x00asm", b"\x7fELF", b"PK\x03\x04")
            )

            if is_binary and response.content:
                hex_preview = response.content[:512].hex()
                body_preview = f"[Binary response, {len(response.content)} bytes]\nHex preview: {hex_preview}"
                if len(response.content) > 512:
                    body_preview += "\n...[truncated]..."
            elif max_body_int > 0:
                body_preview = text[:max_body_int]
                if len(text) > max_body_int:
                    body_preview += "\n...[truncated]..."
                # Phase 2: strip <style>/<script> bodies and collapse
                # repeated lines so CSS boilerplate does not dominate
                # the observation. Flag-preservation contract: any flag
                # match hiding inside a stripped region is appended
                # verbatim so _scan_for_flags below (and the agent's
                # downstream detection) cannot silently lose it.
                body_preview = summarize_for_llm(
                    body_preview,
                    max_chars=max_body_int,
                    flag_regex=_FLAG_SCAN_RE,
                )
            else:
                # max_body_int == 0 → caller asked for the full body
                # verbatim (used for explicit "show me everything"
                # re-fetches, e.g. when a flag is beyond truncation).
                # Do not summarize: the caller wants raw content.
                body_preview = text

        # Scan full response for flags BEFORE truncation so flags beyond
        # max_body are still surfaced to the agent and LoggingToolWrapper.
        # Also scan binary responses (e.g. WASM) for plaintext flags embedded
        # in data sections — regardless of max_body setting.
        flag_section = ""
        if method != "HEAD":
            if is_binary and response.content:
                # Scan raw binary bytes for flag patterns (e.g. plaintext flag in WASM data)
                binary_flags = _scan_binary_for_flags(response.content)
                if binary_flags:
                    flag_lines = "\n".join(f"  {f}" for f in binary_flags)
                    flag_section = (
                        f"\n\n[FLAG PATTERN DETECTED in binary content]\n"
                        f"{flag_lines}\n"
                        "These flag-like strings were found in the raw binary response. "
                        "If the flag is XOR-encoded, use the wasm_analyzer tool with "
                        "operation='xor_decode'."
                    )
            elif not is_binary and max_body_int > 0 and len(text) > max_body_int:
                hidden_flags = _scan_for_flags(text, max_body_int)
                if hidden_flags:
                    flag_lines = "\n".join(f"  {f}" for f in hidden_flags)
                    flag_section = (
                        f"\n\n[FLAG PATTERN DETECTED beyond truncation point]\n"
                        f"{flag_lines}\n"
                        "These flag-like strings were found in the full response body "
                        "beyond the preview above."
                    )

        summary = (
            f"[HttpFetchTool] Method: {method}\n"
            f"URL: {response.url}\n"
            f"Status: {response.status_code}"
            f"{redirect_info}"
            f"{set_cookie_section}\n"
            f"Headers:\n{headers_str}\n\n"
            f"Body (truncated to {max_body_int} chars):\n{body_preview}"
            f"{flag_section}"
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
          "max_body": 4000,
          "multipart": false,                 # optional, send as multipart/form-data
          "files": {"file": {"filename": "test.txt", "content": "hello", "content_type": "text/plain"}}
        }

    Behavior:
      - Uses the shared session to submit the request.
      - For GET, `data` is used as query params.
      - For POST, `data` is used as form data (or JSON body if Content-Type
        is application/json, or multipart if `multipart` is true).
      - `files`: dict of file fields for multipart upload. Each value has
        'filename', 'content', and optional 'content_type'.
      - Returns status code, headers, and a truncated body similar to HttpFetchTool.
    """

    name: str = "form_submit"
    description: str = (
        "Submit an HTTP form using GET or POST with the shared session. "
        "Input JSON keys: 'url' (string, required), 'method' (string, 'GET' or "
        "'POST', required), 'data' (optional dict of form fields or JSON body), "
        "'headers' (optional dict), 'max_body' (optional int, default 4000), "
        "'multipart' (optional bool, send as multipart/form-data), and "
        "'files' (optional dict of file fields: {field_name: {filename, content, "
        "content_type}}). When Content-Type is 'application/json', the data dict "
        "is sent as a JSON request body. Returns status, headers, and a truncated "
        "body. Use this tool to submit login forms, file uploads, or API requests."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "enum": ["GET", "POST"]},
            "data": {
                "type": "object",
                "description": "Form fields (or JSON body if Content-Type is application/json)",
            },
            "headers": {"type": "object"},
            "max_body": {"type": "integer", "default": 4000},
            "multipart": {"type": "boolean", "default": False},
            "files": {
                "type": "object",
                "description": "File uploads keyed by field_name → {filename, content, content_type}",
            },
        },
        "required": ["url", "method"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/login",
            "method": "POST",
            "data": {"user": "admin", "pw": "x"},
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self.session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "FormSubmitTool", url_field="url")
        if err:
            return err

        url = data.get("url")
        method = data.get("method")
        form_data = data.get("data") or {}
        headers = data.get("headers") or {}
        max_body = data.get("max_body", 4000)
        multipart = data.get("multipart", False)
        files_input = data.get("files") or {}

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
                resp = self.session.get(
                    url, params=form_data, headers=headers, timeout=10
                )
            else:  # POST
                # Detect JSON content type and send as JSON body instead of form data
                content_type = ""
                for k, v in headers.items():
                    if k.lower() == "content-type":
                        content_type = v.lower()
                        break

                if "application/json" in content_type:
                    resp = self.session.post(
                        url, json=form_data, headers=headers, timeout=10
                    )
                elif multipart or files_input:
                    # Build multipart files dict
                    files_dict = {}
                    for field_name, file_info in files_input.items():
                        if isinstance(file_info, dict):
                            filename = file_info.get("filename", "file")
                            content = file_info.get("content", "")
                            ct = file_info.get(
                                "content_type", "application/octet-stream"
                            )
                            if isinstance(content, str):
                                # Try base64 decode for binary files:
                                # only attempt if the string looks like
                                # base64 (long, valid charset, padded).
                                import base64
                                import binascii
                                import re as _re

                                _b64_pat = _re.compile(r"^[A-Za-z0-9+/\n\r]+=*$")
                                if len(content) >= 20 and _b64_pat.match(content):
                                    try:
                                        decoded = base64.b64decode(content)
                                        if len(decoded) > 0:
                                            content = decoded
                                        else:
                                            content = content.encode("utf-8")
                                    except (binascii.Error, ValueError):
                                        content = content.encode("utf-8")
                                else:
                                    content = content.encode("utf-8")
                            files_dict[field_name] = (filename, content, ct)
                        elif isinstance(file_info, str):
                            files_dict[field_name] = (
                                field_name,
                                file_info.encode("utf-8"),
                                "application/octet-stream",
                            )

                    if files_dict:
                        resp = self.session.post(
                            url,
                            data=form_data,
                            files=files_dict,
                            headers=headers,
                            timeout=10,
                        )
                    else:
                        # multipart=true but no files: send form_data as multipart
                        # requests sends multipart when files= is used, so we use a trick
                        mp_files = {k: (None, v) for k, v in form_data.items()}
                        resp = self.session.post(
                            url, files=mp_files, headers=headers, timeout=10
                        )
                else:
                    resp = self.session.post(
                        url, data=form_data, headers=headers, timeout=10
                    )
        except Exception as exc:
            return (
                f"[FormSubmitTool] Error during {method!r} request to {url!r}: {exc!r}"
            )

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
            # Phase 2: summarize — same rationale as HttpFetchTool.
            body_preview = summarize_for_llm(
                body_preview,
                max_chars=max_body_int,
                flag_regex=_FLAG_SCAN_RE,
            )
        else:
            body_preview = text

        # Scan full response for flags BEFORE truncation
        flag_section = ""
        if max_body_int > 0 and len(text) > max_body_int:
            hidden_flags = _scan_for_flags(text, max_body_int)
            if hidden_flags:
                flag_lines = "\n".join(f"  {f}" for f in hidden_flags)
                flag_section = (
                    f"\n\n[FLAG PATTERN DETECTED beyond truncation point]\n"
                    f"{flag_lines}\n"
                    "These flag-like strings were found in the full response body "
                    "beyond the preview above."
                )

        summary = (
            f"[FormSubmitTool] Method: {method}\n"
            f"URL: {resp.url}\n"
            f"Status: {resp.status_code}\n"
            f"Headers:\n{headers_str}\n\n"
            f"Body (truncated to {max_body_int} chars):\n{body_preview}"
            f"{flag_section}"
        )
        return summary
