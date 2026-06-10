"""
submit_until_done — server-side request loop that runs without
consuming agent steps.

Motivation: some challenges (e.g. MetaCTF's "Super Quick Logic
Invitational") require the agent to drive an N-iteration server loop
(read question → compute answer → submit → repeat).  When every
iteration costs an agent step, the step budget runs out long before
the loop finishes.  This tool collapses the loop into a single tool
call: the agent describes how each iteration is built, the tool runs
the loop on the shared ``requests.Session`` and returns when the
success marker appears, an iteration cap is hit, or a stop marker
fires.

The tool intentionally supports two iteration shapes:

  - ``static`` (default): every iteration sends the same request,
    optionally with answers selected from a lookup table keyed by the
    previous response.
  - ``regex_extract``: each iteration parses the previous response
    with one or more regexes to populate placeholders in the next
    request body.  This is the trivia-loop case: extract
    ``current_question`` from the cookie/HTML, look up the answer in
    a caller-supplied mapping, post it back, repeat.

Inputs (JSON):

  - ``url`` (required, string)
  - ``method`` (optional, default "POST")
  - ``body_template`` (optional, string): request body with
    ``{placeholder}`` slots filled per iteration.  Ignored for GET.
  - ``headers`` (optional, dict)
  - ``success_marker`` (required, string|list): substring(s) that
    indicate the flag has appeared in a response.  When any marker
    is found, the loop stops and the matching response is returned.
  - ``stop_marker`` (optional, string|list): substring(s) that mean
    "give up, the loop is broken" (e.g. ``"403 Forbidden"``).
  - ``max_iterations`` (optional, int, default 25, capped at 200)
  - ``iteration_mode`` (optional, "static"|"regex_extract", default
    "static")
  - ``extract_regex`` (optional, dict[str, str]): placeholder →
    Python regex with one capture group, applied to the previous
    response body (and to a server-emitted cookie like
    ``session`` via ``flask_session_forge``-style decoding when
    the placeholder name matches a key in ``cookie_lookup``).
  - ``answer_lookup`` (optional, dict[str, str]): maps the extracted
    placeholder value to a substitution.  When set, the substituted
    value replaces ``{placeholder}`` in ``body_template``.
  - ``delay_seconds`` (optional, float, default 0): pause between
    iterations, capped at 2.0.
  - ``share_session`` (optional, bool, default True): use the
    shared session jar so cookies persist across iterations (and
    survive after the tool returns).  Set False for a clean jar.

Returns a JSON summary: how many iterations ran, the matching marker
(if any), the wall time, the final response excerpt (truncated), and
a per-iteration mini-trace (first 20).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any, Dict, List, Optional

import requests

from ctf_solver.tools.core import parse_json_input

_MAX_ITER_CAP = 200
_MAX_DELAY = 2.0
_MAX_BODY_RETURN = 4000
_MAX_TRACE_ENTRIES = 20


class _EmptyDefaultMap(dict):
    """format_map() helper: unknown keys substitute as empty string.

    Used in regex_extract mode so iter 0 (which has no extracted
    values yet) can still send a probe body without raising KeyError.
    """

    def __missing__(self, key: str) -> str:
        return ""


class SubmitUntilDoneTool:
    name: str = "submit_until_done"
    description: str = (
        "Run a server-side request loop in a single tool call (no agent "
        "step per iteration). Use for trivia/scoring loops, brute-force "
        "submissions, paging through ordered responses. Input JSON: "
        "'url' (string, required), 'method' (default 'POST'), "
        "'body_template' (string with {placeholders}), 'headers' (dict), "
        "'success_marker' (string|list, required), 'stop_marker' "
        "(string|list), 'max_iterations' (int, default 25, max 200), "
        "'iteration_mode' ('static'|'regex_extract', default 'static'), "
        "'extract_regex' (dict mapping placeholder -> regex with one "
        "capture group, applied to the previous response), "
        "'answer_lookup' (dict mapping extracted value -> answer to "
        "substitute into body_template), 'delay_seconds' (float, max "
        "2.0), 'share_session' (bool, default True). Returns a JSON "
        "summary with the matching response when a success marker fires."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {"type": "string", "default": "POST"},
            "body_template": {"type": "string"},
            "headers": {"type": "object"},
            "success_marker": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ]
            },
            "stop_marker": {
                "oneOf": [
                    {"type": "string"},
                    {"type": "array", "items": {"type": "string"}},
                ]
            },
            "max_iterations": {"type": "integer", "default": 25},
            "iteration_mode": {
                "type": "string",
                "enum": ["static", "regex_extract"],
                "default": "static",
            },
            "extract_regex": {"type": "object"},
            "answer_lookup": {"type": "object"},
            "delay_seconds": {"type": "number", "default": 0},
            "share_session": {"type": "boolean", "default": True},
        },
        "required": ["url", "success_marker"],
        "additionalProperties": False,
    }
    samples = [
        {
            "url": "http://example.com/submit",
            "method": "POST",
            "body_template": "answer={answer}&csrf_token=abc123",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "success_marker": "MetaCTF{",
            "stop_marker": "403 Forbidden",
            "max_iterations": 100,
            "iteration_mode": "regex_extract",
            "extract_regex": {"question": '"current_question"\\s*:\\s*"([^"]+)"'},
            "answer_lookup": {
                "If you have a 3-bit key and a 3-bit plaintext, how many possible ciphertexts can you produce?": "8"
            },
        },
        {
            "url": "http://example.com/check",
            "method": "GET",
            "success_marker": "FLAG{",
            "max_iterations": 50,
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._shared_session = session or requests.Session()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "SubmitUntilDoneTool")
        if err:
            return err

        url = data.get("url")
        if not isinstance(url, str) or not url:
            return "[SubmitUntilDoneTool] Error: 'url' (string) is required."

        success_marker_raw = data.get("success_marker")
        success_markers = _coerce_markers(success_marker_raw)
        if not success_markers:
            return (
                "[SubmitUntilDoneTool] Error: 'success_marker' (string or "
                "non-empty list) is required."
            )

        stop_markers = _coerce_markers(data.get("stop_marker")) or []

        method = (data.get("method") or "POST").upper()
        if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return (
                f"[SubmitUntilDoneTool] Error: unsupported method "
                f"{method!r}; must be GET/POST/PUT/PATCH/DELETE."
            )

        try:
            max_iter = int(data.get("max_iterations", 25))
        except (TypeError, ValueError):
            return "[SubmitUntilDoneTool] Error: 'max_iterations' must be an integer."
        if max_iter < 1:
            return "[SubmitUntilDoneTool] Error: 'max_iterations' must be >= 1."
        if max_iter > _MAX_ITER_CAP:
            max_iter = _MAX_ITER_CAP

        try:
            delay = float(data.get("delay_seconds", 0))
        except (TypeError, ValueError):
            return "[SubmitUntilDoneTool] Error: 'delay_seconds' must be numeric."
        delay = max(0.0, min(delay, _MAX_DELAY))

        iteration_mode = data.get("iteration_mode", "static")
        if iteration_mode not in ("static", "regex_extract"):
            return (
                "[SubmitUntilDoneTool] Error: 'iteration_mode' must be "
                "'static' or 'regex_extract'."
            )

        body_template = data.get("body_template") or ""
        headers = data.get("headers") or {}
        if not isinstance(headers, dict):
            return "[SubmitUntilDoneTool] Error: 'headers' must be an object."

        extract_regex_raw = data.get("extract_regex") or {}
        if not isinstance(extract_regex_raw, dict):
            return "[SubmitUntilDoneTool] Error: 'extract_regex' must be an object."
        compiled_regex: Dict[str, re.Pattern] = {}
        for placeholder, pattern in extract_regex_raw.items():
            if not isinstance(pattern, str):
                return (
                    f"[SubmitUntilDoneTool] Error: 'extract_regex[{placeholder}]'"
                    " must be a regex string."
                )
            try:
                compiled_regex[str(placeholder)] = re.compile(pattern, re.DOTALL)
            except re.error as exc:
                return (
                    f"[SubmitUntilDoneTool] Error: 'extract_regex[{placeholder}]'"
                    f" is not a valid regex: {exc}"
                )

        answer_lookup = data.get("answer_lookup") or {}
        if not isinstance(answer_lookup, dict):
            return "[SubmitUntilDoneTool] Error: 'answer_lookup' must be an object."

        share_session = bool(data.get("share_session", True))
        sess = self._shared_session if share_session else requests.Session()

        trace: List[Dict[str, Any]] = []
        iter_count = 0
        last_body = ""
        match_marker: Optional[str] = None
        stop_marker_hit: Optional[str] = None
        unmatched_placeholders: List[str] = []
        loop_error: Optional[str] = None
        started = time.monotonic()

        for i in range(max_iter):
            iter_count = i + 1
            # Build placeholders for this iteration.
            placeholder_values: Dict[str, str] = {}
            if iteration_mode == "regex_extract" and i > 0:
                for placeholder, pattern in compiled_regex.items():
                    m = pattern.search(last_body)
                    if not m:
                        unmatched_placeholders.append(placeholder)
                        continue
                    raw_value = m.group(1) if m.groups() else m.group(0)
                    if answer_lookup and placeholder in (
                        "question",
                        "prompt",
                        "challenge",
                    ):
                        placeholder_values[placeholder] = str(
                            answer_lookup.get(raw_value, raw_value)
                        )
                    else:
                        placeholder_values[placeholder] = str(
                            answer_lookup.get(raw_value, raw_value)
                        )

            if iteration_mode == "regex_extract" and i > 0 and unmatched_placeholders:
                loop_error = (
                    "extract_regex failed on iteration "
                    f"{iter_count}: placeholder(s) "
                    f"{sorted(set(unmatched_placeholders))} not found in "
                    "previous response. Stopping."
                )
                break

            try:
                if body_template:
                    if iteration_mode == "regex_extract":
                        # Iter 0 has no extracted values yet, and a later
                        # iter may legitimately lack some placeholders.
                        # Render unbound placeholders as empty rather than
                        # raising — the loop treats iter 0 as a probe.
                        rendered_body = body_template.format_map(
                            _EmptyDefaultMap(placeholder_values)
                        )
                    else:
                        rendered_body = body_template.format(**placeholder_values)
                else:
                    rendered_body = ""
            except (KeyError, IndexError, ValueError) as exc:
                loop_error = (
                    f"body_template render failed on iteration "
                    f"{iter_count}: {exc!r}. Stopping."
                )
                break

            try:
                resp = _send(sess, method, url, rendered_body, headers)
            except Exception as exc:
                loop_error = (
                    f"request raised on iteration {iter_count}: {exc!r}. Stopping."
                )
                break

            last_body = resp.text or ""
            status = resp.status_code

            entry: Dict[str, Any] = {
                "i": iter_count,
                "status": status,
                "len": len(last_body),
            }
            if placeholder_values:
                entry["placeholders"] = placeholder_values
            if len(trace) < _MAX_TRACE_ENTRIES:
                trace.append(entry)

            # Success / stop markers are checked against status-line + body.
            haystack = f"{status} {last_body}"
            for marker in success_markers:
                if marker and marker in haystack:
                    match_marker = marker
                    break
            if match_marker is not None:
                break
            for marker in stop_markers:
                if marker and marker in haystack:
                    stop_marker_hit = marker
                    break
            if stop_marker_hit is not None:
                break

            if delay > 0 and i + 1 < max_iter:
                time.sleep(delay)

        elapsed = time.monotonic() - started

        outcome: str
        if match_marker is not None:
            outcome = "success"
        elif stop_marker_hit is not None:
            outcome = "stopped_by_marker"
        elif loop_error is not None:
            outcome = "error"
        elif iter_count >= max_iter:
            outcome = "max_iterations_reached"
        else:
            outcome = "unknown"

        result: Dict[str, Any] = {
            "tool": "submit_until_done",
            "outcome": outcome,
            "iterations": iter_count,
            "max_iterations": max_iter,
            "elapsed_seconds": round(elapsed, 3),
            "url": url,
            "method": method,
            "iteration_mode": iteration_mode,
        }
        if match_marker is not None:
            result["matched_success_marker"] = match_marker
        if stop_marker_hit is not None:
            result["matched_stop_marker"] = stop_marker_hit
        if loop_error is not None:
            result["loop_error"] = loop_error

        result["final_response_excerpt"] = last_body[:_MAX_BODY_RETURN]
        if len(last_body) > _MAX_BODY_RETURN:
            result["final_response_truncated"] = True
        result["trace"] = trace

        return json.dumps(result, indent=2)


def _coerce_markers(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, (list, tuple)):
        return [str(m) for m in value if isinstance(m, str) and m]
    return []


def _send(
    session: requests.Session,
    method: str,
    url: str,
    body: str,
    headers: Dict[str, Any],
) -> requests.Response:
    if method == "GET":
        return session.get(url, headers=headers, timeout=15, allow_redirects=False)
    if method in ("POST", "PUT", "PATCH"):
        return session.request(
            method,
            url,
            data=body if body else None,
            headers=headers,
            timeout=15,
            allow_redirects=False,
        )
    return session.request(
        method, url, headers=headers, timeout=15, allow_redirects=False
    )
