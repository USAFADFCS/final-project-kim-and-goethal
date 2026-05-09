"""
Collapsed XSS family tool (v3.8 P0 main).

Dispatches to the three underlying XSS tools (``XssProbeTool``,
``XssPayloadGenerator``, ``CspAnalyzerTool``) via a single ``operation``
enum.  Same rationale as ``CollapsedXxeTool``: 3 → 1 entry point so the
26B model picks ``operation`` rather than picking among three near-
synonym tool names.
"""

from __future__ import annotations

import json
from typing import Optional

import requests

from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.xss_tools import (
    CspAnalyzerTool,
    XssPayloadGenerator,
    XssProbeTool,
)

_ALLOWED_OPERATIONS = ("probe", "generate_payload", "csp_analyze")


class CollapsedXssTool:
    """Single XSS entry point with an ``operation`` enum.

    Operations:
      - ``probe``: forwards to ``XssProbeTool`` — detect reflected/stored XSS.
      - ``generate_payload``: forwards to ``XssPayloadGenerator`` — emit
        ready-to-paste XSS payloads (reflected / stored / DOM / filter
        bypass).
      - ``csp_analyze``: forwards to ``CspAnalyzerTool`` — analyze a
        Content-Security-Policy header for bypasses.
    """

    name: str = "xss_attack"
    description: str = (
        "Unified XSS entry point. Pick 'operation' to dispatch: "
        "'probe' (test target for XSS — needs 'url'), 'generate_payload' "
        "(emit XSS payloads — needs 'payload_type'), or 'csp_analyze' "
        "(inspect a CSP header — needs 'url' or 'csp_header')."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": list(_ALLOWED_OPERATIONS),
            },
            "url": {"type": "string", "description": "Target URL"},
            "param": {"type": "string"},
            "method": {"type": "string"},
            "data": {"type": "object"},
            "headers": {"type": "object"},
            "context": {"type": "string"},
            "payload_type": {
                "type": "string",
                "enum": ["reflected", "stored", "dom", "filter_bypass"],
            },
            "filter": {"type": "string"},
            "csp_header": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": False,
    }
    samples = [
        {"operation": "probe", "url": "http://example.com/search", "param": "q"},
        {"operation": "generate_payload", "payload_type": "reflected"},
        {"operation": "csp_analyze", "url": "http://example.com/"},
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._probe = XssProbeTool(session=session) if session else XssProbeTool()
        self._gen = XssPayloadGenerator()
        self._csp = CspAnalyzerTool(session=session) if session else CspAnalyzerTool()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CollapsedXssTool")
        if err:
            return err
        op = data.get("operation")
        if op not in _ALLOWED_OPERATIONS:
            return (
                f"[CollapsedXssTool] Error: 'operation' must be one of "
                f"{list(_ALLOWED_OPERATIONS)}, got {op!r}."
            )
        payload = {k: v for k, v in data.items() if k != "operation"}
        sub_input = json.dumps(payload)
        if op == "probe":
            return self._probe.use(sub_input)
        if op == "generate_payload":
            return self._gen.use(sub_input)
        return self._csp.use(sub_input)
