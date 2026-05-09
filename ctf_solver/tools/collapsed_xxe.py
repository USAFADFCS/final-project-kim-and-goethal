"""
Collapsed XXE family tool (v3.8 P0 main).

Dispatches to the three underlying XXE tools (``XxeProbeTool``,
``XxePayloadGenerator``, ``XxeDocTypeBuilder``) via a single ``operation``
enum.  Collapsing the surface from 3 → 1 cuts the dispatch decision the
26B model has to make in half — when it sees an XXE-related challenge,
it always calls ``xxe_attack`` and just picks the operation.

The underlying tools are re-used unchanged so existing tool-level tests
pass.  ``CollapsedXxeTool`` is registered in place of the three
individual tools when ``SolverConfig.enable_collapsed_families`` is True.
"""

from __future__ import annotations

import json
from typing import Optional

import requests

from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.xxe_tools import (
    XxeDocTypeBuilder,
    XxePayloadGenerator,
    XxeProbeTool,
)

_ALLOWED_OPERATIONS = ("probe", "generate_payload", "build_doctype")


class CollapsedXxeTool:
    """Single XXE entry point with an ``operation`` enum.

    Operations:
      - ``probe``: forwards to ``XxeProbeTool`` — detect XXE on a target URL.
      - ``generate_payload``: forwards to ``XxePayloadGenerator`` — emit
        ready-to-paste XXE payloads (file_read / ssrf / oob / rce).
      - ``build_doctype``: forwards to ``XxeDocTypeBuilder`` — assemble a
        custom DOCTYPE block from an entity list.

    The exact arg shapes per operation match the underlying tools; the
    schema below documents them as a single matrix so the LLM doesn't
    have to learn three near-identical input shapes.
    """

    name: str = "xxe_attack"
    description: str = (
        "Unified XXE entry point. Pick 'operation' to dispatch: "
        "'probe' (test target for XXE — needs 'url'), 'generate_payload' "
        "(emit XXE payloads — needs 'payload_type' + 'target'), or "
        "'build_doctype' (build a custom DOCTYPE — needs 'entities')."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": list(_ALLOWED_OPERATIONS),
            },
            # probe args
            "url": {"type": "string", "description": "Target URL (probe)"},
            "method": {"type": "string", "description": "HTTP method (probe)"},
            "xml_param": {"type": "string"},
            "content_type": {"type": "string"},
            "headers": {"type": "object"},
            "probe_type": {
                "type": "string",
                "enum": ["file_read", "ssrf", "oob", "all"],
            },
            "target_file": {"type": "string"},
            "callback_host": {"type": "string"},
            # payload-generator args
            "payload_type": {
                "type": "string",
                "enum": ["file_read", "ssrf", "oob", "rce"],
            },
            "target": {"type": "string"},
            "callback": {"type": "string"},
            "root_element": {"type": "string"},
            "wrapper": {"type": "string"},
            # doctype-builder args
            "entities": {
                "type": "array",
                "description": "Entity definitions for build_doctype",
            },
            "root": {"type": "string"},
            "content": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": False,
    }
    samples = [
        {
            "operation": "probe",
            "url": "http://example.com/api",
            "probe_type": "file_read",
        },
        {
            "operation": "generate_payload",
            "payload_type": "file_read",
            "target": "/etc/passwd",
        },
        {
            "operation": "build_doctype",
            "entities": [{"name": "xxe", "system": "file:///flag"}],
            "root": "root",
            "content": "&xxe;",
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._probe = XxeProbeTool(session=session) if session else XxeProbeTool()
        self._gen = XxePayloadGenerator()
        self._dtd = XxeDocTypeBuilder()

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CollapsedXxeTool")
        if err:
            return err
        op = data.get("operation")
        if op not in _ALLOWED_OPERATIONS:
            return (
                f"[CollapsedXxeTool] Error: 'operation' must be one of "
                f"{list(_ALLOWED_OPERATIONS)}, got {op!r}."
            )
        # Strip the operation key before forwarding so each sub-tool sees
        # only its own arg shape.
        payload = {k: v for k, v in data.items() if k != "operation"}
        sub_input = json.dumps(payload)
        if op == "probe":
            return self._probe.use(sub_input)
        if op == "generate_payload":
            return self._gen.use(sub_input)
        # build_doctype
        return self._dtd.use(sub_input)
