"""
Collapsed SQLi family tool (v3.8 P0 main).

Dispatches to the five underlying SQLi tools via a single ``operation``
enum.  This is the largest family collapse in the suite — 5 → 1 is the
biggest dispatch reduction the agent benefits from on SQLi-heavy
challenges, where the model historically had to choose between
``sqli_probe`` / ``sqli_column_counter`` / ``sqli_data_dumper`` /
``blind_sqli_boolean`` / ``blind_sqli_time`` without strong cues from
the names alone.
"""

from __future__ import annotations

import json
from typing import Optional

import requests

from ctf_solver.tools.blind_sqli_tools import (
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
)
from ctf_solver.tools.core import parse_json_input
from ctf_solver.tools.sqli_tools import SqliColumnCounter, SqliProbeTool

_ALLOWED_OPERATIONS = (
    "probe",
    "count_columns",
    "dump",
    "blind_boolean",
    "blind_time",
)


class CollapsedSqliTool:
    """Single SQLi entry point with an ``operation`` enum.

    Operations:
      - ``probe``: forwards to ``SqliProbeTool`` — confirm injection.
      - ``count_columns``: forwards to ``SqliColumnCounter`` — find
        column count for UNION-based extraction.
      - ``dump``: forwards to ``SqliDataDumper`` — UNION-based row
        extraction once column count is known.
      - ``blind_boolean``: forwards to ``BlindSqliBooleanTool`` — for
        targets without visible output but boolean-distinguishable
        responses.
      - ``blind_time``: forwards to ``BlindSqliTimeTool`` — for fully
        blind targets where only response timing differs.
    """

    name: str = "sqli_attack"
    description: str = (
        "Unified SQL-injection entry point. Pick 'operation' to dispatch: "
        "'probe' (confirm injection — needs 'url'), 'count_columns' "
        "(find UNION column count — needs 'url'), 'dump' (UNION-based row "
        "extraction — needs 'url' + 'columns'), 'blind_boolean' "
        "(boolean-blind — needs 'url' + 'true_marker'/'false_marker'), or "
        "'blind_time' (time-blind — needs 'url' + 'delay')."
    )
    parameters_schema = {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": list(_ALLOWED_OPERATIONS),
            },
            "url": {"type": "string"},
            "param": {"type": "string"},
            "method": {"type": "string"},
            "data": {"type": "object"},
            "headers": {"type": "object"},
            "columns": {"type": "integer"},
            "table": {"type": "string"},
            "column": {"type": "string"},
            "where": {"type": "string"},
            "true_marker": {"type": "string"},
            "false_marker": {"type": "string"},
            "delay": {"type": "number"},
            "max_columns": {"type": "integer"},
            "dbms": {"type": "string"},
        },
        "required": ["operation"],
        "additionalProperties": True,
    }
    samples = [
        {"operation": "probe", "url": "http://example.com/?id=1", "param": "id"},
        {
            "operation": "count_columns",
            "url": "http://example.com/?id=1",
            "param": "id",
        },
        {
            "operation": "dump",
            "url": "http://example.com/?id=1",
            "param": "id",
            "columns": 3,
            "table": "users",
        },
        {
            "operation": "blind_boolean",
            "url": "http://example.com/login",
            "param": "username",
            "true_marker": "Welcome",
        },
        {
            "operation": "blind_time",
            "url": "http://example.com/login",
            "param": "username",
            "delay": 5,
        },
    ]

    def __init__(self, session: Optional[requests.Session] = None) -> None:
        self._probe = SqliProbeTool(session=session) if session else SqliProbeTool()
        self._counter = (
            SqliColumnCounter(session=session) if session else SqliColumnCounter()
        )
        self._dumper = SqliDataDumper(session=session) if session else SqliDataDumper()
        self._bool = (
            BlindSqliBooleanTool(session=session) if session else BlindSqliBooleanTool()
        )
        self._time = (
            BlindSqliTimeTool(session=session) if session else BlindSqliTimeTool()
        )

    def use(self, tool_input: str) -> str:
        data, err = parse_json_input(tool_input, "CollapsedSqliTool")
        if err:
            return err
        op = data.get("operation")
        if op not in _ALLOWED_OPERATIONS:
            return (
                f"[CollapsedSqliTool] Error: 'operation' must be one of "
                f"{list(_ALLOWED_OPERATIONS)}, got {op!r}."
            )
        payload = {k: v for k, v in data.items() if k != "operation"}
        sub_input = json.dumps(payload)
        if op == "probe":
            return self._probe.use(sub_input)
        if op == "count_columns":
            return self._counter.use(sub_input)
        if op == "dump":
            return self._dumper.use(sub_input)
        if op == "blind_boolean":
            return self._bool.use(sub_input)
        return self._time.use(sub_input)
