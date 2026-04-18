"""Shared utilities for tool implementations (Batch D #6).

All 37+ FAIR-style tools historically hand-rolled the same JSON parsing
boilerplate (~15 LOC × 37 files ≈ 555 LOC).  ``parse_json_input`` gives
them a single call and a consistent error message so new tools avoid the
drift, and existing tools can migrate incrementally (``http_tools.py`` is
the first adopter — a proof-of-concept for the rest of the suite).

Error format is the most common variant across the existing codebase:
``[ToolName] Error: tool_input must be JSON. Decoding failed with: <exc>``.
Migrating a tool should not change the error string it produces — verify
against the tool's own tests before switching.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple


def parse_json_input(
    tool_input: str, tool_name: str
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parse ``tool_input`` as JSON.

    Returns ``(data, None)`` on success or ``(None, error_message)`` on
    JSON decode failure.  Empty / None / whitespace input returns
    ``({}, None)`` — the tool can then apply its own defaults.

    Mirrors the dominant error format used across existing tools; adopt
    incrementally, verifying each tool's own tests still pass.
    """
    if not tool_input or not tool_input.strip():
        return {}, None
    try:
        data = json.loads(tool_input)
    except json.JSONDecodeError as exc:
        return (
            None,
            f"[{tool_name}] Error: tool_input must be JSON. "
            f"Decoding failed with: {exc}",
        )
    if not isinstance(data, dict):
        return (
            None,
            f"[{tool_name}] Error: tool_input must be a JSON object, "
            f"got {type(data).__name__}.",
        )
    return data, None


__all__ = ["parse_json_input"]
