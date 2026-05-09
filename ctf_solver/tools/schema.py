"""
Tool parameter schemas (v3.8 P0 main).

Each FAIR-style tool may declare a class-level ``parameters_schema``
attribute holding a Draft-07 JSON Schema describing its ``tool_input``.
The schema is the single source of truth for:

  1. The tool-listing block rendered into ``DEFAULT_SYSTEM_PROMPT`` (so
     every tool's args show up consistently as a typed key/value table
     instead of free-form prose).
  2. Validation of the model's ``tool_input`` before the tool runs
     (catches missing required keys / wrong types before the wrapped
     tool produces a less helpful error).
  3. Function-calling / structured-output integration on adapters that
     support it (Ollama function calling, Anthropic tool use, OpenAI
     function calling).  The schema feeds straight into the
     ``parameters`` field of the provider's tool-call schema.

The convention deliberately uses a small subset of Draft-07 so the
resulting prompt block stays compact and renderable for a 26B model.
Allowed at the top level:

    {
      "type": "object",
      "properties": {
          "<key>": {
              "type": "string|integer|number|boolean|array|object",
              "description": "<short hint, ideally < 80 chars>",
              "enum": [...],         # optional
              "default": ...,         # optional
              "items": {...},         # only when type == "array"
          }
      },
      "required": ["<key>", ...],
      "additionalProperties": false  # recommended for the tightest gate
    }

A ``samples`` list (also class-level) optionally holds exemplar JSON
inputs that pass the schema; the renderer surfaces the first sample so
the LLM sees a copy-paste template alongside the type info.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

# ── Validation ────────────────────────────────────────────────────────


def _coerce_type(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "null":
        return value is None
    return True  # unknown type — don't fail the validator


def validate_tool_input(
    data: Dict[str, Any], schema: Optional[Dict[str, Any]]
) -> Optional[str]:
    """Validate ``data`` against ``schema``.

    Returns ``None`` on success, or a one-line human-readable error string.
    Designed to be called from each tool's ``.use()`` after JSON parsing —
    cheap and dependency-free (does not pull in jsonschema).

    Only the subset of Draft-07 we use is checked: type, required,
    additionalProperties, enum, items.type.
    """
    if not schema:
        return None
    if schema.get("type") == "object" and not isinstance(data, dict):
        return f"tool_input must be a JSON object, got {type(data).__name__}"
    properties = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []
    for key in required:
        if key not in data:
            return f"missing required key '{key}'"
    additional = schema.get("additionalProperties", True)
    if additional is False:
        unknown = [k for k in data.keys() if k not in properties]
        if unknown:
            return f"unknown key(s): {', '.join(sorted(unknown))}"
    for key, value in data.items():
        prop_schema = properties.get(key)
        if not prop_schema:
            continue
        expected = prop_schema.get("type")
        if expected and not _coerce_type(value, expected):
            return (
                f"key '{key}' must be type '{expected}', " f"got {type(value).__name__}"
            )
        enum = prop_schema.get("enum")
        if enum is not None and value not in enum:
            return f"key '{key}' must be one of {enum}, got {value!r}"
        if expected == "array":
            item_schema = prop_schema.get("items")
            if item_schema and "type" in item_schema:
                inner_type = item_schema["type"]
                for i, item in enumerate(value):
                    if not _coerce_type(item, inner_type):
                        return (
                            f"key '{key}'[{i}] must be type "
                            f"'{inner_type}', got {type(item).__name__}"
                        )
    return None


# ── Rendering for the system prompt ──────────────────────────────────


def render_tool_schema_block(
    tool_name: str,
    description: str,
    schema: Optional[Dict[str, Any]],
    samples: Optional[List[Dict[str, Any]]] = None,
    *,
    description_max: int = 200,
) -> str:
    """Render one tool's schema as a compact prompt block.

    Output format::

        - **<tool_name>** — <truncated description>
            args: key1<type, required>, key2<type, optional, default=…>, …
            sample: {"key1": "...", ...}

    Designed to read densely so 75 tools fit in a few KB of prompt.
    """
    desc_clean = " ".join((description or "").split())
    if len(desc_clean) > description_max:
        desc_clean = desc_clean[: description_max - 1].rstrip() + "…"
    lines = [f"- **{tool_name}** — {desc_clean}"]
    if schema:
        properties = schema.get("properties") or {}
        required = set(schema.get("required") or [])
        if properties:
            arg_parts: List[str] = []
            for key, ps in properties.items():
                t = ps.get("type", "any")
                req = "required" if key in required else "optional"
                tail = ""
                enum = ps.get("enum")
                if enum:
                    tail += f", values=[{', '.join(map(str, enum))}]"
                if "default" in ps:
                    tail += f", default={ps['default']!r}"
                arg_parts.append(f"{key}<{t}, {req}{tail}>")
            lines.append("    args: " + ", ".join(arg_parts))
    if samples:
        sample = samples[0]
        try:
            import json as _json

            lines.append("    sample: " + _json.dumps(sample, separators=(",", ":")))
        except Exception:
            pass
    return "\n".join(lines)


def render_tools_section(
    tools: Iterable[
        Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]]]
    ],
) -> str:
    """Render a list of ``(name, description, schema, samples)`` tuples
    into the full ``Tool listing`` section of the system prompt.

    Tools without a ``parameters_schema`` still render their description
    line — the migration to schemas is incremental.
    """
    blocks = [
        render_tool_schema_block(name, desc, schema, samples)
        for name, desc, schema, samples in tools
    ]
    return "\n".join(blocks)


def collect_tool_descriptors(
    tool_instances: Iterable[Any],
) -> List[Tuple[str, str, Optional[Dict[str, Any]], Optional[List[Dict[str, Any]]]]]:
    """Pull ``(name, description, parameters_schema, samples)`` from each
    tool instance (or LoggingToolWrapper).  Falls back to the inner tool
    when the wrapper does not forward the schema attributes."""
    out = []
    for tool in tool_instances:
        inner = getattr(tool, "inner", tool)
        name = getattr(tool, "name", None) or getattr(inner, "name", "")
        if not name:
            continue
        description = (
            getattr(tool, "description", None)
            or getattr(inner, "description", "")
            or ""
        )
        schema = getattr(inner, "parameters_schema", None) or getattr(
            tool, "parameters_schema", None
        )
        samples = getattr(inner, "samples", None) or getattr(tool, "samples", None)
        out.append((name, description, schema, samples))
    return out
