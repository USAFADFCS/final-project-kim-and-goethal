"""
v3.8 P0: parameters_schema infrastructure.

Validates the Draft-07 subset checker (``validate_tool_input``) and the
prompt-block renderer (``render_tool_schema_block`` / ``render_tools_section``).
"""

from ctf_solver.tools.schema import (
    collect_tool_descriptors,
    render_tool_schema_block,
    render_tools_section,
    validate_tool_input,
)

# ── validate_tool_input ──────────────────────────────────────────────


class TestValidateToolInput:
    schema = {
        "type": "object",
        "properties": {
            "url": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT"],
                "default": "GET",
            },
            "timeout": {"type": "integer"},
            "follow_redirects": {"type": "boolean", "default": True},
            "headers": {"type": "object"},
            "values": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["url"],
        "additionalProperties": False,
    }

    def test_minimal_valid_input(self):
        assert validate_tool_input({"url": "http://x"}, self.schema) is None

    def test_full_valid_input(self):
        data = {
            "url": "http://x",
            "method": "POST",
            "timeout": 5,
            "follow_redirects": False,
            "headers": {"X-A": "1"},
            "values": ["a", "b"],
        }
        assert validate_tool_input(data, self.schema) is None

    def test_missing_required(self):
        err = validate_tool_input({"method": "GET"}, self.schema)
        assert err is not None
        assert "missing required key 'url'" in err

    def test_unknown_key(self):
        err = validate_tool_input({"url": "x", "weird": 1}, self.schema)
        assert err is not None
        assert "weird" in err

    def test_wrong_type(self):
        err = validate_tool_input({"url": "x", "timeout": "five"}, self.schema)
        assert err is not None
        assert "timeout" in err and "integer" in err

    def test_enum_violation(self):
        err = validate_tool_input({"url": "x", "method": "TRACE"}, self.schema)
        assert err is not None
        assert "TRACE" in err

    def test_array_item_type(self):
        err = validate_tool_input({"url": "x", "values": ["a", 2, "b"]}, self.schema)
        assert err is not None
        assert "values" in err and "1" in err  # index 1 is the int

    def test_no_schema_passes_anything(self):
        assert validate_tool_input({"anything": "goes"}, None) is None
        assert validate_tool_input({}, None) is None

    def test_bool_not_integer(self):
        """JSON booleans must not satisfy integer constraints (Python's
        ``isinstance(True, int)`` is True; the helper guards against this)."""
        err = validate_tool_input({"url": "x", "timeout": True}, self.schema)
        assert err is not None and "timeout" in err

    def test_top_level_not_object(self):
        err = validate_tool_input(["url", "x"], self.schema)
        assert err is not None
        assert "object" in err.lower()


# ── render_tool_schema_block ─────────────────────────────────────────


class TestRenderSchemaBlock:
    def test_renders_name_and_description(self):
        block = render_tool_schema_block(
            "http_fetch", "Perform an HTTP request.", schema=None
        )
        assert "**http_fetch**" in block
        assert "Perform an HTTP request" in block

    def test_truncates_long_description(self):
        long = "X " * 500
        block = render_tool_schema_block("noisy", long, schema=None, description_max=80)
        assert "…" in block
        # Stays roughly within bound
        assert len(block.split("—")[1]) <= 130

    def test_renders_args_with_required_optional(self):
        schema = {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"]},
            },
            "required": ["url"],
        }
        block = render_tool_schema_block("x", "desc", schema)
        assert "url<string, required>" in block
        assert "method<string, optional, values=[GET, POST]>" in block

    def test_renders_default(self):
        schema = {
            "type": "object",
            "properties": {"timeout": {"type": "integer", "default": 10}},
            "required": [],
        }
        block = render_tool_schema_block("x", "desc", schema)
        assert "timeout<integer, optional, default=10>" in block

    def test_renders_sample(self):
        schema = {"type": "object", "properties": {"url": {"type": "string"}}}
        samples = [{"url": "http://example.com"}]
        block = render_tool_schema_block("x", "desc", schema, samples)
        assert 'sample: {"url":"http://example.com"}' in block

    def test_no_schema_no_args_line(self):
        block = render_tool_schema_block("x", "desc", None)
        assert "args:" not in block


# ── collect_tool_descriptors / render_tools_section ──────────────────


class _FakeTool:
    def __init__(self, name, description, schema=None, samples=None):
        self.name = name
        self.description = description
        if schema is not None:
            self.parameters_schema = schema
        if samples is not None:
            self.samples = samples


class _FakeWrapper:
    """Mimics LoggingToolWrapper: forwards .name/.description, exposes inner."""

    def __init__(self, inner):
        self.inner = inner
        self.name = inner.name
        self.description = inner.description


class TestCollectAndRender:
    def test_collect_extracts_schema_via_inner(self):
        inner = _FakeTool(
            "robots_txt",
            "Fetch robots.txt",
            schema={
                "type": "object",
                "properties": {"base_url": {"type": "string"}},
                "required": ["base_url"],
            },
        )
        wrapper = _FakeWrapper(inner)
        descriptors = collect_tool_descriptors([wrapper])
        assert len(descriptors) == 1
        name, desc, schema, samples = descriptors[0]
        assert name == "robots_txt"
        assert desc == "Fetch robots.txt"
        assert schema and schema["properties"]["base_url"]["type"] == "string"

    def test_collect_skips_unnamed(self):
        descriptors = collect_tool_descriptors([_FakeTool("", "x")])
        assert descriptors == []

    def test_render_section_handles_mixed_schemas(self):
        tools = [
            _FakeTool(
                "with_schema",
                "has args",
                schema={
                    "type": "object",
                    "properties": {"x": {"type": "string"}},
                    "required": ["x"],
                },
            ),
            _FakeTool("no_schema", "free-form input"),
        ]
        section = render_tools_section(collect_tool_descriptors(tools))
        assert "**with_schema**" in section
        assert "x<string, required>" in section
        assert "**no_schema**" in section
        # The no-schema tool must still appear (gradual migration).
        assert "args:" in section.split("**no_schema**")[0]
        assert "args:" not in section.split("**no_schema**")[1]


# ── get_system_prompt integration ────────────────────────────────────


class TestGetSystemPromptCatalog:
    def test_no_descriptors_no_catalog_section(self):
        from ctf_solver.prompts import get_system_prompt

        prompt = get_system_prompt(platform_name="X")
        assert "## Tool catalog" not in prompt

    def test_descriptors_append_catalog(self):
        from ctf_solver.prompts import get_system_prompt

        descriptors = [
            (
                "robots_txt",
                "Fetch robots.txt",
                {
                    "type": "object",
                    "properties": {"base_url": {"type": "string"}},
                    "required": ["base_url"],
                },
                [{"base_url": "http://example.com"}],
            )
        ]
        prompt = get_system_prompt(platform_name="X", tool_descriptors=descriptors)
        assert "## Tool catalog" in prompt
        assert "**robots_txt**" in prompt
        assert "base_url<string, required>" in prompt
        assert '"base_url":"http://example.com"' in prompt

    def test_real_tools_have_catalog_lines(self):
        """Smoke test: a few of the real top-tier tools render with their
        schemas attached."""
        from ctf_solver.prompts import get_system_prompt
        from ctf_solver.tools import (
            CookieSetTool,
            EncodingTool,
            HttpFetchTool,
        )
        from ctf_solver.tools.schema import collect_tool_descriptors

        tools = [HttpFetchTool(), CookieSetTool(), EncodingTool()]
        descriptors = collect_tool_descriptors(tools)
        prompt = get_system_prompt(tool_descriptors=descriptors)
        assert "**http_fetch**" in prompt
        assert "url<string, required>" in prompt
        assert "**cookie_set**" in prompt
        assert "**encoding**" in prompt
        # Sample line shows up for at least one
        assert "sample:" in prompt
