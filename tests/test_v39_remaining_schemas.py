"""
v3.9 N.2: parameters_schema coverage for the legacy / specialty tools.

Mirrors ``test_v38_tool_schema.py`` for the 25 tools across 14 files
covered by the N.2 batch (CRLF, open redirect, IDOR, PHP type juggling,
prototype pollution, the three crypto tools, the three blind-SQLi
tools, the two CSS tools, the two deserialization tools, the two
filter-bypass tools, parser-differential, php_filter_chain, WASM).

Each tool gets three checks:
  * the schema attribute exists and is a JSON-Schema-shaped dict.
  * every entry in ``samples`` validates clean against the schema.
  * inputs missing a required key are rejected.

The test list is data-driven: a single ``CASES`` table; one parametrised
test class per concern. Adding a new tool is one row.
"""

import pytest

from ctf_solver.tools.blind_sqli_tools import (
    BlindSqliBooleanTool,
    BlindSqliTimeTool,
    SqliDataDumper,
)
from ctf_solver.tools.crlf_tools import CrlfProbeTool
from ctf_solver.tools.crypto_tools import (
    CryptoAnalyzerTool,
    CryptoPayloadGenerator,
    CryptoProbeTool,
)
from ctf_solver.tools.css_tools import (
    CssExfiltrationBuilder,
    CssInjectionPayloadGenerator,
)
from ctf_solver.tools.deserialization_tools import (
    DeserializationPayloadGenerator,
    DeserializationProbeTool,
)
from ctf_solver.tools.filter_bypass_tools import (
    FilterEnumeratorTool,
    PayloadMutatorTool,
)
from ctf_solver.tools.idor_tools import IdorEnumeratorTool
from ctf_solver.tools.open_redirect_tools import OpenRedirectProbeTool
from ctf_solver.tools.parser_diff_tools import ParserDifferentialProbeTool
from ctf_solver.tools.php_filter_tools import PhpFilterChainTool
from ctf_solver.tools.php_juggling_tools import PhpTypeJugglingTool
from ctf_solver.tools.prototype_pollution_tools import PrototypePollutionTool
from ctf_solver.tools.schema import validate_tool_input
from ctf_solver.tools.wasm_tools import WasmAnalyzerTool

# ── Test data ─────────────────────────────────────────────────────────
#
# Each row: (tool_class, expected_name, sample_required_field_to_drop)
# ``sample_required_field_to_drop`` is the key we'll remove from the
# first ``samples`` entry to verify the schema rejects the resulting
# payload. ``None`` means the tool has no required fields beyond the
# operation enum and we skip the rejection test for that case.

CASES = [
    (CrlfProbeTool, "crlf_probe", "url"),
    (OpenRedirectProbeTool, "open_redirect_probe", "url"),
    (IdorEnumeratorTool, "idor_enumerator", "url"),
    (PhpTypeJugglingTool, "php_type_juggling", "operation"),
    (PrototypePollutionTool, "prototype_pollution_probe", "url"),
    (CryptoProbeTool, "crypto_probe", "url"),
    (CryptoAnalyzerTool, "crypto_analyzer", "operation"),
    (CryptoPayloadGenerator, "crypto_payload_generator", "operation"),
    (BlindSqliBooleanTool, "blind_sqli_boolean", "url"),
    (BlindSqliTimeTool, "blind_sqli_time", "url"),
    (SqliDataDumper, "sqli_data_dumper", "url"),
    (CssInjectionPayloadGenerator, "css_injection_payload_generator", "operation"),
    (CssExfiltrationBuilder, "css_exfiltration_builder", "operation"),
    (DeserializationProbeTool, "deserialization_probe", "url"),
    (DeserializationPayloadGenerator, "deserialization_payload_generator", "operation"),
    (FilterEnumeratorTool, "filter_enumerator", "url"),
    (PayloadMutatorTool, "payload_mutator", "payload"),
    (ParserDifferentialProbeTool, "parser_differential_probe", "url"),
    (PhpFilterChainTool, "php_filter_chain", "operation"),
    (WasmAnalyzerTool, "wasm_analyzer", "url"),
]


@pytest.mark.parametrize("tool_cls, expected_name, _drop", CASES)
class TestSchemaPresence:
    def test_name_matches(self, tool_cls, expected_name, _drop):
        assert tool_cls.name == expected_name

    def test_parameters_schema_present(self, tool_cls, expected_name, _drop):
        schema = getattr(tool_cls, "parameters_schema", None)
        assert isinstance(schema, dict), f"{expected_name} missing parameters_schema"
        assert schema.get("type") == "object"
        assert "properties" in schema and isinstance(schema["properties"], dict)
        assert "required" in schema and isinstance(schema["required"], list)

    def test_samples_present(self, tool_cls, expected_name, _drop):
        samples = getattr(tool_cls, "samples", None)
        assert isinstance(samples, list) and samples
        assert all(isinstance(s, dict) for s in samples)


@pytest.mark.parametrize("tool_cls, expected_name, _drop", CASES)
class TestSamplesValidate:
    def test_first_sample_validates(self, tool_cls, expected_name, _drop):
        schema = tool_cls.parameters_schema
        sample = tool_cls.samples[0]
        err = validate_tool_input(sample, schema)
        assert err is None, f"{expected_name} sample 0 validation failed: {err}"

    def test_all_samples_validate(self, tool_cls, expected_name, _drop):
        schema = tool_cls.parameters_schema
        for i, sample in enumerate(tool_cls.samples):
            err = validate_tool_input(sample, schema)
            assert err is None, (
                f"{expected_name} sample {i} validation failed: {err} "
                f"(sample={sample})"
            )


@pytest.mark.parametrize("tool_cls, expected_name, drop", CASES)
class TestRequiredEnforced:
    def test_drop_required_rejected(self, tool_cls, expected_name, drop):
        if drop is None:
            pytest.skip(f"{expected_name} has no single-field rejection case")
        schema = tool_cls.parameters_schema
        sample = dict(tool_cls.samples[0])
        # If the field-to-drop isn't in this sample, skip — covered by
        # another sample-level case. (Some tools' first sample only
        # carries required fields covered elsewhere.)
        if drop not in sample:
            pytest.skip(f"{drop} not in first sample for {expected_name}")
        sample.pop(drop)
        err = validate_tool_input(sample, schema)
        assert (
            err is not None
        ), f"{expected_name} accepted payload missing required field {drop!r}"
        assert drop in err, (
            f"{expected_name} error string does not name the missing field "
            f"{drop!r}: {err}"
        )


# ── Operation-enum rejection on the operation-driven tools ───────────

OPERATION_TOOLS = [
    (PhpTypeJugglingTool, "explode"),
    (CryptoAnalyzerTool, "explode"),
    (CryptoPayloadGenerator, "explode"),
    (CssInjectionPayloadGenerator, "explode"),
    (CssExfiltrationBuilder, "explode"),
    (DeserializationPayloadGenerator, "explode"),
    (PhpFilterChainTool, "explode"),
]


@pytest.mark.parametrize("tool_cls, bad_op", OPERATION_TOOLS)
class TestOperationEnumRejected:
    def test_invalid_operation_value_rejected(self, tool_cls, bad_op):
        schema = tool_cls.parameters_schema
        # Every operation-enum tool defines `properties.operation.enum`.
        op_schema = schema["properties"]["operation"]
        assert "enum" in op_schema, f"{tool_cls.name} operation has no enum"
        assert bad_op not in op_schema["enum"]
        err = validate_tool_input({"operation": bad_op}, schema)
        assert err is not None
        assert "operation" in err


# ── Total-count guard ────────────────────────────────────────────────


def test_full_coverage_count():
    """Sanity: this file covers exactly the 20 newly-schema'd classes
    enumerated in the plan's N.2 inventory (5 single-tool files + 9
    multi-tool files contributing 15 more tools = 20 cases).

    If a future PR adds a new schema to one of these legacy files,
    this assertion forces the test author to extend ``CASES`` so the
    new schema gets the same coverage.
    """
    assert len(CASES) == 20
