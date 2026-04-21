"""Tests for ``ctf_solver.taxonomy`` (Batch C #14).

Canonical tool→category source.  These tests lock in:

- ``failure_analyzer._TOOL_TO_CATEGORY`` is the taxonomy alias (same ``id``)
- ``logging_wrapper._TOOL_CATEGORIES`` keys are either in the canonical
  dict OR explicitly listed as display-only overrides.  Adding a new tool
  to ``logging_wrapper`` without adding it to the taxonomy (or vice versa)
  now fails a test instead of silently drifting.
"""

from ctf_solver.failure_analyzer import _CATEGORY_LABELS, _TOOL_TO_CATEGORY
from ctf_solver.taxonomy import CATEGORY_LABELS, TOOL_TO_CATEGORY
from ctf_solver.tools.logging_wrapper import _TOOL_CATEGORIES

# Keys in logging_wrapper that are intentionally remapped for display.
# ``jwt_tool`` → ``jwt`` (vs canonical ``jwt_attacks``): shorter suggestion text.
# ``attack_planner`` → ``planning`` (vs canonical ``recon``): the call-site
#   filter skips both, so splitting them is cosmetic but deliberate.
# ``html_inspector`` → ``recon`` (vs canonical ``client_side``): logging
#   treats it as still-in-discovery.
# ``http_fetch`` → ``recon`` (not in canonical at all): intentionally omitted
#   from canonical to avoid biasing category inference (``http_fetch`` is the
#   most-called tool in every run).
_DISPLAY_ONLY_OVERRIDES = {
    "jwt_tool",
    "attack_planner",
    "html_inspector",
    "http_fetch",
}


class TestTaxonomyIsCanonical:
    def test_failure_analyzer_imports_the_same_object(self):
        assert _TOOL_TO_CATEGORY is TOOL_TO_CATEGORY
        assert _CATEGORY_LABELS is CATEGORY_LABELS

    def test_canonical_dict_is_non_empty(self):
        assert len(TOOL_TO_CATEGORY) >= 50
        assert len(CATEGORY_LABELS) >= 20

    def test_every_category_value_has_a_label(self):
        categories = set(TOOL_TO_CATEGORY.values())
        missing = categories - set(CATEGORY_LABELS)
        assert (
            missing == set()
        ), f"Categories without a CATEGORY_LABELS entry: {sorted(missing)}"


class TestLoggingWrapperDriftProtection:
    def test_every_logging_key_is_known(self):
        """A tool listed in logging_wrapper must either be in the canonical
        taxonomy or explicitly acknowledged as a display-only override."""
        unknown = [
            tool
            for tool in _TOOL_CATEGORIES
            if tool not in TOOL_TO_CATEGORY and tool not in _DISPLAY_ONLY_OVERRIDES
        ]
        assert unknown == [], (
            f"Tools in logging_wrapper._TOOL_CATEGORIES that are neither in "
            f"canonical taxonomy nor in _DISPLAY_ONLY_OVERRIDES: {unknown}. "
            "Either add them to ctf_solver/taxonomy.py::TOOL_TO_CATEGORY or "
            "extend the override set in tests/test_taxonomy.py."
        )

    def test_overrides_values_differ_intentionally(self):
        """Each override must actually have a different value than the
        canonical — otherwise it shouldn't be an override."""
        for tool in _DISPLAY_ONLY_OVERRIDES:
            if tool in _TOOL_CATEGORIES and tool in TOOL_TO_CATEGORY:
                assert _TOOL_CATEGORIES[tool] != TOOL_TO_CATEGORY[tool], (
                    f"Override for {tool!r} has the same value as canonical "
                    f"({TOOL_TO_CATEGORY[tool]!r}) — drop it from the overrides set."
                )
