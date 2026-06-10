"""
Tests for Tier 2.5 — per-category prompt overlays.

Covers two layers:
  - the overlay-builder ``build_category_overlay`` (pure function over
    a ClassificationResult)
  - integration with ``get_system_prompt`` so we know the overlay
    actually lands in the rendered prompt
"""

from __future__ import annotations

from ctf_solver.classifier.challenge_classifier import (
    ChallengeCategory,
    ClassificationResult,
)
from ctf_solver.config import SolverConfig
from ctf_solver.prompts.category_overlays import (
    MIN_OVERLAY_CONFIDENCE,
    build_category_overlay,
)
from ctf_solver.prompts.templates import get_system_prompt


def _result(
    cat: ChallengeCategory,
    confidence: float = 0.8,
    secondary=(),
) -> ClassificationResult:
    return ClassificationResult(
        primary_category=cat,
        confidence=confidence,
        secondary_categories=[(c, conf) for c, conf in secondary],
    )


# ── build_category_overlay ───────────────────────────────────────────


class TestBuildCategoryOverlay:
    def test_none_result_returns_empty(self):
        assert build_category_overlay(None) == ""

    def test_unknown_category_returns_empty(self):
        result = _result(ChallengeCategory.UNKNOWN, confidence=0.9)
        assert build_category_overlay(result) == ""

    def test_low_confidence_returns_empty(self):
        # Below the threshold → no overlay.
        result = _result(
            ChallengeCategory.SQL_INJECTION,
            confidence=MIN_OVERLAY_CONFIDENCE - 0.01,
        )
        assert build_category_overlay(result) == ""

    def test_threshold_boundary_inclusive(self):
        result = _result(
            ChallengeCategory.SQL_INJECTION,
            confidence=MIN_OVERLAY_CONFIDENCE,
        )
        out = build_category_overlay(result)
        assert out != ""
        assert "sql_injection" in out.lower()

    def test_authentication_overlay_mentions_session_decode(self):
        # This is the SQL Invitational failure-mode category.
        result = _result(ChallengeCategory.AUTHENTICATION, confidence=0.7)
        out = build_category_overlay(result)
        assert "flask_session_forge" in out
        assert "submit_until_done" in out
        # The "do not pivot to SQLi early" anti-pattern is present.
        assert "SQLi" in out or "sqli" in out.lower()

    def test_file_inclusion_overlay_mentions_lfi_probe(self):
        # This is the Microdosing failure-mode category.
        result = _result(ChallengeCategory.FILE_INCLUSION, confidence=0.7)
        out = build_category_overlay(result)
        assert "lfi_probe" in out
        # Anti-pattern: warn against burning steps on /search-style endpoints.
        assert "/search" in out

    def test_overlay_lists_priority_tools(self):
        result = _result(ChallengeCategory.SQL_INJECTION, confidence=0.9)
        out = build_category_overlay(result)
        assert "Priority tools" in out
        assert "sqli_probe" in out

    def test_overlay_includes_approach_section(self):
        result = _result(ChallengeCategory.JWT, confidence=0.9)
        out = build_category_overlay(result)
        assert "Approach" in out
        # APPROACH_SUGGESTIONS for JWT contains "Decode and analyze JWT".
        assert "Decode" in out

    def test_overlay_includes_secondary_categories(self):
        result = _result(
            ChallengeCategory.SQL_INJECTION,
            confidence=0.8,
            secondary=[
                (ChallengeCategory.AUTHENTICATION, 0.5),
                (ChallengeCategory.XSS, 0.3),
            ],
        )
        out = build_category_overlay(result)
        assert "also consider" in out.lower()
        assert "authentication" in out.lower()

    def test_overlay_handles_category_with_no_guidance(self):
        # WASM_RE has no _CATEGORY_GUIDANCE entry; overlay should still
        # render the priority tools + approach without crashing.
        result = _result(ChallengeCategory.WASM_RE, confidence=0.7)
        out = build_category_overlay(result)
        # The "Do" / "Do NOT" sections are absent for this category.
        assert "Do NOT" not in out
        # But the overall header is still there.
        assert "wasm_re" in out


# ── get_system_prompt integration ────────────────────────────────────


class TestPromptIntegration:
    def test_no_classification_yields_no_overlay_section(self):
        prompt = get_system_prompt(platform_name="Test", classification=None)
        assert "Category-specific guidance" not in prompt

    def test_classification_injects_overlay_section(self):
        result = _result(ChallengeCategory.SQL_INJECTION, confidence=0.9)
        prompt = get_system_prompt(platform_name="Test", classification=result)
        assert "Category-specific guidance" in prompt
        assert "sql_injection" in prompt

    def test_low_confidence_classification_skipped(self):
        result = _result(
            ChallengeCategory.SQL_INJECTION,
            confidence=MIN_OVERLAY_CONFIDENCE - 0.1,
        )
        prompt = get_system_prompt(platform_name="Test", classification=result)
        assert "Category-specific guidance" not in prompt

    def test_overlay_appears_after_tool_catalog(self):
        """When both a tool catalog and overlay are present, the overlay
        must come AFTER the catalog — the catalog is the authoritative
        argument reference and the overlay is bias on top."""
        result = _result(ChallengeCategory.SQL_INJECTION, confidence=0.9)
        descriptors = [
            ("http_fetch", "Fetch a URL", None, None),
            ("sqli_probe", "Probe for SQL injection", None, None),
        ]
        prompt = get_system_prompt(
            platform_name="Test",
            tool_descriptors=descriptors,
            classification=result,
        )
        catalog_idx = prompt.index("Tool catalog")
        overlay_idx = prompt.index("Category-specific guidance")
        assert catalog_idx < overlay_idx


# ── Config flag ──────────────────────────────────────────────────────


class TestConfigFlag:
    def test_default_is_on(self):
        cfg = SolverConfig()
        assert cfg.enable_category_overlay is True

    def test_can_be_disabled(self):
        cfg = SolverConfig(enable_category_overlay=False)
        assert cfg.enable_category_overlay is False
