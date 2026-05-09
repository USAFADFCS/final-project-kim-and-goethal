"""Tests for v3.10 live-run remediation (P1, P2, P4, P5).

Anchored to the gemma4:26b run on Crystal Peak (PicoCTF IDOR-by-md5),
2026-04-29:
  - P1: hash-pattern hint in ``summarize_for_llm``.
  - P2: JSON canonicalization in ``StuckDetector._hash_input``.
  - P4: tightened IDOR description + path-IDOR md5 sample.
  - P5a: hash-hint coverage on full tool output via LoggingToolWrapper.
  - P5b: IDOR ``range_end`` default 100 + miss-hint on all-error results.
  - P5c: attack_planner description + ``unknown`` sample.

Plan: /Users/andrewkim/.claude/plans/jaunty-launching-squirrel.md
"""

from __future__ import annotations

import re

from ctf_solver.tools.attack_planner import AttackPlannerTool
from ctf_solver.tools.core import (
    _HASH_HINT_TAG,
    _detect_hash_hints,
    apply_hash_hints,
    summarize_for_llm,
)
from ctf_solver.tools.idor_tools import IdorEnumeratorTool
from ctf_solver.tools.logging_wrapper import LoggingToolWrapper, StuckDetector
from ctf_solver.tools.schema import validate_tool_input

# ── P1: hash-pattern hint ─────────────────────────────────────────────


class TestSummarizeHashHint:
    """``summarize_for_llm`` should append a deterministic hint when an
    isolated 32 / 64 hex-char token is present, and must not fire on
    flag matches or already-hinted text.
    """

    MD5 = "e93028bdc1aacdfb3687181f2031765d"
    SHA256 = "a" * 64

    def test_md5_in_url_path_yields_hint(self) -> None:
        text = (
            "[FormSubmitTool] Method: POST\n"
            f"URL: http://example.com/profile/user/{self.MD5}\n"
            "Body: Access level: Guest (ID: 3000)."
        )
        out = summarize_for_llm(text)
        assert _HASH_HINT_TAG in out
        assert "id_type='md5'" in out
        assert "32-char hex token" in out

    def test_sha256_yields_sha_specific_hint(self) -> None:
        text = f"observed token: {self.SHA256}"
        out = summarize_for_llm(text)
        assert "64-char hex token" in out
        assert "operation='sha256'" in out

    def test_flag_match_is_not_misclassified(self) -> None:
        # The 8-char hex inside picoCTF{...} must NOT trigger a hint
        # because (a) it's only 8 chars, (b) flag matches are excluded.
        text = "Found flag: picoCTF{deadbeef}"
        out = summarize_for_llm(text, flag_regex=r"picoCTF\{[^}]+\}")
        assert _HASH_HINT_TAG not in out

    def test_md5_inside_flag_envelope_excluded(self) -> None:
        # If a 32-hex-char string appears WITHIN a flag, do not hint —
        # the agent already has the flag; a hint would be noise.
        text = f"Final answer: picoCTF{{{self.MD5}}}"
        out = summarize_for_llm(text, flag_regex=r"picoCTF\{[^}]+\}")
        assert _HASH_HINT_TAG not in out

    def test_idempotent_no_double_hint(self) -> None:
        # Running summarize_for_llm on already-summarized output must
        # not duplicate the hint line.
        text = f"User token: {self.MD5}"
        once = summarize_for_llm(text)
        twice = summarize_for_llm(once)
        assert once.count(_HASH_HINT_TAG) == 1
        assert twice.count(_HASH_HINT_TAG) == 1

    def test_dedupe_same_token_repeated(self) -> None:
        # Same token mentioned 3× → still one hint.
        text = f"id={self.MD5} id={self.MD5} id={self.MD5}"
        out = summarize_for_llm(text)
        assert out.count(_HASH_HINT_TAG) == 1

    def test_limit_three_distinct_md5_tokens(self) -> None:
        # Five distinct md5s → cap at three hints.
        tokens = [
            "e" * 32,
            "f" * 32,
            "1" * 32,
            "2" * 32,
            "3" * 32,
        ]
        text = " ".join(f"t={t}" for t in tokens)
        out = summarize_for_llm(text)
        assert out.count(_HASH_HINT_TAG) == 3

    def test_sha1_hex_blob_does_not_match_md5_or_sha256(self) -> None:
        # 40-char hex (SHA-1) is not in the MD5 or SHA-256 boundary —
        # it should NOT produce a hint with the boundary lookarounds.
        text = "sha1=" + ("a" * 40)
        hints = _detect_hash_hints(text, [])
        # No 32/64 isolated tokens present.
        assert hints == []

    def test_helper_returns_empty_when_text_empty(self) -> None:
        assert _detect_hash_hints("", []) == []

    def test_summarize_preserves_flag_when_md5_also_present(self) -> None:
        # The flag-preservation contract must still hold even when a
        # hash hint is appended.
        flag = "picoCTF{my_flag}"
        text = f"<style>{self.MD5}</style>\n{flag}"
        out = summarize_for_llm(text, flag_regex=r"picoCTF\{[^}]+\}")
        assert flag in out
        # The MD5 was inside <style>, so summarize_for_llm strips it
        # before the hash detector sees it — no hint should fire.
        assert _HASH_HINT_TAG not in out


# ── P2: StuckDetector input canonicalization ─────────────────────────


class TestStuckDetectorCanonicalJsonHash:
    def test_key_order_does_not_evade_threshold(self) -> None:
        det = StuckDetector(threshold=3, hard_stop_threshold=None)
        a = '{"url": "http://x/", "method": "GET"}'
        b = '{"method": "GET", "url": "http://x/"}'
        c = '{"url":"http://x/","method":"GET"}'
        # Three semantically-identical calls with different formatting
        # should fire the soft warning by the third.
        assert det.check("deep_recon", a) is None
        assert det.check("deep_recon", b) is None
        warning = det.check("deep_recon", c)
        assert warning is not None
        assert "stuck" in warning.lower() or "loop" in warning.lower()

    def test_whitespace_difference_collapses(self) -> None:
        det = StuckDetector(threshold=3, hard_stop_threshold=None)
        det.check("t", "{}")
        det.check("t", "{ }")
        warning = det.check("t", "  {}  ")
        assert warning is not None

    def test_non_json_falls_back_to_strip(self) -> None:
        # Non-JSON input still hashes — the canonicalize attempt fails
        # silently and we end up with the stripped-string path.
        det = StuckDetector(threshold=3, hard_stop_threshold=None)
        det.check("t", "raw text input")
        det.check("t", "  raw text input  ")
        warning = det.check("t", "raw text input")
        assert warning is not None

    def test_different_inputs_still_distinct(self) -> None:
        det = StuckDetector(threshold=3, hard_stop_threshold=None)
        # Distinct URLs must be tracked under separate counters, even
        # after canonicalization. Two calls each → still under the
        # threshold, no warning fires for either.
        assert det.check("deep_recon", '{"url": "http://a/"}') is None
        assert det.check("deep_recon", '{"url": "http://b/"}') is None
        assert det.check("deep_recon", '{"url": "http://a/"}') is None
        assert det.check("deep_recon", '{"url": "http://b/"}') is None

    def test_hard_stop_still_fires_with_canonicalization(self) -> None:
        det = StuckDetector(threshold=3, hard_stop_threshold=5)
        for _ in range(4):
            det.check("t", '{"a": 1, "b": 2}')
        # Different key order, fifth call total → hard stop fires.
        warning = det.check("t", '{"b": 2, "a": 1}')
        assert warning is not None
        # STUCK_HARD_STOP_TAG is a top-level constant in logging_wrapper;
        # checking the substring is robust to its exact spelling.
        assert "hard stop" in warning.lower() or "STUCK" in warning


# ── P4: IDOR description + path-md5 sample ───────────────────────────


class TestIdorSchemaAndSamples:
    def test_description_disambiguates_param_vs_param_name(self) -> None:
        desc = IdorEnumeratorTool.description.lower()
        # The description must explicitly say what `param` is and what
        # `param_name` is — otherwise gemma will keep confusing them.
        assert "current id value" in desc
        assert "field name" in desc
        # And signal when to use md5 mode.
        assert "32-char hex" in desc

    def test_path_md5_sample_validates_against_schema(self) -> None:
        # The new path-IDOR + md5 sample must validate cleanly.
        samples = IdorEnumeratorTool.samples
        assert len(samples) >= 2, "expected ≥ 2 samples after P4"
        path_md5_sample = next(
            (s for s in samples if s.get("id_type") == "md5"),
            None,
        )
        assert path_md5_sample is not None, "no md5 sample found"
        err = validate_tool_input(path_md5_sample, IdorEnumeratorTool.parameters_schema)
        assert err is None, f"sample failed schema validation: {err}"

    def test_all_samples_validate_against_schema(self) -> None:
        for sample in IdorEnumeratorTool.samples:
            err = validate_tool_input(sample, IdorEnumeratorTool.parameters_schema)
            assert err is None, f"sample {sample!r} failed: {err}"

    def test_path_md5_sample_uses_real_md5_token(self) -> None:
        # The sample's `param` must itself look like an MD5 — defends
        # against a future regression where someone shortens it.
        samples = IdorEnumeratorTool.samples
        md5_sample = next(s for s in samples if s.get("id_type") == "md5")
        token = md5_sample["param"]
        assert re.fullmatch(r"[A-Fa-f0-9]{32}", token), token


# ── P5a: apply_hash_hints + LoggingToolWrapper coverage ──────────────


class TestApplyHashHints:
    MD5 = "e93028bdc1aacdfb3687181f2031765d"

    def test_appends_hint_for_isolated_md5(self) -> None:
        text = f"URL: http://example.com/profile/user/{self.MD5}\nStatus: 200"
        out = apply_hash_hints(text)
        assert _HASH_HINT_TAG in out
        assert "id_type='md5'" in out

    def test_idempotent(self) -> None:
        text = f"token: {self.MD5}"
        once = apply_hash_hints(text)
        twice = apply_hash_hints(once)
        assert once == twice
        assert once.count(_HASH_HINT_TAG) == 1

    def test_short_circuits_when_already_hinted(self) -> None:
        # Even though the input contains a fresh md5, the existing hint
        # tag should suppress double-application.
        text = (
            f"URL: http://x/{self.MD5}\n"
            f"{_HASH_HINT_TAG} 32-char hex token 'aaaaaa…' looks like an MD5.]"
        )
        out = apply_hash_hints(text)
        assert out == text  # unchanged

    def test_empty_text_returns_empty(self) -> None:
        assert apply_hash_hints("") == ""

    def test_no_hash_present_returns_unchanged(self) -> None:
        text = "no interesting content here"
        assert apply_hash_hints(text) == text


class TestLoggingWrapperHintCoverage:
    """``LoggingToolWrapper`` must apply hash-pattern hints to the FULL
    assembled tool output, including fields like ``URL:`` that sit
    outside any ``summarize_for_llm`` body pass.
    """

    MD5 = "e93028bdc1aacdfb3687181f2031765d"

    def test_wrapper_appends_hint_when_md5_in_url_field(self) -> None:
        # Mock a tool whose output is shaped like FormSubmitTool's:
        # the md5 lives in a URL field, NOT in any body summarized via
        # summarize_for_llm. Pre-P5a this would not hint; post-P5a it
        # must.
        class _FakeFormSubmit:
            name = "form_submit"
            description = "fake"

            def use(self, _input: str) -> str:
                return (
                    "[FormSubmitTool] Method: POST\n"
                    f"URL: http://example.com/profile/user/{TestLoggingWrapperHintCoverage.MD5}\n"
                    "Status: 200\n"
                    "Body: Access level: Guest (ID: 3000)."
                )

        wrapper = LoggingToolWrapper(_FakeFormSubmit(), tracker=None)
        out = wrapper.use("{}")
        assert _HASH_HINT_TAG in out
        assert "id_type='md5'" in out

    def test_wrapper_does_not_double_apply_when_inner_already_hinted(
        self,
    ) -> None:
        # If the inner tool's output already carries a hint (e.g. because
        # it ran summarize_for_llm internally), the wrapper must not add
        # a second one.
        already = (
            "[FakeTool] result=info; URL: http://x/" + self.MD5 + "\n"
            f"{_HASH_HINT_TAG} 32-char hex token 'abc…' looks like an MD5.]"
        )

        class _FakeAlreadyHinted:
            name = "fake_tool"
            description = "fake"

            def use(self, _input: str) -> str:
                return already

        wrapper = LoggingToolWrapper(_FakeAlreadyHinted(), tracker=None)
        out = wrapper.use("{}")
        assert out.count(_HASH_HINT_TAG) == 1

    def test_wrapper_skips_hint_when_no_hash_present(self) -> None:
        class _FakePlain:
            name = "fake"
            description = "fake"

            def use(self, _input: str) -> str:
                return "[FakeTool] OK no hashes here."

        wrapper = LoggingToolWrapper(_FakePlain(), tracker=None)
        out = wrapper.use("{}")
        assert _HASH_HINT_TAG not in out


# ── P5b: IDOR range_end default + miss-hint ──────────────────────────


class TestIdorRangeAndMissHint:
    def test_range_end_default_is_100(self) -> None:
        # Schema default is the source of truth for prompt rendering.
        schema = IdorEnumeratorTool.parameters_schema
        assert schema["properties"]["range_end"]["default"] == 100

    def test_description_advertises_default_100(self) -> None:
        assert "default 100" in IdorEnumeratorTool.description

    def test_runtime_default_matches_schema(self) -> None:
        # Mock the network and call use() with no range_end. Inspect the
        # result string for the rendered "ID Range: 0-100" line, which
        # confirms the runtime default. We mock the session so no
        # real HTTP fires.
        from unittest.mock import Mock

        tool = IdorEnumeratorTool(session=Mock())
        # Mock _make_request to always 404 so we don't hit MAX_RANGE
        # iterations on a real connection. We need 101 fake responses
        # (range 0..100 inclusive).
        fake_resp = Mock()
        fake_resp.text = "User not found."
        fake_resp.status_code = 404
        tool._make_request = Mock(return_value=fake_resp)  # type: ignore[method-assign]
        out = tool.use(
            '{"url": "http://x/profile/user/' + "a" * 32 + '",'
            ' "param": "' + "a" * 32 + '", "param_type": "path", '
            '"id_type": "md5"}'
        )
        assert "ID Range: 0-100" in out

    def test_miss_hint_appears_when_all_404(self) -> None:
        from unittest.mock import Mock

        tool = IdorEnumeratorTool(session=Mock())
        fake_resp = Mock()
        fake_resp.text = "User not found."
        fake_resp.status_code = 404
        tool._make_request = Mock(return_value=fake_resp)  # type: ignore[method-assign]
        out = tool.use(
            '{"url": "http://x/profile/user/' + "a" * 32 + '",'
            ' "param": "' + "a" * 32 + '", "param_type": "path", '
            '"id_type": "md5", "range_end": 5}'
        )
        assert "[NEXT STEP]" in out
        assert "range_start=" in out
        assert "1000" in out  # mentions the 4-digit-id heuristic

    def test_miss_hint_absent_when_a_hit_landed(self) -> None:
        from unittest.mock import Mock

        tool = IdorEnumeratorTool(session=Mock())

        call_count = {"n": 0}

        def fake_make_request(*args, **kwargs):
            call_count["n"] += 1
            r = Mock()
            r.text = (
                "Welcome admin. picoCTF{x}"
                if call_count["n"] == 3
                else "User not found."
            )
            r.status_code = 200 if call_count["n"] == 3 else 404
            return r

        tool._make_request = fake_make_request  # type: ignore[method-assign]
        out = tool.use(
            '{"url": "http://x/profile/user/' + "a" * 32 + '",'
            ' "param": "' + "a" * 32 + '", "param_type": "path", '
            '"id_type": "md5", "range_end": 5}'
        )
        # The hint should NOT fire — we got at least one 200 with
        # interesting content.
        assert "[NEXT STEP]" not in out


# ── P5c: attack_planner description + canonical sample ───────────────


class TestAttackPlannerSchemaTightened:
    def test_description_marks_both_required(self) -> None:
        desc = AttackPlannerTool.description
        # Both fields must be flagged as REQUIRED in the description so
        # the model can't miss it on a quick scan.
        assert desc.count("REQUIRED") >= 2

    def test_unknown_challenge_type_sample_present(self) -> None:
        unknowns = [
            s for s in AttackPlannerTool.samples if s.get("challenge_type") == "unknown"
        ]
        assert len(unknowns) >= 1, "no 'unknown' sample — gemma's recovery path"

    def test_all_attack_planner_samples_validate(self) -> None:
        for sample in AttackPlannerTool.samples:
            err = validate_tool_input(sample, AttackPlannerTool.parameters_schema)
            assert err is None, f"sample {sample!r} failed: {err}"
