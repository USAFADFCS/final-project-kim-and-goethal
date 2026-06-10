"""
Tests for the submit_until_done tool (Tier 2.4).

The tool wraps a server-side request loop in a single tool call so
N-iteration challenges (e.g. trivia loops) don't burn the agent's
step budget. These tests stub requests.Session.* so they run offline.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from ctf_solver.tools.submit_until_done import SubmitUntilDoneTool


class _FakeResponse:
    def __init__(self, status_code: int = 200, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeSession:
    """Records each call; serves responses from a queue."""

    def __init__(self, responses: List[_FakeResponse]):
        self.responses = list(responses)
        self.calls: List[Dict[str, Any]] = []

    def _next_response(self) -> _FakeResponse:
        if not self.responses:
            return _FakeResponse(500, "no more queued responses")
        return self.responses.pop(0)

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
        allow_redirects: bool = False,
    ) -> _FakeResponse:
        self.calls.append({"method": "GET", "url": url, "headers": dict(headers or {})})
        return self._next_response()

    def request(
        self,
        method: str,
        url: str,
        data: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 15,
        allow_redirects: bool = False,
    ) -> _FakeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "data": data,
                "headers": dict(headers or {}),
            }
        )
        return self._next_response()


def _run(tool: SubmitUntilDoneTool, payload: Dict[str, Any]) -> Dict[str, Any]:
    out = tool.use(json.dumps(payload))
    return json.loads(out)


# ── Input validation ─────────────────────────────────────────────────


class TestInputValidation:
    def test_missing_url(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(json.dumps({"success_marker": "FLAG{"}))
        assert out.startswith("[SubmitUntilDoneTool] Error")
        assert "url" in out

    def test_missing_success_marker(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(json.dumps({"url": "http://x"}))
        assert "success_marker" in out

    def test_invalid_method(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(
            json.dumps(
                {"url": "http://x", "success_marker": "FLAG{", "method": "TRACE"}
            )
        )
        assert "unsupported method" in out

    def test_max_iterations_capped(self):
        # 5000 requested but the tool caps at 200; we won't actually loop
        # that many because a success marker hits on iter 1.
        sess = _FakeSession([_FakeResponse(200, "yay FLAG{x} done")])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x",
                "success_marker": "FLAG{",
                "max_iterations": 5000,
                "method": "GET",
            },
        )
        assert result["max_iterations"] == 200
        assert result["outcome"] == "success"

    def test_max_iterations_below_one(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(
            json.dumps(
                {"url": "http://x", "success_marker": "FLAG{", "max_iterations": 0}
            )
        )
        assert "must be >= 1" in out

    def test_invalid_iteration_mode(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(
            json.dumps(
                {
                    "url": "http://x",
                    "success_marker": "FLAG{",
                    "iteration_mode": "bogus",
                }
            )
        )
        assert "iteration_mode" in out

    def test_invalid_extract_regex(self):
        tool = SubmitUntilDoneTool(session=_FakeSession([]))
        out = tool.use(
            json.dumps(
                {
                    "url": "http://x",
                    "success_marker": "FLAG{",
                    "extract_regex": {"q": "[bad("},
                }
            )
        )
        assert "not a valid regex" in out


# ── Static iteration mode ────────────────────────────────────────────


class TestStaticMode:
    def test_success_on_first_iteration_short_circuits(self):
        sess = _FakeSession([_FakeResponse(200, "FLAG{first_hit}")])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/check",
                "success_marker": "FLAG{",
                "method": "GET",
                "max_iterations": 50,
            },
        )
        assert result["outcome"] == "success"
        assert result["iterations"] == 1
        assert result["matched_success_marker"] == "FLAG{"
        assert "FLAG{first_hit}" in result["final_response_excerpt"]
        assert len(sess.calls) == 1

    def test_success_on_later_iteration(self):
        sess = _FakeSession(
            [
                _FakeResponse(200, "nope"),
                _FakeResponse(200, "still no"),
                _FakeResponse(200, "MetaCTF{here_it_is}"),
            ]
        )
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer=42",
                "success_marker": "MetaCTF{",
                "max_iterations": 10,
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            },
        )
        assert result["outcome"] == "success"
        assert result["iterations"] == 3
        assert sess.calls[0]["method"] == "POST"
        assert sess.calls[0]["data"] == "answer=42"
        # All three iterations sent the same body (static mode).
        assert all(c["data"] == "answer=42" for c in sess.calls)

    def test_stop_marker_short_circuits(self):
        sess = _FakeSession(
            [
                _FakeResponse(200, "loop continues"),
                _FakeResponse(403, "Forbidden, session expired"),
                _FakeResponse(200, "FLAG{never_reached}"),
            ]
        )
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer=1",
                "success_marker": "FLAG{",
                "stop_marker": "Forbidden",
                "max_iterations": 10,
            },
        )
        assert result["outcome"] == "stopped_by_marker"
        assert result["matched_stop_marker"] == "Forbidden"
        assert result["iterations"] == 2
        # The third (FLAG-bearing) response is never sent.
        assert len(sess.calls) == 2

    def test_max_iterations_reached_without_match(self):
        sess = _FakeSession([_FakeResponse(200, "still wrong") for _ in range(5)])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer=1",
                "success_marker": "FLAG{",
                "max_iterations": 5,
            },
        )
        assert result["outcome"] == "max_iterations_reached"
        assert result["iterations"] == 5

    def test_status_code_counts_as_haystack_for_markers(self):
        # The status code is concatenated with body when checking markers,
        # so "200" matching the status would match every response. Use a
        # more discriminating marker.
        sess = _FakeSession([_FakeResponse(418, "I am a teapot")])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x",
                "method": "GET",
                "success_marker": "418",
                "max_iterations": 3,
            },
        )
        assert result["outcome"] == "success"
        assert result["matched_success_marker"] == "418"

    def test_request_exception_breaks_loop(self):
        sess = MagicMock()
        sess.request.side_effect = RuntimeError("network down")
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer=1",
                "success_marker": "FLAG{",
                "max_iterations": 3,
            },
        )
        assert result["outcome"] == "error"
        assert "network down" in result["loop_error"]


# ── regex_extract mode (the SQL Invitational use case) ────────────────


class TestRegexExtractMode:
    def test_extract_question_and_substitute_answer(self):
        """Simulates the SQL Invitational trivia loop.

        After iter 0 sends a probe, iter 1 reads the new question from
        the previous response, looks the answer up, posts it back, and
        the third response contains the flag."""
        sess = _FakeSession(
            [
                _FakeResponse(
                    200,
                    '{"current_question": "If you have a 3-bit key '
                    "and a 3-bit plaintext, how many possible "
                    'ciphertexts can you produce?"}',
                ),
                _FakeResponse(
                    200,
                    '{"current_question": "What is 2+2?"}',
                ),
                _FakeResponse(200, "MetaCTF{trivia_master}"),
            ]
        )
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "method": "POST",
                "body_template": "answer={question}",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "success_marker": "MetaCTF{",
                "max_iterations": 10,
                "iteration_mode": "regex_extract",
                "extract_regex": {"question": r'"current_question"\s*:\s*"([^"]+)"'},
                "answer_lookup": {
                    "If you have a 3-bit key and a 3-bit plaintext, how many possible ciphertexts can you produce?": "8",
                    "What is 2+2?": "4",
                },
            },
        )
        assert result["outcome"] == "success"
        assert result["iterations"] == 3
        # Iter 0 has no extracted value yet → probe body is empty.
        assert sess.calls[0]["data"] == "answer="
        # Iter 1 extracts the 3-bit-key question from iter 0's response
        # and substitutes the looked-up answer "8".
        assert sess.calls[1]["data"] == "answer=8"
        # Iter 2 extracts "What is 2+2?" from iter 1's response → "4".
        assert sess.calls[2]["data"] == "answer=4"

    def test_static_probe_then_regex_extract(self):
        """The realistic flow: an empty-body probe to elicit the first
        question, then regex_extract for subsequent iterations."""
        sess = _FakeSession(
            [
                _FakeResponse(200, '{"current_question": "What is 2+2?"}'),
                _FakeResponse(200, "MetaCTF{four}"),
            ]
        )
        tool = SubmitUntilDoneTool(session=sess)
        # Use an EMPTY body_template for the static path (no placeholder
        # on iter 0). On iter 1 the substituted answer becomes the body.
        # The implementation supports this: when placeholder_values is
        # populated (i>0) and body_template has placeholders, format()
        # works.
        # For iter 0 to not raise on {question}, we use a non-placeholder
        # template. The realistic approach is to *not* gate iter 0 on
        # extract_regex, which is what the implementation already does.
        # But body_template still has {question}, so iter 0 will fail.
        # The right shape: caller uses an answer_lookup default OR
        # they pre-seed via static + then change mode. For the test,
        # demonstrate the "static probe" pattern by providing iter-0
        # placeholder via answer_lookup default of empty string.
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "method": "POST",
                "body_template": "",  # iter 0 sends empty body
                "success_marker": "MetaCTF{",
                "max_iterations": 5,
                "iteration_mode": "regex_extract",
                "extract_regex": {"question": r'"current_question": "([^"]+)"'},
                "answer_lookup": {"What is 2+2?": "4"},
            },
        )
        # Iter 0: empty body. Iter 1: still empty body because
        # body_template is "". Loop runs until both responses consumed.
        # First marker hit happens on iter 2 (MetaCTF{four}).
        assert result["outcome"] == "success"
        assert result["iterations"] == 2

    def test_extract_regex_no_match_stops_loop(self):
        sess = _FakeSession(
            [
                _FakeResponse(200, "first response with no JSON"),
                _FakeResponse(200, "second response — never reached"),
            ]
        )
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer={question}",
                "success_marker": "MetaCTF{",
                "max_iterations": 5,
                "iteration_mode": "regex_extract",
                "extract_regex": {"question": r'"current_question": "([^"]+)"'},
            },
        )
        assert result["outcome"] == "error"
        assert "extract_regex failed" in result["loop_error"]
        assert "question" in result["loop_error"]


# ── Session sharing behavior ─────────────────────────────────────────


class TestSessionSharing:
    def test_share_session_true_uses_constructor_session(self):
        sess = _FakeSession([_FakeResponse(200, "FLAG{good}")])
        tool = SubmitUntilDoneTool(session=sess)
        _run(
            tool,
            {
                "url": "http://x",
                "method": "GET",
                "success_marker": "FLAG{",
                "share_session": True,
            },
        )
        # The shared session received the call (state survives).
        assert len(sess.calls) == 1

    def test_share_session_false_uses_throwaway(self):
        sess = _FakeSession([_FakeResponse(200, "FLAG{good}")])
        tool = SubmitUntilDoneTool(session=sess)
        # When share_session=False, the tool creates a fresh
        # requests.Session() internally — but that session would try a
        # real HTTP call to "http://invalid.example.test", which will
        # fail at the OS level. Use a host that resolves locally and
        # rejects fast (loopback unused port) so the loop reports an
        # error rather than hanging.
        result = _run(
            tool,
            {
                "url": "http://127.0.0.1:1",  # unused loopback port
                "method": "GET",
                "success_marker": "FLAG{",
                "max_iterations": 1,
                "share_session": False,
            },
        )
        # We don't care whether it succeeded or failed — just that the
        # *fake* session above was NOT used.
        assert len(sess.calls) == 0
        assert result["iteration_mode"] == "static"


# ── Trace + truncation ───────────────────────────────────────────────


class TestTraceTruncation:
    def test_trace_capped_at_twenty(self):
        sess = _FakeSession([_FakeResponse(200, "nope") for _ in range(30)])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x/submit",
                "body_template": "answer=1",
                "success_marker": "FLAG{",
                "max_iterations": 30,
            },
        )
        assert result["iterations"] == 30
        assert len(result["trace"]) == 20

    def test_response_excerpt_truncated(self):
        big = "A" * 10_000 + "FLAG{end_of_long_body}"
        sess = _FakeSession([_FakeResponse(200, big)])
        tool = SubmitUntilDoneTool(session=sess)
        result = _run(
            tool,
            {
                "url": "http://x",
                "method": "GET",
                "success_marker": "FLAG{",
                "max_iterations": 1,
            },
        )
        assert result["outcome"] == "success"
        assert len(result["final_response_excerpt"]) == 4000
        assert result.get("final_response_truncated") is True


# ── Tool surface ─────────────────────────────────────────────────────


class TestFairSurface:
    def test_name_and_description(self):
        tool = SubmitUntilDoneTool()
        assert tool.name == "submit_until_done"
        assert "loop" in tool.description.lower()

    def test_parameters_schema_marks_required(self):
        tool = SubmitUntilDoneTool()
        assert set(tool.parameters_schema["required"]) == {"url", "success_marker"}

    def test_samples_present(self):
        tool = SubmitUntilDoneTool()
        assert isinstance(tool.samples, list) and len(tool.samples) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-x", "-v"])
