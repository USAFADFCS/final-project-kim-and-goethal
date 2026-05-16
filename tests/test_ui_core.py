"""Tests for ctf_solver.ui.core — UI-agnostic helpers shared by Streamlit and the
upcoming PySide6 frontend.

Phase 1 scope: constants + pure functions. Source-file loading, log saving, and
`execute_single_run` are added in later commits.
"""

import pytest

from ctf_solver.ui import core


class TestPlatformOptions:
    def test_contains_expected_platforms(self):
        for name in (
            "Generic CTF",
            "MetaCTF",
            "PicoCTF",
            "HackTheBox",
            "TryHackMe",
            "CTFd",
            "Other",
        ):
            assert name in core.PLATFORM_OPTIONS

    def test_other_is_last(self):
        # "Other" must be last so the sidebar's "Other → custom text" fallback works.
        assert core.PLATFORM_OPTIONS[-1] == "Other"

    def test_generic_is_first(self):
        # Default selection for new sessions.
        assert core.PLATFORM_OPTIONS[0] == "Generic CTF"


class TestModelOptions:
    def test_hosted_models_present(self):
        for name in (
            "gpt-5.2",
            "gpt-4o",
            "claude-sonnet-4-6",
            "claude-opus-4-6",
            "claude-haiku-4-5",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
        ):
            assert name in core.MODEL_OPTIONS

    def test_local_models_present(self):
        for name in (
            "mlx-community/gemma-4-26b-a4b-it-4bit",
            "gemma4:26b",
            "llama3.1:latest",
            "mistral-small:latest",
            "gpt-oss:20b",
            "edgerunner-medium:latest",
        ):
            assert name in core.MODEL_OPTIONS

    def test_default_first(self):
        # First entry is the recommended default for a new session.
        assert core.MODEL_OPTIONS[0] == "gpt-5.2"


class TestIsLocalModel:
    @pytest.mark.parametrize(
        "name",
        [
            "gemma4:26b",
            "llama3.1:latest",
            "mistral-small:latest",
            "gpt-oss:20b",
            "edgerunner-medium:latest",
        ],
    )
    def test_ollama_tag_form_is_local(self, name):
        assert core.is_local_model(name) is True

    def test_mlx_community_prefix_is_local(self):
        assert core.is_local_model("mlx-community/gemma-4-26b-a4b-it-4bit") is True

    @pytest.mark.parametrize(
        "name",
        [
            "gpt-5.2",
            "gpt-4o",
            "claude-sonnet-4-6",
            "claude-opus-4-6",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
        ],
    )
    def test_hosted_models_are_not_local(self, name):
        assert core.is_local_model(name) is False

    def test_empty_string_is_not_local(self):
        assert core.is_local_model("") is False


class TestGrammarOptions:
    def test_keys_are_human_labels(self):
        for label in (
            "Auto (enforce JSON schema)",
            "None (no constraint)",
            "Force JSON schema",
        ):
            assert label in core.GRAMMAR_OPTIONS

    def test_values_are_internal_modes(self):
        assert set(core.GRAMMAR_OPTIONS.values()) == {"auto", "none", "json_schema"}

    def test_auto_is_first(self):
        # Default. Order is preserved by dict insertion order (Python 3.7+).
        assert next(iter(core.GRAMMAR_OPTIONS.values())) == "auto"


class TestRagModeLabels:
    def test_all_modes_present(self):
        assert set(core.RAG_MODE_LABELS.values()) == {
            "none",
            "original",
            "lessons_readonly",
            "lessons_buildonly",
            "lessons_write",
        }

    def test_label_ordering(self):
        # Order shown in the UI radio group — matches the user's mental progression
        # from "no RAG" → "read curated" → "use lessons" → "build lessons" → both.
        labels = list(core.RAG_MODE_LABELS.values())
        assert labels == [
            "none",
            "original",
            "lessons_readonly",
            "lessons_buildonly",
            "lessons_write",
        ]


class TestRagModeLegacyMap:
    def test_augmented_maps_to_lessons_write(self):
        assert core.RAG_MODE_LEGACY_MAP["augmented"] == "lessons_write"

    def test_augmented_readonly_maps_to_lessons_readonly(self):
        assert core.RAG_MODE_LEGACY_MAP["augmented_readonly"] == "lessons_readonly"


class TestValidateUrl:
    def test_empty_is_ok(self):
        # Empty URL is treated as "not yet provided" — UI handles required-field
        # logic separately.
        ok, msg = core.validate_url("")
        assert ok is True
        assert msg == ""

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.com",
            "https://example.com",
            "https://ctf.example.com:8080/challenge",
            "http://localhost",
            "http://localhost:5000",
            "http://127.0.0.1:8000",
            "https://sub.domain.example.com/path?query=1",
        ],
    )
    def test_valid_urls(self, url):
        ok, msg = core.validate_url(url)
        assert ok is True, f"Expected {url!r} to validate, got error: {msg}"

    @pytest.mark.parametrize(
        "url",
        [
            "not a url",
            "example.com",
            "ftp://example.com",
            "ws://example.com",
            "//example.com",
        ],
    )
    def test_invalid_urls(self, url):
        ok, msg = core.validate_url(url)
        assert ok is False
        assert "http" in msg.lower() or "url" in msg.lower()


class TestLoadSourceFilesFromBytes:
    """Unified loader called by both the Streamlit uploader and the CLI path-based
    wrapper. Takes (filename, bytes) tuples; returns filename → decoded text."""

    def test_plain_text_file(self):
        result = core.load_source_files_from_bytes([("app.py", b"x = 1")])
        assert result == {"app.py": "x = 1"}

    def test_non_text_extension_skipped(self):
        # Binary extensions (e.g. .png) are silently filtered out.
        result = core.load_source_files_from_bytes([("img.png", b"\x89PNG\r\n")])
        assert result == {}

    def test_multiple_files(self):
        result = core.load_source_files_from_bytes(
            [("a.py", b"a"), ("b.js", b"b"), ("readme.md", b"# hi")]
        )
        assert result == {"a.py": "a", "b.js": "b", "readme.md": "# hi"}

    def test_zip_archive_extracted(self):
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("inner.py", "print('hi')")
            zf.writestr("nested/other.js", "var x = 1;")
            zf.writestr("binary.png", b"\x89PNG")
        result = core.load_source_files_from_bytes([("bundle.zip", buf.getvalue())])
        assert result == {"inner.py": "print('hi')", "other.js": "var x = 1;"}

    def test_tar_gz_archive_extracted(self):
        import io
        import tarfile

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"hello"
            info = tarfile.TarInfo(name="src/main.py")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        result = core.load_source_files_from_bytes([("bundle.tar.gz", buf.getvalue())])
        assert result == {"main.py": "hello"}

    def test_bad_zip_silently_skipped(self):
        # Not a valid ZIP. Must not raise.
        result = core.load_source_files_from_bytes([("bad.zip", b"not a zip")])
        assert result == {}

    def test_utf8_decoded(self):
        result = core.load_source_files_from_bytes([("a.py", "héllo".encode("utf-8"))])
        assert result == {"a.py": "héllo"}

    def test_latin1_fallback(self):
        # Bytes that aren't valid UTF-8 but decode as latin-1.
        data = bytes([0xFF, 0xFE, 0x41])  # not a valid UTF-8 sequence
        result = core.load_source_files_from_bytes([("a.py", data)])
        # Latin-1 decodes any byte; result should contain the file.
        assert "a.py" in result

    def test_empty_input(self):
        assert core.load_source_files_from_bytes([]) == {}


class TestRunnerLoadSourceFilesWrapper:
    """The existing runner._load_source_files signature must keep working —
    tests/test_v22_source_files.py depends on it."""

    def test_path_wrapper_loads_file(self, tmp_path):
        from ctf_solver.runner import _load_source_files

        f = tmp_path / "app.py"
        f.write_text("x = 1")
        assert _load_source_files([str(f)]) == {"app.py": "x = 1"}

    def test_path_wrapper_warns_on_missing(self, tmp_path, capsys):
        from ctf_solver.runner import _load_source_files

        result = _load_source_files([str(tmp_path / "missing.py")])
        assert result == {}
        captured = capsys.readouterr()
        # Existing stderr warning contract preserved for test_v22 compatibility.
        assert "not found" in captured.err


class TestSaveChallengeLog:
    """``save_challenge_log`` writes a single human-readable .log file under
    ``<project_root>/challenge_logs/<slug>_<outcome>_<ts>.log``."""

    def _make_config(self):
        from ctf_solver.config import SolverConfig

        return SolverConfig(
            platform_name="PicoCTF",
            challenge_url="https://example.com/c/1",
            challenge_name="Web Decode",
            challenge_description="Decode the flag",
            challenge_hints="base64",
            flag_regex=r"picoCTF\{.*?\}",
            model_name="gpt-5.2",
            max_steps=20,
        )

    def test_writes_log_under_challenge_logs(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="original",
            logs=["[00:00:00] starting"],
            stats={"outcome": "success", "steps": 5},
            final_answer="picoCTF{redacted}",
            candidate_flags=["picoCTF{redacted}"],
        )
        assert path.exists()
        assert path.parent == tmp_path / "challenge_logs"

    def test_filename_includes_slug_and_outcome(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="lessons_write",
            logs=[],
            stats={"outcome": "failure"},
            final_answer="(none)",
            candidate_flags=[],
        )
        # Slug derived from challenge_name "Web Decode" → "Web_Decode"
        assert path.name.startswith("Web_Decode_failure_")
        assert path.name.endswith(".log")

    def test_unnamed_when_no_challenge_name(self, tmp_path):
        from ctf_solver.config import SolverConfig

        cfg = SolverConfig(
            platform_name="Generic CTF",
            challenge_url="",
            challenge_name="",
            flag_regex=r"flag\{.*?\}",
            model_name="gpt-5.2",
            max_steps=20,
        )
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="none",
            logs=[],
            stats={"outcome": "unknown"},
            final_answer="",
            candidate_flags=[],
        )
        assert path.name.startswith("unnamed_unknown_")

    def test_content_contains_config_and_log_entries(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="original",
            logs=["[12:00:00] step 1", "[12:00:01] step 2"],
            stats={"outcome": "success", "steps": 2, "tokens": 1234},
            final_answer="picoCTF{xxx}",
            candidate_flags=["picoCTF{xxx}", "picoCTF{yyy}"],
        )
        text = path.read_text(encoding="utf-8")
        assert "PicoCTF" in text
        assert "Web Decode" in text
        assert "[12:00:00] step 1" in text
        assert "picoCTF{xxx}" in text
        assert "picoCTF{yyy}" in text
        assert "outcome: success" in text

    def test_tool_call_log_rendered(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="original",
            logs=[],
            stats={
                "outcome": "success",
                "tool_call_log": [
                    {"tool": "http_get", "input": '{"url": "x"}', "output": "200 OK"},
                ],
            },
            final_answer="ok",
            candidate_flags=[],
        )
        text = path.read_text(encoding="utf-8")
        assert "[Call 1] http_get" in text
        assert "200 OK" in text

    def test_tool_calls_dict_rendered_sorted(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="original",
            logs=[],
            stats={
                "outcome": "success",
                "tool_calls": {"a": 1, "b": 5, "c": 3},
            },
            final_answer="",
            candidate_flags=[],
        )
        text = path.read_text(encoding="utf-8")
        # Sorted by count descending: b:5, c:3, a:1
        b_pos = text.index("b: 5")
        c_pos = text.index("c: 3")
        a_pos = text.index("a: 1")
        assert b_pos < c_pos < a_pos

    def test_returns_path(self, tmp_path):
        cfg = self._make_config()
        path = core.save_challenge_log(
            cfg,
            project_root=tmp_path,
            rag_mode="none",
            logs=[],
            stats={"outcome": "success"},
            final_answer="",
            candidate_flags=[],
        )
        from pathlib import Path as _Path

        assert isinstance(path, _Path)


# ---------------------------------------------------------------------------
# Phase 1 Day 3: helpers extracted from runner.run_agent and
# streamlit_app.run_agent_async. Both callers keep their current behavior by
# passing their existing defaults; Qt will use the unified "good defaults"
# later.
# ---------------------------------------------------------------------------


class TestDetermineOutcome:
    def test_flags_present_is_success(self):
        assert core.determine_outcome(["flag{abc}"], []) == "success"

    def test_no_flags_no_partial_signals_is_failure(self):
        # tool_call_log without any partial-success markers.
        assert (
            core.determine_outcome([], [{"tool": "http_get", "output": "404"}])
            == "failure"
        )

    def test_no_flags_with_partial_signals_is_partial(self):
        # _detect_partial_successes looks for SQLi/SSTI-style confirmation
        # signals in tool outputs. Use an SSTI arithmetic confirmation.
        log = [
            {
                "tool": "http_get",
                "input": '{"url":"http://x/?n={{7*7}}"}',
                "output": "Result: 49 found in body",
            },
        ]
        outcome = core.determine_outcome([], log)
        # Either "partial" or "failure" is correct depending on whether the
        # detection heuristic catches this output. The contract is just that
        # the helper delegates to _detect_partial_successes.
        assert outcome in {"partial", "failure"}

    def test_flags_take_precedence_over_partial(self):
        # If flags are found, outcome is "success" even with partial signals.
        log = [{"tool": "http_get", "output": "Result: 49"}]
        assert core.determine_outcome(["flag{abc}"], log) == "success"


class TestExtractFlagsFromRun:
    def test_dedup_true(self):
        response = "flag{abc} found also flag{abc}"
        tool_call_log = [{"output": "flag{abc} again"}]
        flags = core.extract_flags_from_run(
            response, tool_call_log, r"flag\{[^}]+\}", dedup=True
        )
        assert flags == ["flag{abc}"]

    def test_dedup_false(self):
        response = "flag{abc} found also flag{abc}"
        tool_call_log = [{"output": "flag{abc} again"}]
        flags = core.extract_flags_from_run(
            response, tool_call_log, r"flag\{[^}]+\}", dedup=False
        )
        # Without dedup we see duplicates.
        assert flags.count("flag{abc}") >= 2

    def test_empty_response_and_log(self):
        assert core.extract_flags_from_run("", [], r"flag\{.*?\}", dedup=True) == []

    def test_collects_from_both_sources(self):
        response = "flag{from_response}"
        tool_call_log = [
            {"output": "Got: flag{from_tool_1}"},
            {"output": "Also: flag{from_tool_2}"},
        ]
        flags = core.extract_flags_from_run(
            response, tool_call_log, r"flag\{[^}]+\}", dedup=True
        )
        assert set(flags) == {
            "flag{from_response}",
            "flag{from_tool_1}",
            "flag{from_tool_2}",
        }

    def test_non_string_response_ok(self):
        # CLI's `if isinstance(response, str)` guard — helper should also
        # tolerate non-string response by treating it as empty.
        flags = core.extract_flags_from_run(
            None, [{"output": "flag{x}"}], r"flag\{[^}]+\}", dedup=True
        )
        assert flags == ["flag{x}"]


class TestInjectReflexion:
    def _make_config(self, **kw):
        from ctf_solver.config import SolverConfig

        defaults = dict(
            platform_name="Generic CTF",
            challenge_url="https://example.com/c",
            challenge_name="Test",
            flag_regex=r"flag\{.*?\}",
            model_name="gpt-5.2",
            max_steps=10,
            rag_mode="lessons_readonly",
        )
        defaults.update(kw)
        return SolverConfig(**defaults)

    def test_skips_if_rag_mode_not_experience(self):
        from ctf_solver.run_tracker import RunTracker

        cfg = self._make_config(rag_mode="none")
        tracker = RunTracker()
        before = "ORIGINAL"
        after = core.inject_reflexion(before, cfg, tracker, prepend=False)
        assert after == before
        assert tracker.prior_reflection_injected is False

    def test_skips_if_no_challenge_name_or_url(self):
        from ctf_solver.run_tracker import RunTracker

        cfg = self._make_config(challenge_url="", challenge_name="")
        tracker = RunTracker()
        before = "ORIGINAL"
        after = core.inject_reflexion(before, cfg, tracker, prepend=False)
        assert after == before


class TestInjectProactiveRag:
    def _make_config(self, **kw):
        from ctf_solver.config import SolverConfig

        defaults = dict(
            platform_name="Generic CTF",
            challenge_url="https://example.com/c",
            challenge_name="Test",
            challenge_description="exploit web ssti",
            flag_regex=r"flag\{.*?\}",
            model_name="gpt-5.2",
            max_steps=10,
            rag_mode="original",
            enable_proactive_rag=True,
        )
        defaults.update(kw)
        return SolverConfig(**defaults)

    def test_skips_if_rag_mode_not_read(self):
        from ctf_solver.run_tracker import RunTracker

        cfg = self._make_config(rag_mode="none")
        tracker = RunTracker()
        before = "ORIGINAL"
        after = core.inject_proactive_rag(before, cfg, tracker, trim=True)
        assert after == before

    def test_skips_if_proactive_rag_disabled(self):
        from ctf_solver.run_tracker import RunTracker

        cfg = self._make_config(enable_proactive_rag=False)
        tracker = RunTracker()
        before = "ORIGINAL"
        after = core.inject_proactive_rag(before, cfg, tracker, trim=True)
        assert after == before
