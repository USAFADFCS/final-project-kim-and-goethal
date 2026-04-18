"""
Tests for CTF Solver configuration and flag extraction.
"""

import os
import pytest
from pathlib import Path

from ctf_solver.config import (
    SolverConfig,
    extract_candidate_flags,
    is_valid_flag,
    validate_flag_regex,
    COMMON_FLAG_PATTERNS,
    DEFAULT_FLAG_REGEX,
)


class TestFlagRegex:
    """Tests for flag regex validation and extraction."""

    def test_validate_valid_regex(self):
        """Test that valid regex patterns pass validation."""
        is_valid, error = validate_flag_regex(r"flag\{.*\}")
        assert is_valid is True
        assert error == ""

    def test_validate_invalid_regex(self):
        """Test that invalid regex patterns fail validation."""
        is_valid, error = validate_flag_regex(r"flag\{[")
        assert is_valid is False
        assert "unterminated" in error.lower() or "character" in error.lower()

    def test_default_regex_is_valid(self):
        """Test that the default regex is valid."""
        is_valid, _ = validate_flag_regex(DEFAULT_FLAG_REGEX)
        assert is_valid is True

    def test_all_preset_patterns_valid(self):
        """Test that all preset patterns are valid."""
        for name, pattern in COMMON_FLAG_PATTERNS.items():
            is_valid, error = validate_flag_regex(pattern)
            assert is_valid is True, f"Pattern '{name}' is invalid: {error}"


class TestFlagExtraction:
    """Tests for flag extraction functionality."""

    def test_extract_picoctf_flag(self):
        """Test extracting PicoCTF format flags."""
        text = "The flag is picoCTF{example_flag_123} hidden here."
        flags = extract_candidate_flags(text, COMMON_FLAG_PATTERNS["picoctf"])
        assert flags == ["picoCTF{example_flag_123}"]

    def test_extract_htb_flag(self):
        """Test extracting HackTheBox format flags."""
        text = "Congrats! Your flag: HTB{y0u_g0t_1t_h4x0r}"
        flags = extract_candidate_flags(text, COMMON_FLAG_PATTERNS["htb"])
        assert flags == ["HTB{y0u_g0t_1t_h4x0r}"]

    def test_extract_generic_flag(self):
        """Test extracting generic format flags."""
        text = "Multiple flags: flag{one} and CTF{two} and custom{three}"
        flags = extract_candidate_flags(text, DEFAULT_FLAG_REGEX)
        assert len(flags) == 3
        assert "flag{one}" in flags
        assert "CTF{two}" in flags
        assert "custom{three}" in flags

    def test_extract_no_flags(self):
        """Test extraction when no flags are present."""
        text = "This text contains no flags at all."
        flags = extract_candidate_flags(text, COMMON_FLAG_PATTERNS["picoctf"])
        assert flags == []

    def test_extract_multiple_flags(self):
        """Test extracting multiple flags from text."""
        text = "picoCTF{flag1} some text picoCTF{flag2} more text picoCTF{flag3}"
        flags = extract_candidate_flags(text, COMMON_FLAG_PATTERNS["picoctf"])
        assert len(flags) == 3

    def test_extract_with_invalid_regex(self):
        """Test extraction with invalid regex returns empty list."""
        flags = extract_candidate_flags("test", r"[invalid")
        assert flags == []

    def test_extract_flag_with_special_chars(self):
        """Test extracting flags with special characters."""
        text = "picoCTF{sp3c!al_ch4rs_&_stuff}"
        flags = extract_candidate_flags(text, COMMON_FLAG_PATTERNS["picoctf"])
        assert flags == ["picoCTF{sp3c!al_ch4rs_&_stuff}"]


class TestFlagNoiseFilter:
    """Gap A: generic flag regex must reject CSS/JSON/PHP/bare-brace noise
    while still accepting real prefixed flags. Observed false-positive sources
    come from the 2026-04-17 MetaCTF batch (see out/batch_20260417/)."""

    def test_rejects_bare_brace_php_payload(self):
        """Agent-generated PHP payload must not be mistaken for a flag."""
        assert extract_candidate_flags("{system($_GET['cmd']);}") == []

    def test_rejects_css_rule(self):
        """CSS keyframe / transform rules matched {opacity:0;} under v2.5."""
        noise = ".foo { opacity: 0; transform: translateY(20px); }"
        assert extract_candidate_flags(noise) == []

    def test_rejects_plain_json_object(self):
        """Livestream surfaced 34 JSON false positives in a single run."""
        noise = '{"user":"Administrator","isAdmin":true}'
        assert extract_candidate_flags(noise) == []

    def test_rejects_socketio_framed_json(self):
        """Socket.IO frames have a numeric prefix (e.g. '0', '40', '42')
        followed by JSON. Prefix matches [A-Za-z0-9_]+ so the regex alone
        cannot catch them — the content-shape filter must."""
        noise = '0{"sid":"ABC","pingInterval":25000}'
        assert extract_candidate_flags(noise) == []

    def test_rejects_empty_json_results(self):
        """From Microdosing run #14: {"results":[]}."""
        assert extract_candidate_flags('{"results":[]}') == []

    def test_accepts_real_metactf_flag(self):
        """Exact flag observed in Snowfall Wishes run #8."""
        text = "flag was MetaCTF{c0ld_h4nds_w4rm_h34rts} in the source"
        flags = extract_candidate_flags(text)
        assert "MetaCTF{c0ld_h4nds_w4rm_h34rts}" in flags

    def test_accepts_picoctf_with_underscores(self):
        """Underscores and digits inside braces must still pass."""
        text = "picoCTF{wh4t_1s_7h3_fl4g}"
        flags = extract_candidate_flags(text)
        assert "picoCTF{wh4t_1s_7h3_fl4g}" in flags

    def test_accepts_metactf_with_question_mark_and_punctuation(self):
        """Observed in Dot-Matrix Destruction: MetaCTF{y3ah_xxe_d0e5_r0ck_d0esnt_it?}."""
        text = "MetaCTF{y3ah_xxe_d0e5_r0ck_d0esnt_it?}"
        flags = extract_candidate_flags(text)
        assert "MetaCTF{y3ah_xxe_d0e5_r0ck_d0esnt_it?}" in flags

    def test_is_valid_flag_rejects_css_noise(self):
        """is_valid_flag must share the same filter."""
        assert is_valid_flag("{opacity:0;}") is False

    def test_is_valid_flag_rejects_json_noise(self):
        assert is_valid_flag('0{"sid":"xyz"}') is False

    def test_custom_regex_bare_brace_still_works_when_user_opts_in(self):
        """Users who genuinely want bare-brace flags can override via a
        custom regex. Content filter still runs, so pure CSS noise still
        rejected — but plain {letters} is allowed through."""
        custom = r"\{[a-z_]+\}"
        flags = extract_candidate_flags("value is {realflag} here", custom)
        assert "{realflag}" in flags


class TestIsValidFlag:
    """Tests for flag validation function."""

    def test_valid_picoctf_flag(self):
        """Test validation of valid PicoCTF flag."""
        assert (
            is_valid_flag("picoCTF{s0m3_r34l_fl4g}", COMMON_FLAG_PATTERNS["picoctf"])
            is True
        )

    def test_placeholder_flag_rejected(self):
        """Test that placeholder flags are rejected."""
        assert is_valid_flag("picoCTF{test_flag}") is False
        assert is_valid_flag("HTB{FLAG_HERE}") is False
        assert is_valid_flag("flag{example}") is False

    def test_invalid_flag_format(self):
        """Test validation of invalid flag format."""
        assert is_valid_flag("not_a_flag", COMMON_FLAG_PATTERNS["picoctf"]) is False

    def test_partial_match_fails(self):
        """Test that partial matches fail validation."""
        # This should fail because the full string doesn't match
        assert (
            is_valid_flag(
                "prefix picoCTF{flag} suffix", COMMON_FLAG_PATTERNS["picoctf"]
            )
            is False
        )


class TestSolverConfig:
    """Tests for SolverConfig class."""

    def test_default_config(self):
        """Test default configuration values."""
        config = SolverConfig()
        assert config.platform_name == "Generic CTF"
        assert config.max_steps == 20
        assert config.flag_regex == DEFAULT_FLAG_REGEX
        assert config.docs_dirs == []
        assert config.kb_files == []

    def test_enable_opener_pack_default_true(self):
        """Opener pack is opt-out now — saves 2-3 turns on challenges that
        have a URL, short-circuits when they don't."""
        assert SolverConfig().enable_opener_pack is True

    def test_config_with_custom_values(self):
        """Test configuration with custom values."""
        config = SolverConfig(
            platform_name="PicoCTF",
            flag_regex=COMMON_FLAG_PATTERNS["picoctf"],
            challenge_url="https://example.com",
            max_steps=30,
        )
        assert config.platform_name == "PicoCTF"
        assert config.flag_regex == COMMON_FLAG_PATTERNS["picoctf"]
        assert config.challenge_url == "https://example.com"
        assert config.max_steps == 30

    def test_config_invalid_regex_raises(self):
        """Test that invalid regex in config raises ValueError."""
        with pytest.raises(ValueError, match="Invalid flag_regex"):
            SolverConfig(flag_regex=r"[invalid")

    def test_config_merge_with_args(self):
        """Test merging config with additional arguments."""
        base_config = SolverConfig(
            platform_name="Base",
            max_steps=10,
        )

        merged = base_config.merge_with_args(
            platform_name="Merged",
            challenge_url="https://new-url.com",
        )

        assert merged.platform_name == "Merged"
        assert merged.max_steps == 10  # Preserved from base
        assert merged.challenge_url == "https://new-url.com"

    def test_config_merge_ignores_none(self):
        """Test that merge ignores None values."""
        base_config = SolverConfig(platform_name="Original")
        merged = base_config.merge_with_args(platform_name=None)
        assert merged.platform_name == "Original"

    def test_get_all_kb_paths_empty(self):
        """Test getting KB paths when none configured."""
        config = SolverConfig()
        paths = config.get_all_kb_paths()
        assert paths == []

    def test_get_all_kb_paths_with_files(self, tmp_path):
        """Test getting KB paths with configured files."""
        # Create temporary files
        test_file = tmp_path / "test.md"
        test_file.write_text("test content")

        config = SolverConfig(kb_files=[str(test_file)])
        paths = config.get_all_kb_paths()

        assert len(paths) == 1
        assert paths[0] == test_file

    def test_get_all_kb_paths_with_directory(self, tmp_path):
        """Test getting KB paths from directory."""
        # Create temporary files in directory
        (tmp_path / "doc1.md").write_text("doc1")
        (tmp_path / "doc2.txt").write_text("doc2")
        (tmp_path / "ignored.py").write_text("ignored")

        config = SolverConfig(docs_dirs=[str(tmp_path)])
        paths = config.get_all_kb_paths()

        assert len(paths) == 2  # .md and .txt files only
        names = [p.name for p in paths]
        assert "doc1.md" in names
        assert "doc2.txt" in names
        assert "ignored.py" not in names


class TestConfigFromEnv:
    """Tests for loading config from environment."""

    def test_from_env_with_defaults(self, monkeypatch):
        """Test loading config from environment with defaults."""
        # Clear any existing env vars
        monkeypatch.delenv("CTF_PLATFORM_NAME", raising=False)
        monkeypatch.delenv("CTF_FLAG_REGEX", raising=False)

        config = SolverConfig.from_env()
        assert config.platform_name == "Generic CTF"
        assert config.flag_regex == DEFAULT_FLAG_REGEX

    def test_from_env_with_custom_values(self, monkeypatch):
        """Test loading config from environment with custom values."""
        monkeypatch.setenv("CTF_PLATFORM_NAME", "TestCTF")
        monkeypatch.setenv("CTF_MAX_STEPS", "42")
        monkeypatch.setenv("CTF_VERBOSE", "true")

        config = SolverConfig.from_env()
        assert config.platform_name == "TestCTF"
        assert config.max_steps == 42
        assert config.verbose is True


class TestPromptTemplates:
    """Tests for prompt template functionality."""

    def test_get_system_prompt_default(self):
        """Test getting default system prompt."""
        from ctf_solver.prompts import get_system_prompt

        prompt = get_system_prompt()
        assert "Generic CTF" in prompt
        assert "Thought" in prompt or "ReAct" in prompt

    def test_get_system_prompt_custom_platform(self):
        """Test getting system prompt with custom platform."""
        from ctf_solver.prompts import get_system_prompt

        prompt = get_system_prompt(platform_name="PicoCTF")
        assert "PicoCTF" in prompt

    def test_get_initial_message_includes_url(self):
        """Test that initial message includes challenge URL."""
        from ctf_solver.prompts import get_initial_message

        message = get_initial_message(
            challenge_url="https://test.com",
            challenge_description="Test challenge",
        )
        assert "https://test.com" in message
        assert "Test challenge" in message

    def test_get_role_definition(self):
        """Test getting role definition."""
        from ctf_solver.prompts import get_role_definition

        role = get_role_definition(platform_name="HackTheBox")
        assert "HackTheBox" in role


class TestLegacyCompatibility:
    """Tests for legacy argument compatibility."""

    def test_legacy_args_mapping(self):
        """Test that legacy arguments are mapped correctly."""
        from ctf_solver.runner import parse_args, build_config_from_args

        # Simulate legacy arguments
        args = parse_args(
            [
                "--base-url",
                "https://legacy-url.com",
                "--challenge",
                "test-challenge",
            ]
        )

        config = build_config_from_args(args)

        # Legacy args should be mapped to new fields
        assert config.challenge_url == "https://legacy-url.com"
        assert "test-challenge" in config.challenge_description


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
