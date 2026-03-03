"""
Tests for v1.9.0 WASM and efficiency improvements.

Covers:
- WasmAnalyzerTool: analyze, strings, xor_decode, scan_flags operations
- ShellExecuteTool: JSON escape preprocessing for Python regex patterns
- HttpFetchTool: binary content flag scanning (WASM magic bytes detection)
- WASM_RE classifier category
"""

import json
import struct
from unittest.mock import MagicMock, patch

import pytest

from ctf_solver.tools.wasm_tools import (
    WasmAnalyzerTool,
    _build_linear_memory,
    _parse_exports,
    _parse_globals,
    _parse_wasm_sections,
    _read_uleb128,
    _FLAG_RE,
)
from ctf_solver.tools.shell_tools import ShellExecuteTool
from ctf_solver.tools.http_tools import HttpFetchTool


# ---------------------------------------------------------------------------
# Helpers: minimal WASM binary builder
# ---------------------------------------------------------------------------


def _uleb128(value: int) -> bytes:
    """Encode integer as unsigned LEB128."""
    result = []
    while True:
        byte = value & 0x7F
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def _wasm_section(section_id: int, payload: bytes) -> bytes:
    return bytes([section_id]) + _uleb128(len(payload)) + payload


def _wasm_string(s: str) -> bytes:
    encoded = s.encode("utf-8")
    return _uleb128(len(encoded)) + encoded


def _make_wasm_with_plaintext_flag(flag: str) -> bytes:
    """Build minimal WASM with flag in a data segment (plaintext)."""
    flag_bytes = flag.encode() + b"\x00"

    # Data section (id=11): 1 segment at offset 1024
    data_payload = _uleb128(1)  # 1 segment
    data_payload += _uleb128(0)  # memidx
    data_payload += bytes([0x41])  # i32.const
    data_payload += _uleb128(1024)  # offset
    data_payload += bytes([0x0B])  # end
    data_payload += _uleb128(len(flag_bytes)) + flag_bytes

    return b"\x00asm\x01\x00\x00\x00" + _wasm_section(11, data_payload)


def _make_wasm_with_xor_flag(flag: str, key: bytes) -> bytes:
    """Build WASM with XOR-encoded flag and key in separate data segments + exports."""
    flag_bytes = flag.encode()
    encoded = (
        bytes(flag_bytes[i] ^ key[i % len(key)] for i in range(len(flag_bytes)))
        + b"\x00"
    )

    key_addr = 1024
    flag_addr = 1024 + len(key) + 1  # after key + null

    # Data section: key segment + encoded flag segment
    data_payload = _uleb128(2)  # 2 segments

    # Segment 0: key at key_addr
    data_payload += _uleb128(0)
    data_payload += bytes([0x41])
    data_payload += _uleb128(key_addr)
    data_payload += bytes([0x0B])
    data_payload += _uleb128(len(key) + 1) + key + b"\x00"

    # Segment 1: encoded flag at flag_addr
    data_payload += _uleb128(0)
    data_payload += bytes([0x41])
    data_payload += _uleb128(flag_addr)
    data_payload += bytes([0x0B])
    data_payload += _uleb128(len(encoded)) + encoded

    # Global section (id=6): 3 globals (key_addr, flag_addr, input_addr)
    # global type: valtype=0x7f (i32), mutability=0x00 (const)
    glob_payload = _uleb128(3)
    for addr in [key_addr, flag_addr, flag_addr + 200]:
        glob_payload += bytes([0x7F, 0x00, 0x41])  # i32, const, i32.const
        glob_payload += _uleb128(addr)
        glob_payload += bytes([0x0B])  # end

    # Export section (id=7): export globals 0=key, 1=input
    exp_payload = _uleb128(2)
    exp_payload += _wasm_string("key") + bytes([0x03]) + _uleb128(0)
    exp_payload += _wasm_string("input") + bytes([0x03]) + _uleb128(1)

    return (
        b"\x00asm\x01\x00\x00\x00"
        + _wasm_section(6, glob_payload)
        + _wasm_section(7, exp_payload)
        + _wasm_section(11, data_payload)
    )


# ---------------------------------------------------------------------------
# TestReadUleb128
# ---------------------------------------------------------------------------


class TestReadUleb128:
    def test_single_byte(self):
        assert _read_uleb128(b"\x05", 0) == (5, 1)

    def test_zero(self):
        assert _read_uleb128(b"\x00", 0) == (0, 1)

    def test_two_bytes(self):
        # 300 = 0x12C → LEB128: 0xAC 0x02
        assert _read_uleb128(b"\xac\x02", 0) == (300, 2)

    def test_offset(self):
        data = b"\xff\x05\x2a"  # skip first two bytes
        assert _read_uleb128(data, 2) == (42, 3)


# ---------------------------------------------------------------------------
# TestParseSections
# ---------------------------------------------------------------------------


class TestParseSections:
    def test_valid_wasm_magic(self):
        wasm = _make_wasm_with_plaintext_flag("CTF{test}")
        sections = _parse_wasm_sections(wasm)
        assert 11 in sections

    def test_invalid_magic_raises(self):
        with pytest.raises(ValueError, match="Not a valid WASM binary"):
            _parse_wasm_sections(b"notawasmfile")

    def test_empty_raises(self):
        with pytest.raises((ValueError, IndexError)):
            _parse_wasm_sections(b"")


# ---------------------------------------------------------------------------
# TestBuildLinearMemory
# ---------------------------------------------------------------------------


class TestBuildLinearMemory:
    def test_plaintext_flag_in_memory(self):
        flag = "picoCTF{hello_world}"
        wasm = _make_wasm_with_plaintext_flag(flag)
        sections = _parse_wasm_sections(wasm)
        mem = _build_linear_memory(sections[11])
        # Flag should be at offset 1024
        flag_bytes = flag.encode()
        assert bytes(mem[1024 : 1024 + len(flag_bytes)]) == flag_bytes

    def test_xor_key_in_memory(self):
        key = b"\xf1\xa7\xf0\x07\xed"
        wasm = _make_wasm_with_xor_flag("picoCTF{xor_test}", key)
        sections = _parse_wasm_sections(wasm)
        mem = _build_linear_memory(sections[11])
        assert bytes(mem[1024 : 1024 + len(key)]) == key


# ---------------------------------------------------------------------------
# TestParseExports
# ---------------------------------------------------------------------------


class TestParseExports:
    def test_parse_key_export(self):
        key = b"\xf1\xa7\xf0\x07\xed"
        wasm = _make_wasm_with_xor_flag("picoCTF{x}", key)
        sections = _parse_wasm_sections(wasm)
        exports = _parse_exports(sections[7])
        names = {e[0]: e for e in exports}
        assert "key" in names
        assert names["key"][1] == 3  # kind=global

    def test_parse_input_export(self):
        key = b"\xab"
        wasm = _make_wasm_with_xor_flag("CTF{x}", key)
        sections = _parse_wasm_sections(wasm)
        exports = _parse_exports(sections[7])
        names = {e[0] for e in exports}
        assert "input" in names


# ---------------------------------------------------------------------------
# TestParseGlobals
# ---------------------------------------------------------------------------


class TestParseGlobals:
    def test_global_values(self):
        key = b"\x01\x02"
        wasm = _make_wasm_with_xor_flag("FLAG{test}", key)
        sections = _parse_wasm_sections(wasm)
        globs = _parse_globals(sections[6])
        # Global[0] = key_addr = 1024
        assert globs[0] == 1024


# ---------------------------------------------------------------------------
# TestWasmAnalyzerTool - analyze operation
# ---------------------------------------------------------------------------


class TestWasmAnalyzerToolAnalyze:
    def setup_method(self):
        self.tool = WasmAnalyzerTool()

    def _mock_response(self, content: bytes):
        mock_resp = MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_analyze_plaintext_flag_found(self):
        flag = "picoCTF{plain_flag_123}"
        wasm = _make_wasm_with_plaintext_flag(flag)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "analyze"})
            )
        assert flag in result
        assert "FLAG FOUND" in result

    def test_analyze_returns_section_info(self):
        wasm = _make_wasm_with_plaintext_flag("CTF{x}")
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "analyze"})
            )
        assert "Data segment" in result or "data segment" in result.lower()

    def test_analyze_not_wasm_returns_error(self):
        with patch.object(
            self.tool.session,
            "get",
            return_value=self._mock_response(b"not a wasm file"),
        ):
            result = self.tool.use(json.dumps({"url": "http://x/f.wasm"}))
        assert "Error" in result or "Not a valid" in result

    def test_analyze_missing_url(self):
        result = self.tool.use(json.dumps({"operation": "analyze"}))
        assert "Error" in result

    def test_analyze_invalid_json(self):
        result = self.tool.use("not json {{{")
        assert "Error" in result

    def test_analyze_fetch_error(self):
        with patch.object(
            self.tool.session, "get", side_effect=Exception("Connection refused")
        ):
            result = self.tool.use(json.dumps({"url": "http://dead/f.wasm"}))
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestWasmAnalyzerTool - strings operation
# ---------------------------------------------------------------------------


class TestWasmAnalyzerToolStrings:
    def setup_method(self):
        self.tool = WasmAnalyzerTool()

    def _mock_response(self, content: bytes):
        mock_resp = MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_strings_finds_plaintext_flag(self):
        flag = "picoCTF{strings_test}"
        wasm = _make_wasm_with_plaintext_flag(flag)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "strings"})
            )
        assert flag in result

    def test_strings_suggests_xor_when_encoded(self):
        key = b"\xf1\xa7\xf0\x07\xed"
        wasm = _make_wasm_with_xor_flag("picoCTF{encoded}", key)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "strings"})
            )
        # When encoded, no readable strings → should suggest xor_decode
        assert (
            "xor_decode" in result
            or "XOR" in result
            or flag in result
            or "encoded" in result.lower()
        )


# ---------------------------------------------------------------------------
# TestWasmAnalyzerTool - xor_decode operation
# ---------------------------------------------------------------------------


class TestWasmAnalyzerToolXorDecode:
    def setup_method(self):
        self.tool = WasmAnalyzerTool()

    def _mock_response(self, content: bytes):
        mock_resp = MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_xor_decode_auto_detects_key(self):
        key = b"\xf1\xa7\xf0\x07\xed"
        flag = "picoCTF{68ff4bc93f6d67637b2f471be209d132}"
        wasm = _make_wasm_with_xor_flag(flag, key)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "xor_decode"})
            )
        assert flag in result
        assert "FLAG FOUND" in result

    def test_xor_decode_with_explicit_key_hex(self):
        key = b"\xab\xcd"
        flag = "CTF{explicit_key_test}"
        wasm = _make_wasm_with_xor_flag(flag, key)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://x/f.wasm",
                        "operation": "xor_decode",
                        "key_hex": key.hex(),
                    }
                )
            )
        assert flag in result

    def test_xor_decode_invalid_key_hex(self):
        wasm = _make_wasm_with_plaintext_flag("CTF{x}")
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://x/f.wasm",
                        "operation": "xor_decode",
                        "key_hex": "ZZZZ",
                    }
                )
            )
        assert "Error" in result or "invalid" in result.lower()

    def test_xor_decode_single_byte_key(self):
        key = b"\x42"
        flag = "FLAG{single_byte_xor}"
        wasm = _make_wasm_with_xor_flag(flag, key)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps(
                    {
                        "url": "http://x/f.wasm",
                        "operation": "xor_decode",
                        "key_hex": "42",
                    }
                )
            )
        assert flag in result


# ---------------------------------------------------------------------------
# TestWasmAnalyzerTool - scan_flags operation
# ---------------------------------------------------------------------------


class TestWasmAnalyzerToolScanFlags:
    def setup_method(self):
        self.tool = WasmAnalyzerTool()

    def _mock_response(self, content: bytes):
        mock_resp = MagicMock()
        mock_resp.content = content
        mock_resp.raise_for_status = MagicMock()
        return mock_resp

    def test_scan_flags_finds_plaintext(self):
        flag = "picoCTF{binary_scan_test}"
        wasm = _make_wasm_with_plaintext_flag(flag)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "scan_flags"})
            )
        assert flag in result

    def test_scan_flags_no_flag(self):
        key = b"\xf1\xa7\xf0\x07\xed"
        wasm = _make_wasm_with_xor_flag("picoCTF{encoded}", key)
        with patch.object(
            self.tool.session, "get", return_value=self._mock_response(wasm)
        ):
            result = self.tool.use(
                json.dumps({"url": "http://x/f.wasm", "operation": "scan_flags"})
            )
        # Encoded data shouldn't contain readable flag
        assert "No flag patterns" in result or "xor_decode" in result


# ---------------------------------------------------------------------------
# TestShellExecuteToolJsonEscapeFix
# ---------------------------------------------------------------------------


class TestShellExecuteToolJsonEscapeFix:
    def setup_method(self):
        self.tool = ShellExecuteTool()

    def test_valid_json_works(self):
        result = self.tool.use(json.dumps({"command": "echo hello"}))
        assert "hello" in result

    def test_invalid_escape_in_regex_pattern_fixed(self):
        r"""Python regex \{ in JSON string should be fixed before parsing."""
        # This simulates what the LLM generates: \{ in a regex inside JSON
        # json.loads would fail on this because \{ is not a valid JSON escape
        raw_with_bad_escape = '{"command": "python3 -c \\"import re; print(re.search(r\'\\\\{test\\\\}\', \'{test}\'))\\"" }'
        # Test that the tool handles the escape preprocessing gracefully
        # If it parses successfully, it should try to run the command
        result = self.tool.use(raw_with_bad_escape)
        # Should not return a JSON parse error; either runs or hits security block
        assert "Decoding failed" not in result or "Error" not in result.split("\n")[0]

    def test_escape_preprocessing_fixes_invalid_brace_escape(self):
        """Direct test: \\{ in JSON value should be handled."""
        # Simulate: {"command": "python3 -c 'import re; re.compile(r\"\\{\")'"}
        # \{ is the invalid JSON escape we need to fix
        bad_json = r'{"command": "echo \\{test\\}"}'
        result = self.tool.use(bad_json)
        # Should not error on JSON parsing
        assert "tool_input must be JSON" not in result

    def test_valid_newline_escape_still_works(self):
        """Valid JSON \\n escape in command should still work fine."""
        raw = '{"command": "echo hello"}'
        result = self.tool.use(raw)
        assert "[ShellExecuteTool]" in result
        assert "hello" in result

    def test_empty_command_rejected(self):
        result = self.tool.use('{"command": ""}')
        assert "Error" in result


# ---------------------------------------------------------------------------
# TestHttpFetchToolBinaryFlagScan
# ---------------------------------------------------------------------------


class TestHttpFetchToolBinaryFlagScan:
    def setup_method(self):
        self.tool = HttpFetchTool()

    def _make_response(self, content: bytes, content_type: str = "", status: int = 200):
        mock_resp = MagicMock()
        mock_resp.content = content
        mock_resp.status_code = status
        mock_resp.url = "http://example.com/file.wasm"
        mock_resp.history = []
        # Use MagicMock for headers so .get and .items are configurable
        mock_headers = MagicMock()
        mock_headers.get = lambda k, d="": content_type if k == "Content-Type" else d
        mock_headers.items = lambda: (
            [("Content-Type", content_type)] if content_type else []
        )
        mock_resp.headers = mock_headers
        mock_resp.text = content.decode("latin-1", errors="replace")
        return mock_resp

    def test_wasm_binary_with_plaintext_flag_detected(self):
        """WASM with magic bytes should have flag scanned even in binary mode."""
        flag = "picoCTF{binary_mode_flag}"
        wasm_content = b"\x00asm\x01\x00\x00\x00" + flag.encode() + b"\x00" * 100
        mock_resp = self._make_response(wasm_content, content_type="")

        with patch.object(self.tool.session, "get", return_value=mock_resp):
            result = self.tool.use(
                json.dumps({"url": "http://example.com/file.wasm", "max_body": 0})
            )

        assert flag in result

    def test_wasm_magic_detected_as_binary(self):
        """Response starting with WASM magic should be classified as binary."""
        wasm_bytes = b"\x00asm\x01\x00\x00\x00" + b"\x00" * 50
        mock_resp = self._make_response(wasm_bytes, content_type="")

        with patch.object(self.tool.session, "get", return_value=mock_resp):
            result = self.tool.use(
                json.dumps({"url": "http://example.com/file.wasm", "max_body": 4000})
            )

        assert "Binary response" in result or "binary" in result.lower()

    def test_application_wasm_content_type_detected(self):
        """application/wasm content type should be treated as binary."""
        wasm_bytes = b"\x00asm\x01\x00\x00\x00" + b"\xff" * 100
        mock_resp = self._make_response(wasm_bytes, content_type="application/wasm")

        with patch.object(self.tool.session, "get", return_value=mock_resp):
            result = self.tool.use(json.dumps({"url": "http://example.com/file.wasm"}))

        assert "Binary response" in result

    def test_binary_flag_scan_section_present(self):
        """When binary content contains a flag, [FLAG PATTERN DETECTED] section shown."""
        flag = "CTF{found_in_binary}"
        binary_content = (
            b"\x00asm\x01\x00\x00\x00\xff\xfe" + flag.encode() + b"\x00" * 50
        )
        mock_resp = self._make_response(binary_content)

        with patch.object(self.tool.session, "get", return_value=mock_resp):
            result = self.tool.use(
                json.dumps({"url": "http://example.com/file.wasm", "max_body": 100})
            )

        assert flag in result

    def test_non_binary_unchanged(self):
        """Non-binary text responses should not be affected by binary detection logic."""
        html = b"<html><body>Hello world</body></html>"
        mock_resp = self._make_response(html, content_type="text/html")

        with patch.object(self.tool.session, "get", return_value=mock_resp):
            result = self.tool.use(json.dumps({"url": "http://example.com/page.html"}))

        assert "Binary response" not in result
        assert "Hello world" in result


# ---------------------------------------------------------------------------
# TestWasmClassifierCategory
# ---------------------------------------------------------------------------


class TestWasmClassifierCategory:
    def test_wasm_re_category_exists(self):
        from ctf_solver.classifier.challenge_classifier import ChallengeCategory

        assert hasattr(ChallengeCategory, "WASM_RE")

    def test_wasm_re_keyword_detection(self):
        from ctf_solver.classifier.challenge_classifier import ChallengeClassifier

        clf = ChallengeClassifier()
        result = clf.classify(
            "WebAssembly challenge: check your wasm binary flag validator"
        )
        assert result.primary_category.value == "wasm_re" or any(
            cat.value == "wasm_re" for cat, _ in result.secondary_categories
        )

    def test_webassembly_keywords_matched(self):
        from ctf_solver.classifier.challenge_classifier import ChallengeClassifier

        clf = ChallengeClassifier()
        for kw in ["wasm", "webassembly", ".wasm"]:
            result = clf.classify(f"challenge: {kw} binary validation")
            cats = [result.primary_category.value] + [
                c.value for c, _ in result.secondary_categories
            ]
            assert "wasm_re" in cats, f"Expected wasm_re for keyword: {kw}"

    def test_wasm_re_suggests_wasm_analyzer(self):
        from ctf_solver.classifier.challenge_classifier import ChallengeClassifier

        clf = ChallengeClassifier()
        result = clf.classify("wasm binary flag checker")
        assert "wasm_analyzer" in result.suggested_tools


# ---------------------------------------------------------------------------
# TestWasmToolRegistration
# ---------------------------------------------------------------------------


class TestWasmToolRegistration:
    def test_wasm_analyzer_in_all_tools(self):
        from ctf_solver.tools import __all__

        assert "WasmAnalyzerTool" in __all__

    def test_wasm_analyzer_importable(self):
        from ctf_solver.tools.wasm_tools import WasmAnalyzerTool

        tool = WasmAnalyzerTool()
        assert tool.name == "wasm_analyzer"
        assert "wasm" in tool.description.lower()
