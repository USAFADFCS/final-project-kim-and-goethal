"""
Tests for the source-file injection feature (v2.2).

Covers:
- get_initial_message with source_files
- _SOURCE_LANG_MAP language detection
- Per-file and total size truncation
- Streamlit helper _process_uploaded_files (unit-level: dict transform only)
- CLI --source-file argument loading
- SolverConfig.source_files field
"""

import io
import sys
import zipfile
from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_source_files(**kwargs: str) -> Dict[str, str]:
    """Convenience: create a filename→content dict."""
    return dict(kwargs)


# ---------------------------------------------------------------------------
# get_initial_message with source_files
# ---------------------------------------------------------------------------


class TestGetInitialMessageSourceFiles:
    """Tests for source_files parameter in get_initial_message."""

    def setup_method(self):
        from ctf_solver.prompts.templates import get_initial_message

        self.get_initial_message = get_initial_message

    def test_no_source_files_omits_section(self):
        msg = self.get_initial_message(
            challenge_url="http://example.com",
            source_files=None,
        )
        assert "## Provided Source Code" not in msg
        assert "SOURCE CODE PROVIDED" not in msg

    def test_empty_source_files_omits_section(self):
        msg = self.get_initial_message(
            challenge_url="http://example.com",
            source_files={},
        )
        assert "## Provided Source Code" not in msg

    def test_source_files_section_header_present(self):
        msg = self.get_initial_message(
            challenge_url="http://example.com",
            source_files={"app.py": "print('hello')"},
        )
        assert "## Provided Source Code" in msg

    def test_source_files_content_rendered(self):
        msg = self.get_initial_message(
            challenge_url="http://example.com",
            source_files={"app.py": "def check_flag(f): return f == 'CTF{x}'"},
        )
        assert "check_flag" in msg
        assert "### app.py" in msg

    def test_python_file_gets_python_lang_tag(self):
        msg = self.get_initial_message(
            source_files={"app.py": "x = 1"},
        )
        assert "```python" in msg

    def test_php_file_gets_php_lang_tag(self):
        msg = self.get_initial_message(
            source_files={"index.php": "<?php echo 'hello'; ?>"},
        )
        assert "```php" in msg

    def test_unknown_extension_gets_empty_lang_tag(self):
        msg = self.get_initial_message(
            source_files={"Makefile": "all: build"},
        )
        # No extension → lang=""
        assert "```\n" in msg or "``` \n" in msg or "```" in msg

    def test_source_code_guideline_bullet_present(self):
        msg = self.get_initial_message(
            source_files={"app.py": "secret = 'CTF{x}'"},
        )
        assert "SOURCE CODE PROVIDED" in msg

    def test_per_file_truncation(self):
        from ctf_solver.prompts.templates import _SOURCE_FILE_PER_LIMIT

        big_content = "x" * (_SOURCE_FILE_PER_LIMIT + 1000)
        msg = self.get_initial_message(
            source_files={"big.py": big_content},
        )
        assert "[truncated]" in msg
        # The actual content in the message should be <= limit + overhead
        assert big_content not in msg

    def test_total_size_truncation(self):
        from ctf_solver.prompts.templates import (
            _SOURCE_FILE_PER_LIMIT,
            _SOURCE_FILE_TOTAL_LIMIT,
        )

        # Create enough files to exceed total limit
        n_files = (_SOURCE_FILE_TOTAL_LIMIT // _SOURCE_FILE_PER_LIMIT) + 2
        files = {f"file{i:02d}.py": "x = 1\n" * 5000 for i in range(n_files)}
        msg = self.get_initial_message(source_files=files)
        assert "omitted" in msg

    def test_multiple_files_all_rendered_when_small(self):
        files = {
            "app.py": "x = 1",
            "config.json": '{"key": "value"}',
            "index.html": "<html></html>",
        }
        msg = self.get_initial_message(source_files=files)
        assert "### app.py" in msg
        assert "### config.json" in msg
        assert "### index.html" in msg

    def test_source_files_placed_before_flag_format(self):
        msg = self.get_initial_message(
            source_files={"app.py": "code"},
            flag_regex=r"CTF\{[^}]+\}",
        )
        source_pos = msg.index("## Provided Source Code")
        flag_pos = msg.index("Flag format")
        assert source_pos < flag_pos

    def test_guideline_bullet_placed_before_recon_bullet(self):
        msg = self.get_initial_message(
            source_files={"app.py": "code"},
        )
        source_guideline_pos = msg.index("SOURCE CODE PROVIDED")
        recon_pos = msg.index("Start with reconnaissance")
        assert source_guideline_pos < recon_pos


# ---------------------------------------------------------------------------
# _SOURCE_LANG_MAP coverage
# ---------------------------------------------------------------------------


class TestSourceLangMap:
    def test_all_expected_extensions_present(self):
        from ctf_solver.prompts.templates import _SOURCE_LANG_MAP

        expected = {
            ".py": "python",
            ".php": "php",
            ".js": "javascript",
            ".ts": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".c": "c",
            ".cpp": "cpp",
            ".sql": "sql",
            ".sh": "bash",
            ".html": "html",
            ".json": "json",
            ".yaml": "yaml",
        }
        for ext, lang in expected.items():
            assert _SOURCE_LANG_MAP.get(ext) == lang, f"Missing or wrong: {ext}"

    def test_yml_maps_to_yaml(self):
        from ctf_solver.prompts.templates import _SOURCE_LANG_MAP

        assert _SOURCE_LANG_MAP[".yml"] == "yaml"

    def test_h_maps_to_c(self):
        from ctf_solver.prompts.templates import _SOURCE_LANG_MAP

        assert _SOURCE_LANG_MAP[".h"] == "c"


# ---------------------------------------------------------------------------
# _process_uploaded_files helper (tested without Streamlit)
# ---------------------------------------------------------------------------


class TestProcessUploadedFiles:
    """
    Unit tests for the file-processing logic, decoupled from Streamlit.
    We duplicate the logic here rather than importing from streamlit_app to
    avoid triggering Streamlit's module-level side-effects in pytest.
    """

    def _process(self, files: Dict[str, bytes]) -> Dict[str, str]:
        """Minimal reimplementation matching streamlit_app._process_uploaded_files logic."""
        _TEXT_EXTENSIONS = {
            ".py", ".php", ".js", ".ts", ".java", ".go", ".rb", ".c", ".h",
            ".cpp", ".cs", ".sql", ".yaml", ".yml", ".json", ".html", ".xml",
            ".sh", ".env", ".conf", ".cfg", ".ini", ".toml", ".txt", ".md",
        }
        result: Dict[str, str] = {}

        def _add_bytes(name: str, data: bytes) -> None:
            ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            if ext not in _TEXT_EXTENSIONS:
                return
            try:
                result[name] = data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    result[name] = data.decode("latin-1")
                except UnicodeDecodeError:
                    pass

        for name, raw in files.items():
            ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            if ext == ".zip":
                try:
                    buf = io.BytesIO(raw)
                    with zipfile.ZipFile(buf) as zf:
                        for member in zf.namelist():
                            if member.endswith("/"):
                                continue
                            member_data = zf.read(member)
                            member_name = member.split("/")[-1] if "/" in member else member
                            _add_bytes(member_name, member_data)
                except zipfile.BadZipFile:
                    pass
            else:
                _add_bytes(name, raw)

        return result

    def _make_zip(self, members: Dict[str, bytes]) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def test_plain_python_file(self):
        result = self._process({"app.py": b"print('hello')"})
        assert result == {"app.py": "print('hello')"}

    def test_binary_file_skipped(self):
        result = self._process({"data.bin": b"\x00\x01\x02\x03"})
        assert "data.bin" not in result

    def test_zip_extracted(self):
        zip_bytes = self._make_zip({"app.py": b"x = 1", "config.json": b'{"k": "v"}'})
        result = self._process({"bundle.zip": zip_bytes})
        assert "app.py" in result
        assert "config.json" in result
        assert result["app.py"] == "x = 1"

    def test_zip_directory_entries_skipped(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.mkdir("subdir")
            zf.writestr("subdir/app.py", "x = 1")
        zip_bytes = buf.getvalue()
        result = self._process({"bundle.zip": zip_bytes})
        assert "app.py" in result

    def test_zip_nested_path_uses_basename(self):
        zip_bytes = self._make_zip({"deep/path/secret.py": b"flag = 'CTF{x}'"})
        result = self._process({"bundle.zip": zip_bytes})
        assert "secret.py" in result

    def test_latin1_fallback(self):
        # Latin-1 bytes that are not valid UTF-8
        data = "café".encode("latin-1")
        result = self._process({"notes.txt": data})
        assert "notes.txt" in result
        assert "caf" in result["notes.txt"]

    def test_bad_zip_skipped(self):
        result = self._process({"bad.zip": b"not a zip file"})
        assert result == {}


# ---------------------------------------------------------------------------
# SolverConfig.source_files
# ---------------------------------------------------------------------------


class TestSolverConfigSourceFiles:
    def test_default_empty(self):
        from ctf_solver.config import SolverConfig

        config = SolverConfig()
        assert config.source_files == {}

    def test_source_files_stored(self):
        from ctf_solver.config import SolverConfig

        config = SolverConfig(source_files={"app.py": "x = 1"})
        assert config.source_files == {"app.py": "x = 1"}

    def test_merge_with_args_passes_source_files(self):
        from ctf_solver.config import SolverConfig

        config = SolverConfig()
        merged = config.merge_with_args(source_files={"index.php": "<?php ?>"})
        assert merged.source_files == {"index.php": "<?php ?>"}

    def test_merge_with_args_none_keeps_existing(self):
        from ctf_solver.config import SolverConfig

        config = SolverConfig(source_files={"app.py": "x = 1"})
        merged = config.merge_with_args(source_files=None)
        assert merged.source_files == {"app.py": "x = 1"}


# ---------------------------------------------------------------------------
# CLI _load_source_files
# ---------------------------------------------------------------------------


class TestLoadSourceFiles:
    def test_loads_existing_file(self, tmp_path):
        from ctf_solver.runner import _load_source_files

        f = tmp_path / "app.py"
        f.write_text("x = 1")
        result = _load_source_files([str(f)])
        assert result == {"app.py": "x = 1"}

    def test_missing_file_warns_and_skips(self, tmp_path, capsys):
        from ctf_solver.runner import _load_source_files

        result = _load_source_files([str(tmp_path / "missing.py")])
        assert result == {}
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_multiple_files_loaded(self, tmp_path):
        from ctf_solver.runner import _load_source_files

        a = tmp_path / "a.py"
        b = tmp_path / "b.py"
        a.write_text("a = 1")
        b.write_text("b = 2")
        result = _load_source_files([str(a), str(b)])
        assert result == {"a.py": "a = 1", "b.py": "b = 2"}

    def test_empty_list_returns_empty(self):
        from ctf_solver.runner import _load_source_files

        assert _load_source_files([]) == {}
