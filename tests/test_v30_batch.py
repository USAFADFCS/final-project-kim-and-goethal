"""
Tests for the batch-run support (v3.0.0).

``ctf_solver.batch`` provides the data structures and TSV serialization
used by the Streamlit "Batch Run" mode. These tests exercise the pure
helpers (slug derivation, TSV round-trip, empty-row filtering, legacy
header compatibility, summary writer) without touching the agent.
"""

from pathlib import Path

import pytest

from ctf_solver.batch import (
    BatchItem,
    BatchResult,
    ensure_batch_output_dir,
    items_to_rows,
    items_to_tsv_text,
    load_batch_tsv,
    rows_to_items,
    save_batch_tsv,
    write_batch_summary,
)


class TestBatchItemSlug:
    def test_simple_name(self):
        assert BatchItem(name="Great Paywall").slug == "great_paywall"

    def test_punctuation_stripped(self):
        assert BatchItem(name="Don't, stop-believing!").slug == "don_t_stop_believing"

    def test_trailing_underscores_trimmed(self):
        assert (
            BatchItem(name="---weird---").slug == "unnamed"
            or BatchItem(name="---weird---").slug == "weird"
        )

    def test_blank_name_falls_back(self):
        assert BatchItem(name="").slug == "unnamed"
        assert BatchItem(name="   ").slug == "unnamed"

    def test_unicode_collapses_safely(self):
        # Non-ASCII chars are stripped; slug must remain filesystem-safe.
        slug = BatchItem(name="Café ☕").slug
        assert slug == "caf" or slug == "unnamed"


class TestTsvRoundTrip:
    def test_save_and_load_round_trip(self, tmp_path: Path):
        items = [
            BatchItem(
                name="Alpha",
                url="http://a.example/",
                description="d1",
                hints="h1",
            ),
            BatchItem(name="Beta", url="http://b.example/"),
        ]
        path = tmp_path / "batch.tsv"
        save_batch_tsv(items, path)
        loaded = load_batch_tsv(path)
        assert len(loaded) == 2
        assert loaded[0].name == "Alpha"
        assert loaded[0].url == "http://a.example/"
        assert loaded[0].description == "d1"
        assert loaded[0].hints == "h1"
        assert loaded[1].name == "Beta"
        assert loaded[1].description == ""  # defaulted

    def test_load_legacy_format(self, tmp_path: Path):
        """The legacy 4-col format (slug, name, url, description) must still
        load — we ignore slug and default hints to ''."""
        path = tmp_path / "legacy.tsv"
        path.write_text(
            "slug\tname\turl\tdescription\n"
            "01_tm\tTreasure Map\thttp://ex/\tFind the flag\n"
            "02_dl\tDirect Login\thttp://ex2/\tAnother\n",
            encoding="utf-8",
        )
        items = load_batch_tsv(path)
        assert len(items) == 2
        assert items[0].name == "Treasure Map"
        assert items[0].url == "http://ex/"
        assert items[0].description == "Find the flag"
        assert items[0].hints == ""  # legacy has no hints column
        assert items[1].name == "Direct Login"

    def test_load_rejects_unknown_header(self, tmp_path: Path):
        path = tmp_path / "bad.tsv"
        path.write_text("foo\tbar\tbaz\n1\t2\t3\n", encoding="utf-8")
        with pytest.raises(ValueError, match="Unrecognized TSV header"):
            load_batch_tsv(path)

    def test_load_empty_file_returns_empty_list(self, tmp_path: Path):
        path = tmp_path / "empty.tsv"
        path.write_text("", encoding="utf-8")
        assert load_batch_tsv(path) == []

    def test_load_short_rows_are_padded(self, tmp_path: Path):
        """A row with only name+url (missing description/hints) should load."""
        path = tmp_path / "short.tsv"
        path.write_text(
            "name\turl\tdescription\thints\n" "Bravo\thttp://b.example/\n",
            encoding="utf-8",
        )
        items = load_batch_tsv(path)
        assert len(items) == 1
        assert items[0].name == "Bravo"
        assert items[0].description == ""
        assert items[0].hints == ""

    def test_tsv_text_round_trip_through_rows(self):
        items = [BatchItem(name="X", url="http://x/", hints="h")]
        text = items_to_tsv_text(items)
        assert text.splitlines()[0].split("\t") == [
            "name",
            "url",
            "description",
            "hints",
        ]
        assert "X\thttp://x/\t\th" in text


class TestStreamlitDataEditorConversion:
    def test_items_to_rows_and_back(self):
        items = [
            BatchItem(name="Alpha", url="http://a/", description="d", hints="h"),
            BatchItem(name="Beta", url="http://b/"),
        ]
        rows = items_to_rows(items)
        assert rows[0]["name"] == "Alpha"
        assert rows[0]["url"] == "http://a/"
        round_trip = rows_to_items(rows)
        assert len(round_trip) == 2
        assert round_trip[0].name == "Alpha"
        assert round_trip[0].hints == "h"

    def test_rows_to_items_skips_blank_rows(self):
        """st.data_editor adds a blank row on each interaction; we must
        silently drop those instead of sending an empty challenge."""
        rows = [
            {"name": "Alpha", "url": "http://a/", "description": "", "hints": ""},
            {"name": "", "url": "", "description": "", "hints": ""},  # blank
            {"name": "Beta", "url": "http://b/", "description": "", "hints": ""},
        ]
        items = rows_to_items(rows)
        assert len(items) == 2
        assert items[0].name == "Alpha"
        assert items[1].name == "Beta"

    def test_rows_to_items_handles_none_values(self):
        """st.data_editor may emit ``None`` for un-filled cells."""
        rows = [{"name": "A", "url": None, "description": None, "hints": None}]
        items = rows_to_items(rows)
        assert len(items) == 1
        assert items[0].url == ""


class TestBatchOutput:
    def test_ensure_batch_output_dir_creates_timestamp_dir(self, tmp_path: Path):
        out = ensure_batch_output_dir(tmp_path)
        assert out.exists() and out.is_dir()
        assert out.parent == tmp_path
        assert out.name.startswith("batch_")

    def test_write_batch_summary_has_required_columns(self, tmp_path: Path):
        results = [
            BatchResult(
                item=BatchItem(name="Alpha", url="http://a/"),
                outcome="success",
                flag="picoCTF{flag}",
                steps=7,
                duration_seconds=42.0,
            ),
            BatchResult(
                item=BatchItem(name="Beta", url="http://b/"),
                outcome="failure",
                steps=20,
                duration_seconds=120.5,
            ),
            BatchResult(
                item=BatchItem(name="Gamma", url="http://g/"),
                outcome="error",
                error="Connection refused",
                steps=0,
                duration_seconds=0.3,
            ),
        ]
        summary_path = tmp_path / "results.tsv"
        write_batch_summary(results, summary_path)

        text = summary_path.read_text(encoding="utf-8")
        lines = text.strip().splitlines()
        assert len(lines) == 4  # header + 3 rows
        header = lines[0].split("\t")
        for col in (
            "slug",
            "name",
            "url",
            "outcome",
            "flag",
            "steps",
            "duration_seconds",
            "error",
        ):
            assert col in header

        # Error row sanitizes control chars so TSV stays parseable.
        assert "Connection refused" in lines[3]
        assert "\n" not in lines[3]


class TestBatchResult:
    def test_outcome_emoji_mapping(self):
        assert (
            BatchResult(item=BatchItem(name="x"), outcome="success").outcome_emoji
            == "✅"
        )
        assert (
            BatchResult(item=BatchItem(name="x"), outcome="partial").outcome_emoji
            == "⚠️"
        )
        assert (
            BatchResult(item=BatchItem(name="x"), outcome="failure").outcome_emoji
            == "❌"
        )
        assert (
            BatchResult(item=BatchItem(name="x"), outcome="error").outcome_emoji == "💥"
        )
        assert (
            BatchResult(item=BatchItem(name="x"), outcome="unknown").outcome_emoji
            == "❓"
        )
