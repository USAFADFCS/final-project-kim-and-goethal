"""Smoke tests for the Qt UI skeleton.

Run with ``QT_QPA_PLATFORM=offscreen`` so no display is required. Conftest
sets this automatically below via an autouse fixture.

Tests only check that the modules import and the window instantiates —
widget-level interaction tests come later (with pytest-qt) once the
sidebar and pages are wired up.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


pytest.importorskip("PySide6")


@pytest.fixture
def qapp():
    """Headless QApplication shared across tests in this module.

    Uses a unique org name per test invocation so QSettings doesn't leak
    state across tests (e.g. an invalid regex saved by one test breaking
    a later test's Run-button check).
    """
    import uuid

    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    app.setOrganizationName(f"test-{uuid.uuid4().hex[:8]}")
    app.setApplicationName("CTF Solver Test")
    yield app
    # Wipe whatever this test stored so the org name is reusable.
    QSettings().clear()


class TestQtSkeleton:
    def test_imports_clean(self):
        from ctf_solver.ui import qt as qt_pkg

        assert callable(qt_pkg.main)

    def test_main_window_instantiates(self, qapp):
        from ctf_solver.ui.qt.main_window import MainWindow

        window = MainWindow()
        assert window.windowTitle() == "CTF Solver"
        assert window.statusBar().currentMessage() == "Ready"
        tabs = window.centralWidget()
        assert tabs is not None
        assert tabs.count() == 2
        assert tabs.tabText(0) == "Single"
        assert tabs.tabText(1) == "Batch"

    def test_sidebar_dock_present(self, qapp):
        from PySide6.QtWidgets import QDockWidget

        from ctf_solver.ui.qt.main_window import MainWindow

        window = MainWindow()
        docks = window.findChildren(QDockWidget)
        assert len(docks) == 1
        assert docks[0].windowTitle() == "Configuration"


class TestSidebarConditionalUI:
    def test_grammar_hidden_for_hosted_model(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.model_combo.setCurrentText("gpt-5.2")
        assert not w.grammar_combo.isVisible()
        assert not w.grammar_label.isVisible()

    def test_grammar_visible_for_ollama_model(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()  # required for isVisible()
        w.model_combo.setCurrentText("gemma4:26b")
        assert w.grammar_combo.isVisible()
        assert w.grammar_label.isVisible()

    def test_grammar_visible_for_mlx_model(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.model_combo.setCurrentText("mlx-community/gemma-4-26b-a4b-it-4bit")
        assert w.grammar_combo.isVisible()

    def test_lessons_enrich_hidden_for_read_modes(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.rag_buttons["original"].setChecked(True)
        assert not w.lessons_enrich.isVisible()
        w.rag_buttons["lessons_readonly"].setChecked(True)
        assert not w.lessons_enrich.isVisible()
        w.rag_buttons["none"].setChecked(True)
        assert not w.lessons_enrich.isVisible()

    def test_lessons_enrich_visible_for_write_modes(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.rag_buttons["lessons_write"].setChecked(True)
        assert w.lessons_enrich.isVisible()
        w.rag_buttons["lessons_buildonly"].setChecked(True)
        assert w.lessons_enrich.isVisible()

    def test_flag_preset_custom_reveals_regex_field(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.flag_preset.setCurrentText("Custom")
        assert w.flag_regex.isVisible()
        w.flag_preset.setCurrentText("picoctf")
        assert not w.flag_regex.isVisible()

    def test_invalid_regex_emits_validation_signal(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.flag_preset.setCurrentText("Custom")

        # Make regex valid
        w.flag_regex.setText(r"flag\{.*?\}")
        assert not w.flag_regex_error.isVisible()

        # Break it
        w.flag_regex.setText(r"flag\{(")
        assert w.flag_regex_error.isVisible()

    def test_platform_other_reveals_custom_field(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.show()
        w.platform_combo.setCurrentText("Other")
        assert w.platform_custom.isVisible()
        w.platform_combo.setCurrentText("PicoCTF")
        assert not w.platform_custom.isVisible()

    def test_reset_kb_button_restores_defaults(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.docs_dirs.setPlainText("custom_dir/")
        w.kb_files.setPlainText("custom.pdf")
        w.reset_kb_btn.click()
        assert w.docs_dirs.toPlainText() == "docs/"
        assert w.kb_files.toPlainText() == "Book-3-Web-Exploitation.pdf"

    def test_reset_prompt_button_restores_default(self, qapp):
        from ctf_solver.prompts import DEFAULT_SYSTEM_PROMPT
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        w = SidebarWidget()
        w.agent_prompt.setPlainText("custom prompt")
        w.reset_prompt_btn.click()
        assert w.agent_prompt.toPlainText() == DEFAULT_SYSTEM_PROMPT


class TestTraceView:
    def test_appends_event_after_flush(self, qapp):
        from PySide6.QtCore import QTimer

        from ctf_solver.ui.qt.trace_view import TraceView

        view = TraceView()
        # Empty initially.
        assert view.toPlainText() == ""

        view.append_event(
            {
                "type": "thought_action",
                "step": 1,
                "thought": "look at robots.txt",
                "tool": "http_get",
                "tool_input": '{"url":"/robots.txt"}',
            }
        )
        # Batched — content not yet appended.
        assert view.toPlainText() == ""

        # Spin the event loop briefly so the QTimer.singleShot fires
        # (flush interval is 16 ms).
        timer_done = [False]

        def _done():
            timer_done[0] = True

        QTimer.singleShot(60, _done)
        while not timer_done[0]:
            qapp.processEvents()

        text = view.toPlainText()
        assert "Step 1" in text
        assert "thought_action" in text
        assert "look at robots.txt" in text

    def test_clear_resets_pane(self, qapp):
        from PySide6.QtCore import QTimer

        from ctf_solver.ui.qt.trace_view import TraceView

        view = TraceView()
        view.append_event({"type": "final_answer", "step": 5, "text": "flag{abc}"})

        done = [False]
        QTimer.singleShot(60, lambda: done.__setitem__(0, True))
        while not done[0]:
            qapp.processEvents()
        assert "flag{abc}" in view.toPlainText()

        view.clear()
        assert view.toPlainText() == ""


class TestSingleRunPage:
    def test_instantiates(self, qapp):
        from ctf_solver.ui.qt.sidebar import SidebarWidget
        from ctf_solver.ui.qt.single_run_page import SingleRunPage

        sidebar = SidebarWidget()
        page = SingleRunPage(sidebar)
        assert page.run_btn.text().startswith("🚀")
        assert page.cancel_btn.isEnabled() is False
        # Five results tabs: Final Answer, Candidate Flags, Run Statistics,
        # Execution Log, History.
        assert page.results_tabs.count() == 5
        labels = [page.results_tabs.tabText(i) for i in range(5)]
        assert labels == [
            "Final Answer",
            "Candidate Flags",
            "Run Statistics",
            "Execution Log",
            "History",
        ]

    def test_run_button_disabled_without_api_key(self, qapp, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("GENAI_API_KEY", raising=False)

        from ctf_solver.ui.qt.sidebar import SidebarWidget
        from ctf_solver.ui.qt.single_run_page import SingleRunPage

        sidebar = SidebarWidget()
        page = SingleRunPage(sidebar)
        page.url_input.setText("https://example.com")
        page._refresh_run_enabled()
        assert page.run_btn.isEnabled() is False

    def test_run_button_enabled_with_api_key_and_valid_url(self, qapp, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        from ctf_solver.ui.qt.sidebar import SidebarWidget
        from ctf_solver.ui.qt.single_run_page import SingleRunPage

        sidebar = SidebarWidget()
        page = SingleRunPage(sidebar)
        # isEnabled is independent of show-state, unlike isVisible.
        page.url_input.setText("https://example.com")
        page._refresh_run_enabled()
        assert page.run_btn.isEnabled() is True

    def test_run_button_disabled_with_invalid_url(self, qapp, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        from ctf_solver.ui.qt.sidebar import SidebarWidget
        from ctf_solver.ui.qt.single_run_page import SingleRunPage

        sidebar = SidebarWidget()
        page = SingleRunPage(sidebar)
        page.url_input.setText("not a url")
        assert page.run_btn.isEnabled() is False
        # Use isHidden (False if setVisible(True) was called) rather than
        # isVisible (False until shown).
        assert page.url_error.isHidden() is False


class TestAgentRunner:
    def test_initial_state(self, qapp):
        from ctf_solver.ui.qt.runner_bridge import AgentRunner

        runner = AgentRunner()
        assert runner.is_running() is False

    def test_cancel_no_task_is_safe(self, qapp):
        from ctf_solver.ui.qt.runner_bridge import AgentRunner

        runner = AgentRunner()
        # No task yet — cancel must not raise.
        runner.cancel()
        assert runner.is_running() is False


class TestBatchTableModel:
    def test_empty_model(self, qapp):
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel()
        assert m.rowCount() == 0
        assert m.columnCount() == 4

    def test_initial_items(self, qapp):
        from ctf_solver.batch import BatchItem
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        items = [BatchItem(name="A"), BatchItem(name="B", url="https://x")]
        m = BatchTableModel(items)
        assert m.rowCount() == 2

    def test_add_and_remove_row(self, qapp):
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel()
        m.add_row()
        m.add_row()
        assert m.rowCount() == 2
        m.remove_row(0)
        assert m.rowCount() == 1

    def test_set_data_updates_item(self, qapp):
        from PySide6.QtCore import Qt

        from ctf_solver.batch import BatchItem
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel([BatchItem(name="old", url="")])
        idx = m.index(0, 1)  # URL column
        m.setData(idx, "https://new.example.com", Qt.EditRole)
        assert m.items()[0].url == "https://new.example.com"

    def test_set_data_strips_status_prefix_on_name(self, qapp):
        from PySide6.QtCore import Qt

        from ctf_solver.batch import BatchItem
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel([BatchItem(name="X")])
        m.set_status(0, "running")
        # If the user edits the displayed value (which includes the status
        # icon prefix), we must strip the prefix back off.
        idx = m.index(0, 0)
        m.setData(idx, "▶ Renamed", Qt.EditRole)
        assert m.items()[0].name == "Renamed"

    def test_status_changes_emit_dataChanged(self, qapp):
        from ctf_solver.batch import BatchItem
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel([BatchItem(name="A")])
        emitted = []
        m.dataChanged.connect(lambda *args: emitted.append(args))
        m.set_status(0, "success")
        assert emitted

    def test_replace_items_resets_statuses(self, qapp):
        from ctf_solver.batch import BatchItem
        from ctf_solver.ui.qt.batch_table_model import BatchTableModel

        m = BatchTableModel([BatchItem(name="A"), BatchItem(name="B")])
        m.set_status(0, "success")
        m.set_status(1, "failure")
        m.replace_items([BatchItem(name="C")])
        assert m.rowCount() == 1
        assert m.get_status(0) == "pending"


class TestBatchPage:
    def test_instantiates(self, qapp):
        from ctf_solver.ui.qt.batch_page import BatchPage
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        sidebar = SidebarWidget()
        page = BatchPage(sidebar)
        # Default state: one empty row, no name → run button disabled.
        assert page.run_btn.isEnabled() is False
        assert page.cancel_btn.isEnabled() is False

    def test_run_button_disabled_with_only_empty_rows(self, qapp, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        from ctf_solver.ui.qt.batch_page import BatchPage
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        sidebar = SidebarWidget()
        page = BatchPage(sidebar)
        page._refresh_buttons()
        # All rows have empty name → still disabled even with API key set.
        assert page.run_btn.isEnabled() is False

    def test_run_button_enabled_with_named_row_and_api_key(self, qapp, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

        from PySide6.QtCore import Qt

        from ctf_solver.ui.qt.batch_page import BatchPage
        from ctf_solver.ui.qt.sidebar import SidebarWidget

        sidebar = SidebarWidget()
        page = BatchPage(sidebar)
        page._model.setData(page._model.index(0, 0), "Test challenge", Qt.EditRole)
        page._refresh_buttons()
        assert page.run_btn.isEnabled() is True


class TestSourceFilesWidget:
    def test_initial_state(self, qapp):
        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        w = SourceFilesWidget()
        assert w.source_files() == {}

    def test_add_paths_from_real_files(self, qapp, tmp_path):
        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        f1 = tmp_path / "app.py"
        f1.write_text("x = 1")
        f2 = tmp_path / "schema.sql"
        f2.write_text("SELECT * FROM users")

        w = SourceFilesWidget()
        w._add_paths([str(f1), str(f2)])
        files = w.source_files()
        assert files == {"app.py": "x = 1", "schema.sql": "SELECT * FROM users"}

    def test_add_paths_skips_missing(self, qapp, tmp_path):
        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        f = tmp_path / "real.py"
        f.write_text("real")
        w = SourceFilesWidget()
        w._add_paths([str(f), str(tmp_path / "missing.py")])
        assert "real.py" in w.source_files()
        assert "missing.py" not in w.source_files()

    def test_add_paths_extracts_zip(self, qapp, tmp_path):
        import io
        import zipfile

        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        zpath = tmp_path / "bundle.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("inner.py", "print('hi')")

        w = SourceFilesWidget()
        w._add_paths([str(zpath)])
        assert w.source_files() == {"inner.py": "print('hi')"}

    def test_clear_resets_state(self, qapp, tmp_path):
        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        f = tmp_path / "x.py"
        f.write_text("data")
        w = SourceFilesWidget()
        w._add_paths([str(f)])
        assert w.source_files() != {}
        w.clear()
        assert w.source_files() == {}

    def test_emits_files_changed_signal(self, qapp, tmp_path):
        from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget

        f = tmp_path / "x.py"
        f.write_text("data")
        w = SourceFilesWidget()
        emitted = []
        w.files_changed.connect(lambda: emitted.append(True))
        w._add_paths([str(f)])
        assert emitted


class TestRunHistoryModel:
    def test_empty_when_no_log_dir(self, qapp, tmp_path):
        from ctf_solver.ui.qt.run_history_model import RunHistoryModel

        m = RunHistoryModel(tmp_path)
        assert m.rowCount() == 0

    def test_parses_filename(self, qapp, tmp_path):
        from ctf_solver.ui.qt.run_history_model import RunHistoryModel

        log_dir = tmp_path / "challenge_logs"
        log_dir.mkdir()
        (log_dir / "Web_Decode_success_20260401_120000.log").write_text("log body")
        (log_dir / "Cookie_Forge_failure_20260402_130000.log").write_text("log body")

        m = RunHistoryModel(tmp_path)
        assert m.rowCount() == 2
        # Newest first.
        first = m.entry_at(0)
        assert first is not None
        assert first.slug == "Cookie_Forge"
        assert first.outcome == "failure"

    def test_skips_malformed_filenames(self, qapp, tmp_path):
        from ctf_solver.ui.qt.run_history_model import RunHistoryModel

        log_dir = tmp_path / "challenge_logs"
        log_dir.mkdir()
        (log_dir / "good_success_20260401_120000.log").write_text("ok")
        (log_dir / "not-a-valid-format.log").write_text("ignored")

        m = RunHistoryModel(tmp_path)
        assert m.rowCount() == 1

    def test_refresh_picks_up_new_file(self, qapp, tmp_path):
        from ctf_solver.ui.qt.run_history_model import RunHistoryModel

        log_dir = tmp_path / "challenge_logs"
        log_dir.mkdir()
        m = RunHistoryModel(tmp_path)
        assert m.rowCount() == 0

        (log_dir / "X_success_20260401_120000.log").write_text("ok")
        m.refresh()
        assert m.rowCount() == 1
