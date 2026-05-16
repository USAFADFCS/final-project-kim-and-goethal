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
    """Headless QApplication shared across tests in this module."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


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
