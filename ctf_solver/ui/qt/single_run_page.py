"""Single-run page: challenge inputs, Run/Cancel buttons, live trace, and a
minimal results panel.

Source-file uploads, batch mode, the full 5-tab results panel, and the
run-history view come in follow-up commits — this page is the smallest
useful slice so we can solve a real challenge end-to-end from the Qt UI.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from ctf_solver.config import SolverConfig
from ctf_solver.ui.core import validate_url
from ctf_solver.ui.qt.run_history_model import RunHistoryModel
from ctf_solver.ui.qt.runner_bridge import AgentRunner
from ctf_solver.ui.qt.sidebar import SidebarWidget
from ctf_solver.ui.qt.source_files_widget import SourceFilesWidget
from ctf_solver.ui.qt.trace_view import TraceView


class SingleRunPage(QWidget):
    """Inputs + trace + results for one challenge."""

    def __init__(
        self, sidebar: SidebarWidget, parent: Optional[QWidget] = None
    ) -> None:
        super().__init__(parent)
        self._sidebar = sidebar
        self._runner = AgentRunner(self)

        self._build_ui()
        self._wire_signals()
        self._refresh_run_enabled()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        # --- Top form: URL / description / hints ---
        outer.addWidget(QLabel("Challenge URL"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com/challenge")
        outer.addWidget(self.url_input)

        self.url_error = QLabel("")
        self.url_error.setStyleSheet("color: #c0392b;")
        self.url_error.setVisible(False)
        outer.addWidget(self.url_error)

        outer.addWidget(QLabel("Description"))
        self.description_input = QPlainTextEdit()
        self.description_input.setFixedHeight(70)
        self.description_input.setPlaceholderText("Describe the challenge goal")
        outer.addWidget(self.description_input)

        outer.addWidget(QLabel("Hints (optional)"))
        self.hints_input = QPlainTextEdit()
        self.hints_input.setFixedHeight(50)
        outer.addWidget(self.hints_input)

        self.source_files_widget = SourceFilesWidget()
        outer.addWidget(self.source_files_widget)

        # --- Run / Cancel row ---
        button_row = QHBoxLayout()
        self.run_btn = QPushButton("🚀 Run Agent")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        button_row.addWidget(self.run_btn)
        button_row.addWidget(self.cancel_btn)
        button_row.addStretch()
        self.status_label = QLabel("Idle")
        self.status_label.setStyleSheet("color: #888;")
        button_row.addWidget(self.status_label)
        outer.addLayout(button_row)

        # --- Splitter: live trace (top) / results tabs (bottom) ---
        splitter = QSplitter(Qt.Orientation.Vertical)
        outer.addWidget(splitter, 1)

        self.trace_view = TraceView()
        splitter.addWidget(self.trace_view)

        self.results_tabs = QTabWidget()
        splitter.addWidget(self.results_tabs)

        # Tab 1: Final Answer
        self.final_answer_view = QTextBrowser()
        self.final_answer_view.setOpenExternalLinks(True)
        self.results_tabs.addTab(self.final_answer_view, "Final Answer")

        # Tab 2: Candidate Flags
        self.flags_view = QListWidget()
        self.results_tabs.addTab(self.flags_view, "Candidate Flags")

        # Tab 3: Stats (JSON-ish)
        self.stats_view = QTextBrowser()
        self.results_tabs.addTab(self.stats_view, "Run Statistics")

        # Tab 4: Logs
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.results_tabs.addTab(self.log_view, "Execution Log")

        # Tab 5: History — past challenge_logs entries.
        self._history_model = RunHistoryModel(Path.cwd())
        history_container = QWidget()
        history_layout = QHBoxLayout(history_container)
        history_layout.setContentsMargins(0, 0, 0, 0)

        self.history_view = QListView()
        self.history_view.setModel(self._history_model)
        self.history_view.setMinimumWidth(280)
        history_layout.addWidget(self.history_view, 1)

        self.history_detail = QTextBrowser()
        self.history_detail.setOpenExternalLinks(True)
        history_layout.addWidget(self.history_detail, 2)

        refresh_btn = QPushButton("⟳")
        refresh_btn.setFixedWidth(30)
        refresh_btn.setToolTip("Refresh history")
        refresh_btn.clicked.connect(self._history_model.refresh)
        history_layout.addWidget(refresh_btn)

        self.history_view.clicked.connect(self._on_history_selected)
        self.results_tabs.addTab(history_container, "History")

        splitter.setSizes([500, 250])

    # --------------------------------------------------------------- wiring

    def _wire_signals(self) -> None:
        self.url_input.textChanged.connect(self._on_url_changed)
        self.run_btn.clicked.connect(self._on_run_clicked)
        self.cancel_btn.clicked.connect(self._runner.cancel)

        self._runner.event.connect(self.trace_view.append_event)
        self._runner.log.connect(self._on_log)
        self._runner.finished.connect(self._on_finished)
        self._runner.error.connect(self._on_error)
        self._runner.state_changed.connect(self._on_state_changed)

        # Re-evaluate Run-button enabled state whenever the sidebar or URL
        # changes (the sidebar covers regex + API key; this covers URL).
        self._sidebar.validation_changed.connect(self._refresh_run_enabled)
        self._sidebar.config_changed.connect(self._refresh_run_enabled)

    # ------------------------------------------------------------- handlers

    def _on_url_changed(self, _text: str) -> None:
        ok, msg = validate_url(self.url_input.text())
        if ok or not self.url_input.text():
            self.url_error.setVisible(False)
        else:
            self.url_error.setText(msg)
            self.url_error.setVisible(True)
        self._refresh_run_enabled()

    def _refresh_run_enabled(self) -> None:
        url_ok, _ = validate_url(self.url_input.text())
        ready = url_ok and self._sidebar.is_valid() and not self._runner.is_running()
        self.run_btn.setEnabled(ready)

    def _on_run_clicked(self) -> None:
        config = self._build_config()
        self._reset_results()
        self._runner.start(config)

    def _build_config(self) -> SolverConfig:
        overrides: dict = {
            "challenge_url": self.url_input.text(),
            "challenge_description": self.description_input.toPlainText(),
            "challenge_hints": self.hints_input.toPlainText(),
            "challenge_name": self._sidebar.challenge_name.text(),
            "platform_name": self._sidebar.current_platform_name(),
            "flag_regex": self._sidebar.current_flag_regex(),
            "model_name": self._sidebar.model_combo.currentText(),
            "max_steps": self._sidebar.max_steps.value(),
            "rag_mode": self._sidebar.current_rag_mode(),
            "use_llm_for_lessons": self._sidebar.lessons_enrich.isChecked(),
            "docs_dirs": [
                d.strip()
                for d in self._sidebar.docs_dirs.toPlainText().splitlines()
                if d.strip()
            ],
            "kb_files": [
                f.strip()
                for f in self._sidebar.kb_files.toPlainText().splitlines()
                if f.strip()
            ],
            "grammar_mode": self._sidebar.current_grammar_mode(),
            "agent_system_prompt": self._sidebar.agent_prompt.toPlainText(),
        }
        source_files = self.source_files_widget.source_files()
        if source_files:
            overrides["source_files"] = source_files
        return SolverConfig.from_env().merge_with_args(**overrides)

    def _reset_results(self) -> None:
        self.trace_view.clear()
        self.final_answer_view.clear()
        self.flags_view.clear()
        self.stats_view.clear()
        self.log_view.clear()

    @Slot(str)
    def _on_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    @Slot(str, list, dict)
    def _on_finished(self, response: str, flags: list, stats: dict) -> None:
        self.final_answer_view.setMarkdown(response or "(no answer)")
        for flag in flags:
            self.flags_view.addItem(flag)
        self.stats_view.setPlainText(_render_stats(stats))
        outcome = stats.get("outcome", "unknown")
        self.status_label.setText(f"Done · outcome: {outcome} · flags: {len(flags)}")
        # Refresh history so the new run's log file appears at the top.
        self._history_model.refresh()

    def _on_history_selected(self, index) -> None:
        entry = self._history_model.entry_at(index.row())
        if entry is None:
            return
        try:
            text = entry.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            self.history_detail.setPlainText(f"Could not read log: {exc}")
            return
        # 200k chars is plenty even for verbose batch runs; trim to keep
        # the QTextBrowser responsive.
        self.history_detail.setPlainText(text[:200_000])

    @Slot(str)
    def _on_error(self, msg: str) -> None:
        # Status label shows a one-line summary; the full text lives in the
        # log panel. Show a modal too so a silent background failure (e.g.
        # an Ollama timeout) doesn't look like "nothing happened" — the
        # user shouldn't have to dig in the log panel to find out a run
        # blew up.
        short = msg.splitlines()[0][:200] if msg else "Run failed."
        self.status_label.setText(short)
        self.log_view.appendPlainText(f"[ERROR] {msg}")
        QMessageBox.warning(self, "Run failed", msg)

    @Slot(bool)
    def _on_state_changed(self, is_running: bool) -> None:
        self.cancel_btn.setEnabled(is_running)
        if is_running:
            self.status_label.setText("Running…")
        self._refresh_run_enabled()


def _render_stats(stats: dict) -> str:
    keep = [
        "outcome",
        "steps",
        "duration_seconds",
        "tokens_total",
        "tokens_prompt",
        "tokens_completion",
        "tool_call_count",
        "unique_tools_used",
        "rag_queries_made",
        "prior_reflection_injected",
        "failure_doc_generated",
        "model_name",
    ]
    lines = []
    for k in keep:
        if k in stats:
            lines.append(f"{k}: {stats[k]}")
    tool_calls = stats.get("tool_calls")
    if isinstance(tool_calls, dict) and tool_calls:
        lines.append("")
        lines.append("Tool calls:")
        for name, count in sorted(tool_calls.items(), key=lambda x: -x[1]):
            lines.append(f"  {name}: {count}")
    return "\n".join(lines)
