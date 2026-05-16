"""Batch-run page: editable challenge table, TSV import/export, sequential
runner with per-row status, summary metrics, and cancel.

Uses the same orchestration helper as the single-run page
(``execute_qt_run``) so both paths share the v3.10-audit "good defaults".
The KB index rebuild after a write-mode run is the reason challenges run
sequentially rather than in parallel: lessons from item N must be queryable
when item N+1 starts.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QProcess, Qt, Slot
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from ctf_solver.batch import (
    BatchItem,
    BatchResult,
    ensure_batch_output_dir,
    items_to_tsv_text,
    load_batch_tsv,
    write_batch_summary,
)
from ctf_solver.config import SolverConfig
from ctf_solver.ui.qt.batch_table_model import BatchTableModel
from ctf_solver.ui.qt.runner_bridge import execute_qt_run
from ctf_solver.ui.qt.sidebar import SidebarWidget
from ctf_solver.ui.qt.trace_view import TraceView


class BatchPage(QWidget):
    """Batch editor + sequential runner."""

    def __init__(
        self, sidebar: SidebarWidget, parent: Optional[QWidget] = None
    ) -> None:
        super().__init__(parent)
        self._sidebar = sidebar
        self._model = BatchTableModel([BatchItem(name="")])
        self._task: Optional[asyncio.Task] = None
        self._results: list[BatchResult] = []
        self._output_dir: Optional[Path] = None

        self._build_ui()
        self._wire_signals()
        self._refresh_buttons()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(12, 12, 12, 12)
        outer.setSpacing(8)

        outer.addWidget(QLabel("Batch Challenges"))

        # Toolbar
        toolbar = QHBoxLayout()
        self.add_row_btn = QPushButton("➕ Add Row")
        self.remove_row_btn = QPushButton("➖ Remove Selected")
        self.import_btn = QPushButton("📂 Import TSV…")
        self.export_btn = QPushButton("💾 Export TSV…")
        self.clear_results_btn = QPushButton("🗑 Clear Results")
        for b in (
            self.add_row_btn,
            self.remove_row_btn,
            self.import_btn,
            self.export_btn,
            self.clear_results_btn,
        ):
            toolbar.addWidget(b)
        toolbar.addStretch()
        outer.addLayout(toolbar)

        # Table
        self.table = QTableView()
        self.table.setModel(self._model)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Interactive
        )
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setMinimumHeight(180)
        outer.addWidget(self.table)

        # Run / Cancel + summary row
        run_row = QHBoxLayout()
        self.run_btn = QPushButton("🚀 Run Batch")
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        run_row.addWidget(self.run_btn)
        run_row.addWidget(self.cancel_btn)
        run_row.addStretch()
        self.summary_label = QLabel(self._summary_text())
        self.summary_label.setStyleSheet("color: #888;")
        run_row.addWidget(self.summary_label)
        outer.addLayout(run_row)

        self.output_dir_label = QLabel("")
        self.output_dir_label.setStyleSheet("color: #888; font-size: 11px;")
        outer.addWidget(self.output_dir_label)

        # Splitter: live trace (top) + per-item results (bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        outer.addWidget(splitter, 1)

        self.trace_view = TraceView()
        splitter.addWidget(self.trace_view)

        self.results_view = QLabel("(no runs yet)")
        self.results_view.setWordWrap(True)
        self.results_view.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft
        )
        self.results_view.setStyleSheet(
            "background: rgba(127,127,127,0.05); padding: 8px;"
        )
        self.results_view.setMinimumHeight(120)
        # Allow opening the log via right-click context menu.
        self.results_view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results_view.customContextMenuRequested.connect(
            self._on_results_context_menu
        )
        splitter.addWidget(self.results_view)

        splitter.setSizes([350, 200])

    # --------------------------------------------------------------- wiring

    def _wire_signals(self) -> None:
        self.add_row_btn.clicked.connect(self._model.add_row)
        self.remove_row_btn.clicked.connect(self._remove_selected)
        self.import_btn.clicked.connect(self._import_tsv)
        self.export_btn.clicked.connect(self._export_tsv)
        self.clear_results_btn.clicked.connect(self._clear_results)
        self.run_btn.clicked.connect(self._on_run_clicked)
        self.cancel_btn.clicked.connect(self._cancel_batch)
        self._sidebar.validation_changed.connect(self._refresh_buttons)
        self._sidebar.config_changed.connect(self._refresh_buttons)
        self._model.dataChanged.connect(lambda *_: self._refresh_buttons())
        self._model.rowsInserted.connect(lambda *_: self._refresh_buttons())
        self._model.rowsRemoved.connect(lambda *_: self._refresh_buttons())

    # --------------------------------------------------------- table editing

    def _remove_selected(self) -> None:
        idx = self.table.currentIndex()
        if idx.isValid():
            self._model.remove_row(idx.row())

    def _import_tsv(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Import batch TSV",
            str(Path.cwd()),
            "TSV files (*.tsv);;All files (*)",
        )
        if not path:
            return
        try:
            items = load_batch_tsv(path)
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid TSV", str(exc))
            return
        self._model.replace_items(items)

    def _export_tsv(self) -> None:
        from datetime import datetime

        suggested = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tsv"
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export batch TSV",
            str(Path.cwd() / suggested),
            "TSV files (*.tsv);;All files (*)",
        )
        if not path:
            return
        Path(path).write_text(items_to_tsv_text(self._model.items()), encoding="utf-8")

    # ----------------------------------------------------------- run lifecycle

    def _refresh_buttons(self) -> None:
        running = self._task is not None and not self._task.done()
        non_empty = any(item.name.strip() for item in self._model.items())
        self.run_btn.setEnabled(non_empty and self._sidebar.is_valid() and not running)
        self.cancel_btn.setEnabled(running)
        for b in (
            self.add_row_btn,
            self.remove_row_btn,
            self.import_btn,
            self.export_btn,
            self.clear_results_btn,
        ):
            b.setEnabled(not running)

    def _on_run_clicked(self) -> None:
        # Reset prior state and start the sequential run loop.
        self._results.clear()
        self._model.clear_statuses()
        self.trace_view.clear()
        self._output_dir = ensure_batch_output_dir(Path.cwd() / "out")
        self.output_dir_label.setText(f"📁 Output: {self._output_dir}")
        self._task = asyncio.create_task(self._run_batch())
        self._refresh_buttons()
        self._update_summary()

    def _cancel_batch(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    async def _run_batch(self) -> None:
        try:
            for row, item in enumerate(self._model.items()):
                if not item.name.strip():
                    continue
                self._model.set_status(row, "running")
                self._update_summary()
                start = time.monotonic()
                config = self._build_config(item)
                try:
                    response, flags, stats = await execute_qt_run(
                        config,
                        event_emitter=self.trace_view.append_event,
                        log_emitter=lambda msg: None,
                    )
                    outcome = stats.get("outcome", "failure")
                    result = BatchResult(
                        item=item,
                        outcome=outcome,
                        flag=flags[0] if flags else None,
                        steps=int(stats.get("steps", 0)),
                        duration_seconds=time.monotonic() - start,
                        stats=stats,
                    )
                except asyncio.CancelledError:
                    self._model.set_status(row, "cancelled")
                    raise
                except Exception as exc:
                    outcome = "error"
                    result = BatchResult(
                        item=item,
                        outcome=outcome,
                        error=f"{type(exc).__name__}: {exc}",
                        duration_seconds=time.monotonic() - start,
                    )
                self._model.set_status(row, outcome)
                self._results.append(result)
                self._update_summary()
            # Write summary TSV when the loop completes naturally.
            if self._output_dir is not None and self._results:
                write_batch_summary(self._results, self._output_dir / "results.tsv")
        except asyncio.CancelledError:
            pass
        finally:
            self._refresh_buttons()
            self._update_summary()

    def _build_config(self, item: BatchItem) -> SolverConfig:
        return SolverConfig.from_env(
            challenge_url=item.url,
            challenge_description=item.description,
            challenge_hints=item.hints,
            challenge_name=item.name,
            platform_name=self._sidebar.current_platform_name(),
            flag_regex=self._sidebar.current_flag_regex(),
            model_name=self._sidebar.model_combo.currentText(),
            max_steps=self._sidebar.max_steps.value(),
            rag_mode=self._sidebar.current_rag_mode(),
            use_llm_for_lessons=self._sidebar.lessons_enrich.isChecked(),
            docs_dirs=[
                d.strip()
                for d in self._sidebar.docs_dirs.toPlainText().splitlines()
                if d.strip()
            ],
            kb_files=[
                f.strip()
                for f in self._sidebar.kb_files.toPlainText().splitlines()
                if f.strip()
            ],
            grammar_mode=self._sidebar.current_grammar_mode(),
            agent_prompt=self._sidebar.agent_prompt.toPlainText(),
        )

    # -------------------------------------------------------- summary view

    def _summary_text(self, results: Optional[list[BatchResult]] = None) -> str:
        results = results if results is not None else self._results
        total = len(results)
        success = sum(1 for r in results if r.outcome == "success")
        partial = sum(1 for r in results if r.outcome == "partial")
        failure = sum(1 for r in results if r.outcome == "failure")
        error = sum(1 for r in results if r.outcome == "error")
        return (
            f"Total: {total}   ✅ {success}   ⚠ {partial}   "
            f"❌ {failure}   💥 {error}"
        )

    def _update_summary(self) -> None:
        self.summary_label.setText(self._summary_text())
        if not self._results:
            self.results_view.setText("(no runs yet)")
            return
        lines = []
        for idx, r in enumerate(self._results, 1):
            flag = f" — {r.flag}" if r.flag else ""
            err = f" — {r.error}" if r.error else ""
            lines.append(
                f"{r.outcome_emoji} [{idx}] {r.item.name}  "
                f"({r.duration_seconds:.1f}s · {r.steps} steps){flag}{err}"
            )
        self.results_view.setText("\n".join(lines))

    def _clear_results(self) -> None:
        self._results.clear()
        self._model.clear_statuses()
        self._update_summary()
        self.trace_view.clear()

    @Slot(object)
    def _on_results_context_menu(self, pos) -> None:
        # Right-click on the results area opens the batch output dir in Finder.
        if self._output_dir is None:
            return
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        action = menu.addAction("Reveal in Finder")
        chosen = menu.exec(self.results_view.mapToGlobal(pos))
        if chosen is action:
            QProcess.startDetached("open", [str(self._output_dir)])
