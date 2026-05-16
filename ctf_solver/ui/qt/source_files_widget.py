"""Source-file uploader with drag-and-drop and file picker.

CTF challenges that ship source code (PHP, Python, Node, ...) need their
files visible to the agent's planner. This widget collects them and
exposes ``source_files() -> Dict[str, str]`` for the SolverConfig wiring.

Archives (.zip, .tar, .tar.gz, .tar.bz2, .tgz, .tbz2) are extracted
in-memory via ``core.load_source_files_from_bytes`` — no on-disk staging.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from ctf_solver.ui.core import load_source_files_from_bytes


class _DropList(QListWidget):
    """QListWidget that emits ``files_dropped`` with the dropped paths."""

    files_dropped = Signal(list)

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragDropMode(QListWidget.DragDropMode.DropOnly)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event: QDragEnterEvent) -> None:  # noqa: N802
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event: QDropEvent) -> None:  # noqa: N802
        urls = event.mimeData().urls() if event.mimeData() else []
        paths = [u.toLocalFile() for u in urls if u.isLocalFile()]
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)


class SourceFilesWidget(QWidget):
    """Editor for the ``source_files`` field on ``SolverConfig``."""

    files_changed = Signal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._files: dict[str, str] = {}  # filename → text

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        header = QHBoxLayout()
        header.addWidget(QLabel("Source files (drag-drop or browse)"))
        header.addStretch()
        self.add_btn = QPushButton("Browse…")
        self.clear_btn = QPushButton("Clear")
        header.addWidget(self.add_btn)
        header.addWidget(self.clear_btn)
        layout.addLayout(header)

        self._list = _DropList()
        self._list.setFixedHeight(80)
        layout.addWidget(self._list)

        self._status = QLabel("No files loaded.")
        self._status.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(self._status)

        self.add_btn.clicked.connect(self._on_browse)
        self.clear_btn.clicked.connect(self._on_clear)
        self._list.files_dropped.connect(self._add_paths)

    # ----------------------------------------------------------- public API

    def source_files(self) -> dict[str, str]:
        return dict(self._files)

    def clear(self) -> None:
        self._on_clear()

    # ----------------------------------------------------------- handlers

    def _on_browse(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self,
            "Add source files",
            str(Path.cwd()),
            "Source / archives (*.py *.php *.js *.ts *.java *.go *.rb *.c *.h "
            "*.cpp *.cs *.sql *.yaml *.yml *.json *.html *.xml *.sh *.env "
            "*.conf *.cfg *.ini *.toml *.txt *.md *.htm *.jsx *.tsx *.rs "
            "*.swift *.kt *.zip *.tar *.tar.gz *.tar.bz2 *.tgz *.tbz2);;All files (*)",
        )
        if paths:
            self._add_paths(paths)

    def _on_clear(self) -> None:
        if not self._files:
            return
        self._files.clear()
        self._list.clear()
        self._status.setText("No files loaded.")
        self.files_changed.emit()

    def _add_paths(self, paths: list[str]) -> None:
        named_blobs: list[tuple[str, bytes]] = []
        skipped: list[str] = []
        for raw in paths:
            p = Path(raw)
            if not p.exists():
                skipped.append(p.name)
                continue
            try:
                named_blobs.append((p.name, p.read_bytes()))
            except OSError:
                skipped.append(p.name)
        new_files = load_source_files_from_bytes(named_blobs)
        if not new_files and not skipped:
            self._status.setText("Selected files had no readable text content.")
            return

        added = 0
        for name, text in new_files.items():
            if name not in self._files:
                self._list.addItem(name)
                added += 1
            self._files[name] = text

        total = len(self._files)
        msg = f"{total} file(s) loaded"
        if skipped:
            msg += f" — skipped: {', '.join(skipped)}"
        self._status.setText(msg)
        if added or new_files:
            self.files_changed.emit()
