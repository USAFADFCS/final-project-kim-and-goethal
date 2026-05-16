"""Lazy-loading list model over the ``challenge_logs/`` directory.

Each entry is one ``<slug>_<outcome>_<YYYYMMDD_HHMMSS>.log`` file —
produced by both the Streamlit and Qt paths (via ``core.save_challenge_log``)
and by the CLI's batch runner. The model parses the filename for
display; reading the log body is deferred until the user opens it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt

_FILENAME_RE = re.compile(
    r"^(?P<slug>.+)_(?P<outcome>[a-z_]+)_(?P<ts>\d{8}_\d{6})\.log$"
)

_OUTCOME_ICONS = {
    "success": "✅",
    "partial": "⚠",
    "failure": "❌",
    "error": "💥",
    "unknown": "❓",
}


@dataclass
class RunHistoryEntry:
    path: Path
    slug: str
    outcome: str
    timestamp: datetime

    @property
    def label(self) -> str:
        icon = _OUTCOME_ICONS.get(self.outcome, "·")
        return f"{icon}  {self.timestamp:%Y-%m-%d %H:%M:%S}  {self.slug}"


class RunHistoryModel(QAbstractListModel):
    """Sorted list of past challenge logs."""

    def __init__(self, project_root: Path) -> None:
        super().__init__()
        self._project_root = project_root
        self._entries: list[RunHistoryEntry] = []
        self.refresh()

    # ----------------------------------------------------- standard QAM API

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._entries)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid() or index.row() >= len(self._entries):
            return None
        entry = self._entries[index.row()]
        if role == Qt.ItemDataRole.DisplayRole:
            return entry.label
        if role == Qt.ItemDataRole.ToolTipRole:
            return str(entry.path)
        if role == Qt.ItemDataRole.UserRole:
            return entry  # opaque payload for view code to use
        return None

    # ------------------------------------------------------------- refresh

    def refresh(self) -> None:
        """Re-scan the log dir. Call after a run completes to surface the
        new entry without a full app restart."""
        log_dir = self._project_root / "challenge_logs"
        entries: list[RunHistoryEntry] = []
        if log_dir.exists():
            for path in log_dir.glob("*.log"):
                parsed = _parse_filename(path)
                if parsed is not None:
                    entries.append(parsed)
        # Newest first.
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        self.beginResetModel()
        self._entries = entries
        self.endResetModel()

    def entry_at(self, row: int) -> Optional[RunHistoryEntry]:
        if 0 <= row < len(self._entries):
            return self._entries[row]
        return None


def _parse_filename(path: Path) -> Optional[RunHistoryEntry]:
    match = _FILENAME_RE.match(path.name)
    if match is None:
        return None
    try:
        ts = datetime.strptime(match.group("ts"), "%Y%m%d_%H%M%S")
    except ValueError:
        return None
    return RunHistoryEntry(
        path=path,
        slug=match.group("slug"),
        outcome=match.group("outcome"),
        timestamp=ts,
    )
