"""Qt model wrapping a list of ``BatchItem`` for the batch table editor.

Columns: name, url, description, hints — matching the TSV schema in
``ctf_solver.batch``. Per-row status (pending/running/success/partial/
failure/error/cancelled) is stored alongside the items and surfaced via
``Qt.DecorationRole`` on the first column so the user sees a coloured
status pill next to each row.
"""

from __future__ import annotations

from typing import Any, Optional

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from ctf_solver.batch import BatchItem

_HEADERS: tuple[str, ...] = ("Name", "URL", "Description", "Hints")
_FIELDS: tuple[str, ...] = ("name", "url", "description", "hints")

_STATUS_ICONS: dict[str, str] = {
    "pending": "·",
    "running": "▶",
    "success": "✅",
    "partial": "⚠",
    "failure": "❌",
    "error": "💥",
    "cancelled": "■",
}


class BatchTableModel(QAbstractTableModel):
    """Editable model of batch items + per-row status."""

    def __init__(self, items: Optional[list[BatchItem]] = None) -> None:
        super().__init__()
        self._items: list[BatchItem] = list(items or [])
        self._status: dict[int, str] = {}

    # ----------------------------------------------------- standard QAM API

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._items)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(_HEADERS)

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.DisplayRole
    ) -> Any:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return _HEADERS[section]
        return section + 1

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if not (0 <= row < len(self._items)):
            return None
        item = self._items[row]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            value = getattr(item, _FIELDS[col], "")
            if col == 0:
                status = self._status.get(row, "pending")
                return f"{_STATUS_ICONS.get(status, '·')} {value}"
            return value
        if role == Qt.ItemDataRole.ToolTipRole and col == 0:
            return self._status.get(row, "pending")
        return None

    def setData(  # noqa: N802
        self, index: QModelIndex, value: Any, role: int = Qt.EditRole
    ) -> bool:
        if role != Qt.ItemDataRole.EditRole or not index.isValid():
            return False
        row, col = index.row(), index.column()
        if not (0 <= row < len(self._items)):
            return False
        field = _FIELDS[col]
        # For column 0 (Name) the display includes a status icon prefix —
        # strip it back off when editing.
        new_value = str(value)
        if col == 0:
            for prefix in _STATUS_ICONS.values():
                if new_value.startswith(prefix + " "):
                    new_value = new_value[len(prefix) + 1 :]
                    break
        setattr(self._items[row], field, new_value)
        self.dataChanged.emit(index, index, [role])
        return True

    def flags(self, index: QModelIndex) -> Qt.ItemFlag:
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return (
            Qt.ItemFlag.ItemIsEnabled
            | Qt.ItemFlag.ItemIsSelectable
            | Qt.ItemFlag.ItemIsEditable
        )

    # -------------------------------------------------------- editing API

    def items(self) -> list[BatchItem]:
        return list(self._items)

    def replace_items(self, items: list[BatchItem]) -> None:
        self.beginResetModel()
        self._items = list(items)
        self._status.clear()
        self.endResetModel()

    def add_row(self) -> None:
        idx = len(self._items)
        self.beginInsertRows(QModelIndex(), idx, idx)
        self._items.append(BatchItem(name=""))
        self.endInsertRows()

    def remove_row(self, row: int) -> None:
        if not (0 <= row < len(self._items)):
            return
        self.beginRemoveRows(QModelIndex(), row, row)
        del self._items[row]
        # Shift status entries down.
        new_status: dict[int, str] = {}
        for r, status in self._status.items():
            if r < row:
                new_status[r] = status
            elif r > row:
                new_status[r - 1] = status
        self._status = new_status
        self.endRemoveRows()

    def set_status(self, row: int, status: str) -> None:
        if not (0 <= row < len(self._items)):
            return
        self._status[row] = status
        idx = self.index(row, 0)
        # Name column re-renders to show the new icon.
        self.dataChanged.emit(idx, idx, [Qt.ItemDataRole.DisplayRole])

    def get_status(self, row: int) -> str:
        return self._status.get(row, "pending")

    def clear_statuses(self) -> None:
        if not self._status:
            return
        self._status.clear()
        top = self.index(0, 0)
        bottom = self.index(self.rowCount() - 1, 0)
        self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.DisplayRole])
