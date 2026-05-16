"""Main window. Phase 2 Day 1 is a skeleton: titled window, status bar, an
empty left ``QDockWidget`` for the sidebar, and an empty central
``QTabWidget`` for Single/Batch tabs.

Day 2 populates the sidebar with the config widgets and wires
``QSettings`` persistence; Day 3 adds validation and conditional UI.
Day 4+ wires the single-run page, live trace, batch mode, and results.
"""

from __future__ import annotations

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QDockWidget,
    QLabel,
    QMainWindow,
    QStatusBar,
    QTabWidget,
    QWidget,
)

from ctf_solver.ui.qt.sidebar import SidebarWidget

_WINDOW_TITLE = "CTF Solver"
_DEFAULT_WIDTH = 1280
_DEFAULT_HEIGHT = 820


class MainWindow(QMainWindow):
    """Top-level window. Layout: left dock sidebar | central tabs | bottom status."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(_WINDOW_TITLE)
        self.resize(_DEFAULT_WIDTH, _DEFAULT_HEIGHT)

        # QSettings: stored under ~/Library/Preferences/edu.dig.ctfsolver.plist
        # on macOS once the app is bundled; org/app names set in app.py.
        self._settings = QSettings()
        self._restore_window_state()

        self._build_sidebar()
        self._build_central()
        self._build_statusbar()

    def _build_sidebar(self) -> None:
        self._sidebar_dock = QDockWidget("Configuration", self)
        self._sidebar_dock.setObjectName("SidebarDock")
        self._sidebar_dock.setAllowedAreas(
            Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea
        )
        self.sidebar = SidebarWidget(self)
        self.sidebar.setMinimumWidth(340)
        self._sidebar_dock.setWidget(self.sidebar)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, self._sidebar_dock)

    def _build_central(self) -> None:
        self._tabs = QTabWidget(self)
        # Placeholders — Day 4+ swaps these for the real pages.
        single = QLabel("Single challenge (Day 4)")
        single.setAlignment(Qt.AlignmentFlag.AlignCenter)
        batch = QLabel("Batch run (Day 5)")
        batch.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._tabs.addTab(single, "Single")
        self._tabs.addTab(batch, "Batch")
        self.setCentralWidget(self._tabs)

    def _build_statusbar(self) -> None:
        bar = QStatusBar(self)
        bar.showMessage("Ready")
        self.setStatusBar(bar)

    def _restore_window_state(self) -> None:
        geometry = self._settings.value("MainWindow/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        state = self._settings.value("MainWindow/state")
        if state is not None:
            self.restoreState(state)

    def closeEvent(self, event) -> None:  # noqa: N802 (Qt method name)
        self._settings.setValue("MainWindow/geometry", self.saveGeometry())
        self._settings.setValue("MainWindow/state", self.saveState())
        super().closeEvent(event)
