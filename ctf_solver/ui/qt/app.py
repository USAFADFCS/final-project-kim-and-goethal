"""Qt entry point.

Wires PySide6's event loop to asyncio via ``qasync`` so the agent's
``await agent.arun(...)`` codepath can run from a slot directly.

Run with::

    python -m ctf_solver.ui.qt

When bundled as a .app the wrapper ``ctf_solver_qt.py`` also installs the
``DYLD_INSERT_LIBRARIES`` libomp guard before any faiss/torch import — see
``memory/faiss_libomp_crash.md``.
"""

from __future__ import annotations

import os
import sys

# Match the env-var prelude that streamlit_app.py uses on import — keeps
# Apple Silicon stable when faiss/torch are pulled in by the agent.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

import warnings  # noqa: E402

warnings.filterwarnings("ignore", message=r"Accessing `__path__` from .*")

import asyncio  # noqa: E402

import qasync  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from ctf_solver.ui.qt.main_window import MainWindow  # noqa: E402


def main() -> int:
    """Build the QApplication, install the qasync event loop, show the
    main window, and run."""
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("CTF Solver")
    app.setOrganizationName("DIG")
    app.setOrganizationDomain("edu.dig.ctfsolver")

    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = MainWindow()
    window.show()

    with loop:
        loop.run_forever()
    return 0
