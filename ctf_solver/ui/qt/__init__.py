"""PySide6 Qt UI for CTF Solver — Phase 2 of the rewrite.

Entry: ``python -m ctf_solver.ui.qt`` (dev) or the bundled .app (release).
See ``ctf_solver/ui/qt/app.py`` for the main entry point.
"""

__all__ = ["main"]


def main() -> int:
    """Lazy-import the real entry so importing this package is cheap."""
    from ctf_solver.ui.qt.app import main as _main

    return _main()
