"""Top-level entry shim for the bundled CTF Solver Qt app.

py2app turns *this* file into ``CTF Solver.app`` — its ``main()`` is what
runs when the user double-clicks the bundle.

Critical: env vars and the FAISS/OpenMP libomp guard must be set
**before** any module that pulls in faiss, torch, or sentence-transformers
is imported, otherwise the dyld linker resolves their libomp.dylib copies
in the wrong order and the first faiss::IndexIDMap::search_ex call
segfaults silently. Memory note: ``memory/faiss_libomp_crash.md``.

When launched via Finder we still set the env var here as a backstop,
but the more reliable approach is the ``LSEnvironment`` block in
``setup_py2app.py`` which the system applies before Python starts.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


def _install_libomp_guard() -> None:
    """On Darwin: point ``DYLD_INSERT_LIBRARIES`` at the faiss-bundled
    libomp so torch / sklearn / faiss all share one OpenMP runtime.
    Safe no-op if the file isn't present (e.g. the user installs without
    faiss) or if the env var is already set externally."""
    if sys.platform != "darwin":
        return
    if os.environ.get("DYLD_INSERT_LIBRARIES"):
        return  # respect whatever the user / launcher already set
    # Search both the dev venv layout and the py2app bundle Resources tree.
    candidates: list[Path] = []
    here = Path(__file__).resolve()
    candidates.extend(
        here.parent.glob(".venv/lib/python*/site-packages/faiss/.dylibs/libomp.dylib")
    )
    # py2app bundles site-packages under <Contents>/Resources/lib/python*/...
    try:
        bundle_root = here.parent.parent  # Contents/
        candidates.extend(
            bundle_root.glob(
                "Resources/lib/python*/site-packages/faiss/.dylibs/libomp.dylib"
            )
        )
    except OSError:
        pass
    for c in candidates:
        if c.is_file():
            os.environ["DYLD_INSERT_LIBRARIES"] = str(c)
            os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
            os.environ.setdefault("KMP_INIT_AT_FORK", "FALSE")
            return


# Set the thread caps and tokenizer flag matching scripts/run.sh — these
# must be in place before sentence-transformers / faiss / torch import.
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")
os.environ.setdefault("VECLIB_MAXIMUM_THREADS", "1")
os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")

_install_libomp_guard()


def main() -> int:
    # Import lazily so the env-var prelude runs first.
    from ctf_solver.ui.qt.app import main as _qt_main

    return _qt_main()


if __name__ == "__main__":
    sys.exit(main())
