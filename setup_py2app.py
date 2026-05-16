"""py2app build script for ``CTF Solver.app``.

Dev iteration (symlinks Python source back to the bundle):

    python setup_py2app.py py2app -A

Release build (everything embedded):

    python setup_py2app.py py2app

After a release build:

    codesign --deep --force --sign - "dist/CTF Solver.app"
    open "dist/CTF Solver.app"

Bundle size: ~2-3 GB. The big contributors are faiss-cpu, torch, and
sentence-transformers — see the ``excludes`` list for what we drop.
"""

from __future__ import annotations

from pathlib import Path

from setuptools import setup

HERE = Path(__file__).resolve().parent

APP = ["ctf_solver_qt.py"]
DATA_FILES: list = []

# LSEnvironment is applied by the OS *before* Python starts when the .app is
# launched via Finder — the most reliable place to set the libomp guard
# env var. The path is relative to the bundle's Contents/Resources/.
LIBOMP_REL_PATH = "@executable_path/../Resources/lib/python3.13/site-packages/faiss/.dylibs/libomp.dylib"

PLIST = {
    "CFBundleName": "CTF Solver",
    "CFBundleDisplayName": "CTF Solver",
    "CFBundleIdentifier": "edu.dig.ctfsolver",
    "CFBundleVersion": "0.1.0",
    "CFBundleShortVersionString": "0.1.0",
    "LSMinimumSystemVersion": "12.0",
    "NSHighResolutionCapable": True,
    # Env applied at launch time for double-click invocations.
    "LSEnvironment": {
        "DYLD_INSERT_LIBRARIES": LIBOMP_REL_PATH,
        "KMP_DUPLICATE_LIB_OK": "TRUE",
        "KMP_INIT_AT_FORK": "FALSE",
        "TOKENIZERS_PARALLELISM": "false",
        "OMP_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "VECLIB_MAXIMUM_THREADS": "1",
        "TRANSFORMERS_VERBOSITY": "error",
    },
}

OPTIONS = {
    "argv_emulation": False,
    "plist": PLIST,
    # Include the whole ctf_solver package (UI + agent + tools).
    "packages": ["ctf_solver", "PySide6", "shiboken6"],
    # Force-include modules py2app's static analyser doesn't always find.
    "includes": [
        "qasync",
        "asyncio",
        "faiss",
        "sentence_transformers",
    ],
    # Skip the Streamlit stack — it's a parallel UI we no longer launch
    # from the bundle. Saves ~200 MB.
    "excludes": [
        "streamlit",
        "tornado",
        "altair",
        "pyarrow",
        # MLX is optional; users who want it should run from the dev venv
        # in ~/mlx-env. Stripping it keeps the bundle smaller.
        "mlx",
        "mlx_lm",
        "outlines",
    ],
    # Optional: set after generating ``ctf_solver/ui/qt/resources/icon.icns``.
    # "iconfile": str(HERE / "ctf_solver" / "ui" / "qt" / "resources" / "icon.icns"),
}


if __name__ == "__main__":
    setup(
        name="CTF Solver",
        app=APP,
        data_files=DATA_FILES,
        options={"py2app": OPTIONS},
        setup_requires=["py2app"],
    )
