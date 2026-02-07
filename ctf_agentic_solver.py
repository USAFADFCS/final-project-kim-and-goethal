#!/usr/bin/env python3
"""
ctf_agentic_solver.py - Platform-agnostic CTF solving agent

This is the main entry point for the CTF Solver framework.
It replaces the old pico_agentic_solver.py / andrewtesting17.py with a
fully platform-agnostic implementation.

Usage:
    # CLI mode
    python ctf_agentic_solver.py --challenge-url https://example.com/ctf \\
        --description "Web challenge with hidden flag"

    # With PicoCTF preset
    python ctf_agentic_solver.py --challenge-url https://saturn.picoctf.net:12345 \\
        --flag-preset picoctf

    # Interactive mode
    python ctf_agentic_solver.py

    # Streamlit GUI
    streamlit run ctf_solver/ui/streamlit_app.py

For legacy compatibility, this script also accepts the old arguments:
    --base-url (use --challenge-url instead)
    --challenge (use --description instead)
    --task (use --description instead)

See 'python ctf_agentic_solver.py --help' for all options.
"""

# =============================================================================
# CRITICAL: Set environment variables BEFORE any other imports
# Prevents segfaults on Apple Silicon with FAISS + sentence-transformers
# =============================================================================
import os
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("OMP_NUM_THREADS", "1")

import sys
from pathlib import Path

# Ensure the ctf_solver package is importable
sys.path.insert(0, str(Path(__file__).parent))

from ctf_solver.runner import cli_main

if __name__ == "__main__":
    cli_main()
