"""
Allow running the CTF Solver as a module: python -m ctf_solver

Usage:
    python -m ctf_solver --challenge-url https://example.com/ctf
    python -m ctf_solver --help
"""

from ctf_solver.runner import cli_main

if __name__ == "__main__":
    cli_main()
