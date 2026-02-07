"""
CTF Solver - A platform-agnostic agentic CTF solving framework.

This package provides tools and agents for solving Capture-The-Flag challenges
using the FAIR agentic framework with RAG-enhanced knowledge retrieval.
"""

from ctf_solver.config import SolverConfig
from ctf_solver.agent import build_agent

__version__ = "1.0.0"
__all__ = ["SolverConfig", "build_agent", "__version__"]
