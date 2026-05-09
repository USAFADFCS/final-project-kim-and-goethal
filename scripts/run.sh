#!/usr/bin/env bash
# Workaround for the FAISS + multi-libomp segfault on Apple Silicon
# when MLX coexists with torch / sklearn / faiss-cpu in the same venv.
# Three competing libomp.dylib copies race during the first
# faiss::IndexIDMap::search_ex (the proactive RAG query) and segfault
# inside __kmp_suspend_initialize_thread.  DYLD_INSERT_LIBRARIES forces
# faiss's libomp to load first, so torch / sklearn pick it up too —
# single libomp wins.  Memory note: memory/faiss_libomp_crash.md.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAISS_OMP="${HERE}/.venv/lib/python3.13/site-packages/faiss/.dylibs/libomp.dylib"

if [[ "$(uname -s)" == "Darwin" && -f "${FAISS_OMP}" ]]; then
  export DYLD_INSERT_LIBRARIES="${FAISS_OMP}"
  export KMP_DUPLICATE_LIB_OK=TRUE
  export KMP_INIT_AT_FORK=FALSE
  export OMP_NUM_THREADS=1
  export MKL_NUM_THREADS=1
  export VECLIB_MAXIMUM_THREADS=1
fi
export PYTHONUNBUFFERED=1

exec "${HERE}/.venv/bin/python" -m ctf_solver.runner "$@"
