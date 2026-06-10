#!/usr/bin/env bash
# Launch the Qt UI with the same Apple-Silicon libomp guard as scripts/run.sh.
#
# The FAISS + torch + sklearn libomp.dylib race on M-series segfaults during
# the first ``faiss::IndexIDMap::search_ex`` unless DYLD_INSERT_LIBRARIES
# forces a single libomp to win the load race. Setting this env var inside
# Python is too late — dyld has already resolved imports. Memory note:
# memory/faiss_libomp_crash.md.

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

exec "${HERE}/.venv/bin/python" -m ctf_solver.ui.qt "$@"
