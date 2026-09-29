#!/usr/bin/env bash
# SentiNet launcher for Linux / macOS:  bash run.sh
# First run creates .venv and installs dependencies (needs internet once); later runs are offline.
set -e
cd "$(dirname "$0")"
PY=${PYTHON:-python3}
command -v "$PY" >/dev/null || { echo "Python 3.10-3.13 is required (python3 not found)"; exit 1; }
if [ ! -x .venv/bin/python ]; then
  echo "[SentiNet] creating virtual environment in .venv"
  "$PY" -m venv .venv
fi
if ! cmp -s requirements.txt .venv/installed.txt; then   # first run, or requirements changed
  echo "[SentiNet] installing dependencies (first run or after an update)"
  .venv/bin/python -m pip install --upgrade pip
  if [ "$(uname -s)" = "Linux" ]; then
    # CPU-only PyTorch: ~200 MB instead of several GB of CUDA libraries
    .venv/bin/python -m pip install torch --index-url https://download.pytorch.org/whl/cpu || true
  fi
  .venv/bin/python -m pip install --upgrade -r requirements.txt
  cp requirements.txt .venv/installed.txt
fi
echo "[SentiNet] starting the app (default http://localhost:8501, Ctrl+C to stop)"
exec .venv/bin/python -m sentinet app "$@"
