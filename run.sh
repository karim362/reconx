#!/data/data/com.termux/files/usr/bin/bash
# ReconX launcher for Termux / Linux
set -e
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd):$PYTHONPATH"
python -m reconx "$@"
