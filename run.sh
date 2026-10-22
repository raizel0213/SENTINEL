#!/usr/bin/env bash
# SENTINEL — one-command start (creates a venv on first run).
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[sentinel] creating virtual environment…"
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r backend/requirements.txt
exec python -m backend.app
