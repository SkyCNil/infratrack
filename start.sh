#!/usr/bin/env bash
set -euo pipefail

ITAM_HOST="${ITAM_HOST:-127.0.0.1}"
ITAM_PORT="${ITAM_PORT:-8000}"

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
fi

source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

echo "Starting ITAM on http://${ITAM_HOST}:${ITAM_PORT}"
uvicorn main:app --host "${ITAM_HOST}" --port "${ITAM_PORT}" --reload
