#!/usr/bin/env bash
# Run the console locally in MOCK mode — no model weights, no GPU, instant.
# Good for demoing the UI and the end-to-end flow. For the real models use
# provision.sh + deploy.sh (or set MODEL_BACKEND=transformers after installing
# the model layer from requirements.txt).
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
VENV=".venv-demo"

if [[ ! -d "$VENV" ]]; then
  "$PY" -m venv "$VENV"
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

pip install --quiet --upgrade pip
pip install --quiet \
  fastapi==0.137.2 "uvicorn[standard]==0.40.0" jinja2==3.1.6 \
  python-multipart==0.0.20 pydantic==2.13.4 pypdf==5.9.0 defusedxml==0.7.1

export MODEL_BACKEND="${MODEL_BACKEND:-mock}"
export DATA_DIR="${DATA_DIR:-$PWD/.data}"
HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-8080}"

echo "──────────────────────────────────────────────────────────────"
echo "  Leak-Inspect console  (backend=$MODEL_BACKEND)"
echo "  Console : http://$HOST:$PORT/"
echo "  API docs: http://$HOST:$PORT/docs"
echo "──────────────────────────────────────────────────────────────"
exec uvicorn app.main:app --host "$HOST" --port "$PORT"
