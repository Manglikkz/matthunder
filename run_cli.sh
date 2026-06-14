#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "Starting matthunder CLI..."

if [ ! -f config.py ] && [ -f config.example.py ]; then
  cp config.example.py config.py
  echo "[OK] config.py dibuat dari config.example.py"
  echo "Edit config.py isi BOT_TOKEN, lalu jalankan script ini lagi."
  exit 0
fi

if [ -x ".venv/bin/python" ]; then
  PYTHON_BIN=".venv/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
  if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python"
  fi
fi

exec "$PYTHON_BIN" matthunder_cli.py "$@"
