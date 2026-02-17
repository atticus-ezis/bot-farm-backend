#!/usr/bin/env bash
set -e

# Optional: print a header
echo ">>> entrypoint: starting (pid $$)"

# Set defaults
APP_HOME="${APP_HOME:-/app}"
VENV_PATH="${VENV_PATH:-${APP_HOME}/.venv}"

# Run migrations (only if enabled)
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo ">>> entrypoint: running migrations"
  # Use python from venv if it exists, otherwise use system python
  if [ -f "${VENV_PATH}/bin/python" ]; then
    "${VENV_PATH}/bin/python" manage.py migrate --noinput || {
      echo ">>> WARNING: Migrations failed, continuing anyway"
    }
  else
    python manage.py migrate --noinput || {
      echo ">>> WARNING: Migrations failed, continuing anyway"
    }
  fi
fi

# Load fixture (only if enabled and file exists)
if [ "${RUN_LOADDATA:-true}" = "true" ] && [ -f "${APP_HOME}/data-snapshot.json" ]; then
  echo ">>> entrypoint: loading data-snapshot.json"
  if [ -f "${VENV_PATH}/bin/python" ]; then
    "${VENV_PATH}/bin/python" manage.py loaddata data-snapshot.json || {
      echo ">>> WARNING: loaddata failed (e.g. duplicate keys if DB already has data), continuing anyway"
    }
  else
    python manage.py loaddata data-snapshot.json || {
      echo ">>> WARNING: loaddata failed (e.g. duplicate keys if DB already has data), continuing anyway"
    }
  fi
fi

# Finally exec the CMD (this becomes PID 1)
# If CMD is provided, use it; otherwise use default gunicorn command
if [ $# -eq 0 ]; then
  echo ">>> entrypoint: no CMD provided, using default gunicorn"
  exec gunicorn codex_test.wsgi:application \
    --bind "0.0.0.0:${PORT:-10000}" \
    --workers 3 \
    --timeout 120 \
    --graceful-timeout 30
else
  echo ">>> entrypoint: exec: $@"
  exec "$@"
fi

