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
  # Use python from PATH (which includes venv/bin if set correctly)
  python manage.py migrate --noinput || {
    echo ">>> WARNING: Migrations failed, continuing anyway"
  }
fi

# Finally exec the CMD (this becomes PID 1)
# If CMD is provided, use it; otherwise use default gunicorn command
if [ $# -eq 0 ]; then
  echo ">>> entrypoint: no CMD provided, using default gunicorn"
  exec gunicorn codex_test.wsgi:application --bind "0.0.0.0:${PORT:-10000}" --workers 3
else
  echo ">>> entrypoint: exec: $@"
  exec "$@"
fi

