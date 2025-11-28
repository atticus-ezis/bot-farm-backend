#!/usr/bin/env bash
set -e

# Ensure script is executable (in case volume mount lost permissions)
chmod +x /app/entrypoint.sh 2>/dev/null || true

# Wait for database to be ready
echo "Waiting for database to be ready..."
until pg_isready -h "${DB_HOST:-db}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" > /dev/null 2>&1; do
  echo "Database is unavailable - sleeping"
  sleep 1
done
echo "Database is ready!"

# Run migrations
python manage.py migrate --noinput

# Run tests if RUN_TESTS environment variable is set
if [ "${RUN_TESTS:-false}" = "true" ]; then
    echo "Running tests..."
    pytest myapp/tests/ -v
    TEST_EXIT_CODE=$?
    if [ $TEST_EXIT_CODE -ne 0 ]; then
        echo "Tests failed with exit code $TEST_EXIT_CODE"
        exit $TEST_EXIT_CODE
    fi
    echo "All tests passed!"
fi

exec "$@"