#!/usr/bin/env bash
set -e

# Wait for database to be ready
echo "Waiting for database to be ready..."
until pg_isready -h "${DB_HOST:-db}" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" > /dev/null 2>&1; do
  echo "Database is unavailable - sleeping"
  sleep 1
done
echo "Database is ready!"

# Run migrations
python manage.py migrate --noinput

exec "$@"