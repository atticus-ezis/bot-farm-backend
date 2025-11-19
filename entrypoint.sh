#!/usr/bin/env bash
set -e

# wait for db to be ready


# Run migrations
python manage.py migrate --noinput


exec "$@"