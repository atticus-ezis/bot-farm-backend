#!/bin/bash
# Quick database reset script

echo "⚠️  WARNING: This will DROP ALL TABLES in the database!"
read -p "Are you sure? (type 'yes' to continue): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Cancelled."
    exit 1
fi

cd "$(dirname "$0")"

echo "Dropping all tables..."
python manage.py dbshell <<EOF
DO \$\$ DECLARE
    r RECORD;
BEGIN
    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
    END LOOP;
END \$\$;
EOF

echo "Running migrations..."
python manage.py migrate

echo "✅ Database reset complete!"

