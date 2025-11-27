from django.core.management.base import BaseCommand
from django.core.management import call_command
from django.db import connection


class Command(BaseCommand):
    help = "Reset database by dropping all tables and running migrations"

    def add_arguments(self, parser):
        parser.add_argument(
            "--noinput",
            "--no-input",
            action="store_true",
            help="Skip confirmation prompt",
        )

    def handle(self, *args, **options):
        if not options["noinput"]:
            confirm = input(
                "This will DROP ALL TABLES in the database. Are you sure? (yes/no): "
            )
            if confirm.lower() != "yes":
                self.stdout.write(self.style.WARNING("Operation cancelled."))
                return

        self.stdout.write(self.style.WARNING("Dropping all tables..."))

        with connection.cursor() as cursor:
            # Drop all tables in the public schema
            cursor.execute("""
                DO $$ DECLARE
                    r RECORD;
                BEGIN
                    -- Drop all tables
                    FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
                        EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                    END LOOP;
                END $$;
            """)

            # Reset the django_migrations table
            cursor.execute("DROP TABLE IF EXISTS django_migrations CASCADE;")

        self.stdout.write(self.style.SUCCESS("All tables dropped."))

        self.stdout.write("Running migrations...")
        call_command("migrate", verbosity=1)

        self.stdout.write(self.style.SUCCESS("Database reset complete!"))
