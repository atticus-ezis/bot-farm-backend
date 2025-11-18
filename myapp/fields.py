from django.db import models

try:
    from django.contrib.postgres.fields import ArrayField as DjangoArrayField
except ModuleNotFoundError:  # pragma: no cover - local fallback
    DjangoArrayField = None


class FlexibleArrayField(models.JSONField if DjangoArrayField is None else DjangoArrayField):
    """
    Behaves like a Postgres ArrayField when psycopg is available, otherwise falls back to JSON.
    """

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('default', list)
        if DjangoArrayField is None:
            super().__init__(*args, **kwargs)
        else:
            kwargs.setdefault('base_field', models.CharField(max_length=64))
            super().__init__(*args, **kwargs)
