"""
SQLite-compatible list aggregation (replaces PostgreSQL ArrayAgg).
Uses GROUP_CONCAT; serializers should split by LISTAGG_DELIMITER to get a list.
"""
from django.db.models import Aggregate, CharField

# Delimiter unlikely to appear in category names or emails
LISTAGG_DELIMITER = "\x1e"


class ListAgg(Aggregate):
    """
    Aggregate that returns a delimiter-separated string of values (SQLite GROUP_CONCAT).
    In serializers, split by LISTAGG_DELIMITER to get a list. Replaces ArrayAgg on SQLite.
    """
    function = "GROUP_CONCAT"
    name = "ListAgg"
    template = "GROUP_CONCAT(DISTINCT %(expressions)s, '%(delimiter)s')"
    output_field = CharField()

    def __init__(self, expression, delimiter=LISTAGG_DELIMITER, **extra):
        super().__init__(expression, delimiter=delimiter, **extra)
