"""
SQLite-compatible list aggregation (replaces PostgreSQL ArrayAgg).
Uses GROUP_CONCAT; serializers should split by LISTAGG_DELIMITER to get a list.
"""
from django.db.models import Aggregate, CharField

# SQLite GROUP_CONCAT with DISTINCT uses comma separator (cannot specify custom delimiter with DISTINCT)
LISTAGG_DELIMITER = ","


class ListAgg(Aggregate):
    """
    Aggregate that returns a comma-separated string of DISTINCT values (SQLite GROUP_CONCAT).
    In serializers, split by LISTAGG_DELIMITER (comma) to get a list. Replaces ArrayAgg on SQLite.
    """
    function = "GROUP_CONCAT"
    name = "ListAgg"
    template = "GROUP_CONCAT(DISTINCT %(expressions)s)"
    output_field = CharField()

    def __init__(self, expression, **extra):
        super().__init__(expression, **extra)
