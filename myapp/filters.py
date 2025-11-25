from django_filters import rest_framework as filters
from django.db.models import Q

from .models import BotEvent, AttackType
from .enums import MethodChoice


class AggregatePathFilter(filters.FilterSet):
    """Custom filterset for AggregatePath with advanced filtering options."""

    most_popular_attack = filters.ChoiceFilter(
        field_name="most_popular_attack", choices=AttackType.AttackCategory.choices
    )

    class Meta:
        model = BotEvent
        fields = ["most_popular_attack"]


class AggregateIPFilter(filters.FilterSet):
    """Custom filterset for AggregateIP with advanced filtering options."""

    # Exact filters
    ip_address = filters.CharFilter(field_name="ip_address", lookup_expr="exact")
    referer = filters.CharFilter(field_name="referer", lookup_expr="exact")
    agent = filters.CharFilter(field_name="agent", lookup_expr="exact")
    language = filters.CharFilter(field_name="language", lookup_expr="exact")
    geo_location = filters.CharFilter(field_name="geo_location", lookup_expr="exact")
    attack_categories = filters.MultipleChoiceFilter(
        field_name="attacks__category",
        choices=AttackType.AttackCategory.choices,
    )

    class Meta:
        model = BotEvent
        fields = [
            "ip_address",
            "referer",
            "agent",
            "language",
            "geo_location",
            "attack_categories",
        ]


class BotEventFilter(filters.FilterSet):
    """Custom filterset for BotEvent with advanced filtering options."""

    # Exact filters
    ip_address = filters.CharFilter(field_name="ip_address", lookup_expr="exact")
    exact_request_path = filters.CharFilter(
        field_name="request_path",
        lookup_expr="exact",
        help_text="Exact match filter for request path. Alternative to request_path filter.",
    )
    email = filters.CharFilter(field_name="email", lookup_expr="exact")
    geo_location = filters.CharFilter(field_name="geo_location", lookup_expr="exact")
    language = filters.CharFilter(field_name="language", lookup_expr="exact")
    request_path = filters.CharFilter(field_name="request_path", lookup_expr="exact")
    referer = filters.CharFilter(field_name="referer", lookup_expr="exact")
    origin = filters.CharFilter(field_name="origin", lookup_expr="exact")
    agent = filters.CharFilter(field_name="agent", lookup_expr="exact")
    raw_attack_value = filters.CharFilter(
        field_name="attacks__raw_value",
        lookup_expr="icontains",
        help_text="Search in attack raw values (case-insensitive partial match).",
    )
    bot_data = filters.CharFilter(
        field_name="data",
        lookup_expr="icontains",
    )
    # Boolean filter
    attack_attempted = filters.BooleanFilter(field_name="attack_attempted")

    # Choice filters
    method = filters.ChoiceFilter(
        field_name="method", choices=[MethodChoice.GET.value, MethodChoice.POST.value]
    )
    attack_categories = filters.MultipleChoiceFilter(
        field_name="attacks__category",  # is this model field?
        choices=AttackType.AttackCategory.choices,
        help_text="Filter by attack categories. Can select multiple categories.",
    )

    # Custom bundled filters
    spam_bot = filters.BooleanFilter(
        method="filter_spam_bot",
        help_text="Filter for spam bots: attack_attempted=False, method=POST, data__isnull=False. Set to true to show only spam bots.",
    )
    scan_bot = filters.BooleanFilter(
        method="filter_scan_bot",
        help_text="Filter for scan bots: attack_attempted=False, method=GET, (data__isnull=True OR data={}). Set to true to show only scan bots.",
    )

    def filter_spam_bot(self, queryset, name, value):
        """Filter for spam bots: attack_attempted=False, method=POST, data__isnull=False"""
        if value:
            return queryset.filter(
                attack_attempted=False,
                method=MethodChoice.POST.value,
                data__isnull=False,
            )
        return queryset

    def filter_scan_bot(self, queryset, name, value):
        """Filter for scan bots: attack_attempted=False, method=GET, (data__isnull=True OR data={})"""
        if value:
            return queryset.filter(
                Q(
                    attack_attempted=False,
                    method=MethodChoice.GET.value,
                    data__isnull=True,
                )
                | Q(
                    attack_attempted=False,
                    method=MethodChoice.GET.value,
                    data={},
                )
            )
        return queryset

    class Meta:
        model = BotEvent
        fields = [
            "ip_address",
            "email",
            "geo_location",
            "request_path",
            "referer",
            "origin",
            "method",
            "agent",
            "language",
            "attack_attempted",
            "attack_categories",
            "raw_attack_value",
            "bot_data",
            "correlation_token",
            "exact_request_path",
            "spam_bot",
            "scan_bot",
        ]


class AttackTypeFilter(filters.FilterSet):
    """Custom filterset for AttackType with advanced filtering options."""

    # Exact filters
    category = filters.ChoiceFilter(  # linked from snapshot view
        field_name="category", choices=AttackType.AttackCategory.choices
    )
    pattern = filters.CharFilter(field_name="pattern", lookup_expr="exact")
    target_field = filters.CharFilter(field_name="target_field", lookup_expr="exact")
    raw_value = filters.CharFilter(field_name="raw_value", lookup_expr="icontains")

    # BotEvent relationship filters
    bot_event_id = filters.UUIDFilter(field_name="bot_event__id")
    ip_address = filters.CharFilter(
        field_name="bot_event__ip_address", lookup_expr="exact"
    )
    request_path = filters.CharFilter(
        field_name="bot_event__request_path", lookup_expr="exact"
    )
    method = filters.ChoiceFilter(
        field_name="bot_event__method",
        choices=[("GET", "GET"), ("POST", "POST")],
    )

    class Meta:
        model = AttackType
        fields = [
            "category",
            "pattern",
            "target_field",
            "raw_value",
            "bot_event_id",
            "ip_address",
            "request_path",
            "method",
        ]
