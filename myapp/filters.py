from django_filters import rest_framework as filters

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


class BotEventFilter(filters.FilterSet):
    """Custom filterset for BotEvent with advanced filtering options."""

    # exact filters
    ip_address = filters.CharFilter(field_name="ip_address", lookup_expr="exact")
    exact_request_path = filters.CharFilter(
        field_name="request_path", lookup_expr="exact"
    )
    # Text filters with icontains lookup
    email = filters.CharFilter(field_name="email", lookup_expr="icontains")
    geo_location = filters.CharFilter(
        field_name="geo_location", lookup_expr="icontains"
    )
    language = filters.CharFilter(field_name="language", lookup_expr="icontains")
    request_path = filters.CharFilter(
        field_name="request_path", lookup_expr="icontains"
    )
    referer = filters.CharFilter(field_name="referer", lookup_expr="icontains")
    origin = filters.CharFilter(field_name="origin", lookup_expr="icontains")
    agent = filters.CharFilter(field_name="agent", lookup_expr="icontains")
    raw_attack_value = filters.CharFilter(
        field_name="attacks__raw_value",
        lookup_expr="icontains",
    )
    bot_data = filters.JSONFilter(
        field_name="data",
        lookup_expr="icontains",
    )
    # Boolean filter
    attack_attempted = filters.BooleanFilter(field_name="attack_attempted")

    # Choice filters
    method = filters.ChoiceFilter(
        field_name="method", choices=[MethodChoice.GET.value, MethodChoice.POST.value]
    )

    # Attack category filter (through related AttackType)
    attack_category = filters.ChoiceFilter(
        field_name="attacks__category",
        distinct=True,
        choices=AttackType.AttackCategory.choices,
    )

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
            "attack_category",
            "raw_attack_value",
            "bot_data",
            "correlation_token",
            "exact_request_path",
        ]
