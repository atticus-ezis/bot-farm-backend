from django.contrib import admin
from django.db.models import Count

from .models import BotEvent, AttackType


class AttackTypeInline(admin.TabularInline):
    """Inline admin for AttackType, displayed within BotEvent admin."""

    model = AttackType
    extra = 0
    readonly_fields = ("target_field", "pattern", "category", "raw_value", "created_at")
    can_delete = False
    fields = ("target_field", "pattern", "category", "raw_value", "created_at")
    verbose_name = "Attack"
    verbose_name_plural = "Attacks"


@admin.register(BotEvent)
class BotEventAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "created_at",
        "method",
        "request_path",
        "email",
        "ip_address",
        "agent",
        "language",
        "attack_attempted",
        "attack_count",
        "attack_categories",
    )
    list_filter = (
        "created_at",
        "method",
        "attack_attempted",
        "ip_address",
        "language",
    )
    search_fields = (
        "email",
        "ip_address",
        "request_path",
        "agent",
        "referer",
        "correlation_token",
    )
    readonly_fields = (
        "id",
        "created_at",
        "correlation_token",
        "attack_count",
        "attack_categories",
    )
    ordering = ("-created_at",)
    inlines = [AttackTypeInline]
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Request Information",
            {
                "fields": (
                    "method",
                    "request_path",
                    "correlation_token",
                    "data",
                )
            },
        ),
        (
            "Client Information",
            {
                "fields": (
                    "ip_address",
                    "geo_location",
                    "agent",
                    "referer",
                    "language",
                )
            },
        ),
        (
            "Contact Information",
            {
                "fields": ("email",),
            },
        ),
        (
            "Security",
            {
                "fields": (
                    "attack_attempted",
                    "attack_count",
                    "attack_categories",
                ),
            },
        ),
        (
            "Metadata",
            {
                "fields": (
                    "id",
                    "created_at",
                )
            },
        ),
    )

    def get_queryset(self, request):
        qs = super().get_queryset(request)
        qs = qs.annotate(_attack_count=Count("attacks", distinct=True))
        return qs

    def attack_count(self, obj):
        """Display count of attacks for this event."""
        count = obj.attacks.count()
        return count if count > 0 else "—"

    attack_count.short_description = "Attack Count"
    attack_count.admin_order_field = "_attack_count"

    def attack_categories(self, obj):
        """Display attack categories found in this event."""
        categories = obj.attacks.values_list("category", flat=True).distinct()
        if categories:
            return ", ".join(sorted(categories))
        return "—"

    attack_categories.short_description = "Attack Categories"


@admin.register(AttackType)
class AttackTypeAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "bot_event",
        "target_field",
        "pattern",
        "category",
        "created_at",
        "bot_event_created_at",
        "bot_event_method",
        "bot_event_path",
    )
    list_filter = (
        "category",
        "pattern",
        "target_field",
        "created_at",
        "bot_event__method",
    )
    search_fields = (
        "target_field",
        "pattern",
        "category",
        "raw_value",
        "bot_event__email",
        "bot_event__request_path",
        "bot_event__ip_address",
    )
    readonly_fields = (
        "bot_event_created_at",
        "bot_event_method",
        "bot_event_path",
        "created_at",
    )
    ordering = ("-created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        (
            "Attack Details",
            {
                "fields": (
                    "bot_event",
                    "target_field",
                    "pattern",
                    "category",
                    "raw_value",
                )
            },
        ),
        (
            "Event Information",
            {
                "fields": (
                    "bot_event_method",
                    "bot_event_path",
                    "bot_event_created_at",
                )
            },
        ),
        (
            "Metadata",
            {
                "fields": ("created_at",),
            },
        ),
    )

    def bot_event_created_at(self, obj):
        """Display the bot event's created_at timestamp."""
        return obj.bot_event.created_at if obj.bot_event else None

    bot_event_created_at.short_description = "Event Date"
    bot_event_created_at.admin_order_field = "bot_event__created_at"

    def bot_event_method(self, obj):
        """Display the bot event's HTTP method."""
        return obj.bot_event.method if obj.bot_event else None

    bot_event_method.short_description = "Method"
    bot_event_method.admin_order_field = "bot_event__method"

    def bot_event_path(self, obj):
        """Display the bot event's request path."""
        return obj.bot_event.request_path if obj.bot_event else None

    bot_event_path.short_description = "Request Path"
    bot_event_path.admin_order_field = "bot_event__request_path"
