from django.contrib import admin

from .models import BotEvent, XSSAttack


class XSSAttackInline(admin.TabularInline):
    """Inline admin for XSSAttack, displayed within BotEvent admin."""

    model = XSSAttack
    extra = 0
    readonly_fields = ("field", "pattern", "raw_value", "created_at")
    can_delete = False
    fields = ("field", "pattern", "raw_value", "created_at")
    verbose_name = "XSS Attack"
    verbose_name_plural = "XSS Attacks"


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
        "xss_attempted",
        "xss_attack_count",
        "xss_patterns",
    )
    list_filter = (
        "created_at",
        "method",
        "xss_attempted",
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
    )
    ordering = ("-created_at",)
    inlines = [XSSAttackInline]
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
                "fields": ("xss_attempted",),
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

    def xss_attack_count(self, obj):
        """Display count of XSS attacks for this event."""
        count = obj.xss_attacks.count()
        return count if count > 0 else "—"

    xss_attack_count.short_description = "XSS Count"
    xss_attack_count.admin_order_field = "xss_attempted"

    def xss_patterns(self, obj):
        """Display XSS attack patterns, sortable by pattern."""
        patterns = obj.xss_attacks.values_list("pattern", flat=True).distinct()
        if patterns:
            return ", ".join(sorted(patterns))
        return "—"

    xss_patterns.short_description = "XSS Patterns"
    xss_patterns.admin_order_field = "xss_attacks__pattern"


@admin.register(XSSAttack)
class XSSAttackAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "bot_event",
        "field",
        "pattern",
        "created_at",
        "bot_event_created_at",
        "bot_event_method",
        "bot_event_path",
    )
    list_filter = ("pattern", "field", "created_at", "bot_event__method")
    search_fields = (
        "field",
        "pattern",
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
                    "field",
                    "pattern",
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
