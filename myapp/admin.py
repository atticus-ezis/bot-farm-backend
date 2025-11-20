from django.contrib import admin

from .models import BotSubmission, XSSAttack


class XSSAttackInline(admin.TabularInline):
    """Inline admin for XSSAttack, displayed within BotSubmission admin."""

    model = XSSAttack
    extra = 0
    readonly_fields = ("field", "pattern", "snippet")
    can_delete = False
    fields = ("field", "pattern", "snippet")
    verbose_name = "XSS Attack"
    verbose_name_plural = "XSS Attacks"


@admin.register(BotSubmission)
class BotSubmissionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "created_at",
        "name",
        "email_preview",
        "ip_address",
        "agent",
        "language",
        "has_xss_attacks",
        "xss_patterns",
    )
    list_filter = ("created_at", "ip_address", "language")
    search_fields = ("name", "email", "ip_address", "message", "agent", "referer")
    readonly_fields = ("created_at", "email_preview")
    ordering = ("-created_at",)
    inlines = [XSSAttackInline]

    def has_xss_attacks(self, obj):
        """Display whether this submission has XSS attacks."""
        count = obj.xss_attacks.count()
        return f"Yes ({count})" if count > 0 else "No"

    has_xss_attacks.short_description = "XSS Attacks"
    has_xss_attacks.boolean = False

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
        "submission",
        "field",
        "pattern",
        "submission_created_at",
    )
    list_filter = ("pattern", "field")
    search_fields = (
        "field",
        "pattern",
        "snippet",
        "submission__email",
        "submission__name",
    )
    readonly_fields = ("submission_created_at",)
    ordering = ("-id",)

    def submission_created_at(self, obj):
        """Display the submission's created_at timestamp."""
        return obj.submission.created_at if obj.submission else None

    submission_created_at.short_description = "Submission Date"
    submission_created_at.admin_order_field = "submission__created_at"
