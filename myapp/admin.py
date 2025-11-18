from django.contrib import admin

from .models import BotSubmission


@admin.register(BotSubmission)
class BotSubmissionAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'created_at',
        'ip_address',
        'email_submitted',
        'forwarded_for',
        'referer',
        'is_honeypot',
    )
    list_filter = ('created_at', 'ip_address', 'detection_tags')
    search_fields = ('email_submitted', 'ip_address', 'headers_json', 'raw_body')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
