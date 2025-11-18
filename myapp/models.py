from django.db import models

from .fields import FlexibleArrayField


class BotSubmission(models.Model):
    email_submitted = models.CharField(max_length=254, null=True, blank=True)
    raw_body = models.TextField()
    ip_address = models.CharField(max_length=64)
    forwarded_for = models.CharField(max_length=256, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    referer = models.TextField(null=True, blank=True)
    headers_json = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)
    geo = models.JSONField(null=True, blank=True)
    detection_tags = FlexibleArrayField(blank=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-created_at']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['email_submitted']),
        ]

    def __str__(self) -> str:
        return f'{self.email_submitted or "unknown"} @ {self.ip_address}'

    def save(self, *args, **kwargs):
        tags = [tag for tag in (self.detection_tags or []) if tag]
        self.detection_tags = sorted(set(tags))
        super().save(*args, **kwargs)

    @property
    def is_honeypot(self) -> bool:
        return 'honeypot-hit' in (self.detection_tags or [])

    @property
    def email_preview(self) -> str:
        if not self.email_submitted:
            return ''
        return (self.email_submitted[:48] + '…') if len(self.email_submitted) > 48 else self.email_submitted
