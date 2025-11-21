# myapp/models.py
import uuid
from django.db import models


class BotEvent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    geo_location = models.CharField(max_length=255, null=True, blank=True)
    agent = models.TextField(null=True, blank=True)
    referer = models.TextField(null=True, blank=True)
    language = models.CharField(max_length=100, null=True, blank=True)
    request_path = models.CharField(max_length=500)
    method = models.CharField(max_length=10)
    email = models.EmailField(null=True, blank=True)
    # Params submitted (JSON format)
    data = models.JSONField(null=True, blank=True)
    # Correlation token
    correlation_token = models.UUIDField(null=True, blank=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True)

    xss_attempted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.method} | {self.request_path} | XSS: {self.xss_attempted}"

    # def save(self, *args, **kwargs):
    #     if self.xss_attempted:
    #         return super().save(*args, **kwargs)
    #     if XSSAttack.objects.filter(bot_event=self).exists():
    #         self.xss_attempted = True
    #     super().save(*args, **kwargs)


class XSSAttack(models.Model):
    bot_event = models.ForeignKey(
        BotEvent,
        related_name="xss_attacks",
        on_delete=models.PROTECT,
    )
    field = models.CharField(max_length=200)  # which input had the XSS
    pattern = models.CharField(max_length=100)  # pattern name
    raw_value = models.TextField()  # full payload/context

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.pattern} attack in field '{self.field}'"
