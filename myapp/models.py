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

    attack_attempted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.method} | {self.request_path} | XSS: {self.attack_attempted}"


class AttackType(models.Model):
    class AttackCategory(models.TextChoices):
        XSS = "XSS", "Cross-Site Scripting"
        SQLI = "SQLI", "SQL Injection"
        LFI = "LFI", "Local File Inclusion"
        CMD = "CMD", "Command Injection"
        TRAVERSAL = "TRAVERSAL", "Directory Traversal"
        SSTI = "SSTI", "Template Injection"
        OTHER = "OTHER", "Other"

    bot_event = models.ForeignKey(
        BotEvent,
        related_name="attacks",
        on_delete=models.PROTECT,
    )

    target_field = models.CharField(max_length=200)  # which input triggered detection
    pattern = models.CharField(max_length=100)  # e.g. img_onerror, or_1_eq_1
    category = models.CharField(
        "Attack Type",
        max_length=50,
        choices=AttackCategory.choices,
    )

    raw_value = models.TextField()  # full context: "<img src=x onerror=alert(1)>"

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.category} ({self.pattern}) in '{self.target_field}'"
