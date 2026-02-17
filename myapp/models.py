# myapp/models.py
import uuid
from django.db import models


class BotEvent(models.Model):
    class MethodChoice(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"

    class EventCategory(models.TextChoices):
        SCAN = "scan", "Scan"
        SPAM = "spam", "Spam"
        ATTACK = "attack", "Attack"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # Tracking
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    geo_location = models.CharField(
        max_length=255, null=True, blank=True, db_index=True
    )
    agent = models.TextField(null=True, blank=True)
    referer = models.TextField(null=True, blank=True, db_index=True)
    origin = models.TextField(null=True, blank=True, db_index=True)
    language = models.CharField(max_length=100, null=True, blank=True)
    request_path = models.CharField(max_length=500, db_index=True)
    email = models.EmailField(null=True, blank=True, db_index=True)
    # Correlation token
    correlation_token = models.UUIDField(null=True, blank=True, db_index=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    attack_attempted = models.BooleanField(default=False, db_index=True)
    event_category = models.CharField(
        max_length=10,
        choices=EventCategory.choices,
        null=True,
        blank=True,
        db_index=True,
        help_text="Category determined at creation: scan, spam, or attack",
    )

    # params
    method = models.CharField(
        max_length=10,
        choices=MethodChoice.choices,
        db_index=True,
        default=MethodChoice.GET.value,
    )
    data_present = models.BooleanField(default=False, db_index=True)
    field_count = models.IntegerField(default=0)
    target_fields = models.JSONField(
        default=list,
        null=True,
        blank=True,
        help_text="List of field names (stored as JSON for SQLite compatibility)",
    )
    data_details = models.JSONField(null=True, blank=True)

    class Meta:
        indexes = [
            # Composite index for spam_bot filter (attack_attempted=False, method=POST, data__isnull=False)
            models.Index(
                fields=["attack_attempted", "method"], name="botevent_attack_method_idx"
            ),
            # Composite index for scan_bot filter (attack_attempted=False, method=GET)
            models.Index(
                fields=["attack_attempted", "method", "request_path"],
                name="botevent_atk_meth_path_idx",
            ),
            # Composite index for IP aggregations with ordering
            models.Index(
                fields=["ip_address", "created_at"], name="botevent_ip_created_idx"
            ),
            # Composite index for path aggregations with attack filtering
            models.Index(
                fields=["request_path", "attack_attempted"],
                name="botevent_path_attack_idx",
            ),
            # Composite index for common filter combinations
            models.Index(
                fields=["ip_address", "request_path"], name="botevent_ip_path_idx"
            ),
        ]

    def set_category(self, save=True):
        """
        Determine and set the event_category based on current instance attributes.
        Uses the utility function to determine the category, then sets it on the instance.

        Args:
            save: If True, save the instance after setting the category. Default True.
        """
        data_present = self.data_present
        attack_attempted = self.attack_attempted

        if attack_attempted:
            self.event_category = self.EventCategory.ATTACK
        elif data_present:
            self.event_category = self.EventCategory.SPAM
        else:
            self.event_category = self.EventCategory.SCAN

        if save:
            self.save(update_fields=["event_category"])

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

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

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
        db_index=True,
    )

    raw_value = models.TextField()
    full_value = models.TextField(default="")

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            # Composite index for filtering by bot_event and category (common query pattern)
            models.Index(
                fields=["bot_event", "category"],
                name="attacktype_be_cat_idx",
            ),
            # Composite index for category aggregations
            models.Index(
                fields=["category", "created_at"],
                name="attacktype_cat_created_idx",
            ),
        ]

    def __str__(self):
        return f"{self.category} ({self.pattern}) in '{self.target_field}'"
