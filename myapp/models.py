from django.db import models


class BotSubmission(models.Model):
    # Form submission data
    name = models.CharField(max_length=255, null=True, blank=True)
    email = models.CharField(max_length=254, null=True, blank=True)
    message = models.TextField(null=True, blank=True)

    # Analytics data
    ip_address = models.CharField(max_length=64, null=True, blank=True)
    full_ip_address = models.CharField(max_length=512, null=True, blank=True)
    agent = models.TextField(null=True, blank=True)
    language = models.CharField(max_length=50, null=True, blank=True)
    referer = models.TextField(null=True, blank=True)

    # Timestamp
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        parts = []

        # Add email if available
        if self.email:
            parts.append(self.email)

        # Add name if available
        if self.name:
            parts.append(f"({self.name})")

        # Add IP address for context
        if self.ip_address:
            parts.append(f"from {self.ip_address}")

        # Build the string
        if parts:
            return " ".join(parts)

        # Fallback to ID if nothing else is available
        return f"Bot Submission #{self.id or 'new'}"

    @property
    def email_preview(self) -> str:
        if not self.email:
            return ""
        return (self.email[:48] + "…") if len(self.email) > 48 else self.email


class XSSAttack(models.Model):
    field = models.CharField(max_length=255)
    pattern = models.CharField(max_length=255)
    snippet = models.TextField()
    submission = models.ForeignKey(
        BotSubmission, on_delete=models.CASCADE, related_name="xss_attacks"
    )

    def __str__(self) -> str:
        return f"{self.pattern} in {self.field}"
