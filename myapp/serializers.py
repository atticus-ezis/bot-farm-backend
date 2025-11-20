from rest_framework import serializers

from .models import BotSubmission


class ContactBotSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    phone = serializers.CharField(required=False, allow_blank=True)
    message = serializers.CharField(required=True)


class BotSubmissionListSerializer(serializers.ModelSerializer):
    email_preview = serializers.CharField(read_only=True)

    class Meta:
        model = BotSubmission
        fields = [
            "id",
            "created_at",
            "name",
            "email_preview",
            "ip_address",
            "agent",
            "language",
            "referer",
        ]


class BotSubmissionDetailSerializer(serializers.ModelSerializer):
    email_preview = serializers.CharField(read_only=True)
    xss_attacks = serializers.SerializerMethodField()

    class Meta:
        model = BotSubmission
        fields = [
            "id",
            "created_at",
            "name",
            "email",
            "email_preview",
            "message",
            "ip_address",
            "full_ip_address",
            "agent",
            "language",
            "referer",
            "xss_attacks",
        ]

    def get_xss_attacks(self, obj):
        """Return related XSS attacks for this submission."""
        from .models import XSSAttack

        attacks = XSSAttack.objects.filter(submission=obj)
        return [
            {
                "field": attack.field,
                "pattern": attack.pattern,
                "snippet": attack.snippet,
            }
            for attack in attacks
        ]


class SubmissionStatsSerializer(serializers.Serializer):
    total_submissions = serializers.IntegerField()
    honeypot_hits = serializers.IntegerField()
    unique_ips = serializers.IntegerField()
    recent = BotSubmissionListSerializer(many=True, read_only=True)
    tag_counts = serializers.DictField(child=serializers.IntegerField())
