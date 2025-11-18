from rest_framework import serializers

from .models import BotSubmission


class BotSubmissionListSerializer(serializers.ModelSerializer):
    email_preview = serializers.CharField(read_only=True)

    class Meta:
        model = BotSubmission
        fields = [
            'id',
            'created_at',
            'ip_address',
            'email_preview',
            'detection_tags',
            'user_agent',
            'referer',
        ]


class BotSubmissionDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = BotSubmission
        fields = [
            'id',
            'email_submitted',
            'raw_body',
            'ip_address',
            'forwarded_for',
            'user_agent',
            'referer',
            'headers_json',
            'geo',
            'detection_tags',
            'created_at',
        ]


class SubmissionStatsSerializer(serializers.Serializer):
    total_submissions = serializers.IntegerField()
    honeypot_hits = serializers.IntegerField()
    unique_ips = serializers.IntegerField()
    recent = BotSubmissionListSerializer(many=True, read_only=True)
    tag_counts = serializers.DictField(child=serializers.IntegerField())
