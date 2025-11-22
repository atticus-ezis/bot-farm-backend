# myapp/serializers.py
from rest_framework import serializers
from .models import BotEvent, AttackType


##### Snapshot Serializers #####
class SnapShotCategoryPathListSerializer(serializers.Serializer):
    """Serializer for category path list."""

    request_path = serializers.CharField()
    path_count = serializers.IntegerField()


class SnapShotHighestThreatIpSerializer(serializers.Serializer):
    """Serializer for highest threat ip list."""

    ip_address = serializers.CharField()
    count = serializers.IntegerField()
    geo_location = serializers.CharField(allow_null=True)
    origin = serializers.CharField(allow_null=True)


class SnapShotCategorySerializer(serializers.Serializer):
    """Serializer for category snapshot aggregated data."""

    category = serializers.CharField()
    total_count = serializers.IntegerField()
    get_method_count = serializers.IntegerField()
    post_method_count = serializers.IntegerField()
    most_popular_paths = SnapShotCategoryPathListSerializer(many=True)


##### List Serializers #####
class PathAnalyticsSerializer(serializers.Serializer):
    """Serializer for path analytics aggregated data."""

    request_path = serializers.CharField()
    traffic_count = serializers.IntegerField(allow_null=True)
    scan_count = serializers.IntegerField(allow_null=True)
    spam_count = serializers.IntegerField(allow_null=True)
    attack_count = serializers.IntegerField(allow_null=True)
    created_at = serializers.DateTimeField(
        allow_null=True
    )  # Most recent event per path
    most_popular_attack = serializers.CharField(allow_null=True)


##### Detail Serializers #####
class AttackTypeDetailSerializer(serializers.ModelSerializer):
    """Serializer for AttackType (nested in BotEvent)."""

    class Meta:
        model = AttackType
        fields = [
            "id",
            "target_field",
            "pattern",
            "category",
            "raw_value",
            "created_at",
        ]
        read_only_fields = fields


class BotEventDetailSerializer(serializers.ModelSerializer):
    """Serializer for BotEvent detail view (full data)."""

    attacks = AttackTypeDetailSerializer(many=True, read_only=True)
    attack_count = serializers.SerializerMethodField()

    class Meta:
        model = BotEvent
        fields = [
            "id",
            "created_at",
            "method",
            "request_path",
            "email",
            "ip_address",
            "geo_location",
            "agent",
            "referer",
            "origin",
            "language",
            "data",
            "attack_attempted",
            "attacks",
            "attack_count",
        ]
        read_only_fields = fields

    def get_attack_count(self, obj):
        """Get attack count, using annotation if available."""
        if hasattr(obj, "attack_count"):
            return obj.attack_count
        return obj.attacks.count()


##### List Serializers #####
class BotEventListSerializer(serializers.ModelSerializer):
    """Serializer for BotEvent list view (summary)."""

    attack_count = serializers.SerializerMethodField()
    attack_categories = serializers.SerializerMethodField()

    class Meta:
        model = BotEvent
        fields = [
            "id",
            "created_at",
            "method",
            "request_path",
            "referer",
            "email",
            "ip_address",
            "agent",
            "language",
            "attack_attempted",
            "attack_count",
            "attack_categories",
        ]
        read_only_fields = fields

    def get_attack_count(self, obj):
        """Get attack count, using annotation if available."""
        if hasattr(obj, "attack_count"):
            return obj.attack_count
        return obj.attacks.count()

    def get_attack_categories(self, obj):
        """Get list of unique attack categories."""
        return list(obj.attacks.values_list("category", flat=True).distinct())
