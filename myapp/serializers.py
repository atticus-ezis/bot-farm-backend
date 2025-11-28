# myapp/serializers.py
from rest_framework import serializers
from .models import BotEvent, AttackType


##### Snapshot Serializers #####
class SnapShotCategoryPathListSerializer(serializers.Serializer):
    """Serializer for category path list."""

    request_path = serializers.CharField()
    path_count = serializers.IntegerField()


class SnapShotCategorySerializer(serializers.Serializer):
    """Serializer for category snapshot aggregated data."""

    category = serializers.CharField()  # links to AttackTypeList with category filter
    total_count = serializers.IntegerField()
    most_popular_paths = SnapShotCategoryPathListSerializer(many=True)


##### Attack Serializers (defined first to avoid circular dependencies) #####
class AttackTypeDetailSerializer(serializers.ModelSerializer):
    """Serializer for AttackType (nested in BotEvent or standalone)."""

    bot_event_id = serializers.UUIDField(source="bot_event.id", read_only=True)
    ip_address = serializers.CharField(
        source="bot_event.ip_address", read_only=True, allow_null=True
    )
    request_path = serializers.CharField(
        source="bot_event.request_path", read_only=True
    )

    class Meta:
        model = AttackType
        fields = [
            "id",
            "target_field",
            "pattern",
            "category",
            "raw_value",
            "full_value",
            "created_at",
            "bot_event_id",  # BotEventDetailSerializer filter on id
            "ip_address",  # IPAnalyticsDetailSerializer filter on ip_address
            "request_path",  # BotEventList filter on path
        ]
        read_only_fields = fields


class AttackTypeListSerializer(serializers.ModelSerializer):
    """Serializer for AttackType list view (summary)."""

    bot_event_id = serializers.UUIDField(source="bot_event.id", read_only=True)
    ip_address = serializers.CharField(
        source="bot_event.ip_address", read_only=True, allow_null=True
    )
    request_path = serializers.CharField(
        source="bot_event.request_path", read_only=True
    )

    class Meta:
        model = AttackType
        fields = [
            "id",
            "bot_event_id",  # BotEventDetailSerializer filter on id
            "ip_address",  # IPAnalyticsDetailSerializer filter on ip_address
            "request_path",  # BotEventList filter on path
            "target_field",
            "pattern",
            "category",
            "created_at",
        ]
        read_only_fields = fields


##### APIList Serializers #####
class PathAnalyticsSerializer(serializers.Serializer):
    """Serializer for path analytics aggregated data."""

    request_path = serializers.CharField()  # BotEventList filter on path
    traffic_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList filter on request_path
    scan_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList scan_bot = True
    spam_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList spam_bot = True
    attack_count = serializers.IntegerField(
        allow_null=True
    )  # AttackTypeList filter on request_path
    created_at = serializers.DateTimeField(allow_null=True)
    most_popular_attack = serializers.CharField(
        allow_null=True
    )  # AttackTypeList filter on category
    attacks_used = serializers.ListField(
        child=serializers.CharField(), allow_null=True, allow_empty=True
    )


##### IP Analytics Serializers #####
class IPAnalyticsListSerializer(serializers.Serializer):
    """Simple list serializer for IP analytics - minimal fields."""

    ip_address = serializers.CharField()
    traffic_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList filter on ip_address
    attack_count = serializers.IntegerField(
        allow_null=True
    )  # AttackTypeList filter on ip_address
    scan_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList scan_bot = True
    spam_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList spam_bot = True
    attack_categories = serializers.ListField(
        child=serializers.CharField(), allow_null=True, allow_empty=True
    )
    email_count = serializers.IntegerField(allow_null=True)
    created_at = serializers.DateTimeField(allow_null=True)
    geo_location = serializers.CharField(allow_null=True)
    language = serializers.CharField(allow_null=True)
    agent = serializers.CharField(allow_null=True)
    referer = serializers.CharField(allow_null=True)
    email = serializers.ListField(
        child=serializers.EmailField(),
        allow_null=True,
        allow_empty=True,
        source="emails_used",
    )


class IPAnalyticsDetailSerializer(serializers.Serializer):
    """Detailed serializer for IP analytics with full information and nested attacks."""

    ip_address = serializers.CharField()
    traffic_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList filter on ip_address
    scan_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList scan_bot = True
    spam_count = serializers.IntegerField(
        allow_null=True
    )  # BotEventList spam_bot = True
    attack_count = serializers.IntegerField(
        allow_null=True
    )  # AttackTypeList filter on ip_address
    referer = serializers.CharField(allow_null=True)
    email = serializers.ListField(
        child=serializers.EmailField(),
        allow_null=True,
        allow_empty=True,
        source="emails_used",
    )
    email_count = serializers.IntegerField(allow_null=True)
    agent = serializers.CharField(allow_null=True)
    language = serializers.CharField(allow_null=True)
    geo_location = serializers.CharField(allow_null=True)
    created_at = serializers.DateTimeField(allow_null=True)


##### Bot Event Serializers #####
class BotEventDetailSerializer(serializers.ModelSerializer):
    """Serializer for BotEvent detail view (full data)."""

    attack_categories = serializers.SerializerMethodField()
    attack_count = serializers.SerializerMethodField()

    def get_attack_categories(self, obj):
        """Get list of unique attack categories."""
        return list(obj.attacks.values_list("category", flat=True).distinct())

    def get_attack_count(self, obj):
        """Get attack count."""
        return obj.attacks.count()

    class Meta:
        model = BotEvent
        fields = [
            "id",
            "created_at",
            "method",
            "request_path",  # BotEventList filter on path
            "email",
            "ip_address",  # IPAnalyticsDetailSerializer filter on ip_address
            "geo_location",
            "agent",
            "referer",
            "language",
            "data_present",
            "field_count",
            "target_fields",
            "data_details",
            "attack_categories",
            "attack_count",
        ]
        read_only_fields = fields


class BotEventListSerializer(serializers.ModelSerializer):
    """Serializer for BotEvent list view (summary)."""

    attack_count = serializers.SerializerMethodField()
    attack_categories = serializers.SerializerMethodField()
    agent_snapshot = serializers.SerializerMethodField()

    class Meta:
        model = BotEvent
        fields = [
            "id",
            "created_at",
            "method",
            "request_path",
            "agent_snapshot",
            "ip_address",  # IPAnalyticsListSerializer filter on ip_address
            "attack_count",  # AttackTypeList filter on bot_event_id
            "attack_categories",  # AttackTypeList filter on category
            "attack_attempted",
            "geo_location",
            "event_category",
        ]
        read_only_fields = fields

    def get_agent_snapshot(self, obj):
        """Get agent snapshot - first part of user agent string (e.g., 'Mozilla/5.0')."""
        if obj.agent:
            return obj.agent.split(" ")[0]
        return None

    def get_attack_count(self, obj):
        """Get attack count, using annotation if available."""
        if hasattr(obj, "attack_count"):
            return obj.attack_count
        return obj.attacks.count()

    def get_attack_categories(self, obj):
        """Get list of unique attack categories."""
        if hasattr(obj, "attack_categories"):
            return obj.attack_categories or []
        return list(obj.attacks.values_list("category", flat=True).distinct())
