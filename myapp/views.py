# myapp/views.py

from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from uuid import uuid4
from .filters import BotEventFilter, AggregatePathFilter
from .models import BotEvent, AttackType
from .utils import extract_attacks, extract_meta_data, extract_email_from_payload
from .pagination import StandardResultsSetPagination
from .serializers import (
    BotEventListSerializer,
    BotEventDetailSerializer,
    PathAnalyticsSerializer,
    SnapShotCategorySerializer,
    SnapShotHighestThreatIpSerializer,
    SnapShotCategoryPathListSerializer,
)
from django.db.models import Count, Q, Subquery, OuterRef, Max
from .enums import MethodChoice


class SnapShotView(APIView):
    """
    Returns a summary of the analytics data.
    """

    def get(self, request):
        # headers
        total_events = BotEvent.objects.count()
        total_injection_attempts = AttackType.objects.count()
        total_ips = BotEvent.objects.values("ip_address").distinct().count()
        highest_threat_ips = (
            BotEvent.objects.values("ip_address", "geo_location", "origin")
            .annotate(count=Count("attacks", distinct=False))
            .order_by("-count")[:3]
        )

        highest_threat_ips = list(highest_threat_ips)
        highest_threat_ips_serializer = SnapShotHighestThreatIpSerializer(
            highest_threat_ips, many=True
        )
        # attack categories
        # totals, get vs post, most popular paths
        category_queryset = (
            AttackType.objects.values("category")
            .annotate(
                total_count=Count("id"),
                get_method_count=Count(
                    "id",
                    filter=Q(
                        bot_event__method=MethodChoice.GET.value,
                    ),
                    distinct=False,
                ),
                post_method_count=Count(
                    "id",
                    filter=Q(
                        bot_event__method=MethodChoice.POST.value,
                    ),
                    distinct=False,
                ),
            )
            .order_by("-total_count")
        )
        category_data = []
        for category_item in list(category_queryset):
            category = category_item["category"]

            most_popular_paths = (
                BotEvent.objects.filter(
                    attack_attempted=True, attacks__category=category
                )
                .values("request_path")
                .annotate(path_count=Count("id", distinct=False))
                .order_by("-path_count", "request_path")[:3]
            )
            most_popular_paths = list(most_popular_paths)
            category_data.append(
                {
                    "category": category,
                    "total_count": category_item["total_count"],
                    "get_method_count": category_item["get_method_count"],
                    "post_method_count": category_item["post_method_count"],
                    "most_popular_paths": most_popular_paths,
                }
            )
        category_serializer = SnapShotCategorySerializer(category_data, many=True)
        ### popular paths

        popular_paths_queryset = (
            BotEvent.objects.values("request_path")
            .annotate(path_count=Count("id"))
            .order_by("-path_count", "request_path")[:3]
        )
        popular_paths_list = list(popular_paths_queryset)
        popular_paths_serializer = SnapShotCategoryPathListSerializer(
            popular_paths_list, many=True
        )
        return Response(
            {
                "total_events": total_events,
                "total_injection_attempts": total_injection_attempts,
                "total_ips": total_ips,
                "highest_threat_ips": highest_threat_ips_serializer.data,
                "attack_category_snapshot": category_serializer.data,
                "paths_snapshot": popular_paths_serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class AggregatePathListViewSet(generics.ListAPIView):
    """
    Read-only ViewSet for aggregated path analytics with filtering, searching, and ordering.
    """

    permission_classes = [AllowAny]
    pagination_class = StandardResultsSetPagination
    serializer_class = PathAnalyticsSerializer
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AggregatePathFilter
    search_fields = ["request_path"]
    ordering_fields = [
        "traffic_count",
        "scan_count",
        "spam_count",
        "attack_count",
        "request_path",
        "created_at",  # Most recent event per path
    ]
    ordering = [
        "-traffic_count",
        "-created_at",
        "request_path",
    ]

    def get_queryset(self):
        # path_names
        # annotate values --
        # traffic types + counts
        # attack categories present and counts
        queryset = BotEvent.objects.values(
            "request_path"
        ).annotate(
            traffic_count=Count("id"),
            scan_count=Count(
                "id",
                filter=Q(
                    attack_attempted=False,
                    method=MethodChoice.GET.value,
                    data__isnull=True,
                )
                | Q(attack_attempted=False, method=MethodChoice.GET.value, data={}),
            ),
            spam_count=Count(
                "id",
                filter=Q(
                    attack_attempted=False,
                    data__isnull=False,
                    method=MethodChoice.POST.value,
                ),
            ),
            attack_count=Count("id", filter=Q(attack_attempted=True)),
            created_at=Max("created_at"),  # Most recent event per path
            most_popular_attack=Subquery(
                AttackType.objects.filter(
                    bot_event__request_path=OuterRef("request_path")
                )
                .values("category")
                .annotate(count=Count("id"))
                .order_by("-count", "category")
                .values_list("category", flat=True)[:1]
            ),
        )
        return queryset


class BotEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only ViewSet for BotEvent with advanced filtering, searching, and ordering.

    list:
    Returns a paginated list of bot events with filtering, searching, and ordering.

    retrieve:
    Returns a single bot event with all related attack details.
    """

    queryset = BotEvent.objects.prefetch_related("attacks").all()
    permission_classes = [AllowAny]
    pagination_class = StandardResultsSetPagination
    filter_backends = [
        DjangoFilterBackend,
        SearchFilter,
        OrderingFilter,
    ]
    filterset_class = BotEventFilter

    # Search fields (for SearchFilter)
    search_fields = [
        "email",
        "origin",
        "ip_address",
        "geo_location",
        "agent",
        "request_path",
        "attacks__raw_value",  # Search in attack raw values
    ]

    # Ordering fields
    ordering_fields = [
        "created_at",
        "ip_address",
        "geo_location",
        "attack_count",  # Can order by annotated attack_count
    ]
    ordering = ["-created_at"]  # Default ordering (newest first)

    def get_queryset(self):
        """Annotate queryset with attack count for ordering."""
        from django.db.models import Count

        queryset = super().get_queryset()

        # Annotate with attack count for ordering
        queryset = queryset.annotate(attack_count=Count("attacks", distinct=True))

        return queryset

    def get_serializer_class(self):
        """Use detail serializer for retrieve, list serializer for list."""
        if self.action == "retrieve":
            return BotEventDetailSerializer
        return BotEventListSerializer


class HoneypotView(APIView):
    """
    Logs GET and POST bot activity, detects XSS, and correlates follow-up requests.
    """

    permission_classes = [AllowAny]

    def _log_event(self, request, method_type, ctoken):
        params = request.GET if method_type == "GET" else request.data

        meta_data = extract_meta_data(request.META)
        email = extract_email_from_payload(params)

        # Create main BotEvent
        bot_event = BotEvent.objects.create(
            method=method_type,
            ip_address=meta_data["ip_address"],
            geo_location=meta_data["geo_location"],
            agent=meta_data["agent"],
            referer=meta_data["referer"],
            language=meta_data["lang"],
            origin=meta_data["origin"],
            request_path=request.path,
            data=params,
            correlation_token=ctoken,
            email=email,
        )

        # Detect attacks in all fields
        attacks_found = False
        for key, value in params.items():
            attack_list = extract_attacks(value)
            if attack_list:
                for attack in attack_list:
                    pattern, category, match = attack
                    AttackType.objects.create(
                        bot_event=bot_event,
                        target_field=key,
                        pattern=pattern,
                        raw_value=match,
                        category=category.value,  # Convert enum to string value
                    )
                attacks_found = True

        # Only set attack_attempted if XSS was actually detected
        if attacks_found:
            bot_event.attack_attempted = True
            bot_event.save(update_fields=["attack_attempted"])

    def get(self, request):
        # Create a correlation token
        ctoken = uuid4()

        self._log_event(request, "GET", ctoken)

        html = f"""
        <html><body>
            <h3>Loading...</h3>
            <form id='hp' method='POST'>
                <input type="hidden" name="ctoken" value="{ctoken}">
                <input name="username">
                <input name="message">
                <input name="comment">
                <textarea name="content"></textarea>
                <button type="submit">Submit</button>
            </form>
            <script>
            setTimeout(() => document.getElementById('hp').submit(), 300);
            </script>
        </body></html>
        """

        return Response(html, content_type="text/html", status=200)

    #
    # POST → logs XSS in posted form data, correlates via ctoken
    #
    def post(self, request):
        ctoken = request.data.get("ctoken")

        self._log_event(request, "POST", ctoken)

        return Response({"status": "ok"}, status=status.HTTP_200_OK)
