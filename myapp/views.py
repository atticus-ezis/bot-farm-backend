from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, viewsets
from rest_framework.permissions import AllowAny
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from uuid import uuid4
from .filters import (
    BotEventFilter,
    AggregatePathFilter,
    AggregateIPFilter,
    AttackTypeFilter,
)
from .models import BotEvent, AttackType
from .utils import extract_attacks, extract_meta_data, extract_email_from_payload
from .pagination import StandardResultsSetPagination
from .serializers import (
    BotEventListSerializer,
    BotEventDetailSerializer,
    PathAnalyticsSerializer,
    IPAnalyticsListSerializer,
    IPAnalyticsDetailSerializer,
    SnapShotCategorySerializer,
    AttackTypeDetailSerializer,
    AttackTypeListSerializer,
)
from django.db.models import Count, Q, Subquery, OuterRef, Max
from .enums import MethodChoice
from django.contrib.postgres.aggregates import ArrayAgg


class SnapShotView(APIView):
    """
    Returns a summary of the analytics data.
    """

    permission_classes = [AllowAny]

    def get(self, request):
        # Optimize: Use single query with select_related/prefetch_related where possible
        # Count queries can be combined or cached, but these are simple aggregations
        total_events = BotEvent.objects.count()
        total_injection_attempts = AttackType.objects.count()
        total_ips = BotEvent.objects.values("ip_address").distinct().count()

        top_three_categories = (
            AttackType.objects.values("category")
            .annotate(total_count=Count("id"))
            .order_by("-total_count")[:3]
        )
        category_data = list(top_three_categories)

        categories = [item["category"] for item in category_data]

        qs = (
            AttackType.objects.filter(category__in=categories)
            .values("bot_event__request_path", "category")
            .annotate(path_count=Count("id"))
            .order_by("category", "-path_count")
        )
        path_count = {}
        for item in qs:
            cat = item["category"]
            if cat not in path_count:
                path_count[cat] = []
            if len(path_count[cat]) < 3:
                path_count[cat].append(
                    {
                        "request_path": item["bot_event__request_path"],
                        "path_count": item["path_count"],
                    }
                )

        for item in category_data:
            cat = item["category"]
            item["most_popular_paths"] = path_count.get(cat, [])

        category_serializer = SnapShotCategorySerializer(category_data, many=True)

        return Response(
            {
                "total_events": total_events,
                "total_injection_attempts": total_injection_attempts,  # link AttackTypeViewSet (default)
                "total_ips": total_ips,  # link aggregate ip viewset (default)
                "attack_category_snapshot": category_serializer.data,  # link AttackTypeViewSet (filter by category clicked)
            },
            status=status.HTTP_200_OK,
        )


class AggregatePathList(generics.ListAPIView):
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
        "created_at",
    ]
    ordering = [
        "-traffic_count",
        "-attack_count",
        "-created_at",
        "request_path",
    ]

    def get_queryset(self):
        # path_names
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
            created_at=Max("created_at"),  # Most recent event per path,
            attacks_used=ArrayAgg(
                "attacks__category",
                distinct=True,
                filter=Q(attack_attempted=True),
            ),
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


class AggregateIPViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only ViewSet for aggregated IP analytics with filtering, searching, and ordering.

    list:
    Returns a paginated list of IP addresses with minimal information (ip_address, traffic_count, created_at).

    retrieve:
    Returns detailed information for a specific IP address including all attacks committed by that IP.
    """

    permission_classes = [AllowAny]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AggregateIPFilter
    search_fields = ["ip_address", "referer"]  # email
    lookup_field = "ip_address"
    lookup_value_regex = (
        r"[^/]+"  # Allow any characters except forward slash (for IP addresses)
    )
    ordering_fields = [
        "traffic_count",
        "scan_count",
        "spam_count",
        "attack_count",
        "ip_address",
        "created_at",
        "email_count",
    ]
    ordering = ["-traffic_count", "-created_at"]

    def _build_annotated_queryset(self, base_queryset=None):
        """
        Build the annotated queryset for IP analytics.

        Args:
            base_queryset: Optional base queryset to annotate. If None, uses BotEvent.objects.

        Returns:
            Annotated queryset grouped by ip_address.
        """
        if base_queryset is None:
            base_queryset = BotEvent.objects

        # Note: Subqueries are necessary due to different ordering requirements
        # PostgreSQL can optimize these with proper indexes on (ip_address, created_at)
        return base_queryset.values("ip_address").annotate(
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
            attack_categories=ArrayAgg(
                "attacks__category",
                distinct=True,
                filter=Q(
                    attacks__category__isnull=False,
                ),
            ),
            referer=Subquery(
                BotEvent.objects.filter(ip_address=OuterRef("ip_address"))
                .order_by("created_at")
                .values("referer")[:1]
                .values_list("referer", flat=True)
            ),
            emails_used=ArrayAgg(
                "email",
                distinct=True,
                filter=Q(email__isnull=False),
            ),
            email_count=Count("email", filter=Q(email__isnull=False)),
            agent=Subquery(
                BotEvent.objects.filter(ip_address=OuterRef("ip_address"))
                .order_by("created_at")
                .values("agent")[:1]
                .values_list("agent", flat=True)
            ),
            language=Subquery(
                BotEvent.objects.filter(ip_address=OuterRef("ip_address"))
                .order_by("created_at")
                .values("language")[:1]
                .values_list("language", flat=True)
            ),
            geo_location=Subquery(
                BotEvent.objects.filter(ip_address=OuterRef("ip_address"))
                .order_by("created_at")
                .values("geo_location")[:1]
                .values_list("geo_location", flat=True)
            ),
            created_at=Max("created_at"),  # Most recent event per IP
        )

    def get_queryset(self):
        """Get the base queryset with annotations for IP analytics."""
        return self._build_annotated_queryset()

    def filter_queryset(self, queryset):
        """
        Override to handle email search in the emails_used array via the 'search' parameter.
        This allows email to be searched alongside ip_address and referer in a single search.
        """
        from django.db.models import Q, Exists, OuterRef
        from rest_framework.filters import SearchFilter

        # Get search term
        search_term = self.request.query_params.get("search", "").strip()

        if search_term:
            # Build complete OR condition: ip_address OR referer OR email
            search_conditions = Q()
            search_conditions |= Q(ip_address__icontains=search_term)
            search_conditions |= Q(referer__icontains=search_term)
            search_conditions |= Q(
                Exists(
                    BotEvent.objects.filter(
                        ip_address=OuterRef("ip_address"), email__icontains=search_term
                    )
                )
            )

            # Apply search conditions
            queryset = queryset.filter(search_conditions)

            # Temporarily remove SearchFilter to use super() for other backends
            # This ensures DjangoFilterBackend and OrderingFilter still work
            original_backends = self.filter_backends
            self.filter_backends = [b for b in original_backends if b != SearchFilter]
            try:
                queryset = super().filter_queryset(queryset)
            finally:
                self.filter_backends = original_backends
        else:
            # No search term, apply all filters normally (including SearchFilter for future use)
            queryset = super().filter_queryset(queryset)

        return queryset

    def get_object(self):
        """Override to handle lookup on values queryset."""
        # Get the lookup value from URL
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
        lookup_value = self.kwargs[lookup_url_kwarg]

        # Build the queryset with the IP filter applied at the base level
        # Filtering before .values() ensures it works correctly
        base_queryset = BotEvent.objects.filter(ip_address=lookup_value)
        queryset = self._build_annotated_queryset(base_queryset)

        # Get the first (and should be only) result
        # Use list() with slicing instead of .first() to avoid issues with OuterRef in subqueries
        results = list(queryset[:1])
        obj = results[0] if results else None

        if obj is None:
            from rest_framework.exceptions import NotFound

            raise NotFound("No IP analytics found for this IP address.")
        return obj

    def get_serializer_class(self):
        """Use list serializer for list, detail serializer for retrieve."""
        if self.action == "retrieve":
            return IPAnalyticsDetailSerializer
        return IPAnalyticsListSerializer


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
        "data",
        "referer",
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
        "attack_count",
    ]
    ordering = ["-created_at"]

    def get_queryset(self):
        """Annotate queryset with attack count for ordering."""
        from django.db.models import Count

        queryset = super().get_queryset()

        # Annotate with attack count for ordering
        queryset = queryset.annotate(attack_count=Count("attacks"))
        # get attack categories
        queryset = queryset.annotate(
            attack_categories=ArrayAgg(
                "attacks__category",
                distinct=True,
                filter=Q(attack_attempted=True),
            )
        )

        return queryset

    def get_serializer_class(self):
        """Use detail serializer for retrieve, list serializer for list."""
        if self.action == "retrieve":
            return BotEventDetailSerializer
        return BotEventListSerializer


class AttackTypeViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Read-only ViewSet for AttackType with advanced filtering, searching, and ordering.

    list:
    Returns a paginated list of all attacks with filtering, searching, and ordering.

    retrieve:
    Returns a single attack with full details and linked BotEvent information.
    """

    # filtered by CATEGORY on snapshot view + path analytics view

    queryset = AttackType.objects.select_related("bot_event").all()
    permission_classes = [AllowAny]
    pagination_class = StandardResultsSetPagination
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = AttackTypeFilter
    search_fields = [
        "category",
        "pattern",
        "target_field",
        "raw_value",
        "bot_event__email",
        "bot_event__referer",
    ]
    ordering_fields = [
        "created_at",
    ]
    ordering = ["-created_at"]  # Default ordering (newest first)

    def get_serializer_class(self):
        """Use detail serializer for retrieve, list serializer for list."""
        if self.action == "retrieve":
            return AttackTypeDetailSerializer
        return AttackTypeListSerializer


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

        # Optimize: Collect all attacks and use bulk_create instead of individual creates
        # This reduces N database writes to 1
        attacks_to_create = []
        attacks_found = False

        for key, value in params.items():
            attack_list = extract_attacks(value)
            if attack_list:
                for attack in attack_list:
                    pattern, category, match = attack
                    attacks_to_create.append(
                        AttackType(
                            bot_event=bot_event,
                            target_field=key,
                            pattern=pattern,
                            raw_value=match,
                            category=category.value,  # Convert enum to string value
                        )
                    )
                attacks_found = True

        # Bulk create all attacks in a single query
        if attacks_to_create:
            AttackType.objects.bulk_create(attacks_to_create)

        # Only set attack_attempted if attacks were actually detected
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
