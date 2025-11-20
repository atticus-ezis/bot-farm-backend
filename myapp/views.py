import csv
import io

from django.conf import settings
from django.http import HttpResponse
from drf_yasg.utils import swagger_auto_schema
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import BotSubmission
from .pagination import StandardResultsSetPagination
from .serializers import (
    BotSubmissionDetailSerializer,
    BotSubmissionListSerializer,
    SubmissionStatsSerializer,
    ContactBotSerializer,
)
from .swagger_schema import contact_bot_post_schema
from .throttles import BotSubmissionRateThrottle
from .services import create_bot_record
from . import utils


class ContactBotView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [BotSubmissionRateThrottle]

    @swagger_auto_schema(**contact_bot_post_schema)
    def post(self, request, *args, **kwargs):
        if not settings.CONTACT_BOT_ENABLED:
            return Response(
                {"error": "Contact bot is disabled"}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ContactBotSerializer(data=request.data)
        if serializer.is_valid():
            cleaned_data = serializer.validated_data
            meta_data = request.META
            create_bot_record(cleaned_data, meta_data)
            return Response(status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BotSubmissionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = BotSubmission.objects.all()
    permission_classes = [AllowAny]
    pagination_class = StandardResultsSetPagination

    def get_serializer_class(self):
        if self.action == "retrieve":
            return BotSubmissionDetailSerializer
        return BotSubmissionListSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params
        if params.get("ip"):
            qs = qs.filter(ip_address__icontains=params["ip"])
        if params.get("email"):
            qs = qs.filter(email_submitted__icontains=params["email"])
        if params.get("tag"):
            qs = qs.filter(detection_tags__contains=[params["tag"]])

        start_date = params.get("start_date")
        if start_date:
            qs = qs.filter(created_at__date__gte=start_date)
        end_date = params.get("end_date")
        if end_date:
            qs = qs.filter(created_at__date__lte=end_date)
        return qs

    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated])
    def export(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "id",
                "timestamp",
                "ip_address",
                "email",
                "user_agent",
                "referer",
                "tags",
            ]
        )
        for submission in queryset:
            writer.writerow(
                [
                    submission.id,
                    submission.created_at.isoformat(),
                    submission.ip_address,
                    submission.email_submitted or "",
                    (submission.user_agent or "")[:200],
                    submission.referer or "",
                    ",".join(submission.detection_tags or []),
                ]
            )

        response = HttpResponse(buffer.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="bot_submissions.csv"'
        return response


class AnalyticsSummaryView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        total = BotSubmission.objects.count()
        honeypot = BotSubmission.objects.filter(
            detection_tags__contains=["honeypot-hit"]
        ).count()
        unique_ips = (
            BotSubmission.objects.values_list("ip_address", flat=True)
            .distinct()
            .count()
        )
        recent_limit = getattr(settings, "BOT_ANALYTICS_RECENT_LIMIT", 50)
        recent = BotSubmission.objects.all()[:recent_limit]
        stats = {
            "total_submissions": total,
            "honeypot_hits": honeypot,
            "unique_ips": unique_ips,
            "recent": recent,
            "tag_counts": utils.summarize_tags(BotSubmission.objects.all()),
        }
        stats_serializer = SubmissionStatsSerializer(stats)
        return Response(stats_serializer.data)


class PublicRecentSubmissionsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        limit = min(int(request.query_params.get("limit", 20)), 100)
        submissions = BotSubmission.objects.all()[:limit]
        serializer = BotSubmissionListSerializer(submissions, many=True)
        return Response(serializer.data)
