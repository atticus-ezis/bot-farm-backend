import csv
import io

from django.conf import settings
from django.http import HttpResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import BotSubmission
from .pagination import StandardResultsSetPagination
from .serializers import (
    BotSubmissionDetailSerializer,
    BotSubmissionListSerializer,
    SubmissionStatsSerializer,
)
from .throttles import BotSubmissionRateThrottle
from . import utils


class ContactBotView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [BotSubmissionRateThrottle]

    def post(self, request, *args, **kwargs):
        if not settings.CONTACT_BOT_ENABLED:
            return HttpResponse('<html><body>offline</body></html>', status=404)

        if hasattr(request.data, 'items'):
            payload = {key: request.data.get(key) for key in request.data}
        else:
            payload = dict(request.data)
        raw_body = utils.sanitize_body(request.body)
        headers = utils.collect_headers(request.META)
        ip_address, forwarded_for = utils.get_client_ip(request.META)
        detection_tags: list[str] = []

        if utils.has_honeypot_hit(payload):
            detection_tags.append('honeypot-hit')

        payload['raw_body'] = raw_body
        email_submitted = utils.extract_email_from_payload(payload)
        if email_submitted:
            detection_tags.append('email-detected')

        geo = utils.build_geo_from_headers(request.META)

        BotSubmission.objects.create(
            email_submitted=email_submitted,
            raw_body=raw_body,
            ip_address=ip_address,
            forwarded_for=forwarded_for,
            user_agent=request.META.get('HTTP_USER_AGENT'),
            referer=request.META.get('HTTP_REFERER'),
            headers_json=headers,
            geo=geo,
            detection_tags=detection_tags,
        )

        return HttpResponse(
            '<html><body>Thanks for your submission.</body></html>',
            content_type='text/html',
            status=status.HTTP_200_OK,
        )


class BotSubmissionViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = BotSubmission.objects.all()
    permission_classes = [IsAdminUser]
    pagination_class = StandardResultsSetPagination

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return BotSubmissionDetailSerializer
        return BotSubmissionListSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        params = self.request.query_params
        if params.get('ip'):
            qs = qs.filter(ip_address__icontains=params['ip'])
        if params.get('email'):
            qs = qs.filter(email_submitted__icontains=params['email'])
        if params.get('tag'):
            qs = qs.filter(detection_tags__contains=[params['tag']])

        start_date = params.get('start_date')
        if start_date:
            qs = qs.filter(created_at__date__gte=start_date)
        end_date = params.get('end_date')
        if end_date:
            qs = qs.filter(created_at__date__lte=end_date)
        return qs

    @action(detail=False, methods=['get'])
    def export(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                'id',
                'timestamp',
                'ip_address',
                'email',
                'user_agent',
                'referer',
                'tags',
            ]
        )
        for submission in queryset:
            writer.writerow(
                [
                    submission.id,
                    submission.created_at.isoformat(),
                    submission.ip_address,
                    submission.email_submitted or '',
                    (submission.user_agent or '')[:200],
                    submission.referer or '',
                    ','.join(submission.detection_tags or []),
                ]
            )

        response = HttpResponse(buffer.getvalue(), content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="bot_submissions.csv"'
        return response


class AnalyticsSummaryView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        total = BotSubmission.objects.count()
        honeypot = BotSubmission.objects.filter(detection_tags__contains=['honeypot-hit']).count()
        unique_ips = BotSubmission.objects.values_list('ip_address', flat=True).distinct().count()
        recent_limit = getattr(settings, 'BOT_ANALYTICS_RECENT_LIMIT', 50)
        recent = BotSubmission.objects.all()[:recent_limit]
        stats = {
            'total_submissions': total,
            'honeypot_hits': honeypot,
            'unique_ips': unique_ips,
            'recent': recent,
            'tag_counts': utils.summarize_tags(BotSubmission.objects.all()),
        }
        stats_serializer = SubmissionStatsSerializer(stats)
        return Response(stats_serializer.data)


class PublicRecentSubmissionsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, *args, **kwargs):
        limit = min(int(request.query_params.get('limit', 20)), 100)
        submissions = BotSubmission.objects.all()[:limit]
        serializer = BotSubmissionListSerializer(submissions, many=True)
        return Response(serializer.data)
