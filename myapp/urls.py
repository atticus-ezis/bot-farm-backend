from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import AnalyticsSummaryView, BotSubmissionViewSet, ContactBotView, PublicRecentSubmissionsView

router = DefaultRouter()
router.register('submissions', BotSubmissionViewSet, basename='submission')

urlpatterns = [
    path('contact-bot/', ContactBotView.as_view(), name='contact-bot'),
    path('analytics/summary/', AnalyticsSummaryView.as_view(), name='analytics-summary'),
    path('analytics/recent/', PublicRecentSubmissionsView.as_view(), name='analytics-recent'),
    path('', include(router.urls)),
]
