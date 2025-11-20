from django.urls import include, path

from .views import (
    AnalyticsSummaryView,
    ContactBotView,
    PublicRecentSubmissionsView,
)
from .routers import submissions_router

urlpatterns = [
    path("contact-bot/", ContactBotView.as_view(), name="contact-bot"),
    path(
        "analytics/summary/", AnalyticsSummaryView.as_view(), name="analytics-summary"
    ),
    path(
        "analytics/recent/",
        PublicRecentSubmissionsView.as_view(),
        name="analytics-recent",
    ),
    path("", include(submissions_router.urls)),
]
