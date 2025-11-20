from rest_framework.routers import DefaultRouter

from .views import BotSubmissionViewSet

submissions_router = DefaultRouter()
submissions_router.register("submissions", BotSubmissionViewSet, basename="submission")
submissions_router.urls
