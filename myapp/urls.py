from django.urls import path

from .views import (
    HoneypotView,
    SnapShotView,
    AggregatePathList,
)
from .routers import router
from .fake_urls import FAKE_URLS

urlpatterns = [
    path("api/snapshot/", SnapShotView.as_view(), name="snapshot"),
    # Aggregate analytics endpoints
    path(
        "api/aggregate-paths/",
        AggregatePathList.as_view(),
        name="aggregate-path-list",
    ),
    *[path(url, HoneypotView.as_view(), name="honeypot") for url in FAKE_URLS],
] + router.urls
