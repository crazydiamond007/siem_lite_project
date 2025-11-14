from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import LogEntryViewSet, LogIngestionAPIView

router = DefaultRouter()
router.register(r"", LogEntryViewSet, basename="logentry")

urlpatterns = [
    path("ingest/", LogIngestionAPIView.as_view(), name="log-ingest"),
    path("", include(router.urls)),
]
