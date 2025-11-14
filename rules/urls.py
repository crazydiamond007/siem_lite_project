from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import RuleViewSet

router = DefaultRouter()
router.register(r"", RuleViewSet, basename="rule")

urlpatterns = [
    path("", include(router.urls)),
]
