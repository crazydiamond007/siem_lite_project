from __future__ import annotations

from django.contrib import admin
from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    # Django admin
    path("admin/", admin.site.urls),
    # Browsable API login for DRF
    path("api/auth/", include("rest_framework.urls")),
    # JWT auth for human users
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # API endpoints
    path("api/machines/", include("machines.urls")),
    path("api/logs/", include("logs.urls")),
    path("api/rules/", include("rules.urls")),
    path("api/alerts/", include("alerts.urls")),
    # Web dashboard (root URL)
    path("", include("dashboard.urls")),
]
