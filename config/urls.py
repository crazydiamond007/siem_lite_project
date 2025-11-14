"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
"""

from django.contrib import admin
from django.urls import include, path

from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    # Browsable API login/logout for human users (session auth)
    path("api/auth/", include("rest_framework.urls")),
    # JWT endpoints for human users / admin UI
    path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("api/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    # SIEM-Lite APIs
    path("api/machines/", include("machines.urls")),
    path("api/logs/", include("logs.urls")),
    # Future:
    # path("api/alerts/", include("alerts.urls")),
    # path("api/rules/", include("rules.urls")),
    # path("api/reports/", include("reports.urls")),
    # path("api/dashboard/", include("dashboard.urls")),
]
