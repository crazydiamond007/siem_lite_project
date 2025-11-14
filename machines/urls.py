from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import MachineRegistrationAPIView, MachineViewSet

router = DefaultRouter()
router.register(r"", MachineViewSet, basename="machine")

urlpatterns = [
    path("register/", MachineRegistrationAPIView.as_view(), name="machine-register"),
    path("", include(router.urls)),
]
