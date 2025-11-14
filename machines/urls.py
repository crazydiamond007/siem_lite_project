from __future__ import annotations

from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import MachineRegistrationAPIView, MachineTokenAPIView, MachineViewSet

router = DefaultRouter()
router.register(r"", MachineViewSet, basename="machine")

urlpatterns = [
    path("register/", MachineRegistrationAPIView.as_view(), name="machine-register"),
    path("token/", MachineTokenAPIView.as_view(), name="machine-token"),
    path("", include(router.urls)),
]
