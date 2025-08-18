from django.urls import path, include
from rest_framework.routers import DefaultRouter
from core.views import AuthViewSet, InvitationAndAcceptViewset, UserDataViewset

router = DefaultRouter()
router.register("auth", AuthViewSet, basename="auth")
router.register("invitation", InvitationAndAcceptViewset, basename="invitation")
router.register("userdata", UserDataViewset, basename="userdata")

urlpatterns = [
    path("", include(router.urls)),
]
