from django.urls import path

from accounts.api.views import LoginAPIView, RequestResetPasswordAPIView, ResetPasswordAPIView
from accounts.api.views import RegisterAPIView

urlpatterns = [
    path('auth/register/', RegisterAPIView.as_view()),
    path('auth/login/', LoginAPIView.as_view()),
    path('auth/request-reset-password/', RequestResetPasswordAPIView.as_view()),
    path('auth/reset-password/', ResetPasswordAPIView.as_view()),
]
