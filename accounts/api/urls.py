from django.urls import path

from accounts.api.views import ChangePasswordAPIView
from accounts.api.views import LoginAPIView
from accounts.api.views import RegisterAPIView
from accounts.api.views import RequestResetPasswordAPIView
from accounts.api.views import ResetPasswordAPIView
from accounts.api.views import UsersListAPIView

urlpatterns = [
    path('auth/register/', RegisterAPIView.as_view()),
    path('auth/login/', LoginAPIView.as_view()),
    path('auth/request-reset-password/', RequestResetPasswordAPIView.as_view()),
    path('auth/reset-password/', ResetPasswordAPIView.as_view()),
    path('auth/change-password/', ChangePasswordAPIView.as_view()),
    path('users/', UsersListAPIView.as_view()),
]
