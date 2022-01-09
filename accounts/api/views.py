from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.generics import CreateAPIView
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.api.serializers import ChangePasswordSerializer
from accounts.api.serializers import LoginSerializer
from accounts.api.serializers import RegisterSerializer
from accounts.api.serializers import ResetPasswordSerializer
from accounts.api.serializers import ResetPasswordTokenSerializer
from accounts.api.serializers import UserSerializer
from accounts.models import User
from project.utils import PasswordResetTokenGenerator


class RegisterAPIView(CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = ()
    authentication_classes = ()
    model = User


class LoginAPIView(APIView):
    serializer_class = LoginSerializer
    permission_classes = ()
    authentication_classes = ()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            return Response(
                {
                    'token': user.token,
                    'name': user.name,
                    'username': user.username,
                },
                status=status.HTTP_200_OK)
        else:
            return Response(
                {
                    'errors': "invalid credentials",
                },
                status=status.HTTP_400_BAD_REQUEST)


class RequestResetPasswordAPIView(APIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = ()
    authentication_classes = ()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data.get('username')
        user = User.objects.get(username=username)
        return Response(
            {'uid': urlsafe_base64_encode(force_bytes(user.pk)),
             'token': PasswordResetTokenGenerator().make_token(user),
             }, status=status.HTTP_200_OK)


def get_user(uidb64):
    try:
        # urlsafe_base64_decode() decodes to bytestring
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
        user = None
    return user


class ResetPasswordAPIView(APIView):
    serializer_class = ResetPasswordTokenSerializer
    permission_classes = ()
    authentication_classes = ()

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data.get('token')
        uid = serializer.validated_data.get('uid')
        password = serializer.validated_data.get('password')
        user = get_user(uid)
        if user is not None:
            if PasswordResetTokenGenerator().check_token(user, token):
                user.set_password(password)
                user.save()
                return Response({'message': "password reset success"}, status=status.HTTP_200_OK)
        return Response({'errors': "invalid token or uuid", }, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordAPIView(APIView):
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data.get('old_password')
        new_password = serializer.validated_data.get('new_password')
        if request.user.check_password(old_password):
            request.user.set_password(new_password)
            request.user.save()
            return Response({'message': "password changed"}, status=status.HTTP_200_OK)
        return Response({'errors': "wrong password", }, status=status.HTTP_400_BAD_REQUEST)



class UsersListAPIView(ListAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()
