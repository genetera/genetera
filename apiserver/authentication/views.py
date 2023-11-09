import jwt
import uuid

# Django imports

from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str
from django.conf import settings

# Thirdparty imports
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import permissions

from rest_framework_simplejwt.tokens import RefreshToken

from sentry_sdk import capture_exception

# Module imports
from .models import User
from .serializers import (
    UserSerializer,
    ChangePasswordSerializer,
    SignUpSerializer,
    PasswordResetSerializer,
)

# Background tasks imports
from .tasks import verify_email_task, forgot_password_task


def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return (
        str(refresh.access_token),
        str(refresh),
    )


class SignInApiView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        try:
            email = request.data.get("email", False)
            password = request.data.get("password", False)

            # Raise Exception when email or password not provided
            if not email or not password:
                return Response(
                    {"error": "Email or password required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            email = email.strip().lower()

            try:
                validate_email(email)
            except ValidationError as e:
                return Response(
                    {"error": "Please provide a valid email adress."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.filter(email=email).first()

            if user is None:
                # The user does not exist
                return Response(
                    {"error": "No user with provided credentials"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            is_correct_password = user.check_password(password)

            if not is_correct_password:
                # The password is incorrect
                return Response(
                    {"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST
                )

            if not user.is_active:
                return Response(
                    {
                        "error": "You account has been deactivated. Contuct us to activate it again"
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )

            # settings
            user.last_active = timezone.now()
            user.last_login_time = timezone.now()
            user.last_login_ip = request.META.get("REMOTE_ADDR")
            user.save()

            access_token, refresh_token = get_tokens_for_user(user)
            user_data = UserSerializer(user).data

            return Response(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": user_data,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            return Response(
                {"error": "There was error signing in."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SignUpApiView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None, *args, **kwargs):
        try:
            serializer = SignUpSerializer(data=request.data)

            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=serializer.data.get("email")).exists():
                return Response(
                    {"error": "User with email arleady exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.create(
                email=serializer.data.get("email"),
                first_name=serializer.data.get("first_name"),
                last_name=serializer.data.get("last_name"),
                username=uuid.uuid4().hex,
            )
            user.set_password(serializer.data.get("password"))
            user.is_email_verified = False
            user.save()

            # Trigger send email verification
            token = RefreshToken.for_user(user).access_token
            verify_email_task.delay(str(token), user.email)

            return Response(
                {"message": "Account created successfully."},
                status=status.HTTP_201_CREATED,
            )
        except Exception as e:
            # capture_exception(e)
            return Response(
                {"error": "Failed try again. " + str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SignOutApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get("refresh_token", False)

            if not refresh_token:
                # Refresh token is not passed from the client app.
                return Response(
                    {"error": "Refresh token is required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.get(pk=request.user.id)

            user.last_logout_time = timezone.now()
            user.last_logout_ip = request.META.get("REMOTE_ADDR")
            user.save()

            token = RefreshToken(refresh_token)
            token.blacklist()

            return Response({"message": "Success"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(
                {"error": "There was error try again." + str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ChangePasswordApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            user = User.objects.get(pk=request.user.id)
            serializer = ChangePasswordSerializer(request.data)

            if serializer.is_valid():
                # Check if old password is incorrect and raise error.
                if not user.check_password(serializer.data.get("old_password")):
                    return Response(
                        {"error": "Invalid password"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                user.set_password(serializer.data.get("new_password"))
                user.save()
                return Response({"message": "success"}, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(
                {"error": "There was error, try again."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class RequestEmailVerificationApiView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, format=None, *args, **kwargs):
        try:
            token = RefreshToken.for_user(request.user).access_token

            # Trigger verify email task
            verify_email_task.delay(str(token), request.user.email)
            return Response(
                {"message": "Email sent successfully."}, status=status.HTTP_200_OK
            )
        except Exception as e:
            capture_exception(e)
            return Response(
                {"error": "There was error try again"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class VerifyEmailApiView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, format=None, *args, **kwargs):
        try:
            token = request.GET.get("token")
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms="HS256")

            try:
                user = User.objects.get(pk=payload["user_id"])
                if not user.is_email_verified:
                    user.is_email_verified = True
                    user.save()
                return Response(
                    {"message": "Successfully activated."}, status=status.HTTP_200_OK
                )
            except User.DoesNotExist:
                return Response(
                    {"error": "User does not exist"}, status=status.HTTP_400_BAD_REQUEST
                )

        except jwt.ExpiredSignatureError:
            return Response(
                {"error": "Token is expired."}, status=status.HTTP_400_BAD_REQUEST
            )
        except jwt.DecodeError:
            return Response(
                {"error": "Invalid token.."}, status=status.HTTP_400_BAD_REQUEST
            )


class ForgotPasswordApiView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, format=None, *args, **kwargs):
        email = request.data.get("email", False)

        try:
            validate_email(email)
        except ValidationError as e:
            return Response(
                {"error": "Please provide a valid email adress."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not User.objects.filter(email=email).exists():
            # Raise error when user with provided email does not exists
            return Response(
                {"error": "Invalid email."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = User.objects.get(email=email)
        uuidb64 = urlsafe_base64_encode(bytes(str(user.id), "UTF-8"))
        token = PasswordResetTokenGenerator().make_token(user)

        # Trigger forgot email task
        forgot_password_task.delay(uuidb64, token, email)

        return Response(
            {"message": "Check your email to reset password."},
            status=status.HTTP_200_OK,
        )


class PasswordResetApiView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uuidb64, token, format=None, *args, **kwargs):
        try:
            id = smart_str(urlsafe_base64_decode(uuidb64))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response(
                    {"error": "Token is not valid."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            serializer = PasswordResetSerializer(data=request.data)

            if serializer.is_valid():
                user.set_password(serializer.data.get("new_password"))
                user.save()
                return Response(
                    {"message": "Password reset successfully."},
                    status=status.HTTP_200_OK,
                )
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            capture_exception(e)
            return Response(
                {"error": "Failed try again." + str(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )


class SocialLoginApiView(APIView):
    permission_classes = [permissions.AllowAny]
