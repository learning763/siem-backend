from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse
from django.contrib.auth.password_validation import validate_password


from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserSerializer,
    TokenResponseSerializer,
    SignupResponseSerializer,
    LoginRequestSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)

User = get_user_model()


class SignupView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary='Register a new user',
        request=SignupSerializer,
        responses={
            201: SignupResponseSerializer,
            400: OpenApiResponse(description='Validation error'),
        },
        tags=['Authentication'],
    )
    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response(
            {
                'user': UserSerializer(user).data,
                'access': str(refresh.access_token),
                'refresh': str(refresh),
            },
            status=status.HTTP_201_CREATED,
        )


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    @extend_schema(
        summary='Login and obtain JWT tokens',
        request=LoginRequestSerializer,
        responses={
            200: TokenResponseSerializer,
            401: OpenApiResponse(description='Invalid credentials'),
        },
        tags=['Authentication'],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class TokenRefreshView(TokenRefreshView):
    @extend_schema(
        summary='Refresh access token',
        tags=['Authentication'],
    )
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Logout — blacklist the refresh token',
        request={'application/json': {'type': 'object', 'properties': {'refresh': {'type': 'string'}}, 'required': ['refresh']}},
        responses={
            204: OpenApiResponse(description='Logged out successfully'),
            400: OpenApiResponse(description='Invalid or expired token'),
        },
        tags=['Authentication'],
    )
    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response({'detail': 'Refresh token is required.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_204_NO_CONTENT)


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary='Get current authenticated user',
        responses={200: UserSerializer},
        tags=['Authentication'],
    )
    def get(self, request):
        return Response(UserSerializer(request.user).data)

class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={
            200: OpenApiResponse(description="Reset email sent if user exists")
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"message": "If email exists, reset link will be sent"},
                status=status.HTTP_200_OK
            )

        token_generator = PasswordResetTokenGenerator()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)

        reset_link = f"http://127.0.0.1:8000/api/auth/password-reset-confirm/?uid={uid}&token={token}"

        send_mail(
            subject="Password Reset Request",
            message=f"Reset your password using this link: {reset_link}",
            from_email="noreply@yourapp.com",
            recipient_list=[user.email],
        )

        return Response(
            {"message": "If email exists, reset link will be sent"},
            status=status.HTTP_200_OK
        )
    

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={
            200: OpenApiResponse(description="Password reset successful"),
            400: OpenApiResponse(description="Invalid or expired token"),
        },
        tags=["Authentication"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        uid = serializer.validated_data['uid']
        token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']

        # -----------------------------
        # 1. Decode user from UID
        # -----------------------------
        try:
            user_id = force_str(urlsafe_base64_decode(uid))
            user = User.objects.get(pk=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid link"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # -----------------------------
        # 2. Validate token
        # -----------------------------
        token_generator = PasswordResetTokenGenerator()

        if not token_generator.check_token(user, token):
            return Response(
                {"error": "Invalid or expired token"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # -----------------------------
        # 3. Validate password strength
        # -----------------------------
        try:
            validate_password(new_password, user)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        # -----------------------------
        # 4. Set new password
        # -----------------------------
        user.set_password(new_password)
        user.save()

        return Response(
            {"message": "Password reset successful"},
            status=status.HTTP_200_OK
        )