from django.contrib.auth import get_user_model
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.exceptions import TokenError
from drf_spectacular.utils import extend_schema, OpenApiResponse

from .serializers import (
    SignupSerializer,
    LoginSerializer,
    UserSerializer,
    TokenResponseSerializer,
)

User = get_user_model()


class SignupView(APIView):
    permission_classes = [AllowAny]

    @extend_schema(
        summary='Register a new user',
        request=SignupSerializer,
        responses={
            201: OpenApiResponse(response=TokenResponseSerializer, description='User created, tokens returned'),
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
        responses={
            200: OpenApiResponse(response=TokenResponseSerializer, description='Access and refresh tokens'),
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
