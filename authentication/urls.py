from django.urls import path
from .views import SignupView, LoginView, TokenRefreshView, LogoutView, MeView, PasswordResetRequestView, PasswordResetConfirmView, ActivateUserView, UserView

urlpatterns = [
    path('signup/', SignupView.as_view(), name='auth-signup'),
    path('login/', LoginView.as_view(), name='auth-login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='auth-token-refresh'),
    path('logout/', LogoutView.as_view(), name='auth-logout'),
    path('me/', MeView.as_view(), name='auth-me'),
    path('password-reset/', PasswordResetRequestView.as_view()),
    path('password-reset-confirm/', PasswordResetConfirmView.as_view()),
    path('activate-user/', ActivateUserView.as_view()),
    path("users/", UserView.as_view(), name="user-list"),

]
