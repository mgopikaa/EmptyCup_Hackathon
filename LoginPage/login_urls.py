from django.urls import path
from LoginPage import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('', views.login_view, name='login'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('token/obtain/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', views.register_view, name='register'),
    # # path('verify_otp/', views.verify_otp, name='verify_otp'),
    # # path('generate_otp/', views.send_otp_email, name='generate_otp'),
    path('generate_otp/', views.generate_otp, name='generate_otp'),
    # path('reset-password/', views.reset_password, name='reset_password'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
]