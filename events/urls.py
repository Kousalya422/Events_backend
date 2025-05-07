from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import EventViewSet
from .views import RegisterView, LoginView, LogoutView

router = DefaultRouter()

router.register(r'events', EventViewSet, basename='events')

urlpatterns = [
    path('api/auth/register/', RegisterView.as_view(), name='register'),
    path('api/auth/login/', LoginView.as_view(), name='login'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/', include(router.urls)),
]

