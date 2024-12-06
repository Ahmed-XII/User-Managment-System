from django.urls import path
from . import views
from .views import RegisterView, LoginView, ProfileView, DeleteUser, UserListView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('delete-user/<int:user_id>/', DeleteUser.as_view(), name='delete-user'),
    path('users/', UserListView.as_view(), name='user-list')
]