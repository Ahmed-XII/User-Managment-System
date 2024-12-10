from django.urls import path
from .views import RegisterView, LoginView, ProfileView, DeleteUser, UserListView, ResetPassword, UpdateView,ManageRoleView

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('delete-user/<int:user_id>/', DeleteUser.as_view(), name='delete-user'),
    path('users/', UserListView.as_view(), name='user-list'),
    path('reset-password/', ResetPassword.as_view(), name='reset-password'),
    path('update-user/<int:user_id>/', UpdateView.as_view(), name='update-user'),
    path('manage-users/<int:user_id>/', ManageRoleView.as_view(), name='manage-users'),
] 