from django.contrib.auth.models import User
from django.db import models

class UserRole(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, default='customer')
    is_active = models.BooleanField(default=True) 

    def __str__(self):
        return f"{self.user.username} - {self.role} - {'Active' if self.is_active else 'Inactive'}"