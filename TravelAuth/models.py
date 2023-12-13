from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()


# Create your models here.

class Traveler(models.Model):
    user = models.ForeignKey(User, on_delete =models.CASCADE)
    full_name = models.CharField(max_length=255)

    def __str__(self):
        return self.full_name






