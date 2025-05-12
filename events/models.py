from django.db import models
from django.contrib.auth.models import AbstractUser

class Event(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    date = models.DateTimeField()
    venue = models.CharField(max_length=200)
    image = models.ImageField(upload_to='media/')

    def __str__(self):
        return self.title

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('Attendee', 'attendee'),
        ('Organizer', 'organizer'),
    )
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='attendee')

    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_set',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups'
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_set',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions'
    )
