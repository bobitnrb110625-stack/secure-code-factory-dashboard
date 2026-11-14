
from django.db import models


class SecurityFinding(models.Model):

    PILLAR_CHOICES = [
        ('Endpoint / IDE', 'Endpoint / IDE'),
        ('Version Control System', 'Version Control System'),
        ('CI/CD Pipeline', 'CI/CD Pipeline'),
        ('Container Registry', 'Container Registry'),
        ('Production', 'Production'),
    ]

    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]

    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved'),
    ]

    title = models.CharField(max_length=200)

    pillar = models.CharField(
        max_length=50,
        choices=PILLAR_CHOICES
    )

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Open'
    )

    description = models.TextField()

    date_discovered = models.DateField()

    date_recorded = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


# Create your models here.
