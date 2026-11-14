
from django.db import models
from django.contrib.auth.models import User


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

    # Remediation tracking fields

    remediation_action = models.TextField(
        blank=True,
        help_text="Describe the steps required to fix this security finding."
    )

    assigned_to = models.CharField(
        max_length=100,
        blank=True
    )

    remediation_notes = models.TextField(
        blank=True
    )

    date_resolved = models.DateField(
        null=True,
        blank=True
    )

    due_date = models.DateField(
        null=True,
        blank=True
    )

    def __str__(self):
        return self.title


# ==========================================
# ACTIVITY LOG MODEL
# ==========================================

class ActivityLog(models.Model):

    ACTION_CHOICES = [
        ('Created', 'Created'),
        ('Updated', 'Updated'),
        ('Deleted', 'Deleted'),
        ('Profile Updated', 'Profile Updated'),
        ('Password Changed', 'Password Changed'),
        ('Logged In', 'Logged In'),
        ('Logged Out', 'Logged Out'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='activity_logs'
    )

    action = models.CharField(
        max_length=50,
        choices=ACTION_CHOICES
    )

    description = models.TextField()

    timestamp = models.DateTimeField(
        auto_now_add=True
    )

    def __str__(self):
        username = self.user.username if self.user else "Deleted User"

        return f"{username} - {self.action}"
