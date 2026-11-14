from django.db import models
from django.contrib.auth.models import User


class SecurityFinding(models.Model):
    SEVERITY_CHOICES = [
        ("Low", "Low"),
        ("Medium", "Medium"),
        ("High", "High"),
        ("Critical", "Critical"),
    ]

    STATUS_CHOICES = [
        ("Open", "Open"),
        ("In Progress", "In Progress"),
        ("Resolved", "Resolved"),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    component = models.CharField(
        max_length=100,
        choices=[
            ("Endpoint/IDE", "Endpoint/IDE"),
            ("Version Control", "Version Control"),
            ("CI/CD", "CI/CD"),
            ("Container Registry", "Container Registry"),
            ("Production", "Production"),
        ],
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        default="Medium",
    )
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="Open",
    )
    reported_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name="security_findings",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.title} - {self.severity}"
