from django.test import TestCase
from .models import SecurityFinding
from datetime import date


class SecurityFindingTests(TestCase):

    def test_security_finding_creation(self):
        finding = SecurityFinding.objects.create(
            title="Test Security Finding",
            pillar="Endpoint / IDE",
            severity="High",
            status="Open",
            description="Testing security finding creation.",
            date_discovered=date.today()
        )

        self.assertEqual(finding.title, "Test Security Finding")
        self.assertEqual(finding.severity, "High")

    def test_default_status_is_open(self):
        finding = SecurityFinding.objects.create(
            title="Test Default Status",
            pillar="Production",
            severity="Medium",
            description="Testing default status.",
            date_discovered=date.today()
        )

        self.assertEqual(finding.status, "Open")