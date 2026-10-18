from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.contrib.auth.models import User

class MetricData(models.Model):
    # Foreign key relationship strictly defined to prevent orphaned scopes
    tenant = models.ForeignKey(User, on_delete=models.CASCADE, related_name='metrics')
    
    # Strictly validated metric limits to prevent buffer or database overflow anomalies
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    cpu_usage_pct = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)]
    )
    memory_usage_pct = models.FloatField(
        validators=[MinValueValidator(0.0), MaxValueValidator(100.0)]
    )
    network_throughput_mbps = models.FloatField(
        validators=[MinValueValidator(0.0)]
    )
    active_threats_blocked = models.IntegerField(
        validators=[MinValueValidator(0)]
    )

    class Meta:
        verbose_name_plural = "Metric Data Points"
        # Database indexing for security analytics performance
        indexes = [
            models.Index(fields=['tenant', '-timestamp']),
        ]
