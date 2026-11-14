
from django.contrib import admin
from .models import SecurityFinding


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):

    list_display = (
        'title',
        'pillar',
        'severity',
        'status',
        'date_discovered',
    )

    list_filter = (
        'pillar',
        'severity',
        'status',
    )

    search_fields = (
        'title',
        'description',
    )

    ordering = ('-date_recorded',)
