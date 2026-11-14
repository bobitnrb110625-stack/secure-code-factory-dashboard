
from django.urls import path
from . import views

urlpatterns = [

    # Dashboard
    path('', views.dashboard, name='dashboard'),

    # Authentication
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    # Security findings
    path('finding/<int:pk>/edit/', views.edit_finding, name='edit_finding'),
    path('finding/<int:pk>/delete/', views.delete_finding, name='delete_finding'),

    # Remediation tracking
    path('remediation/', views.remediation_tracking, name='remediation_tracking'),
    path('remediation/<int:pk>/update/', views.update_remediation, name='update_remediation'),

    # Reports and analytics
    path('reports/', views.reports_analytics, name='reports_analytics'),
    path('reports/export/', views.export_security_report, name='export_security_report'),

    # Settings
    path('settings/', views.settings_page, name='settings_page'),

    # Activity Logs
    path('activity-logs/', views.activity_logs, name='activity_logs'),
    path('activity-logs/export/', views.export_activity_logs, name='export_activity_logs'),

]
