
from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    path('finding/<int:pk>/edit/', views.edit_finding, name='edit_finding'),
    path('finding/<int:pk>/delete/', views.delete_finding, name='delete_finding'),
]
