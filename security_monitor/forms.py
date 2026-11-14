
from django import forms
from .models import SecurityFinding


class SecurityFindingForm(forms.ModelForm):

    class Meta:
        model = SecurityFinding

        fields = [
            'title',
            'pillar',
            'severity',
            'status',
            'description',
            'date_discovered',
        ]

        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter finding title'
            }),

            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Describe the security finding',
                'rows': 4
            }),

            'date_discovered': forms.DateInput(attrs={
                'type': 'date',
                'class': 'form-control'
            }),
        }
