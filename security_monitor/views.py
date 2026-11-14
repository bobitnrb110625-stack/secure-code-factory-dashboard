
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied

from .models import SecurityFinding
from .forms import SecurityFindingForm

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import io
import base64


def user_login(request):

    error = ''

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:
            login(request, user)
            return redirect('dashboard')

        else:
            error = 'Invalid username or password.'

    return render(request, 'login.html', {'error': error})


def user_logout(request):
    logout(request)
    return redirect('login')


@login_required(login_url='login')
def dashboard(request):

    if not request.user.has_perm('security_monitor.view_securityfinding'):
        raise PermissionDenied

    can_add_finding = request.user.has_perm(
        'security_monitor.add_securityfinding'
    )

    can_change_finding = request.user.has_perm(
        'security_monitor.change_securityfinding'
    )

    can_delete_finding = request.user.has_perm(
        'security_monitor.delete_securityfinding'
    )

    if request.method == 'POST':

        if not can_add_finding:
            raise PermissionDenied

        form = SecurityFindingForm(request.POST)

        if form.is_valid():
            form.save()
            return redirect('dashboard')

    else:
        form = SecurityFindingForm()

    findings = SecurityFinding.objects.all().order_by('-date_recorded')

    critical = findings.filter(severity='Critical').count()
    high = findings.filter(severity='High').count()
    medium = findings.filter(severity='Medium').count()
    low = findings.filter(severity='Low').count()

    labels = ['Critical', 'High', 'Medium', 'Low']
    values = [critical, high, medium, low]

    plt.figure(figsize=(7, 4))

    plt.bar(
        labels,
        values,
        color=['#e05252', '#e6a23c', '#e8c547', '#22a879']
    )

    plt.title('Security Findings by Severity')
    plt.xlabel('Severity Level')
    plt.ylabel('Number of Findings')

    plt.tight_layout()

    buffer = io.BytesIO()

    plt.savefig(buffer, format='png')
    buffer.seek(0)

    chart_image = base64.b64encode(
        buffer.getvalue()
    ).decode('utf-8')

    plt.close()
    buffer.close()

    context = {
        'findings': findings,
        'form': form,

        'total_findings': findings.count(),
        'critical_findings': critical,
        'high_findings': high,
        'medium_findings': medium,
        'low_findings': low,

        'open_findings': findings.filter(status='Open').count(),
        'resolved_findings': findings.filter(status='Resolved').count(),

        'chart_image': chart_image,

        'can_add_finding': can_add_finding,
        'can_change_finding': can_change_finding,
        'can_delete_finding': can_delete_finding,
    }

    return render(request, 'dashboard.html', context)


# EDIT SECURITY FINDING

@login_required(login_url='login')
def edit_finding(request, pk):

    if not request.user.has_perm('security_monitor.change_securityfinding'):
        raise PermissionDenied

    finding = get_object_or_404(SecurityFinding, pk=pk)

    if request.method == 'POST':

        form = SecurityFindingForm(request.POST, instance=finding)

        if form.is_valid():
            form.save()
            return redirect('dashboard')

    else:
        form = SecurityFindingForm(instance=finding)

    return render(request, 'edit_finding.html', {
        'form': form,
        'finding': finding
    })


# DELETE SECURITY FINDING

@login_required(login_url='login')
def delete_finding(request, pk):

    if not request.user.has_perm('security_monitor.delete_securityfinding'):
        raise PermissionDenied

    finding = get_object_or_404(SecurityFinding, pk=pk)

    if request.method == 'POST':
        finding.delete()
        return redirect('dashboard')

    return render(request, 'delete_finding.html', {
        'finding': finding
    })
