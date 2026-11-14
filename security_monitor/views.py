
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.http import HttpResponse
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.db.models import Q

from .models import SecurityFinding, ActivityLog
from .forms import SecurityFindingForm

import matplotlib
matplotlib.use('Agg')

import matplotlib.pyplot as plt
import io
import base64
import csv


# ==========================================
# CHART GENERATION HELPER
# ==========================================

def generate_chart(labels, values, title, xlabel, ylabel, chart_type='bar'):

    figure, axis = plt.subplots(figsize=(7, 4))

    if chart_type == 'pie' and sum(values) > 0:

        axis.pie(
            values,
            labels=labels,
            autopct='%1.1f%%',
            startangle=90
        )

    else:

        axis.bar(
            labels,
            values,
            color=[
                '#258bd5',
                '#e05252',
                '#e6a23c',
                '#22a879',
                '#8064a2'
            ][:len(labels)]
        )

        axis.set_xlabel(xlabel)
        axis.set_ylabel(ylabel)

    axis.set_title(title)
    figure.tight_layout()

    buffer = io.BytesIO()

    figure.savefig(buffer, format='png')
    buffer.seek(0)

    chart_image = base64.b64encode(
        buffer.getvalue()
    ).decode('utf-8')

    plt.close(figure)
    buffer.close()

    return chart_image


# ==========================================
# ACTIVITY LOG HELPER
# ==========================================

def record_activity(user, action, description):

    ActivityLog.objects.create(
        user=user,
        action=action,
        description=description
    )


# ==========================================
# LOGIN
# ==========================================

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

            record_activity(
                user,
                'Logged In',
                f'{user.username} logged into the system.'
            )

            return redirect('dashboard')

        else:

            error = 'Invalid username or password.'

    return render(request, 'login.html', {'error': error})


# ==========================================
# LOGOUT
# ==========================================

@login_required(login_url='login')
def user_logout(request):

    user = request.user

    record_activity(
        user,
        'Logged Out',
        f'{user.username} logged out of the system.'
    )

    logout(request)

    return redirect('login')


# ==========================================
# DASHBOARD
# ==========================================

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

            finding = form.save()

            record_activity(
                request.user,
                'Created',
                f'Created security finding: {finding.title}'
            )

            return redirect('dashboard')

    else:

        form = SecurityFindingForm()

    all_findings = SecurityFinding.objects.all().order_by('-date_recorded')

    search_query = request.GET.get('search', '').strip()
    selected_pillar = request.GET.get('pillar', '')
    selected_severity = request.GET.get('severity', '')
    selected_status = request.GET.get('status', '')

    findings = all_findings

    if search_query:
        findings = findings.filter(title__icontains=search_query)

    if selected_pillar:
        findings = findings.filter(pillar=selected_pillar)

    if selected_severity:
        findings = findings.filter(severity=selected_severity)

    if selected_status:
        findings = findings.filter(status=selected_status)

    critical = all_findings.filter(severity='Critical').count()
    high = all_findings.filter(severity='High').count()
    medium = all_findings.filter(severity='Medium').count()
    low = all_findings.filter(severity='Low').count()

    endpoint_count = all_findings.filter(
        pillar='Endpoint / IDE'
    ).count()

    version_control_count = all_findings.filter(
        pillar='Version Control System'
    ).count()

    cicd_count = all_findings.filter(
        pillar='CI/CD Pipeline'
    ).count()

    registry_count = all_findings.filter(
        pillar='Container Registry'
    ).count()

    production_count = all_findings.filter(
        pillar='Production'
    ).count()

    labels = ['Critical', 'High', 'Medium', 'Low']
    values = [critical, high, medium, low]

    chart_image = generate_chart(
        labels,
        values,
        'Security Findings by Severity',
        'Severity Level',
        'Number of Findings'
    )

    context = {
        'findings': findings,
        'form': form,

        'total_findings': all_findings.count(),
        'critical_findings': critical,
        'high_findings': high,
        'medium_findings': medium,
        'low_findings': low,

        'open_findings': all_findings.filter(status='Open').count(),
        'resolved_findings': all_findings.filter(status='Resolved').count(),

        'chart_image': chart_image,

        'endpoint_count': endpoint_count,
        'version_control_count': version_control_count,
        'cicd_count': cicd_count,
        'registry_count': registry_count,
        'production_count': production_count,

        'can_add_finding': can_add_finding,
        'can_change_finding': can_change_finding,
        'can_delete_finding': can_delete_finding,

        'search_query': search_query,
        'selected_pillar': selected_pillar,
        'selected_severity': selected_severity,
        'selected_status': selected_status,

        'pillar_choices': SecurityFinding.PILLAR_CHOICES,
        'severity_choices': SecurityFinding.SEVERITY_CHOICES,
        'status_choices': SecurityFinding.STATUS_CHOICES,
    }

    return render(request, 'dashboard.html', context)


# ==========================================
# EDIT SECURITY FINDING
# ==========================================

@login_required(login_url='login')
def edit_finding(request, pk):

    if not request.user.has_perm('security_monitor.change_securityfinding'):
        raise PermissionDenied

    finding = get_object_or_404(SecurityFinding, pk=pk)

    if request.method == 'POST':

        form = SecurityFindingForm(request.POST, instance=finding)

        if form.is_valid():

            finding = form.save()

            record_activity(
                request.user,
                'Updated',
                f'Updated security finding: {finding.title}'
            )

            return redirect('dashboard')

    else:

        form = SecurityFindingForm(instance=finding)

    return render(request, 'edit_finding.html', {
        'form': form,
        'finding': finding
    })


# ==========================================
# DELETE SECURITY FINDING
# ==========================================

@login_required(login_url='login')
def delete_finding(request, pk):

    if not request.user.has_perm('security_monitor.delete_securityfinding'):
        raise PermissionDenied

    finding = get_object_or_404(SecurityFinding, pk=pk)

    if request.method == 'POST':

        finding_title = finding.title

        record_activity(
            request.user,
            'Deleted',
            f'Deleted security finding: {finding_title}'
        )

        finding.delete()

        return redirect('dashboard')

    return render(request, 'delete_finding.html', {
        'finding': finding
    })


# ==========================================
# REMEDIATION TRACKING PAGE
# ==========================================

@login_required(login_url='login')
def remediation_tracking(request):

    if not request.user.has_perm('security_monitor.view_securityfinding'):
        raise PermissionDenied

    findings = SecurityFinding.objects.all().order_by('-date_recorded')

    context = {
        'findings': findings,

        'can_change_finding': request.user.has_perm(
            'security_monitor.change_securityfinding'
        ),

        'total_findings': findings.count(),

        'open_findings': findings.filter(status='Open').count(),

        'in_progress_findings': findings.filter(
            status='In Progress'
        ).count(),

        'resolved_findings': findings.filter(
            status='Resolved'
        ).count(),

        'status_choices': SecurityFinding.STATUS_CHOICES,
    }

    return render(request, 'remediation_tracking.html', context)


# ==========================================
# UPDATE REMEDIATION DETAILS
# ==========================================

@login_required(login_url='login')
def update_remediation(request, pk):

    if not request.user.has_perm('security_monitor.change_securityfinding'):
        raise PermissionDenied

    finding = get_object_or_404(SecurityFinding, pk=pk)

    if request.method == 'POST':

        remediation_status = request.POST.get('status', '')

        valid_statuses = [
            choice[0] for choice in SecurityFinding.STATUS_CHOICES
        ]

        if remediation_status not in valid_statuses:
            raise PermissionDenied

        due_date_value = request.POST.get('due_date', '').strip()

        if due_date_value:

            due_date = parse_date(due_date_value)

            if due_date is None:
                raise PermissionDenied

        else:

            due_date = None

        finding.status = remediation_status
        finding.due_date = due_date

        finding.remediation_action = request.POST.get(
            'remediation_action', ''
        ).strip()

        finding.assigned_to = request.POST.get(
            'assigned_to', ''
        ).strip()

        finding.remediation_notes = request.POST.get(
            'remediation_notes', ''
        ).strip()

        if remediation_status == 'Resolved':

            if not finding.date_resolved:
                finding.date_resolved = timezone.localdate()

        else:

            finding.date_resolved = None

        finding.save()

        record_activity(
            request.user,
            'Updated',
            f'Updated remediation details for: {finding.title}. '
            f'New status: {finding.status}.'
        )

        return redirect('remediation_tracking')

    return redirect('remediation_tracking')


# ==========================================
# REPORTS AND ANALYTICS
# ==========================================

@login_required(login_url='login')
def reports_analytics(request):

    if not request.user.has_perm('security_monitor.view_securityfinding'):
        raise PermissionDenied

    findings = SecurityFinding.objects.all()

    total_findings = findings.count()

    critical = findings.filter(severity='Critical').count()
    high = findings.filter(severity='High').count()
    medium = findings.filter(severity='Medium').count()
    low = findings.filter(severity='Low').count()

    severity_labels = [
        'Critical',
        'High',
        'Medium',
        'Low'
    ]

    severity_values = [
        critical,
        high,
        medium,
        low
    ]

    pillar_labels = [
        'Endpoint / IDE',
        'Version Control System',
        'CI/CD Pipeline',
        'Container Registry',
        'Production'
    ]

    pillar_values = [
        findings.filter(pillar=pillar).count()
        for pillar in pillar_labels
    ]

    status_labels = [
        'Open',
        'In Progress',
        'Resolved'
    ]

    status_values = [
        findings.filter(status=status).count()
        for status in status_labels
    ]

    severity_chart = generate_chart(
        severity_labels,
        severity_values,
        'Findings by Severity',
        'Severity',
        'Number of Findings'
    )

    pillar_chart = generate_chart(
        pillar_labels,
        pillar_values,
        'Findings by Infrastructure Pillar',
        'Infrastructure Pillar',
        'Number of Findings'
    )

    status_chart = generate_chart(
        status_labels,
        status_values,
        'Findings by Remediation Status',
        'Remediation Status',
        'Number of Findings'
    )

    context = {

        'total_findings': total_findings,

        'critical_findings': critical,
        'high_findings': high,
        'medium_findings': medium,
        'low_findings': low,

        'open_findings': status_values[0],
        'in_progress_findings': status_values[1],
        'resolved_findings': status_values[2],

        'endpoint_count': pillar_values[0],
        'version_control_count': pillar_values[1],
        'cicd_count': pillar_values[2],
        'registry_count': pillar_values[3],
        'production_count': pillar_values[4],

        'severity_chart': severity_chart,
        'pillar_chart': pillar_chart,
        'status_chart': status_chart,

        'findings': findings.order_by('-date_recorded'),

    }

    return render(request, 'reports_analytics.html', context)


# ==========================================
# DOWNLOAD SECURITY FINDINGS REPORT (CSV)
# ==========================================

@login_required(login_url='login')
def export_security_report(request):

    if not request.user.has_perm('security_monitor.view_securityfinding'):
        raise PermissionDenied

    findings = SecurityFinding.objects.all().order_by('-date_recorded')

    response = HttpResponse(
        content_type='text/csv'
    )

    response['Content-Disposition'] = (
        'attachment; filename="secure_factory_security_report.csv"'
    )

    writer = csv.writer(response)

    writer.writerow([
        'Finding ID',
        'Security Finding',
        'Infrastructure Pillar',
        'Severity',
        'Status',
        'Date Discovered',
        'Due Date',
        'Assigned To',
        'Remediation Action',
        'Remediation Notes',
        'Date Resolved'
    ])

    for finding in findings:

        writer.writerow([
            finding.id,
            finding.title,
            finding.pillar,
            finding.severity,
            finding.status,
            finding.date_discovered,
            finding.due_date,
            finding.assigned_to,
            finding.remediation_action,
            finding.remediation_notes,
            finding.date_resolved
        ])

    return response


# ==========================================
# SETTINGS PAGE
# PROFILE EDITING AND PASSWORD CHANGE
# ==========================================

@login_required(login_url='login')
def settings_page(request):

    password_success = False
    profile_success = False
    profile_errors = ''

    # PROFILE UPDATE FORM

    if request.method == 'POST' and request.POST.get('form_type') == 'profile':

        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        email = request.POST.get('email', '').strip()

        if len(first_name) > 150:
            profile_errors = 'First name must not exceed 150 characters.'

        elif len(last_name) > 150:
            profile_errors = 'Last name must not exceed 150 characters.'

        elif len(email) > 254:
            profile_errors = 'Email address must not exceed 254 characters.'

        elif email:

            try:
                validate_email(email)

            except ValidationError:
                profile_errors = 'Please enter a valid email address.'

        if not profile_errors:

            request.user.first_name = first_name
            request.user.last_name = last_name
            request.user.email = email

            request.user.save()

            record_activity(
                request.user,
                'Profile Updated',
                f'{request.user.username} updated their profile information.'
            )

            profile_success = True

    # PASSWORD CHANGE FORM

    password_form = PasswordChangeForm(
        user=request.user,
        data=(
            request.POST
            if request.method == 'POST'
            and request.POST.get('form_type') == 'password'
            else None
        )
    )

    if request.method == 'POST' and request.POST.get('form_type') == 'password':

        if password_form.is_valid():

            user = password_form.save()

            update_session_auth_hash(request, user)

            record_activity(
                user,
                'Password Changed',
                f'{user.username} changed their account password.'
            )

            password_success = True

            password_form = PasswordChangeForm(
                user=request.user
            )

    return render(request, 'settings.html', {

        'user': request.user,

        'password_form': password_form,
        'password_success': password_success,

        'profile_success': profile_success,
        'profile_errors': profile_errors,

    })


# ==========================================
# ACTIVITY LOGS
# ADMINISTRATORS ONLY
# WITH SEARCH AND FILTERS
# ==========================================

@login_required(login_url='login')
def activity_logs(request):

    if not request.user.has_perm('security_monitor.delete_securityfinding'):
        raise PermissionDenied

    all_logs = ActivityLog.objects.select_related(
        'user'
    ).all().order_by('-timestamp')

    logs = all_logs

    # SEARCH FILTER

    search_query = request.GET.get('search', '').strip()

    if search_query:
        logs = logs.filter(
            Q(user__username__icontains=search_query) |
            Q(action__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    # USER FILTER

    selected_user = request.GET.get('user', '')

    if selected_user.isdigit():
        logs = logs.filter(user_id=int(selected_user))

    # ACTION FILTER

    selected_action = request.GET.get('action', '')

    valid_actions = [
        choice[0] for choice in ActivityLog.ACTION_CHOICES
    ]

    if selected_action in valid_actions:
        logs = logs.filter(action=selected_action)

    # DATE FILTERS

    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')

    if start_date:
        parsed_start_date = parse_date(start_date)

        if parsed_start_date:
            logs = logs.filter(
                timestamp__date__gte=parsed_start_date
            )

    if end_date:
        parsed_end_date = parse_date(end_date)

        if parsed_end_date:
            logs = logs.filter(
                timestamp__date__lte=parsed_end_date
            )

    # GET USERS WHO HAVE ACTIVITY LOGS

    user_choices = ActivityLog.objects.filter(
        user__isnull=False
    ).values_list(
        'user_id',
        'user__username'
    ).distinct().order_by('user__username')

    context = {
        'logs': logs,
        'search_query': search_query,
        'selected_user': selected_user,
        'selected_action': selected_action,
        'start_date': start_date,
        'end_date': end_date,
        'user_choices': user_choices,
        'action_choices': ActivityLog.ACTION_CHOICES,
        'total_logs': ActivityLog.objects.count(),
    }

    return render(request, 'activity_logs.html', context)


# ==========================================
# EXPORT ACTIVITY LOGS TO CSV
# ADMINISTRATORS ONLY
# ==========================================

@login_required(login_url='login')
def export_activity_logs(request):

    if not request.user.has_perm('security_monitor.delete_securityfinding'):
        raise PermissionDenied

    logs = ActivityLog.objects.select_related(
        'user'
    ).all().order_by('-timestamp')

    # SEARCH FILTER

    search_query = request.GET.get('search', '').strip()

    if search_query:
        logs = logs.filter(
            Q(user__username__icontains=search_query) |
            Q(action__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    # USER FILTER

    selected_user = request.GET.get('user', '')

    if selected_user.isdigit():
        logs = logs.filter(user_id=int(selected_user))

    # ACTION FILTER

    selected_action = request.GET.get('action', '')

    valid_actions = [
        choice[0] for choice in ActivityLog.ACTION_CHOICES
    ]

    if selected_action in valid_actions:
        logs = logs.filter(action=selected_action)

    # DATE FILTERS

    start_date = request.GET.get('start_date', '')
    end_date = request.GET.get('end_date', '')

    if start_date:
        parsed_start_date = parse_date(start_date)

        if parsed_start_date:
            logs = logs.filter(
                timestamp__date__gte=parsed_start_date
            )

    if end_date:
        parsed_end_date = parse_date(end_date)

        if parsed_end_date:
            logs = logs.filter(
                timestamp__date__lte=parsed_end_date
            )

    # CREATE CSV RESPONSE

    response = HttpResponse(
        content_type='text/csv; charset=utf-8'
    )

    response['Content-Disposition'] = (
        'attachment; filename="secure_factory_activity_logs.csv"'
    )

    # EXCEL UTF-8 SUPPORT

    response.write('\ufeff')

    writer = csv.writer(response)

    writer.writerow([
        'Activity ID',
        'Username',
        'Action',
        'Description',
        'Date and Time'
    ])

    for log in logs:
        writer.writerow([
            log.id,
            log.user.username if log.user else 'Deleted User',
            log.action,
            log.description,
            log.timestamp.strftime('%d %b %Y, %H:%M')
        ])

    return response
