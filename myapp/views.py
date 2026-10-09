from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.shortcuts import render, redirect, get_object_or_404

# Create your views here.
from django.views.decorators.csrf import csrf_exempt

from myapp.models import *
from myapp.phishing.phishing import predict_phishing


def public_home(request):

    return render(request, 'public page.html', )




from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .models import Bank


@csrf_exempt
def login_page(request):

    if request.method == 'POST':

        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        user = authenticate(request, username=username, password=password)

        if user is not None:

            if user.groups.filter(name='admin').exists():

                login(request, user)

                return redirect('/myapp/admin_home/')


            elif user.groups.filter(name='bank').exists():

                try:

                    bank = Bank.objects.get(auth_user=user)

                except Bank.DoesNotExist:

                    messages.error(request, "Bank profile not found.")

                    return redirect('/myapp/login_page/#a')


                if bank.status == 'Approved':

                    login(request, user)

                    return redirect('/myapp/bank_home/')

                else:

                    messages.error(request, "Your bank account is not approved yet.")

                    return redirect('/myapp/login_page/#a')


            else:

                messages.error(
                    request,
                    "Your account does not have an assigned role."
                )

                return redirect('/myapp/login_page/#a')


        else:

            messages.error(request, "Invalid username or password.")

            return redirect('/myapp/login_page/#a')


    return render(request, 'login page.html')


def logout_page(request):
    logout(request)
    return redirect('/myapp/login_page/#a')




# admin

from datetime import timedelta

from django.contrib.admin.views.decorators import staff_member_required
from django.db.models import Count
from django.shortcuts import render
from django.utils import timezone



def admin_home(request):
    now = timezone.now()
    today = now.date()
    last_30_days = now - timedelta(days=30)

    # Network monitoring statistics
    network_logs = NetworkLog.objects.order_by('-created_at')

    total_network_logs = network_logs.count()

    ddos_count = network_logs.filter(
        status='DDoS Detected',
        created_at__gte=last_30_days,
    ).count()

    suspicious_network_count = network_logs.filter(
        status='Suspicious',
        created_at__gte=last_30_days,
    ).count()

    blocked_requests = network_logs.filter(
        action_taken='Blocked',
        created_at__gte=last_30_days,
    ).count()

    # APK / sandbox statistics
    malware_logs = MalwareScanLog.objects.order_by('-created_at')

    apk_count = malware_logs.filter(
        scan_result='Malicious',
        created_at__gte=last_30_days,
    ).count()

    suspicious_apk_count = malware_logs.filter(
        scan_result='Suspicious',
        created_at__gte=last_30_days,
    ).count()

    # Latest alerts
    alerts = []

    for log in network_logs.filter(
        status__in=['Suspicious', 'DDoS Detected']
    )[:10]:
        alerts.append({
            'kind': 'bad' if log.status == 'DDoS Detected' else 'warn',
            'message': (
                f'{log.status}: IP {log.client_ip}, '
                f'route {log.route}, '
                f'{log.request_count} requests in monitoring window'
            ),
            'created_at': log.created_at,
        })

    for log in malware_logs.filter(
        scan_result__in=['Malicious', 'Suspicious']
    )[:10]:
        alerts.append({
            'kind': 'bad' if log.scan_result == 'Malicious' else 'warn',
            'message': (
                f'APK scan {log.scan_result}: '
                f'{log.apk_file.name if log.apk_file else "Uploaded file"}'
            ),
            'created_at': log.created_at,
        })

    alerts.sort(
        key=lambda item: item['created_at'],
        reverse=True,
    )

    # Chart: recent request-count readings, not requests per second
    recent_logs = list(
        network_logs.order_by('-created_at')[:12]
    )
    recent_logs.reverse()

    net_series = [
        log.request_count for log in recent_logs
    ]

    max_rate = max(net_series, default=1)

    # Current model does not contain a requests-per-second measurement.
    current_rate = net_series[-1] if net_series else 0

    context = {
        'active': 'dashboard',

        'total_banks': Bank.objects.count(),
        'total_users': UserProfile.objects.count(),
        'blocked_users': UserProfile.objects.filter(
            status='Blocked'
        ).count(),

        'total_network_logs': total_network_logs,
        'ddos_count': ddos_count,
        'suspicious_network_count': suspicious_network_count,
        'blocked_requests': blocked_requests,

        'phishing_count': 0,  # Connect this to your phishing model.
        'apk_count': apk_count,
        'suspicious_apk_count': suspicious_apk_count,

        'current_rate': current_rate,
        'net_series': net_series,
        'max_rate': max_rate,

        'alerts': alerts,

        'pending_banks': Bank.objects.filter(status='Pending').count(),
    }

    return render(request, 'admin/home.html', context)



def admin_home_sub(request):
    return render(request, 'admin/home sub.html')

def manage_banks(request):
    banks = Bank.objects.all().order_by('-created_at')
    return render(request, 'admin/manage_banks.html', {'banks': banks})

def view_bank(request, bank_id):
    bank = get_object_or_404(Bank, id=bank_id)
    return render(request, 'admin/view_bank.html', {'bank': bank})






def approve_bank(request, bank_id):
    bank = get_object_or_404(Bank, id=bank_id)
    bank.status = 'Approved'
    bank.save()
    return redirect('/myapp/manage_banks/')


def reject_bank(request, bank_id):
    bank = get_object_or_404(Bank, id=bank_id)
    bank.status = 'Rejected'
    bank.save()
    return redirect('/myapp/manage_banks/')


def view_users(request):
    users = UserProfile.objects.all().order_by('-created_at')
    return render(request, 'admin/view_users.html', {'users': users})


def unblock_user(request, user_id):
    user = get_object_or_404(UserProfile, id=user_id)
    user.status = 'Active'
    user.save()
    return redirect('/myapp/view_users/')


def view_accounts(request):
    accounts = Account.objects.select_related('user', 'bank').all().order_by('-created_at')
    return render(request, 'admin/view_accounts.html', {'accounts': accounts})

def view_transactions(request):
    transactions = BankTransaction.objects.select_related('sender_account', 'receiver_account').all().order_by('-created_at')
    return render(request, 'admin/view_transactions.html', {'transactions': transactions})

def view_fraud_logs(request):
    fraud_logs = FraudLog.objects.select_related('transaction').all().order_by('-created_at')
    return render(request, 'admin/view_fraud_logs.html', {'fraud_logs': fraud_logs})

def view_threats(request):
    phishing_logs = PhishingURLLog.objects.filter(prediction='Phishing').order_by('-created_at')
    malware_logs = MalwareScanLog.objects.filter(scan_result='Malicious').order_by('-created_at')
    network_logs = NetworkLog.objects.all().order_by('-created_at')

    context = {
        'phishing_logs': phishing_logs,
        'malware_logs': malware_logs,
        'network_logs': network_logs,
    }

    return render(request, 'admin/view_threats.html', context)


def view_network_monitoring(request):
    network_logs = NetworkLog.objects.select_related('user').all().order_by('-created_at')
    return render(request, 'admin/network_monitoring.html', {'network_logs': network_logs})


def view_notifications(request):
    notifications = Notification.objects.select_related('user').all().order_by('-created_at')
    return render(request, 'admin/view_notifications.html', {'notifications': notifications})


def admin_all_network_monitoring(request):
    all_logs = NetworkLog.objects.select_related(
        'user',
        'user__bank'
    ).order_by('-created_at')

    # Search by IP, route, bank, username, status or action
    search_query = request.GET.get('q', '').strip()
    selected_status = request.GET.get('status', '').strip()
    selected_action = request.GET.get('action', '').strip()

    if search_query:
        all_logs = all_logs.filter(
            Q(client_ip__icontains=search_query)
            | Q(route__icontains=search_query)
            | Q(status__icontains=search_query)
            | Q(action_taken__icontains=search_query)
            | Q(user__full_name__icontains=search_query)
            | Q(user__bank__bank_name__icontains=search_query)
        )

    if selected_status:
        all_logs = all_logs.filter(status=selected_status)

    if selected_action:
        all_logs = all_logs.filter(action_taken=selected_action)

    # Summary values use all records, not only filtered results
    logs = NetworkLog.objects.all()

    context = {
        'reports': all_logs[:500],
        'total_reports': logs.count(),
        'normal_count': logs.filter(status='Normal').count(),
        'suspicious_count': logs.filter(status='Suspicious').count(),
        'ddos_count': logs.filter(status='DDoS Detected').count(),
        'blocked_count': logs.filter(action_taken='Blocked').count(),
        'allowed_count': logs.filter(action_taken='Allowed').count(),
        'pending_count': logs.filter(status='Pending').count(),
        'total_banks': Bank.objects.count(),
        'search_query': search_query,
        'selected_status': selected_status,
        'selected_action': selected_action,
    }

    return render(
        request,
        'admin/all_network_monitoring.html',
        context
    )

# bankssssss================

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from .models import Bank


from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User, Group
from .models import Bank


def bank_register(request):

    if request.method == 'POST':

        username = request.POST.get('username')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        bank_name = request.POST.get('bank_name')
        bank_code = request.POST.get('bank_code')
        ifsc_code = request.POST.get('ifsc_code')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        license_doc = request.FILES.get('license_doc')

        if password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('/myapp/bank_register/')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
            return redirect('/myapp/bank_register/')

        if Bank.objects.filter(bank_code=bank_code).exists():
            messages.error(request, 'Bank code already exists.')
            return redirect('/myapp/bank_register/')

        if Bank.objects.filter(email=email).exists():
            messages.error(request, 'Bank email already exists.')
            return redirect('/myapp/bank_register/')

        user = User.objects.create_user(
            username=username,
            password=password,
            email=email
        )

        bank_group, created = Group.objects.get_or_create(name='bank')

        user.groups.add(bank_group)

        bank = Bank.objects.create(
            auth_user=user,
            bank_name=bank_name,
            bank_code=bank_code,
            ifsc_code=ifsc_code,
            email=email,
            phone=phone,
            address=address,
            license_doc=license_doc,
            status='Pending'
        )

        messages.success(
            request,
            'Bank registration submitted successfully. Wait for admin approval.'
        )

        return redirect('/myapp/login_page/')

    return render(request, 'bank/register.html')


from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q, Sum, Count
from decimal import Decimal

from .models import (
    Bank, UserProfile, Account, BankTransaction,
    FraudLog, PhishingURLLog, MalwareScanLog, NetworkLog
)


@login_required
def bank_home(request):
    # Ensure the logged-in user is a bank
    try:
        bank = request.user.bank_profile
    except Bank.DoesNotExist:
        return redirect('login')  # or your login page name



    now = timezone.now()
    today = now.date()
    last_30_days = now - timedelta(days=30)
    last_7_days = now - timedelta(days=7)

    # ---------- Users of this bank ----------
    users = UserProfile.objects.filter(bank=bank)
    total_users = users.count()
    active_users = users.filter(status='Active').count()
    blocked_users = users.filter(status='Blocked').count()
    pending_users = users.filter(status='Pending').count()

    # ---------- Accounts ----------
    accounts = Account.objects.filter(bank=bank)
    total_accounts = accounts.count()
    active_accounts = accounts.filter(status='Active').count()
    total_balance = accounts.aggregate(total=Sum('balance'))['total'] or Decimal('0.00')

    # ---------- Transactions (sent or received by this bank's accounts) ----------
    bank_account_ids = accounts.values_list('id', flat=True)

    transactions = BankTransaction.objects.filter(
        Q(sender_account_id__in=bank_account_ids) |
        Q(receiver_account_id__in=bank_account_ids)
    ).order_by('-created_at')

    total_transactions = transactions.count()
    txns_today = transactions.filter(created_at__date=today).count()
    txns_last_7 = transactions.filter(created_at__gte=last_7_days).count()

    success_txns = transactions.filter(status='Success').count()
    failed_txns = transactions.filter(status='Failed').count()
    blocked_txns = transactions.filter(status='Blocked').count()
    suspicious_txns = transactions.filter(status='Suspicious').count()

    # Volume
    volume_today = transactions.filter(
        created_at__date=today,
        status='Success'
    ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')

    # ---------- Fraud ----------
    fraud_logs = FraudLog.objects.filter(
        transaction__in=transactions
    ).order_by('-created_at')

    fraud_count = fraud_logs.count()
    fraud_pending = fraud_logs.filter(status='Pending').count()
    fraud_confirmed = fraud_logs.filter(status='Confirmed').count()

    # ---------- Network logs (users belonging to this bank) ----------
    network_logs = NetworkLog.objects.filter(
        user__bank=bank
    ).order_by('-created_at')

    total_network_logs = network_logs.count()
    ddos_count = network_logs.filter(
        status='DDoS Detected',
        created_at__gte=last_30_days
    ).count()
    suspicious_network_count = network_logs.filter(
        status='Suspicious',
        created_at__gte=last_30_days
    ).count()
    blocked_requests = network_logs.filter(
        action_taken='Blocked',
        created_at__gte=last_30_days
    ).count()

    # Chart data – last 12 request counts
    recent_logs = list(network_logs[:12])
    recent_logs.reverse()
    net_series = [log.request_count for log in recent_logs]
    max_rate = max(net_series, default=1)
    current_rate = net_series[-1] if net_series else 0

    # ---------- Phishing & APK (reported by this bank's users) ----------
    bank_user_ids = users.values_list('auth_user_id', flat=True)

    phishing_count = PhishingURLLog.objects.filter(
        reported_by_id__in=bank_user_ids,
        prediction='Phishing',
        created_at__gte=last_30_days
    ).count()

    malware_logs = MalwareScanLog.objects.filter(
        uploaded_by_id__in=bank_user_ids
    ).order_by('-created_at')

    apk_count = malware_logs.filter(
        scan_result='Malicious',
        created_at__gte=last_30_days
    ).count()
    suspicious_apk_count = malware_logs.filter(
        scan_result='Suspicious',
        created_at__gte=last_30_days
    ).count()

    # ---------- Latest alerts (network + fraud + apk) ----------
    alerts = []

    for log in network_logs.filter(status__in=['Suspicious', 'DDoS Detected'])[:8]:
        alerts.append({
            'kind': 'bad' if log.status == 'DDoS Detected' else 'warn',
            'message': (
                f'{log.status}: IP {log.client_ip}, '
                f'route {log.route}, {log.request_count} requests'
            ),
            'created_at': log.created_at,
        })

    for log in fraud_logs[:8]:
        alerts.append({
            'kind': 'bad' if log.risk_score >= 70 else 'warn',
            'message': (
                f'Fraud alert (score {log.risk_score}): '
                f'{log.reason[:80]}{"…" if len(log.reason) > 80 else ""}'
            ),
            'created_at': log.created_at,
        })

    for log in malware_logs.filter(scan_result__in=['Malicious', 'Suspicious'])[:6]:
        alerts.append({
            'kind': 'bad' if log.scan_result == 'Malicious' else 'warn',
            'message': (
                f'APK scan {log.scan_result}: '
                f'{log.apk_file.name if log.apk_file else "Uploaded file"}'
            ),
            'created_at': log.created_at,
        })

    alerts.sort(key=lambda x: x['created_at'], reverse=True)
    alerts = alerts[:12]   # keep only the newest 12

    # ---------- Weekly transaction chart data ----------
    week = []
    max_total = 1
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_txns = transactions.filter(created_at__date=day)
        total = day_txns.count()
        flagged = day_txns.filter(
            Q(is_fraud='Yes') | Q(status__in=['Blocked', 'Suspicious'])
        ).count()
        week.append({
            'day': day.strftime('%a'),
            'total': total,
            'flagged': flagged,
        })
        if total > max_total:
            max_total = total

    context = {
        'active': 'dashboard',
        'bank': bank,

        # Users
        'total_users': total_users,
        'active_users': active_users,
        'blocked_users': blocked_users,
        'pending_users': pending_users,

        # Accounts
        'total_accounts': total_accounts,
        'active_accounts': active_accounts,
        'total_balance': total_balance,

        # Transactions
        'total_transactions': total_transactions,
        'txns_today': txns_today,
        'txns_last_7': txns_last_7,
        'success_txns': success_txns,
        'failed_txns': failed_txns,
        'blocked_txns': blocked_txns,
        'suspicious_txns': suspicious_txns,
        'volume_today': volume_today,

        # Fraud
        'fraud_count': fraud_count,
        'fraud_pending': fraud_pending,
        'fraud_confirmed': fraud_confirmed,

        # Network
        'total_network_logs': total_network_logs,
        'ddos_count': ddos_count,
        'suspicious_network_count': suspicious_network_count,
        'blocked_requests': blocked_requests,
        'current_rate': current_rate,
        'net_series': net_series,
        'max_rate': max_rate,

        # Threats
        'phishing_count': phishing_count,
        'apk_count': apk_count,
        'suspicious_apk_count': suspicious_apk_count,

        # Charts & alerts
        'week': week,
        'max_total': max_total,
        'alerts': alerts,
    }

    return render(request, 'bank/bank home.html', context)

def bank_profile(request):

    bank = Bank.objects.get(auth_user_id=request.user.id)

    return render(request, 'bank/profile.html', {'bank': bank})

def edit_profile(request):

    bank = Bank.objects.get(auth_user_id=request.user.id)

    if request.method == 'POST':

        bank.bank_name = request.POST.get('bank_name')
        bank.bank_code = request.POST.get('bank_code')
        bank.ifsc_code = request.POST.get('ifsc_code')
        bank.email = request.POST.get('email')
        bank.phone = request.POST.get('phone')
        bank.address = request.POST.get('address')

        if request.FILES.get('license_doc'):
            bank.license_doc = request.FILES.get('license_doc')

        bank.save()

        request.user.email = bank.email
        request.user.save()

        messages.success(request, 'Profile updated successfully.')

        return redirect('/myapp/bank_profile/')

    return render(request, 'bank/edit_profile.html', {'bank': bank})


def create_user(request):

    bank = get_object_or_404(Bank, auth_user=request.user)

    if request.method == 'POST':

        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        address = request.POST.get('address', '').strip()

        account_number = request.POST.get('account_number', '').strip()
        account_type = request.POST.get('account_type', '').strip()
        balance = request.POST.get('balance', '0').strip()

        profile_pic = request.FILES.get('profile_pic')

        if User.objects.filter(username=email).exists():
            messages.error(request, 'Email already registered.')
            return redirect('/myapp/create_user/')

        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return redirect('/myapp/create_user/')

        if UserProfile.objects.filter(phone=phone).exists():
            messages.error(request, 'Phone number already registered.')
            return redirect('/myapp/create_user/')

        if Account.objects.filter(account_number=account_number).exists():
            messages.error(request, 'Account number already exists.')
            return redirect('/myapp/create_user/')

        user = User.objects.create_user(
            username=email,
            password=phone,
            email=email
        )

        user_group, created = Group.objects.get_or_create(name='user')

        user.groups.add(user_group)

        user_profile = UserProfile.objects.create(
            auth_user=user,
            bank=bank,
            full_name=full_name,
            email=email,
            phone=phone,
            address=address,
            profile_pic=profile_pic,
            status='Active'
        )

        Account.objects.create(
            user=user_profile,
            bank=bank,
            account_number=account_number,
            account_type=account_type,
            balance=balance,
            status='Active'
        )

        messages.success(request, 'User and bank account created successfully.')

        return redirect('/myapp/view_bank_users/')

    return render(request, 'bank/create_user.html')


def view_bank_users(request):

    bank = get_object_or_404(Bank, auth_user=request.user)

    users = UserProfile.objects.filter(
        bank=bank
    ).prefetch_related(
        'accounts'
    ).order_by('-created_at')

    return render(
        request,
        'bank/view_users.html',
        {'users': users}
    )

def delete_bank_user(request, id):

    bank = get_object_or_404(Bank, auth_user=request.user)

    user_profile = get_object_or_404(
        UserProfile,
        id=id,
        bank=bank
    )

    auth_user = user_profile.auth_user

    user_profile.delete()
    auth_user.delete()

    messages.success(request, 'User and bank account deleted successfully.')

    return redirect('/myapp/view_bank_users/')


def view_bank_accounts(request):

    bank = get_object_or_404(Bank, auth_user=request.user)

    accounts = Account.objects.filter(
        bank=bank
    ).select_related(
        'user'
    ).order_by('-created_at')

    return render(
        request,
        'bank/view_accounts.html',
        {'accounts': accounts}
    )

from django.db.models import Q
def view_bank_transactions(request):

    bank = get_object_or_404(Bank, auth_user=request.user)

    transactions = BankTransaction.objects.filter(
        Q(sender_account__bank=bank) |
        Q(receiver_account__bank=bank)
    ).select_related(
        'sender_account',
        'sender_account__user',
        'receiver_account',
        'receiver_account__user'
    ).order_by('-created_at')

    return render(
        request,
        'bank/view_transactions.html',
        {'transactions': transactions}
    )




import requests

from django.shortcuts import render
from django.http import JsonResponse


import requests

from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth.models import User

from .models import PhishingURLLog


# =========================================================
# PHISHING DETECTION PAGE
# =========================================================

def phishing_detection(request):

    context = {
        "result": None,
        "url": "",
        "phishing_probability": None,
        "legitimate_probability": None,
        "error": None,
    }

    # -----------------------------------------------------
    # Only process POST request
    # -----------------------------------------------------

    if request.method == "POST":

        # Get URL from form
        url = request.POST.get("url", "").strip()

        context["url"] = url

        # -------------------------------------------------
        # Empty URL validation
        # -------------------------------------------------

        if not url:

            context["error"] = "Please enter a URL."

            return render(
                request,
                "bank/phishing_detection.html",
                context
            )

        # -------------------------------------------------
        # URL length validation
        # -------------------------------------------------

        if len(url) > 2048:

            context["error"] = "URL is too long."

            return render(
                request,
                "bank/phishing_detection.html",
                context
            )

        try:

            # -------------------------------------------------
            # DJANGO → SPRING CLOUD GATEWAY
            # -------------------------------------------------

            gateway_url = "http://localhost:8080/phishing/test"

            response = requests.post(
                gateway_url,
                json={
                    "url": url
                },
                timeout=30
            )

            # Convert response to JSON
            result = response.json()

            # -------------------------------------------------
            # HANDLE GATEWAY ERROR
            # -------------------------------------------------

            if response.status_code != 200:

                context["error"] = result.get(
                    "error",
                    result.get(
                        "detail",
                        "Unable to analyse this URL."
                    )
                )

                return render(
                    request,
                    "bank/phishing_detection.html",
                    context
                )

            # -------------------------------------------------
            # GET ML RESULT
            # -------------------------------------------------

            prediction_result = result.get("result")

            phishing_probability = result.get(
                "phishing_probability"
            )

            legitimate_probability = result.get(
                "legitimate_probability"
            )

            context["result"] = prediction_result

            context["phishing_probability"] = (
                phishing_probability
            )

            context["legitimate_probability"] = (
                legitimate_probability
            )

            # -------------------------------------------------
            # CONVERT ML RESULT TO DATABASE VALUES
            # -------------------------------------------------

            if prediction_result == "PHISHING":

                prediction = "Phishing"
                risk_level = "High"

            elif prediction_result == "LEGITIMATE":

                prediction = "Safe"
                risk_level = "Low"

            else:

                prediction = "Safe"
                risk_level = "Low"

            # -------------------------------------------------
            # SAVE RESULT TO DATABASE
            # -------------------------------------------------

            PhishingURLLog.objects.create(

                reported_by=User.objects.get(
                    id=request.user.id
                ),

                url=url,

                prediction=prediction,

                risk_level=risk_level,

                status="Completed"
            )

        # -----------------------------------------------------
        # CONNECTION ERROR
        # -----------------------------------------------------

        except requests.exceptions.ConnectionError:

            context["error"] = (
                "Phishing detection service is unavailable."
            )

        # -----------------------------------------------------
        # TIMEOUT ERROR
        # -----------------------------------------------------

        except requests.exceptions.Timeout:

            context["error"] = (
                "Phishing detection service timed out."
            )

        # -----------------------------------------------------
        # REQUEST ERROR
        # -----------------------------------------------------

        except requests.exceptions.RequestException as e:

            print(
                "Phishing Gateway error:",
                e
            )

            context["error"] = (
                "Unable to connect to phishing service."
            )

        # -----------------------------------------------------
        # INVALID JSON
        # -----------------------------------------------------

        except ValueError:

            context["error"] = (
                "Invalid response received from "
                "phishing service."
            )

        # -----------------------------------------------------
        # DATABASE / OTHER ERROR
        # -----------------------------------------------------

        except Exception as e:

            print(
                "Phishing detection error:",
                e
            )

            context["error"] = (
                "Unable to analyse this URL. "
                "Please try again."
            )

    # ---------------------------------------------------------
    # DISPLAY PAGE
    # ---------------------------------------------------------

    return render(
        request,
        "bank/phishing_detection.html",
        context
    )


# =========================================================
# PHISHING DETECTION API
# =========================================================

def phishing_detection_api(request):

    # -----------------------------------------------------
    # Only POST request allowed
    # -----------------------------------------------------

    if request.method != "POST":

        return JsonResponse(
            {
                "success": False,
                "error": "POST request required."
            },
            status=405
        )

    # -----------------------------------------------------
    # Get URL
    # -----------------------------------------------------

    url = request.POST.get(
        "url",
        ""
    ).strip()

    # -----------------------------------------------------
    # Empty URL
    # -----------------------------------------------------

    if not url:

        return JsonResponse(
            {
                "success": False,
                "error": "URL is required."
            },
            status=400
        )

    # -----------------------------------------------------
    # URL length validation
    # -----------------------------------------------------

    if len(url) > 2048:

        return JsonResponse(
            {
                "success": False,
                "error": "URL is too long."
            },
            status=400
        )

    try:

        # -------------------------------------------------
        # DJANGO → SPRING CLOUD GATEWAY
        # -------------------------------------------------

        gateway_url = (
            "http://localhost:8080/phishing/test"
        )

        response = requests.post(
            gateway_url,
            json={
                "url": url
            },
            timeout=30
        )

        # Convert response to JSON
        result = response.json()

        # -------------------------------------------------
        # SAVE SUCCESSFUL RESULT
        # -------------------------------------------------

        if response.status_code == 200:

            prediction_result = result.get(
                "result"
            )

            if prediction_result == "PHISHING":

                prediction = "Phishing"
                risk_level = "High"

            elif prediction_result == "LEGITIMATE":

                prediction = "Safe"
                risk_level = "Low"

            else:

                prediction = "Safe"
                risk_level = "Low"

            # -------------------------------------------------
            # DATABASE INSERT
            # -------------------------------------------------

            PhishingURLLog.objects.create(

                reported_by=User.objects.get(
                    id=request.user.id
                ),

                url=url,

                prediction=prediction,

                risk_level=risk_level,

                status="Completed"
            )

        # -------------------------------------------------
        # RETURN RESULT
        # -------------------------------------------------

        return JsonResponse(
            result,
            status=response.status_code
        )

    # -----------------------------------------------------
    # CONNECTION ERROR
    # -----------------------------------------------------

    except requests.exceptions.ConnectionError:

        return JsonResponse(
            {
                "success": False,
                "error": (
                    "Phishing detection service "
                    "is unavailable."
                )
            },
            status=503
        )

    # -----------------------------------------------------
    # TIMEOUT
    # -----------------------------------------------------

    except requests.exceptions.Timeout:

        return JsonResponse(
            {
                "success": False,
                "error": (
                    "Phishing detection service "
                    "timed out."
                )
            },
            status=504
        )

    # -----------------------------------------------------
    # REQUEST ERROR
    # -----------------------------------------------------

    except requests.exceptions.RequestException as e:

        print(
            "Phishing Gateway API error:",
            e
        )

        return JsonResponse(
            {
                "success": False,
                "error": (
                    "Unable to connect to "
                    "phishing service."
                )
            },
            status=503
        )

    # -----------------------------------------------------
    # INVALID JSON
    # -----------------------------------------------------

    except ValueError:

        return JsonResponse(
            {
                "success": False,
                "error": (
                    "Invalid response from "
                    "phishing service."
                )
            },
            status=502
        )

    # -----------------------------------------------------
    # OTHER ERROR
    # -----------------------------------------------------

    except Exception as e:

        print(
            "Phishing API error:",
            e
        )

        return JsonResponse(
            {
                "success": False,
                "error": "Unable to analyse URL."
            },
            status=500
        )




# malware==============




import base64
import hashlib
import json
import logging
import os

import requests

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods

from .models import MalwareScanLog, Sandbox_table


logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["GET", "POST"])
def upload_and_sandbox_apk(request):

    if request.method == "GET":
        return render(request, "bank/user_upload_apk.html")

    uploaded_file = request.FILES.get("apk_file")

    if uploaded_file is None:
        messages.error(request, "Please select an APK or EXE file.")
        return redirect("upload_and_sandbox_apk")

    filename = os.path.basename(uploaded_file.name)
    extension = os.path.splitext(filename)[1].lower()

    if extension not in {".apk", ".exe"}:
        messages.error(
            request,
            "Invalid file type. Upload only .apk or .exe files."
        )
        return redirect("upload_and_sandbox_apk")

    max_size = 100 * 1024 * 1024

    if uploaded_file.size == 0:
        messages.error(request, "The uploaded file is empty.")
        return redirect("upload_and_sandbox_apk")

    if uploaded_file.size > max_size:
        messages.error(
            request,
            "File is too large. Maximum allowed size is 100 MB."
        )
        return redirect("upload_and_sandbox_apk")

    # Read once, then reuse the same bytes for hashing and analysis.
    file_bytes = uploaded_file.read()

    if not file_bytes:
        messages.error(request, "The uploaded file could not be read.")
        return redirect("upload_and_sandbox_apk")

    file_hash = hashlib.sha256(file_bytes).hexdigest()

    # Save the uploaded file and create the scan record.
    uploaded_file.seek(0)

    apk_record = MalwareScanLog.objects.create(
        uploaded_by=request.user,
        apk_file=uploaded_file,
        file_hash=file_hash,
        scan_result="Suspicious",
        confidence_score="0.0%",
        prediction_result="Analysis pending",
        reason="Waiting for sandbox analysis.",
        status="Pending",
    )

    try:
        sandbox_base_url = getattr(
            settings,
            "SANDBOX_ENGINE_URL",
            "http://127.0.0.1:5000",
        ).rstrip("/")

        sandbox_endpoint = f"{sandbox_base_url}/analyze"

        encoded_content = base64.b64encode(file_bytes).decode("ascii")

        logger.info(
            "[SANDBOX] Sending %s (%s bytes) to %s",
            filename,
            len(file_bytes),
            sandbox_endpoint,
        )

        response = requests.post(
            sandbox_endpoint,
            json={
                "filename": filename,
                "file_type": extension.lstrip("."),
                "content_base64": encoded_content,
                "sha256": file_hash,
            },
            timeout=(5, 120),
        )

        logger.info(
            "[SANDBOX] HTTP response status: %s",
            response.status_code,
        )

        response.raise_for_status()
        result = response.json()

        if not isinstance(result, dict):
            raise ValueError("Sandbox response is not a JSON object.")

        if "threat_score" not in result or "verdict" not in result:
            raise ValueError(
                "Sandbox response is missing 'threat_score' or 'verdict'."
            )

        threat_score = float(result["threat_score"])

        if not 0 <= threat_score <= 100:
            raise ValueError("Sandbox threat_score must be between 0 and 100.")

        verdict = str(result["verdict"]).strip().upper()

        verdict_mapping = {
            "CLEAN": "Clean",
            "SAFE": "Clean",
            "SUSPICIOUS": "Suspicious",
            "HIGH THREAT": "Malicious",
            "CRITICAL MALWARE": "Malicious",
            "MALICIOUS": "Malicious",
            "MALWARE": "Malicious",
        }

        if verdict not in verdict_mapping:
            raise ValueError(
                f"Unknown sandbox verdict: {verdict!r}"
            )

        scan_result = verdict_mapping[verdict]

        # Support both response key names used by different engine versions.
        signatures = result.get(
            "detected_signatures",
            result.get("signatures", []),
        )

        if isinstance(signatures, str):
            signatures_text = signatures
        else:
            signatures_text = json.dumps(signatures, ensure_ascii=False)

        entropy = result.get("entropy", "Unknown")
        analysis_logs = result.get("execution_logs", "")

        if not isinstance(analysis_logs, str):
            analysis_logs = json.dumps(
                analysis_logs,
                ensure_ascii=False,
            )

        # Be clear that these are engine-reported logs, not proof
        # that the uploaded program was actually executed.
        apk_record.scan_result = scan_result
        apk_record.confidence_score = f"{threat_score:.1f}%"
        apk_record.prediction_result = (
            f"Sandbox verdict: {verdict}\n"
            f"Mapped result: {scan_result}\n"
            f"Threat score: {threat_score:.1f}%\n"
            f"Signatures: {signatures_text}"
        )
        apk_record.reason = (
            f"File: {filename}\n"
            f"File type: {extension.lstrip('.').upper()}\n"
            f"SHA-256: {file_hash}\n"
            f"Threat score: {threat_score:.1f}%\n"
            f"Entropy: {entropy}\n"
            f"Analysis logs returned by engine:\n{analysis_logs}\n\n"
            "Note: A heuristic verdict is not proof of malicious behaviour. "
            "Simulated logs are not evidence of actual program execution."
        )
        apk_record.status = "Completed"
        apk_record.save(
            update_fields=[
                "scan_result",
                "confidence_score",
                "prediction_result",
                "reason",
                "status",
            ]
        )

        Sandbox_table.objects.create(
            APK=apk_record,
            sandbox_status="COMPLETED",
            behaviour_summary=(
                f"File: {filename} | "
                f"Type: {extension.lstrip('.').upper()} | "
                f"Threat score: {threat_score:.1f}% | "
                f"Entropy: {entropy} | "
                f"Verdict: {verdict} | "
                f"Signatures: {signatures_text}"
            ),
            executed_on_server="Standalone Sandbox API at 127.0.0.1:5000",
        )

        logger.info(
            "[SANDBOX] Analysis completed for %s: %s (%.1f%%)",
            filename,
            verdict,
            threat_score,
        )

        messages.success(
            request,
            f"Analysis completed: {scan_result} "
            f"(heuristic threat score: {threat_score:.1f}%).",
        )

    except requests.exceptions.Timeout:
        logger.exception("[SANDBOX] Request timed out for %s", filename)

        apk_record.status = "Failed"
        apk_record.prediction_result = "SANDBOX_TIMEOUT"
        apk_record.reason = (
            "The sandbox did not respond within the allowed time. "
            "No completed analysis result was received."
        )
        apk_record.save(
            update_fields=["status", "prediction_result", "reason"]
        )

        messages.error(
            request,
            "Sandbox timed out. Check the sandbox terminal and try again.",
        )

    except requests.exceptions.RequestException as exc:
        logger.exception("[SANDBOX] Connection/request failed for %s", filename)

        apk_record.status = "Failed"
        apk_record.prediction_result = "SANDBOX_CONNECTION_FAILED"
        apk_record.reason = str(exc)
        apk_record.save(
            update_fields=["status", "prediction_result", "reason"]
        )

        messages.error(
            request,
            "Cannot connect to the sandbox. Check its URL and make sure "
            "the sandbox server is running.",
        )

    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        logger.exception("[SANDBOX] Invalid response for %s", filename)

        apk_record.status = "Failed"
        apk_record.prediction_result = "INVALID_SANDBOX_RESPONSE"
        apk_record.reason = str(exc)
        apk_record.save(
            update_fields=["status", "prediction_result", "reason"]
        )

        messages.error(
            request,
            "The sandbox returned an invalid result. Check the sandbox "
            "terminal for details.",
        )

    except Exception as exc:
        logger.exception("[SANDBOX] Unexpected error for %s", filename)

        apk_record.status = "Failed"
        apk_record.prediction_result = "SANDBOX_ANALYSIS_FAILED"
        apk_record.reason = str(exc)
        apk_record.save(
            update_fields=["status", "prediction_result", "reason"]
        )

        messages.error(
            request,
            "Analysis failed unexpectedly. Check the Django terminal "
            "for the error details.",
        )

    return redirect("/myapp/view_apk_reports/#a")



from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.db.models import Q

from .models import MalwareScanLog, Sandbox_table


@login_required
def view_apk_reports(request):

    # Only show reports uploaded by the logged-in user
    all_reports = MalwareScanLog.objects.filter(
        uploaded_by=request.user
    )

    # Search and filter values
    search_query = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()
    file_filter = request.GET.get('file_type', '').strip()
    result_filter = request.GET.get('result', '').strip()

    reports = all_reports

    # Search by file name, hash, result, or prediction
    if search_query:
        reports = reports.filter(
            Q(apk_file__icontains=search_query)
            | Q(file_hash__icontains=search_query)
            | Q(scan_result__icontains=search_query)
            | Q(prediction_result__icontains=search_query)
        )

    # Filter by processing status
    if status_filter in ['Pending', 'Completed', 'Failed']:
        reports = reports.filter(status=status_filter)

    # Filter by file extension
    if file_filter == 'apk':
        reports = reports.filter(apk_file__iendswith='.apk')
    elif file_filter == 'exe':
        reports = reports.filter(apk_file__iendswith='.exe')

    # Filter by verdict
    if result_filter in ['Clean', 'Suspicious', 'Malicious']:
        reports = reports.filter(scan_result=result_filter)

    reports = reports.order_by('-created_at')

    context = {
        'reports': reports,
        'search_query': search_query,
        'status_filter': status_filter,
        'file_filter': file_filter,
        'result_filter': result_filter,

        'total_reports': all_reports.count(),

        'completed_reports': all_reports.filter(
            status='Completed'
        ).count(),

        'malicious_reports': all_reports.filter(
            scan_result='Malicious'
        ).count(),

        'failed_reports': all_reports.filter(
            status='Failed'
        ).count(),
    }

    return render(
        request,
        'bank/view_apk_reports.html',
        context
    )


@login_required
def view_apk_report_detail(request, report_id):

    # Fetch the exact report and verify its owner
    report = get_object_or_404(
        MalwareScanLog,
        pk=report_id,
        uploaded_by=request.user
    )

    # Fetch sandbox records linked to this scan
    sandbox_reports = Sandbox_table.objects.filter(
        APK=report
    ).order_by('-timestamp')

    context = {
        'report': report,
        'sandbox_reports': sandbox_reports,
    }

    return render(
        request,
        'bank/view_apk_report_detail.html',
        context
    )


def bank_network_monitoring_dashboard(request):
    try:
        bank = Bank.objects.get(auth_user=request.user)
    except Bank.DoesNotExist:
        return render(
            request,
            'bank/network_monitoring.html',
            {
                'error': (
                    'Bank profile not found. '
                    'Please log in using your bank account.'
                ),
                'reports': [],
            }
        )

    # Only logs belonging to users registered under this bank
    bank_logs = NetworkLog.objects.filter(
        user__bank=bank
    ).select_related(
        'user',
        'user__bank'
    ).order_by('-created_at')

    search_query = request.GET.get('q', '').strip()
    selected_status = request.GET.get('status', '').strip()
    selected_action = request.GET.get('action', '').strip()

    if search_query:
        bank_logs = bank_logs.filter(
            Q(client_ip__icontains=search_query)
            | Q(route__icontains=search_query)
            | Q(status__icontains=search_query)
            | Q(action_taken__icontains=search_query)
            | Q(user__full_name__icontains=search_query)
        )

    if selected_status:
        bank_logs = bank_logs.filter(status=selected_status)

    if selected_action:
        bank_logs = bank_logs.filter(action_taken=selected_action)

    # Bank-specific summary values
    logs = NetworkLog.objects.filter(user__bank=bank)

    context = {
        'bank': bank,
        'reports': bank_logs[:500],
        'total_reports': logs.count(),
        'normal_count': logs.filter(status='Normal').count(),
        'suspicious_count': logs.filter(status='Suspicious').count(),
        'ddos_count': logs.filter(status='DDoS Detected').count(),
        'blocked_count': logs.filter(action_taken='Blocked').count(),
        'allowed_count': logs.filter(action_taken='Allowed').count(),
        'pending_count': logs.filter(status='Pending').count(),
        'search_query': search_query,
        'selected_status': selected_status,
        'selected_action': selected_action,
    }

    return render(
        request,
        'bank/network_monitoring.html',
        context
    )