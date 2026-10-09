from django.conf import settings
from django.db import models
from django.core.validators import MinValueValidator
from decimal import Decimal
from django.contrib.auth.models import User


class Bank(models.Model):
    auth_user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='bank_profile')
    bank_name = models.CharField(max_length=200)
    bank_code = models.CharField(max_length=50, unique=True)
    ifsc_code = models.CharField(max_length=20)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    address = models.CharField(max_length=500)
    license_doc = models.FileField(upload_to='bank_licenses/', blank=True, null=True)
    status = models.CharField(max_length=20, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



class UserProfile(models.Model):
    STATUS_CHOICES = [('Pending', 'Pending'), ('Active', 'Active'), ('Blocked', 'Blocked'), ('Inactive', 'Inactive')]

    auth_user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user_profile')
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='users')
    full_name = models.CharField(max_length=200)
    email = models.EmailField()
    phone = models.CharField(max_length=20)
    address = models.CharField(max_length=500)
    profile_pic = models.FileField(upload_to='profile_pictures/', blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



class Account(models.Model):
    ACCOUNT_TYPE_CHOICES = [('Savings', 'Savings'), ('Current', 'Current')]
    STATUS_CHOICES = [('Pending', 'Pending'), ('Active', 'Active'), ('Blocked', 'Blocked'), ('Closed', 'Closed')]

    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, related_name='accounts')
    bank = models.ForeignKey(Bank, on_delete=models.CASCADE, related_name='accounts')
    account_number = models.CharField(max_length=30, unique=True)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPE_CHOICES, default='Savings')
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=Decimal('0.00'), validators=[MinValueValidator(Decimal('0.00'))])
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)



class BankTransaction(models.Model):
    TRANSACTION_TYPE_CHOICES = [('Transfer', 'Transfer'), ('Deposit', 'Deposit'), ('Withdrawal', 'Withdrawal')]
    STATUS_CHOICES = [('Pending', 'Pending'), ('Success', 'Success'), ('Failed', 'Failed'), ('Blocked', 'Blocked'), ('Suspicious', 'Suspicious')]
    FRAUD_CHOICES = [('Yes', 'Yes'), ('No', 'No')]

    sender_account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='sent_transactions')
    receiver_account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='received_transactions')
    transaction_ref = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=15, decimal_places=2, validators=[MinValueValidator(Decimal('0.01'))])
    transaction_type = models.CharField(max_length=20, choices=TRANSACTION_TYPE_CHOICES, default='Transfer')
    description = models.CharField(max_length=500, blank=True, null=True)
    is_fraud = models.CharField(max_length=3, choices=FRAUD_CHOICES, default='No')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)



class FraudLog(models.Model):
    STATUS_CHOICES = [('Pending', 'Pending'), ('Reviewed', 'Reviewed'), ('Confirmed', 'Confirmed'), ('False Positive', 'False Positive')]

    transaction = models.ForeignKey(BankTransaction, on_delete=models.CASCADE, related_name='fraud_logs')
    risk_score = models.IntegerField(default=0)
    reason = models.CharField(max_length=1000)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)



class PhishingURLLog(models.Model):
    PREDICTION_CHOICES = [('Phishing', 'Phishing'), ('Safe', 'Safe')]
    RISK_LEVEL_CHOICES = [('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')]
    STATUS_CHOICES = [('Pending', 'Pending'), ('Completed', 'Completed'), ('Failed', 'Failed')]

    source_transaction = models.ForeignKey(BankTransaction, on_delete=models.SET_NULL, blank=True, null=True, related_name='phishing_logs')
    reported_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='phishing_reports')
    url = models.URLField(max_length=2000)
    prediction = models.CharField(max_length=20, choices=PREDICTION_CHOICES, default='Safe')
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default='Low')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)





class MalwareScanLog(models.Model):

    SCAN_RESULT_CHOICES = [
        ('Clean', 'Clean'),
        ('Suspicious', 'Suspicious'),
        ('Malicious', 'Malicious'),
    ]

    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
    ]

    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='malware_scans'
    )

    apk_file = models.FileField(upload_to='apk_files/')
    file_hash = models.CharField(max_length=64, blank=True, default='')

    scan_result = models.CharField(
        max_length=20,
        choices=SCAN_RESULT_CHOICES,
        default='Suspicious'
    )

    confidence_score = models.CharField(
        max_length=20,
        default='0.0%'
    )

    prediction_result = models.TextField(blank=True, default='')
    reason = models.TextField(blank=True, default='')

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='Pending'
    )

    created_at = models.DateTimeField(auto_now_add=True)




class Sandbox_table(models.Model):

    APK = models.ForeignKey(
        MalwareScanLog,
        on_delete=models.CASCADE,
        related_name='sandbox_reports'
    )

    sandbox_status = models.CharField(max_length=255)
    behaviour_summary = models.TextField()
    executed_on_server = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)





class NetworkLog(models.Model):
    ACTION_CHOICES = [('Allowed', 'Allowed'), ('Blocked', 'Blocked')]
    STATUS_CHOICES = [('Pending', 'Pending'), ('Normal', 'Normal'), ('Suspicious', 'Suspicious'), ('DDoS Detected', 'DDoS Detected')]

    user = models.ForeignKey(UserProfile, on_delete=models.SET_NULL, blank=True, null=True, related_name='network_logs')
    client_ip = models.GenericIPAddressField()
    route = models.CharField(max_length=500)
    request_count = models.PositiveIntegerField(default=0)
    action_taken = models.CharField(max_length=20, choices=ACTION_CHOICES, default='Allowed')
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)




class Notification(models.Model):
    NOTIFY_TYPE_CHOICES = [('Fraud Alert', 'Fraud Alert'), ('Phishing Alert', 'Phishing Alert'), ('Malware Alert', 'Malware Alert'), ('Network Alert', 'Network Alert'), ('General', 'General')]
    STATUS_CHOICES = [('Pending', 'Pending'), ('Read', 'Read')]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    message = models.CharField(max_length=1000)
    notify_type = models.CharField(max_length=30, choices=NOTIFY_TYPE_CHOICES, default='General')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)






