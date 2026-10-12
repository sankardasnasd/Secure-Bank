"""
SecureBank rule-based transaction fraud detection.

Place this file at:
    myapp/fraud_detection.py

This module only calculates a risk score. It does not move money,
create database records, or send email. Call it from views.py.
"""

from datetime import timedelta
from decimal import Decimal

from django.db.models import QuerySet
from django.utils import timezone

from .models import BankTransaction


# Prototype thresholds; tune these for your project.
FRAUD_RISK_THRESHOLD = 50
FRAUD_BLOCK_THRESHOLD = 70


def calculate_transaction_risk(sender_account, amount):
    """
    Return (risk_score, reasons).

    Rules:
      1. Unusually large transfer compared with the sender's last 10
         successful transfers: +40 points.
      2. Four or more successful transfers in the previous 10 minutes:
         +35 points for the next transfer.
      3. Transfer between 00:00 and 03:59 local time: +20 points.

    `amount` should be a positive Decimal.
    """
    amount = Decimal(str(amount))
    risk_score = 0
    reasons = []

    # Rule 1: compare against the sender's recent successful transfers.
    previous_amounts = list(
        BankTransaction.objects.filter(
            sender_account=sender_account,
            transaction_type="Transfer",
            status="Success",
        )
        .order_by("-created_at")
        .values_list("amount", flat=True)[:10]
    )

    if previous_amounts:
        average_amount = sum(
            previous_amounts, Decimal("0.00")
        ) / Decimal(len(previous_amounts))

        comparison_threshold = max(
            average_amount * Decimal("3"),
            Decimal("50000.00"),
        )

        if amount > comparison_threshold:
            risk_score += 40
            reasons.append(
                f"Unusually large amount: ₹{amount:.2f}; "
                f"comparison threshold: ₹{comparison_threshold:.2f}"
            )
    elif amount >= Decimal("100000.00"):
        risk_score += 40
        reasons.append(
            "High-value transfer from an account with no previous "
            "successful transfer history (₹100,000 or more)"
        )

    # Rule 2: frequency in the previous 10 minutes.
    now = timezone.now()
    window_start = now - timedelta(minutes=10)

    recent_count = BankTransaction.objects.filter(
        sender_account=sender_account,
        transaction_type="Transfer",
        status="Success",
        created_at__gte=window_start,
    ).count()

    if recent_count >= 4:
        risk_score += 35
        reasons.append(
            f"High transaction frequency: at least "
            f"{recent_count + 1} transfers in a 10-minute window"
        )

    # Rule 3: unusual local time.
    local_hour = timezone.localtime(now).hour
    if 0 <= local_hour < 4:
        risk_score += 20
        reasons.append(
            "Transfer initiated during unusual hours (00:00–03:59)"
        )

    return min(risk_score, 100), reasons


def classify_transaction_risk(risk_score):
    """
    Return (status, is_fraud) using the project's model choices.

    Scores below 50 -> Success, 50–69 -> Suspicious,
    70+ -> Blocked.
    """
    if risk_score >= FRAUD_BLOCK_THRESHOLD:
        return "Blocked", "Yes"
    if risk_score >= FRAUD_RISK_THRESHOLD:
        return "Suspicious", "Yes"
    return "Success", "No"
