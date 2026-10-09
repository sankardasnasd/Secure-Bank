
from django.contrib import admin
from django.urls import path,include

from myapp import views

urlpatterns = [
    path('public_home/', views.public_home),
    path('login_page/', views.login_page),
    path('logout_page/', views.logout_page),
    path('bank_register/', views.bank_register),

    path('admin_home/', views.admin_home),
    path('admin_home_sub/', views.admin_home_sub),
    path('manage_banks/', views.manage_banks),

    path('manage-banks/', views.manage_banks, name='manage_banks'),
    path('view_bank/<int:bank_id>/', views.view_bank, name='view_bank'),
    path('approve-bank/<int:bank_id>/', views.approve_bank, name='approve_bank'),
    path('reject-bank/<int:bank_id>/', views.reject_bank, name='reject_bank'),

    path('view_notifications/', views.view_notifications, name='view_notifications'),
    path('view_network_monitoring/', views.view_network_monitoring, name='view_network_monitoring'),
    path('view_threats/', views.view_threats, name='view_threats'),
    path('view_fraud_logs/', views.view_fraud_logs, name='view_fraud_logs'),
    path('view_transactions/', views.view_transactions, name='view_transactions'),
    path('view_accounts/', views.view_accounts, name='view_accounts'),
    path('admin_all_network_monitoring/', views.admin_all_network_monitoring, name='admin_all_network_monitoring'),

    path('view_users/', views.view_users, name='view_users'),
    path('unblock-user/<int:user_id>/', views.unblock_user, name='unblock_user'),



    path('bank_home/', views.bank_home, name='bank_home'),
    path('bank_profile/', views.bank_profile, name='bank_profile'),
    path('edit-profile/', views.edit_profile, name='edit_profile'),
    path('create_user/', views.create_user, name='create_user'),
    path('view_bank_users/', views.view_bank_users, name='view_bank_users'),
    path('delete_bank_user/<id>', views.delete_bank_user, name='delete_bank_user'),
    path('view_bank_accounts/', views.view_bank_accounts, name='view_bank_accounts'),
    path('view_bank_transactions/', views.view_bank_transactions, name='view_bank_transactions'),

    path('phishing_detection_api/', views.phishing_detection_api, name='phishing_detection_api'),
    path('phishing_detection/', views.phishing_detection, name='phishing_detection'),

    path('upload_and_sandbox_apk/', views.upload_and_sandbox_apk, name='upload_and_sandbox_apk'),
    path('view_apk_reports/',views.view_apk_reports,name='view_apk_reports'),

    path('view_apk_report_detail/<int:report_id>/',views.view_apk_report_detail,name='view_apk_report_detail'),
    path('bank_network_monitoring_dashboard/',views.bank_network_monitoring_dashboard,name='bank_network_monitoring_dashboard'),

]

