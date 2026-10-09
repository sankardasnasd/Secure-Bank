# Secure-Bank
The system uses Django for user management and the interface, Spring Cloud Gateway and Eureka to route phishing and malware detection requests, and MySQL to store data and logs. A sandboxed network monitoring service detects DDoS attacks, blocks suspicious users, and alerts 
# SecureBank — AI-Powered Banking Security Platform

## 1. Project Overview

SecureBank is an AI-powered banking security platform developed using Django, Spring Cloud, FastAPI, Machine Learning, and MySQL. It combines phishing URL detection, Android APK malware analysis, network traffic monitoring, and automated security responses in a single web application.

Django serves as the main application and user interface for Admin, Bank, and User modules. Spring Cloud Gateway routes phishing detection requests to the FastAPI service, where a trained Random Forest model classifies URLs. A separate sandbox processes APK scans, while the Network Monitoring Service identifies excessive request activity and supports automated blocking.

The platform stores detection results and security incidents in MySQL and displays results through the main Django application.

## 2. Project Objectives

* Detect phishing URLs using a trained Machine Learning model.
* Classify URLs as phishing or legitimate.
* Analyse uploaded Android APK files for potential malware.
* Monitor request patterns and detect DDoS-like behaviour.
* Automatically block users when configured security thresholds are exceeded.
* Check URLs contained in transaction remarks.
* Store phishing, malware, and network incident logs.
* Notify administrators through SMTP email.
* Provide a centralized interface for banking and security management.

## 3. Technologies Used

| Technology                    | Purpose                                        |
| ----------------------------- | ---------------------------------------------- |
| Python 3.10                   | Backend and ML service runtime                 |
| Django                        | Main web application                           |
| Django ORM                    | Database operations                            |
| MySQL                         | Persistent storage                             |
| FastAPI                       | Phishing detection API                         |
| Uvicorn                       | FastAPI server                                 |
| Java                          | Spring Cloud services                          |
| Spring Boot                   | Gateway application                            |
| Spring Cloud Gateway          | API routing                                    |
| Netflix Eureka                | Service registration and discovery, if enabled |
| Random Forest                 | Phishing URL classification                    |
| PhiUSIIL Phishing URL Dataset | Model training data                            |
| Pandas                        | Dataset processing                             |
| Scikit-learn                  | ML training and evaluation                     |
| Joblib                        | Model persistence                              |
| HTML, CSS, JavaScript         | Frontend                                       |
| Bootstrap                     | Responsive interface                           |
| SMTP                          | Email notifications                            |
| Sandbox environment           | APK analysis and isolated processing           |

## 4. System Architecture

```text
                     WEB BROWSER
                          |
                          v
                +---------------------+
                | Django Application  |
                |    Port 8000        |
                +---------------------+
                          |
              +-----------+-----------+
              |           |           |
              v           v           v
            Admin        Bank        User
              |
              v
       Phishing Detection Request
              |
              v
       +---------------------+
       | Spring Cloud Gateway|
       +---------------------+
              |
              v
       +---------------------+
       | FastAPI Service     |
       |    Port 8001        |
       +---------------------+
              |
              v
       +---------------------+
       | Random Forest Model |
       +---------------------+
              |
              v
       Prediction Returned to Django


       APK UPLOAD WORKFLOW
              |
              v
       Django Application
              |
              v
       Malware Sandbox
        Port 5000
              |
              v
       APK Scan Verdict
              |
              v
       Django Application


       NETWORK MONITORING
              |
              v
       Django Monitoring Hook
              |
              v
       Network Monitoring Service
              |
              v
       Request Threshold Analysis
              |
              v
       Django Blocking Policy
              |
              +----> Network_log
              |
              +----> Admin Email Alert


              MYSQL DATABASE
       Users, Accounts, Transactions,
          Detection Results, Logs
```

This diagram represents the logical architecture. Actual service endpoints and communication methods depend on the implementation and configuration.

### Architecture Components

**Django Application:** Handles authentication, banking-related functionality, requests, database operations, security logs, and result presentation.

**Spring Cloud Gateway:** Routes phishing detection requests to the appropriate backend service.

**Eureka Service Registry:** Provides service registration and discovery when configured. If the Gateway depends on Eureka, start the registry before starting the Gateway.

**FastAPI Phishing Service:** Exposes the trained machine-learning model through an HTTP API.

**Malware Sandbox:** Analyses uploaded APK files using the implemented scanning process.

**Network Monitoring Service:** Analyses request metadata and identifies excessive traffic patterns.

**MySQL:** Stores application records and detection logs.

All detection results are returned to Django and displayed through the main application on port `8000`. The backend services do not require separate user interfaces.

## 5. Main Application Modules

### 5.1 Admin Module

The Admin module provides centralized application and security management.

Features:

* Manage registered users.
* Review banking and account information.
* View phishing detection results.
* Review APK scan verdicts.
* Monitor network incidents.
* Inspect security logs.
* Receive email alerts.
* Review and manage blocked users.

### 5.2 Bank Module

The Bank module provides banking-related functionality.

Features:

* Access banking information.
* Manage supported banking operations.
* View transaction records.
* Process transaction remarks containing URLs.
* Submit suspicious links for phishing analysis.
* Review transaction-related security information.

### 5.3 User Module

The User module provides the user-facing interface.

Features:

* Register and log in.
* Access permitted banking functionality.
* Submit URLs for phishing detection.
* Upload APK files for scanning.
* View detection results.
* Receive access restrictions if blocked.

## 6. Phishing URL Detection Module

### Overview

The Phishing URL Detection Module uses a trained Random Forest classifier to predict whether a submitted URL is phishing or legitimate.

**Dataset:** PhiUSIIL Phishing URL Dataset.

**API framework:** FastAPI.

**Server:** Uvicorn.

**Port:** `8001`.

### Workflow

1. The user submits a URL through Django.
2. Django forwards the request to Spring Cloud Gateway.
3. The Gateway routes the request to FastAPI.
4. The service processes the URL using the required feature extraction pipeline.
5. The Random Forest model predicts the classification.
6. The API returns the prediction to Django.
7. Django stores the result in `Phishing_url_log`.
8. The result appears in the Django interface.

### Expected Output

* Submitted URL.
* Predicted classification.
* Risk or confidence score, if implemented.
* Detection timestamp.
* Associated user or transaction reference, if applicable.

### Machine Learning Workflow

```text
PhiUSIIL Dataset
       |
       v
Data Preparation
       |
       v
Feature Extraction
       |
       v
Model Training and Evaluation
       |
       v
Random Forest Classifier
       |
       v
Saved Model
       |
       v
FastAPI Prediction API
       |
       v
Spring Cloud Gateway
       |
       v
Django Result Display
```

The same feature extraction and preprocessing steps used during model training must be used during prediction. Model predictions are estimates and should not be treated as guarantees of safety.

### Required Packages

```cmd
py -3.10 -m pip install fastapi uvicorn joblib pandas scikit-learn
```

## 7. Android APK Malware Detection Module

The Malware Detection Module accepts APK uploads through Django and submits them to the configured sandbox.

### Workflow

1. The user uploads an APK file.
2. Django validates the file.
3. The application submits the APK to the malware sandbox.
4. The sandbox performs the configured analysis.
5. The service returns a scan verdict.
6. Django stores the result in `Malware_scan_log`.
7. The result is displayed through the Django application.

### Expected Output

* APK filename or identifier.
* Scan status.
* Verdict, such as malicious or benign.
* Confidence score, if supported.
* Scan timestamp.

APK files must be treated as untrusted input. Use suitable isolation, file validation, resource limits, and execution restrictions. A benign verdict does not guarantee that an APK is completely safe.

## 8. Network Monitoring and DDoS Detection

The Network Monitoring Service runs independently from the phishing and malware detection services.

A lightweight Django monitoring hook forwards relevant request metadata to the monitoring process.

### Request Metadata

* User identifier.
* Client IP address.
* Requested route.
* Request timestamp.

### Detection Workflow

1. Django captures request metadata.
2. The monitoring hook forwards the metadata to the Network Monitoring Service.
3. The service counts requests within a configured time window.
4. The count is compared against the configured threshold.
5. Excessive activity is flagged as suspicious.
6. Django applies the configured blocking policy.
7. The incident is stored in `Network_log`.
8. An SMTP email alert is sent to the administrator.

Excessive request activity may indicate abusive behaviour, but a threshold breach alone does not prove that a distributed denial-of-service attack has occurred. Legitimate traffic bursts and shared IP addresses should be considered to reduce false positives.

### Automated User Blocking

When the configured policy requires blocking:

1. Django updates the relevant user's blocked status.
2. Middleware or equivalent request validation denies subsequent requests.
3. The incident is recorded.
4. The administrator can review the incident and manage the account.

Provide appropriate recovery and logout routes to avoid locking users out permanently.

## 9. Transaction Remark Link Checking

Transaction remarks may contain URLs associated with phishing attempts.

The application can reuse the phishing detection service to analyse these URLs.

1. Django processes a transaction remark.
2. The application extracts the URL.
3. The URL is submitted for phishing analysis.
4. The service returns its prediction.
5. Django records the result.
6. The result can be associated with the relevant transaction or security log.

## 10. Email Notifications

SecureBank can use SMTP to notify administrators about security incidents.

Possible alert details:

* Incident type.
* Affected user identifier.
* Client IP address.
* Detection timestamp.
* Reason for the alert.
* Incident log reference.

Configure SMTP credentials securely through environment variables. Never commit email passwords or authentication tokens to GitHub.

## 11. Database Design

SecureBank uses MySQL with Django ORM.

| Table                          | Responsibility                           |
| ------------------------------ | ---------------------------------------- |
| User and authentication tables | User accounts and authentication         |
| Bank-related tables            | Banking information                      |
| Account-related tables         | Account records                          |
| Transaction-related tables     | Transaction records and remarks          |
| `Phishing_url_log`             | Phishing detection results               |
| `Malware_scan_log`             | APK malware scan results                 |
| `Network_log`                  | Suspicious traffic and network incidents |

The actual table names, fields, and relationships must match the Django models and migrations in the project.

## 12. Suggested Project Structure

```text
SECUREBANK/
│
├── manage.py
├── requirements.txt
├── README.md
│
├── phishing-service/
│   └── phishing_api.py
│
├── spring-cloud/
│   └── url-security-gateway/
│       ├── pom.xml
│       └── src/
│
├── myapp/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── middleware.py
│   ├── network_monitor.py
│   └── templates/
│
├── run_sandbox.py
├── static/
└── media/
```

This is a suggested structure based on the known project paths. The actual directory layout may differ.

---

# 13. Installation and Initial Setup

## Prerequisites

Install the following:

* Python 3.10.
* Django and the project's Python dependencies.
* Java Development Kit compatible with the Spring Boot project.
* Maven.
* MySQL Server.
* Git.
* The trained phishing model and required feature-processing files.

### Step 1: Clone the Repository

```cmd
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SECUREBANK
```

Replace the placeholder with the actual GitHub repository URL.

### Step 2: Install Python Dependencies

Install the phishing service packages:

```cmd
py -3.10 -m pip install fastapi uvicorn joblib pandas scikit-learn
```

Install the Django dependencies:

```cmd
py -3.10 -m pip install -r requirements.txt
```

If the phishing service has a separate requirements file, install its dependencies as well.

### Step 3: Configure MySQL

Create the database:

```sql
CREATE DATABASE securebank_db;
```

Configure the Django database settings with the correct database name, username, password, host, and port.

Example environment variables:

```env
DB_NAME=securebank_db
DB_USER=your_mysql_username
DB_PASSWORD=your_mysql_password
DB_HOST=127.0.0.1
DB_PORT=3306
```

These are example variable names; your Django settings must read the same names.

### Step 4: Apply Django Migrations

From the main project directory:

```cmd
py -3.10 manage.py makemigrations
py -3.10 manage.py migrate
```

### Step 5: Create an Administrator

```cmd
py -3.10 manage.py createsuperuser
```

Follow the prompts to create an administrator account.

---

# 14. Daily Startup Guide — Five CMD Windows

After closing all terminals, use these commands whenever you want to run SecureBank again.

**Important:** Each service must run in its own terminal. Do not close a terminal while you are using the corresponding service.

## CMD 1 — Phishing URL Detection Service

The Phishing Service is located inside the main SecureBank project directory.

Open CMD 1 and run:

```cmd
cd /d C:\Users\GAYATHRI\PycharmProjects\SECUREBANK\phishing-service
```

Start the FastAPI application:

```cmd
py -3.10 -m uvicorn phishing_api:app --host 127.0.0.1 --port 8001
```

**Service:** Phishing URL Detection API.

**Port:** `8001`.

This service loads the trained model and processes URL classification requests.

Keep this terminal running.

## CMD 2 — Spring Cloud URL Security Gateway

Open CMD 2 and run:

```cmd
cd /d C:\Users\GAYATHRI\PycharmProjects\SECUREBANK\spring-cloud\url-security-gateway
```

Start Spring Boot:

```cmd
mvn spring-boot:run
```

**Service:** Spring Cloud URL Security Gateway.

The port is configured in the Spring Boot application.

If the Gateway requires a separate Eureka registry, start Eureka before this command.

Keep this terminal running.

## CMD 3 — Django Application

Open CMD 3 and run:

```cmd
cd /d C:\Users\GAYATHRI\PycharmProjects\SECUREBANK
```

Start Django:

```cmd
py -3.10 manage.py runserver
```

Open the application:

**http://localhost:8000/**

This is the main interface for the Admin, Bank, and User modules. Detection results are displayed through this application.

Keep this terminal running.

## CMD 4 — Network Monitoring Service

Open CMD 4 and navigate to the main project directory:

```cmd
cd /d C:\Users\GAYATHRI\PycharmProjects\SECUREBANK
```

Set the monitoring authentication token:

```cmd
set NETWORK_MONITOR_TOKEN=YOUR_NETWORK_MONITOR_TOKEN
```

Start Network Monitoring:

```cmd
py -3.10 -m myapp.network_monitor
```

**Service:** Network Monitoring.

The service analyses request activity and supports incident logging, configured user blocking, and administrator alerts.

The `set` command applies only to the current CMD session. Use the same secret configured on the Django and monitoring sides. Never publish the actual token in a public repository.

Keep this terminal running.

## CMD 5 — Malware Detection Sandbox

Open CMD 5 in the directory containing `run_sandbox.py`.

If it is located in the main project directory, run:

```cmd
cd /d C:\Users\GAYATHRI\PycharmProjects\SECUREBANK
```

Start the sandbox:

```cmd
py -3.10 run_sandbox.py 5000
```

**Port:** `5000`.

This starts the configured APK analysis environment. Django must be configured to communicate with the correct sandbox endpoint.

Keep this terminal running.

## Daily Startup Summary

| Terminal | Component                  | Port                      |
| -------- | -------------------------- | ------------------------- |
| CMD 1    | FastAPI Phishing Detection | 8001                      |
| CMD 2    | Spring Cloud Gateway       | Configured in Spring Boot |
| CMD 3    | Django Application         | 8000                      |
| CMD 4    | Network Monitoring         | Configured in the service |
| CMD 5    | Malware Detection Sandbox  | 5000                      |

### Daily Startup Checklist

* [ ] Start the Phishing Detection API.
* [ ] Start the Spring Cloud Gateway.
* [ ] Start the Django application.
* [ ] Set the monitoring token and start Network Monitoring.
* [ ] Start the Malware Detection Sandbox.
* [ ] Open `http://localhost:8000/`.
* [ ] Test phishing URL detection.
* [ ] Test APK malware scanning.
* [ ] Test network monitoring and email alerts.

**Startup note:** If Eureka is a separate required service, it must also be running. The five-terminal guide assumes the current configuration does not require another separately started process. If a service fails to start, check the terminal output and confirm that its dependencies, ports, and endpoints are configured correctly.

---

# 15. Testing Guide

## Test Phishing Detection

1. Open SecureBank in the browser.
2. Navigate to the phishing detection feature.
3. Submit a test URL.
4. Confirm that Django sends the request through the Gateway.
5. Confirm that FastAPI returns a prediction.
6. Verify the result in the Django interface.
7. Confirm that a record is written to `Phishing_url_log`.

## Test APK Malware Detection

1. Open the APK upload feature.
2. Upload an authorized test APK.
3. Confirm that the sandbox receives the request.
4. Verify that the scan process returns a verdict.
5. Confirm that the result appears in Django.
6. Check `Malware_scan_log`.

## Test Network Monitoring

1. Start the monitoring service.
2. Generate controlled test requests.
3. Verify that requests are counted within the configured time window.
4. Check whether the threshold triggers the expected incident.
5. Verify the configured blocking policy.
6. Confirm the `Network_log` record.
7. Confirm that the administrator receives an email alert.

Use a controlled test environment and ensure recovery access is available before testing automatic blocking.

---

# 16. Troubleshooting

### Phishing API Does Not Start

Check the Python version:

```cmd
py -3.10 --version
```

Install missing dependencies:

```cmd
py -3.10 -m pip install fastapi uvicorn joblib pandas scikit-learn
```

Confirm that `phishing_api.py` exists in the `phishing-service` directory and that the application object is named `app`.

### Port 8001 Is Already in Use

Another process may be using port `8001`. Stop the previous service or configure a different port and update the Gateway endpoint accordingly.

### Spring Cloud Gateway Does Not Start

Check that Maven and the required Java version are installed:

```cmd
java -version
mvn -version
```

Review the Spring Boot logs for dependency, port, routing, or service-discovery errors.

### Django Does Not Start

Run:

```cmd
py -3.10 manage.py check
```

Confirm that MySQL is running, database settings are correct, and migrations have been applied.

### Network Monitoring Does Not Work

Check that:

* The monitoring process is running.
* `NETWORK_MONITOR_TOKEN` is set in its terminal.
* Django uses the same configured token.
* The monitoring endpoint and port are correct.
* The request hook forwards the expected metadata.
* The service is configured to record and report incidents.

### Malware Sandbox Does Not Start

Confirm that `run_sandbox.py` exists in the selected directory, its required dependencies are installed, and port `5000` is available.

Verify that the Django endpoint matches the actual sandbox implementation.

### Detection Results Are Not Displayed

Check:

* The Django terminal logs.
* The Gateway routing configuration.
* The FastAPI terminal output.
* The malware sandbox output.
* The configured service URLs.
* Database connectivity and the corresponding log tables.

---

# 17. Security Considerations

* Do not commit passwords, API tokens, SMTP credentials, or database secrets.
* Use environment variables for sensitive configuration.
* Validate URLs and uploaded files.
* Limit upload sizes and request processing time.
* Isolate untrusted APK files.
* Restrict access to administrative functionality.
* Protect service-to-service communication with appropriate authentication.
* Apply rate limiting and request validation.
* Keep security logs without storing unnecessary sensitive data.
* Provide a safe recovery process for blocked users.
* Use HTTPS and appropriate production settings when deploying publicly.
* Do not expose internal detection services unnecessarily.

The example monitoring token should be replaced with a private value in the local environment. Never publish a working token in a public GitHub repository.

## 18. Future Enhancements

Potential future improvements include:

* Additional phishing detection features.
* More detailed APK static and dynamic analysis.
* Improved network anomaly detection.
* IP-based and distributed request aggregation.
* Centralized security dashboards and reporting.
* Historical security analytics.
* More comprehensive transaction risk analysis.
* Model evaluation and retraining workflows.
* Role-based permissions and improved audit trails.
* Containerized deployment and centralized service monitoring.

## 19. Conclusion

SecureBank combines a Django banking application with independent detection services to support phishing URL classification, APK malware analysis, network monitoring, and automated security responses.

The integration of FastAPI, Random Forest, Spring Cloud Gateway, MySQL, and Django provides a modular architecture in which detection results are returned to the main application for display and logging.

The project demonstrates how web development, machine learning, microservices, database management, and network security monitoring can be integrated into a centralized banking security platform.




