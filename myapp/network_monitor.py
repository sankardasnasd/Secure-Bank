
import json
import os
import time
import threading
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import django


# Change SECUREBANK if your Django settings package has another name.
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "SECUREBANK.settings")
django.setup()

from django.conf import settings
from django.db import close_old_connections
from myapp.models import NetworkLog, UserProfile


HOST = "127.0.0.1"
PORT = 5001

WINDOW_SECONDS = int(
    getattr(settings, "NETWORK_MONITOR_WINDOW_SECONDS", 60)
)
MAX_REQUESTS = int(
    getattr(settings, "NETWORK_MONITOR_MAX_REQUESTS", 100)
)
TOKEN = os.environ.get("NETWORK_MONITOR_TOKEN1", "")

# In-memory counters: suitable for a local learning prototype only.
request_times = defaultdict(deque)
counter_lock = threading.Lock()


def inspect_request(client_ip):
    """Count requests from one IP in the configured time window."""
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS

    with counter_lock:
        timestamps = request_times[client_ip]

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        timestamps.append(now)
        count = len(timestamps)

    if count > MAX_REQUESTS:
        return count, "DDoS Detected", "Blocked"

    if count > int(MAX_REQUESTS * 0.7):
        return count, "Suspicious", "Allowed"

    return count, "Normal", "Allowed"


class MonitorHandler(BaseHTTPRequestHandler):

    def send_json(self, status_code, data):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/status":
            self.send_json(200, {
                "status": "ONLINE",
                "service": "SECUREBANK Network Monitor",
                "window_seconds": WINDOW_SECONDS,
                "max_requests": MAX_REQUESTS,
            })
        else:
            self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        close_old_connections()

        try:
            if self.path != "/monitor":
                self.send_json(404, {"error": "Not found"})
                return

            if not TOKEN or self.headers.get("X-Monitor-Token") != TOKEN:
                self.send_json(403, {"error": "Invalid monitor token"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))

            if content_length <= 0 or content_length > 16384:
                self.send_json(400, {"error": "Invalid request size"})
                return

            data = json.loads(
                self.rfile.read(content_length).decode("utf-8")
            )

            client_ip = str(data.get("client_ip", "")).strip()
            route = str(data.get("route", "/"))[:500]
            user_profile_id = data.get("user_profile_id")

            # Validate IP using Django's field validation.
            from django.core.exceptions import ValidationError
            from django.core.validators import validate_ipv46_address

            try:
                validate_ipv46_address(client_ip)
            except ValidationError:
                self.send_json(400, {"error": "Invalid client IP"})
                return

            count, status, action = inspect_request(client_ip)

            profile = None
            if user_profile_id is not None:
                try:
                    profile = UserProfile.objects.filter(
                        pk=int(user_profile_id)
                    ).first()
                except (TypeError, ValueError):
                    profile = None

            NetworkLog.objects.create(
                user=profile,
                client_ip=client_ip,
                route=route,
                request_count=count,
                status=status,
                action_taken=action,
            )

            self.send_json(200, {
                "request_count": count,
                "status": status,
                "action_taken": action,
                "blocked": action == "Blocked",
            })

        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid JSON"})
        except Exception:
            # Do not expose database errors or internal details.
            self.send_json(500, {"error": "Monitoring failed"})
        finally:
            close_old_connections()

    def log_message(self, format_string, *args):
        # Keep the standard HTTP server from logging every request.
        return


if __name__ == "__main__":
    if not TOKEN:
        raise RuntimeError(
            "Set NETWORK_MONITOR_TOKEN before starting the monitor."
        )

    server = ThreadingHTTPServer((HOST, PORT), MonitorHandler)
    print(f"Network monitor running at http://{HOST}:{PORT}")
    print(f"Request window: {WINDOW_SECONDS}s; limit: {MAX_REQUESTS}")
    server.serve_forever()