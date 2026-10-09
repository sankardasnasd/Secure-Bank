
import logging
import requests

from django.conf import settings
from django.http import JsonResponse


logger = logging.getLogger(__name__)


class NetworkMonitoringMiddleware:
    """
    Monitors Django HTTP requests using the local network monitor service.

    Place this middleware after Django AuthenticationMiddleware so
    request.user is available.
    """

    EXCLUDED_PREFIXES = (
        "/static/",
        "/media/",
        "/favicon.ico",
        "/health/",
    )

    def __init__(self, get_response):
        self.get_response = get_response
        self.monitor_url = getattr(
            settings,
            "NETWORK_MONITOR_URL",
            "http://127.0.0.1:5001",
        ).rstrip("/")
        self.monitor_token = getattr(
            settings,
            "NETWORK_MONITOR_TOKEN1",
            "",
        )

    def __call__(self, request):
        path = request.path

        if (
            not self.monitor_token
            or path.startswith(self.EXCLUDED_PREFIXES)
        ):
            return self.get_response(request)

        # Do not trust X-Forwarded-For unless it is configured by
        # a trusted reverse proxy.
        client_ip = request.META.get("REMOTE_ADDR", "")

        user_profile_id = None

        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated:
            try:
                user_profile_id = user.user_profile.pk
            except Exception:
                user_profile_id = None

        payload = {
            "client_ip": client_ip,
            "route": path,
            "user_profile_id": user_profile_id,
        }

        try:
            response = requests.post(
                f"{self.monitor_url}/monitor",
                json=payload,
                headers={
                    "X-Monitor-Token": self.monitor_token,
                },
                timeout=(0.2, 0.5),
            )

            if response.status_code == 200:
                result = response.json()

                if result.get("blocked") is True:
                    return JsonResponse(
                        {
                            "error": "Too many requests",
                            "detail": (
                                "Your requests temporarily exceeded "
                                "the configured rate limit."
                            ),
                        },
                        status=429,
                    )

            elif response.status_code == 403:
                logger.error(
                    "Network monitor rejected the configured token."
                )

        except (requests.RequestException, ValueError) as exc:
            # Fail open: application continues if monitoring is offline.
            logger.warning("Network monitor unavailable: %s", exc)

        return self.get_response(request)