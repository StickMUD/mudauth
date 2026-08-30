"""Loopback HTTP client for a mudauth service.

Games that cannot speak HTTP natively (LPC, for example) call this from
whatever host-language bridge they have. Anything that *can* speak HTTP can
ignore this module and follow docs/protocol.md directly.
"""

from __future__ import annotations

import logging
import os
import urllib.error
import urllib.request

DEFAULT_BASE_URL = os.environ.get("AUTH_SERVICE_URL", "http://127.0.0.1:7700")

_logger = logging.getLogger(__name__)


def request(
    method: str,
    path: str,
    body: str | None = None,
    *,
    base_url: str | None = None,
    timeout: float = 10,
) -> dict:
    """Perform one request and return ``{"status": int, "body": str}``.

    Non-2xx responses are returned with their status (they are normal protocol
    outcomes: 404 unknown provider, 400 bad state). Transport failures — service
    down, timeout — return status 0 with the error text so callers can degrade
    to password login instead of raising.
    """
    if not path.startswith("/"):
        path = "/" + path
    url = (base_url or DEFAULT_BASE_URL).rstrip("/") + path
    method = method.upper()

    data = None
    headers = {"Accept": "application/json"}
    if method == "POST":
        data = (body or "{}").encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"status": resp.status, "body": resp.read().decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return {"status": exc.code, "body": text}
    except Exception as exc:  # noqa: BLE001 — transport failure of any kind
        _logger.warning("mudauth client %s %s failed: %s", method, path, exc)
        return {"status": 0, "body": str(exc)}
