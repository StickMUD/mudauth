"""Loopback HTTP client for a mudauth service.

Games that cannot speak HTTP natively (LPC, for example) call this from
whatever host-language bridge they have. Anything that *can* speak HTTP can
ignore this module and follow docs/protocol.md directly.

When AUTH_SERVICE_TOKEN is set in the game's own environment, every request
carries it in X-Auth-Service-Token, which is how the service tells this game
apart from a browser once that check is enabled -- see server.py's
_is_trusted_loopback and docs/deploy.md for the required migration order.
"""

from __future__ import annotations

import logging
import os
import re
import urllib.error
import urllib.request

DEFAULT_BASE_URL = os.environ.get("AUTH_SERVICE_URL", "http://127.0.0.1:7700")

# Header carrying the shared secret that identifies this game to the auth
# service as trusted-loopback, once AUTH_SERVICE_TOKEN is configured (see
# server.py's _is_trusted_loopback). Must match server.py's
# AUTH_SERVICE_TOKEN_HEADER.
AUTH_SERVICE_TOKEN_HEADER = "X-Auth-Service-Token"

# secrets.token_urlsafe (the generator the docs recommend) only ever emits
# this charset. Anything else -- notably a stray \n or \r from a copy-paste
# into .env -- is not a token this client should send: putheader() would
# reject it anyway, and its ValueError embeds the whole value.
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")

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
    # Read at call time, not at import, so a test can set/unset it around a
    # single request and so an operator does not need a specific process
    # start order for this module vs. the environment.
    token = (os.environ.get("AUTH_SERVICE_TOKEN") or "").strip()
    if token:
        if _SAFE_TOKEN_RE.match(token):
            headers[AUTH_SERVICE_TOKEN_HEADER] = token
        else:
            _logger.warning(
                "AUTH_SERVICE_TOKEN contains characters outside a token's "
                "expected charset; omitting %s on this request",
                AUTH_SERVICE_TOKEN_HEADER,
            )
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
    except ValueError as exc:
        # http.client.putheader raises ValueError("Invalid header value %r" %
        # value) on a header it rejects, embedding the whole value -- which
        # could be the token itself despite the charset check above (e.g.
        # some other header). Log only the exception type, not its text, so a
        # rejected header value never reaches the log.
        _logger.warning("mudauth client %s %s failed: %s", method, path, type(exc).__name__)
        return {"status": 0, "body": type(exc).__name__}
    except Exception as exc:  # noqa: BLE001 — transport failure of any kind
        _logger.warning("mudauth client %s %s failed: %s", method, path, exc)
        return {"status": 0, "body": str(exc)}
