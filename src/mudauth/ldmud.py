"""LDMud python-efun registration (``pip install "mudauth[ldmud]"``).

Registered via the ``ldmud_efun`` entry point as ``auth_service_request``::

    string auth_service_request(string method, string path, string body)

Returns a JSON string ``{"status": int, "body": string}``. Never raises to
LPC; transport errors return status 0.
"""

import json

from . import client


def auth_service_request(method: str, path: str, body: str = "") -> str:
    m = (method or "GET").upper()
    if m not in ("GET", "POST"):
        return json.dumps({"status": 0, "body": f"unsupported method {method}"})
    return json.dumps(client.request(m, path or "/", body if isinstance(body, str) else ""))
