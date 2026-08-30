"""mudauth — standalone HTTP listener for provider login
(OIDC, OAuth2, and Steam's OpenID 2.0).

A small, long-lived service (stdlib ``http.server``) that owns only the OAuth
``state`` (CSRF) map and the completed-login map keyed by a client-generated
``login_nonce``. It is *stateless* with respect to accounts: there is no
database. It verifies a provider identity and hands the verified
``(provider, provider_id, username)`` back to the MUD, which owns all account
and character data. The MUD never accepts an inbound connection: it
*originates* loopback requests to this service to start a login and to poll for
completion, over loopback.

Endpoints
---------
GET  /auth/providers      → {"providers":[...]}
GET  /auth/login/<provider>/<nonce>
                          → 302 to the provider authorize URL
GET  /auth/callback       → code→token→profile (Steam: OpenID 2.0
                            assertion→verify); stores verified identity by nonce
GET  /auth/token-poll     → {"status":"pending"} |
                            {"provider":..,"provider_id":..,"username":..}
POST /auth/login-cancel   → drop a pending nonce

Security model (adapted from MUDdown's auth.ts for loopback):
  * random per-flow ``state`` (CSRF), unknown/expired states rejected;
  * ``login_nonce`` is a client UUID; the verified identity is returned exactly
    once from token-poll then deleted; 10-minute TTL;
  * the IP that started the flow is recorded and must match the poller, except
    trusted loopback callers (the MUD) which are exempt. Forwarding headers are
    read only from a loopback peer (our own reverse proxy) and only from the
    right-hand end, so a caller cannot name its own origin;
  * provider ``client_secret`` lives only in this service's config.
"""

from __future__ import annotations

import html
import ipaddress
import json
import os
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from . import __version__, providers
from .providers import ProviderConfig

# ── Configuration ─────────────────────────────────────────────────────────────


def _load_provider_configs() -> dict[str, ProviderConfig]:
    """Read per-provider client id/secret/callback from the environment."""
    out: dict[str, ProviderConfig] = {}
    callback = os.environ.get(
        "AUTH_CALLBACK_URL",
        _public_base() + "/auth/callback",
    )
    for p in providers.SUPPORTED_PROVIDERS:
        cid = os.environ.get(f"{p.upper()}_CLIENT_ID")
        secret = os.environ.get(f"{p.upper()}_CLIENT_SECRET")
        if cid and secret:
            out[p] = ProviderConfig(
                client_id=cid,
                client_secret=secret,
                callback_url=os.environ.get(f"{p.upper()}_CALLBACK_URL", callback),
            )
    # Steam is OpenID 2.0: no client id/secret, just a Web API key for the
    # profile lookup. The key rides in the client_secret slot.
    steam_key = os.environ.get("STEAM_API_KEY")
    if steam_key:
        out["steam"] = ProviderConfig(
            client_id="steam",
            client_secret=steam_key,
            callback_url=os.environ.get("STEAM_CALLBACK_URL", callback),
        )
    return out


def _public_base() -> str:
    return os.environ.get("AUTH_PUBLIC_BASE", "http://localhost:7700").rstrip("/")


def brand_name() -> str:
    """Name shown on the browser 'you may close this tab' page."""
    return os.environ.get("AUTH_BRAND_NAME") or "mudauth"


PENDING_TTL = 10 * 60  # seconds


# ── In-memory flow state ──────────────────────────────────────────────────────


class _State:
    """Holds the volatile maps for in-flight and completed logins."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        # state(csrf) -> dict(provider, created_at, login_nonce, origin_ip,
        #                     mode, account_id)
        self.pending: dict[str, dict] = {}
        # login_nonce -> dict(token|linked, created_at, origin_ip, mode)
        self.completed: dict[str, dict] = {}

    def sweep(self) -> None:
        cutoff = time.time() - PENDING_TTL
        with self.lock:
            for k in [k for k, v in self.pending.items() if v["created_at"] < cutoff]:
                del self.pending[k]
            for k in [k for k, v in self.completed.items() if v["created_at"] < cutoff]:
                del self.completed[k]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _is_loopback(addr: str | None) -> bool:
    """True for 127.0.0.0/8, ::1, and the IPv4-mapped forms of both."""
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def _trusted_proxy_hops() -> int:
    """How many proxies append to X-Forwarded-For before it reaches us."""
    try:
        hops = int(os.environ.get("AUTH_TRUSTED_PROXY_HOPS", "1"))
    except ValueError:
        return 1
    return max(hops, 1)


def _client_ip(handler: BaseHTTPRequestHandler) -> str | None:
    """The address the request really came from.

    Forwarding headers are hearsay from whoever sent them, so they are read
    only when the immediate peer is loopback — i.e. our own reverse proxy,
    since the listener is loopback-only. From anyone else the socket address is
    the only truth.

    Within X-Forwarded-For, the *rightmost* element is the one our proxy
    appended (both shipped configs append rather than replace, as does Apache's
    mod_proxy), so everything to its left is whatever the client chose to send.
    ``AUTH_TRUSTED_PROXY_HOPS`` counts back further for a chain of proxies; a
    list shorter than the configured chain is not the shape we were promised,
    so it is discarded rather than half-trusted.
    """
    peer = handler.client_address[0] if handler.client_address else None
    if not _is_loopback(peer):
        return peer
    # Repeated header lines are one list; a client can send its own line and a
    # proxy may append a second rather than merging them.
    lines = handler.headers.get_all("X-Forwarded-For") or []
    parts = [p.strip() for line in lines for p in line.split(",") if p.strip()]
    if parts:
        hops = _trusted_proxy_hops()
        if hops <= len(parts):
            return parts[-hops]
        return peer
    real = (handler.headers.get_all("X-Real-IP") or [""])[-1].strip()
    return real or peer


def _is_trusted_loopback(handler: BaseHTTPRequestHandler) -> bool:
    """True only for a direct loopback caller — in practice, the game itself.

    Our own proxy also reaches us over loopback, so the peer address alone
    cannot tell the game apart from a browser on the far side of the proxy.
    The forwarding headers are what distinguish them: a request carrying one
    passed through the proxy and stands for a remote client, so it keeps the
    origin binding instead of inheriting the game's exemption.
    """
    if "X-Forwarded-For" in handler.headers or "X-Real-IP" in handler.headers:
        return False
    return _is_loopback(handler.client_address[0] if handler.client_address else None)


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# Everything from a "?" to the next whitespace, for scrubbing request lines.
_QUERY_RE = re.compile(r"\?\S*")


def _is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))


# ── Request handler ───────────────────────────────────────────────────────────


class AuthHandler(BaseHTTPRequestHandler):
    server_version = f"mudauth/{__version__}"

    # Injected by make_server()
    configs: ClassVar[dict[str, ProviderConfig]] = {}
    flow: _State = None  # type: ignore[assignment]

    # Quieter logging: route through print so it lands in the service log.
    # The raw request line carries live credentials (?code=, ?nonce=, Steam's
    # signed assertion) and is attacker-controlled, so redact query strings,
    # escape control characters, and bound the length before logging.
    def log_message(self, fmt: str, *args) -> None:
        line = _QUERY_RE.sub("?<redacted>", fmt % args)
        print("[auth] " + line.encode("unicode_escape").decode("ascii", "replace")[:300])

    # ── dispatch ──────────────────────────────────────────────────────────

    def do_GET(self) -> None:
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/auth/providers":
            self._providers()
        elif url.path == "/auth/login" or url.path.startswith("/auth/login/"):
            self._login(self._login_params(url, q))
        elif url.path == "/auth/callback":
            self._callback(q)
        elif url.path == "/auth/token-poll":
            self._token_poll(q)
        elif url.path == "/auth/healthz":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        url = urlparse(self.path)
        if url.path == "/auth/login-cancel":
            self._login_cancel()
        else:
            self._json(404, {"error": "not found"})

    # ── responses ─────────────────────────────────────────────────────────

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, html: str) -> None:
        body = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > 64 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {}

    # ── /auth/providers ───────────────────────────────────────────────────

    def _providers(self) -> None:
        self._json(
            200,
            {
                "providers": sorted(self.configs.keys()),
                "public_base": _public_base(),
            },
        )

    # ── /auth/login ───────────────────────────────────────────────────────

    @staticmethod
    def _login_params(url, q: dict) -> dict:
        """Build login params from a path-style URL, falling back to the query.

        Path form: ``/auth/login/<provider>/<login_nonce>``. It carries no
        ``&`` or ``=`` so MUD clients that render OSC 8 link text as MXP/HTML
        cannot escape ``&`` to ``&amp;`` and corrupt ``login_nonce``. Any extra
        trailing segments (e.g. a legacy ``/link``) are ignored — the game now
        owns login vs link vs create. The legacy query form is still accepted.
        """
        prefix = "/auth/login/"
        if not url.path.startswith(prefix):
            return q
        segs = [s for s in url.path[len(prefix):].split("/") if s]
        params = dict(q)
        if len(segs) >= 1:
            params["provider"] = [segs[0]]
        if len(segs) >= 2:
            params["login_nonce"] = [segs[1]]
        return params

    def _login(self, q: dict) -> None:
        provider = (q.get("provider", [""])[0]) or ""
        if provider not in self.configs:
            self._html(404, f"Provider '{html.escape(provider)}' is not configured.")
            return
        nonce = q.get("login_nonce", [""])[0]
        if nonce and not _is_uuid(nonce):
            self._html(400, "Invalid login_nonce format.")
            return

        state = str(uuid.uuid4())
        origin_ip = _client_ip(self) if nonce else None
        with self.flow.lock:
            self.flow.pending[state] = {
                "provider": provider,
                "created_at": time.time(),
                "login_nonce": nonce or None,
                "origin_ip": origin_ip,
            }
        authorize = providers.build_authorize_url(provider, self.configs[provider], state)
        self.send_response(302)
        self.send_header("Location", authorize)
        self.end_headers()

    # ── /auth/callback ────────────────────────────────────────────────────

    def _callback(self, q: dict) -> None:
        state = q.get("state", [""])[0]
        with self.flow.lock:
            pending = self.flow.pending.pop(state, None)
        if not state or pending is None:
            # The user-facing message stays generic, but log the specific cause
            # so an operator can tell a forged/replayed state from other 400s.
            print("[auth] callback: unknown or already-consumed state")
            self._html(400, _AUTH_FAILED_MESSAGE)
            return
        # Enforce the TTL inline so expiry is exact and does not depend on the
        # 60s janitor sweep having run between creation and callback.
        if time.time() - pending["created_at"] > PENDING_TTL:
            print(f"[auth] {pending['provider']} callback: login state expired (TTL)")
            self._html(400, _AUTH_FAILED_MESSAGE)
            return

        provider = pending["provider"]
        cfg = self.configs.get(provider)
        if not cfg:
            print(f"[auth] {provider} callback: provider no longer configured")
            self._html(503, f"Provider '{provider}' is no longer configured.")
            return

        if provider == "steam":
            # OpenID 2.0: no code exchange; verify the signed assertion and
            # carry the steamid64 into the profile step.
            if q.get("openid.mode", [""])[0] == "cancel":
                print("[auth] steam callback: user cancelled at Steam")
                self._html(400, _DECLINED_MESSAGE)
                return
            access = providers.verify_steam_assertion(q, cfg)
        else:
            error = q.get("error", [""])[0]
            if error:
                # The provider answered with an error instead of a code —
                # most commonly the user clicking Cancel (access_denied).
                # Both values arrive on the query string, so bound and repr
                # them like the other attacker-reachable log inputs.
                desc = q.get("error_description", [""])[0]
                print(
                    f"[auth] {provider} callback error: "
                    f"{repr(error)[:100]}: {repr(desc)[:200]}"
                )
                if error == "access_denied":
                    self._html(400, _DECLINED_MESSAGE)
                else:
                    self._html(400, _AUTH_FAILED_MESSAGE)
                return
            code = q.get("code", [""])[0]
            if not code:
                print(f"[auth] {provider} callback missing the code param")
                self._html(400, _AUTH_FAILED_MESSAGE)
                return
            access = providers.exchange_code_for_token(provider, cfg, code)
        if not access:
            self._html(400, _AUTH_FAILED_MESSAGE)
            return
        user = providers.fetch_provider_user(provider, cfg, access)
        if not user:
            self._html(502, f"Could not fetch your {providers.display_name(provider)} profile.")
            return

        nonce = pending.get("login_nonce")
        # Stateless: hand the verified identity back to the polling game. The
        # game owns accounts, characters and the login/link/create decision.
        if nonce:
            with self.flow.lock:
                self.flow.completed[nonce] = {
                    "provider": provider,
                    "provider_id": user.provider_id,
                    "username": user.username,
                    "created_at": time.time(),
                    "origin_ip": pending.get("origin_ip"),
                }
        self._html(200, _done_page("Authentication successful. Return to your MUD client."))

    # ── /auth/token-poll ──────────────────────────────────────────────────

    def _token_poll(self, q: dict) -> None:
        nonce = q.get("nonce", [""])[0]
        if not nonce:
            self._json(400, {"error": "missing nonce"})
            return
        # Hold the lock across the whole check-and-pop so concurrent polls of the
        # same nonce cannot both pass the origin check and retrieve the identity.
        with self.flow.lock:
            entry = self.flow.completed.get(nonce)
            # Treat an expired entry as absent (exact TTL, independent of the
            # janitor sweep) and drop it.
            if entry and time.time() - entry["created_at"] > PENDING_TTL:
                self.flow.completed.pop(nonce, None)
                entry = None
            if not entry:
                self._json(202, {"status": "pending"})
                return
            if (
                entry.get("origin_ip")
                and _client_ip(self) != entry["origin_ip"]
                and not _is_trusted_loopback(self)
            ):
                # A cross-IP retrieval attempt is a hijack signal worth a trace.
                print("[auth] token-poll: origin IP mismatch rejected")
                self._json(403, {"error": "forbidden"})
                return
            self.flow.completed.pop(nonce, None)  # one-time retrieval
        self._json(200, {
            "provider": entry["provider"],
            "provider_id": entry["provider_id"],
            "username": entry.get("username", ""),
        })

    # ── /auth/login-cancel ────────────────────────────────────────────────

    def _login_cancel(self) -> None:
        body = self._read_json_body()
        nonce = body.get("nonce")
        if not nonce or not isinstance(nonce, str) or not _is_uuid(nonce):
            self._json(400, {"error": "invalid nonce"})
            return
        requester_ip = _client_ip(self)
        loopback = _is_trusted_loopback(self)
        cancelled = 0
        with self.flow.lock:
            entry = self.flow.completed.get(nonce)
            if entry:
                if entry.get("origin_ip") and requester_ip != entry["origin_ip"] and not loopback:
                    print("[auth] login-cancel: origin IP mismatch rejected")
                    self._json(403, {"error": "forbidden"})
                    return
                self.flow.completed.pop(nonce, None)
                cancelled += 1
            for st in [s for s, v in self.flow.pending.items() if v.get("login_nonce") == nonce]:
                self.flow.pending.pop(st, None)
                cancelled += 1
        self._json(200, {"cancelled": cancelled})


_DECLINED_MESSAGE = (
    "You declined the sign-in request. You can close this tab and pick "
    "another way to sign in from your MUD client."
)

_AUTH_FAILED_MESSAGE = "Authentication failed. Please try again."


def _done_page(message: str) -> str:
    brand = html.escape(brand_name())
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{brand}</title><style>"
        "body{font-family:system-ui,sans-serif;background:#10161d;color:#cfe3f2;"
        "display:flex;align-items:center;justify-content:center;min-height:100vh;"
        "margin:0;text-align:center}.card{max-width:420px;padding:2rem;border:1px "
        "solid #2a3a4a;border-radius:12px;background:#16202a}h1{color:#5cc8ff;"
        "font-size:1.4rem;margin:0 0 1rem}p{line-height:1.6}</style></head><body>"
        f"<div class=\"card\"><h1>{brand}</h1><p>{message}</p>"
        "<p>You may close this tab.</p></div></body></html>"
    )


# ── Server bootstrap ──────────────────────────────────────────────────────────


class _ThreadingHTTPServer6(ThreadingHTTPServer):
    """IPv6 variant of ThreadingHTTPServer for the ::1 loopback companion."""

    address_family = socket.AF_INET6


def _start_ipv6_loopback_companion(port: int) -> None:
    """Also listen on [::1].

    Browsers resolve ``localhost`` to both ``127.0.0.1`` and ``::1`` and often
    try IPv6 first. The primary server binds IPv4 loopback, so without this the
    browser-side ``/auth/login`` and ``/auth/callback`` would hit ``::1`` and be
    refused — breaking the OAuth round-trip even though the MUD's IPv4 polling
    works. This keeps the service loopback-only while covering both families.
    """
    try:
        comp = _ThreadingHTTPServer6(("::1", port), AuthHandler)
    except OSError as exc:
        print(f"[auth] IPv6 loopback companion not started: {exc}")
        return
    threading.Thread(target=comp.serve_forever, daemon=True).start()
    print(f"[auth] also listening on [::1]:{port} (IPv6 loopback)")


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    configs = _load_provider_configs()
    flow = _State()

    AuthHandler.configs = configs
    AuthHandler.flow = flow

    httpd = ThreadingHTTPServer((host, port), AuthHandler)

    # When bound to IPv4 loopback, also cover IPv6 loopback so browsers that
    # prefer ::1 for "localhost" can still reach the login/callback endpoints.
    if host in ("127.0.0.1", "localhost"):
        _start_ipv6_loopback_companion(port)

    def _janitor() -> None:
        while True:
            time.sleep(60)
            flow.sweep()

    threading.Thread(target=_janitor, daemon=True).start()
    print(
        f"[auth] mudauth {__version__} on {host}:{port} — "
        f"providers: {sorted(configs.keys()) or '(none configured)'}"
    )
    return httpd
