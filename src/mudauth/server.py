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
    trusted loopback callers (the game) which are exempt. Forwarding headers are
    read only from a loopback peer (our own reverse proxy) and only from the
    right-hand end, so a caller cannot name its own origin;
  * the loopback exemption itself: when ``AUTH_SERVICE_TOKEN`` is set, it rests
    on positive evidence — a loopback peer presenting that shared secret in
    ``X-Auth-Service-Token`` — rather than the mere absence of forwarding
    headers, which a proxy misconfiguration can manufacture for anyone. Unset,
    the legacy header-absence behavior stands, so existing deployments do not
    break on restart;
  * provider ``client_secret`` lives only in this service's config.
"""

from __future__ import annotations

import hmac
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
    """Name shown on the browser page after sign-in."""
    return (os.environ.get("AUTH_BRAND_NAME") or "").strip() or "mudauth"


DEFAULT_BRAND_ACCENT = "#4f8fd8"
_HEX_COLOR_RE = re.compile(r"#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})")


def _brand_env_url(name: str, schemes: tuple[str, ...]) -> tuple[str, str | None]:
    """Read a URL setting as ``(url, problem)``; ``url`` is "" when unset or
    unusable, and ``problem`` says why an unusable one was ignored."""
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return "", None
    try:
        # os.environ carries bytes that are not UTF-8 as lone surrogates,
        # which would make every page fail to encode.
        raw.encode("utf-8")
    except UnicodeEncodeError:
        return "", f"{name} is not valid UTF-8; ignoring {raw!r}"
    try:
        parts = urlparse(raw)
    except ValueError:
        parts = None
    if (
        parts is None
        or parts.scheme not in schemes
        or not parts.netloc
        or any(c.isspace() or ord(c) < 32 for c in raw)
    ):
        wanted = " or ".join(f"{s}://" for s in schemes)
        return "", f"{name} must be a {wanted} URL; ignoring {raw!r}"
    return raw, None


def brand() -> tuple[dict[str, str], list[str]]:
    """The browser page's branding, and a problem line for each setting that
    was set but ignored. A bad value never stops the service: the page falls
    back to the default for that setting, and ``mudauth check`` and the
    startup log name it."""
    problems = []
    name = brand_name()
    try:
        name.encode("utf-8")
    except UnicodeEncodeError:
        problems.append(f"AUTH_BRAND_NAME is not valid UTF-8; ignoring {name!r}")
        name = "mudauth"
    url, problem = _brand_env_url("AUTH_BRAND_URL", ("https", "http"))
    if problem:
        problems.append(problem)
    # https only: an http image on an https page is mixed content that
    # browsers block or rewrite.
    logo, problem = _brand_env_url("AUTH_BRAND_LOGO_URL", ("https",))
    if problem:
        problems.append(problem)
    accent = (os.environ.get("AUTH_BRAND_ACCENT") or "").strip() or DEFAULT_BRAND_ACCENT
    if not _HEX_COLOR_RE.fullmatch(accent):
        problems.append(f"AUTH_BRAND_ACCENT must be a #rgb or #rrggbb color; ignoring {accent!r}")
        accent = DEFAULT_BRAND_ACCENT
    return {"name": name, "url": url, "logo": logo, "accent": accent}, problems


# ── Diagnostics ───────────────────────────────────────────────────────────────


def _log(msg: str) -> None:
    """Print one diagnostic line to stdout, flushed immediately.

    Python block-buffers stdout when it is not a TTY -- always true under
    systemd -- so an unflushed print() can sit in a multi-KB buffer long
    after the event it describes, including the [auth][security] lines an
    operator needs live during an incident. Every stdout diagnostic in this
    module goes through here so log ordering and promptness never depend on
    how the process was launched. The unit file also sets PYTHONUNBUFFERED=1
    as a second line of defense; this makes correctness not depend on it.
    """
    print(msg, flush=True)


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


def _is_ip_address(value: str) -> bool:
    """True for a bare IPv4 or IPv6 literal — no port, no brackets."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# Fixed at startup by _configure_trusted_proxy_hops(). The request path reads
# this rather than the environment, so the binding cannot shift under a running
# service and a bad value is caught once, loudly, instead of on every request.
_TRUSTED_PROXY_HOPS = 1


def _configure_trusted_proxy_hops() -> int:
    """Validate AUTH_TRUSTED_PROXY_HOPS and fix it for the process's lifetime.

    Raises ``ValueError`` on anything unusable, for the caller to report and
    exit on. Clamping a typo in silence left the origin binding quietly
    degraded, which is the one thing a security control must not do: a
    misconfiguration belongs at ``systemctl start``, not in a live flow.
    """
    global _TRUSTED_PROXY_HOPS
    raw = (os.environ.get("AUTH_TRUSTED_PROXY_HOPS") or "").strip()
    if not raw:
        _TRUSTED_PROXY_HOPS = 1
        return _TRUSTED_PROXY_HOPS
    try:
        hops = int(raw)
    except ValueError:
        raise ValueError(
            f"AUTH_TRUSTED_PROXY_HOPS must be a whole number of proxies, not {raw!r}"
        ) from None
    if hops < 1:
        raise ValueError(
            f"AUTH_TRUSTED_PROXY_HOPS must be at least 1, not {hops}; it counts the "
            "proxies that append to X-Forwarded-For, and there is always at least one"
        )
    _TRUSTED_PROXY_HOPS = hops
    return _TRUSTED_PROXY_HOPS


def _trusted_proxy_hops() -> int:
    """How many proxies append to X-Forwarded-For before it reaches us."""
    return _TRUSTED_PROXY_HOPS


# The header the game presents its shared secret in. One name, used consistently.
AUTH_SERVICE_TOKEN_HEADER = "X-Auth-Service-Token"

# The client's own charset guard (client.py's _SAFE_TOKEN_RE) refuses to
# transmit anything outside this charset. Kept in sync with that regex by
# hand -- the two modules do not share an import, since the client's copy has
# to survive without this service's other dependencies.
_TOKEN_CHARSET_RE = re.compile(r"^[A-Za-z0-9_-]+$")

# Fixed at startup by _configure_auth_service_token(), for the same reason the
# hop count is: the request path must not be able to drift under a running
# service just because someone edited the environment.
_AUTH_SERVICE_TOKEN: str | None = None


def _configure_auth_service_token() -> str | None:
    """Read AUTH_SERVICE_TOKEN once at startup and fix it for the process's
    lifetime. Returns the token, or None if unset -- the caller uses that to
    decide whether to print the legacy-path startup warning.

    Stripped, and whitespace-only treated as unset, mirroring
    _configure_trusted_proxy_hops() and the client's own normalisation
    (client.py strips before sending): a trailing space is trivial to
    introduce in a ``.env`` file, and without matching normalisation on both
    sides a configuration that looks correct on both can never produce a
    matching header.

    Raises ``ValueError`` -- for the caller to report and exit on, same as a
    bad hop count -- when the token is non-empty but contains a character the
    client's own charset guard will never send. Starting up to require a
    secret the only caller that matters refuses to transmit is worse than
    refusing to start: a misconfiguration belongs at ``systemctl start``, not
    in a live flow that hangs until timeout.
    """
    global _AUTH_SERVICE_TOKEN
    raw = (os.environ.get("AUTH_SERVICE_TOKEN") or "").strip()
    if not raw:
        _AUTH_SERVICE_TOKEN = None
        return None
    if not _TOKEN_CHARSET_RE.match(raw):
        # Report a count, never the offending characters themselves: if every
        # character in the token is outside the charset (e.g. a
        # single-character secret), naming them would name the whole token.
        bad_count = len({c for c in raw if not _TOKEN_CHARSET_RE.match(c)})
        raise ValueError(
            "AUTH_SERVICE_TOKEN contains character(s) the client will never "
            f"send: {bad_count} distinct offending character(s); only A-Z "
            "a-z 0-9 _ - are accepted. Whitespace or a control character -- "
            "a trailing newline/carriage return or a stray space from a "
            "copy-paste -- is the usual cause. Generate a safe token with: "
            'python3 -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    _AUTH_SERVICE_TOKEN = raw
    return _AUTH_SERVICE_TOKEN


def _client_ip(handler: BaseHTTPRequestHandler) -> str | None:
    """The address the request really came from, or None if we cannot tell.

    Forwarding headers are hearsay from whoever sent them, so they are read
    only when the immediate peer is loopback — i.e. our own reverse proxy,
    since the listener is loopback-only. From anyone else the socket address is
    the only truth.

    Within X-Forwarded-For, the *rightmost* element is the one our proxy
    appended (both shipped configs append rather than replace, as does Apache's
    mod_proxy), so everything to its left is whatever the client chose to send.
    ``AUTH_TRUSTED_PROXY_HOPS`` counts back further for a chain of proxies.

    A forwarding header that is present but not the promised shape — a chain
    shorter than the configured hop count, or a hop that is not an address —
    has no answer in it, so None is returned and the caller refuses. Falling
    back to the peer here would resolve every proxied request to 127.0.0.1,
    the very origin the game's own flows record, so every origin would match
    and the binding would be off with nothing in the log to say so.
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
        if hops > len(parts):
            _log(
                "[auth][security] forwarded chain is shorter than "
                f"AUTH_TRUSTED_PROXY_HOPS={hops}: {len(parts)} element(s) via peer "
                f"{peer}; refusing rather than falling back to the peer address"
            )
            return None
        claimed = parts[-hops]
        if not _is_ip_address(claimed):
            _log(
                f"[auth][security] X-Forwarded-For hop {hops} is not an IP address: "
                f"{claimed[:64]!r} via peer {peer}; refusing"
            )
            return None
        return claimed
    # Our proxy *sets* X-Real-IP, so the last line is the one it wrote. An
    # empty or non-address value means the proxy is not the one we were
    # promised; that is a refusal, not a fallback to the loopback peer.
    real_lines = handler.headers.get_all("X-Real-IP") or []
    if real_lines:
        claimed = real_lines[-1].strip()
        if not _is_ip_address(claimed):
            _log(
                f"[auth][security] X-Real-IP is not an IP address: {claimed[:64]!r} "
                f"via peer {peer}; refusing"
            )
            return None
        return claimed
    return peer


def _lacks_forwarding_headers(handler: BaseHTTPRequestHandler) -> bool:
    """True when the request carries neither X-Forwarded-For nor X-Real-IP.

    Shared by the legacy exemption rule, the token rule below (which now
    requires this too -- see _is_trusted_loopback), and the "loopback
    exemption denied" logging, which must fire only for a genuinely
    headerless loopback caller rather than for every proxied browser request
    that simply lacks a valid token, which in production is the common case.
    """
    return "X-Forwarded-For" not in handler.headers and "X-Real-IP" not in handler.headers


def _is_trusted_loopback(handler: BaseHTTPRequestHandler) -> bool:
    """True only for a direct loopback caller — in practice, the game itself.

    Our own proxy also reaches us over loopback, so the peer address alone
    cannot tell the game apart from a browser on the far side of the proxy.

    When AUTH_SERVICE_TOKEN is configured, the exemption rests on positive
    evidence: a loopback peer presenting that shared secret in
    AUTH_SERVICE_TOKEN_HEADER, compared with hmac.compare_digest since it is a
    bearer credential -- AND the absence of a forwarding header. The token
    alone is not enough to grant the exemption: neither shipped reverse-proxy
    config strips a client-supplied X-Auth-Service-Token, so a caller who has
    learned the token (from a paste, a log, /proc/<pid>/environ under the
    same uid) could otherwise present it *through* the proxy and inherit the
    exemption remotely -- a widening of remote attack surface the legacy
    header-absence rule never had, since a correctly configured proxy always
    appends X-Forwarded-For. Requiring both makes the token path a strict
    tightening of the legacy rule, never a trade against it: the game polls
    over loopback directly and never traverses a proxy, so it never carries a
    forwarding header, and this costs it nothing. A valid token from a
    non-loopback peer is still refused regardless.

    When AUTH_SERVICE_TOKEN is unset, today's behavior is unchanged so an
    existing deployment does not break on restart: a request carrying a
    forwarding header passed through the proxy and stands for a remote
    client, so it keeps the origin binding instead of inheriting the game's
    exemption.
    """
    peer = handler.client_address[0] if handler.client_address else None
    if not _is_loopback(peer):
        return False
    no_forwarding_headers = _lacks_forwarding_headers(handler)
    if _AUTH_SERVICE_TOKEN:
        # Exactly one line, like every other credential-bearing check this
        # service makes: a repeated header is not a value to pick a winner
        # from, it is the request not looking like what was promised.
        lines = handler.headers.get_all(AUTH_SERVICE_TOKEN_HEADER) or []
        supplied = lines[0] if len(lines) == 1 else ""
        # Compare as bytes: compare_digest raises TypeError on non-ASCII str
        # input, and the header is attacker-controlled even on this branch
        # (a loopback caller without the real token is exactly the local
        # process / SSRF this token is meant to keep out) -- a malformed
        # value must fail the check, not crash the request thread.
        token_matches = hmac.compare_digest(supplied.encode(), _AUTH_SERVICE_TOKEN.encode())
        return token_matches and no_forwarding_headers
    return no_forwarding_headers


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

# Everything from a "?" to the next whitespace, for scrubbing request lines.
_QUERY_RE = re.compile(r"\?\S*")

# A UUID anywhere in a request line: the preferred login form carries the
# login_nonce as a path segment, where the query scrub cannot reach it.
_UUID_ANYWHERE_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE
)


def _is_uuid(value: str) -> bool:
    return bool(_UUID_RE.match(value))


def _log_rejected_exemption(
    endpoint: str, peer: str | None, claimed: str | None, recorded, provider
) -> None:
    """A loopback peer tried to claim the game's exemption and failed the
    token check. Worth its own line, distinct from an ordinary origin
    mismatch: this is specifically someone on-box without the shared secret,
    which is the exact gap AUTH_SERVICE_TOKEN closes. Same evidence
    conventions as the origin-mismatch logging below -- peer, claimed origin,
    recorded origin, provider -- and never the credential itself.
    """
    _log(
        f"[auth][security] {endpoint}: loopback exemption denied (missing or "
        f"invalid {AUTH_SERVICE_TOKEN_HEADER}) — peer={peer} claimed={claimed} "
        f"recorded={recorded} provider={provider}"
    )


# ── Request handler ───────────────────────────────────────────────────────────


class AuthHandler(BaseHTTPRequestHandler):
    server_version = f"mudauth/{__version__}"

    # Injected by make_server()
    configs: ClassVar[dict[str, ProviderConfig]] = {}
    flow: _State = None  # type: ignore[assignment]

    # Quieter logging: route through print so it lands in the service log.
    # The raw request line carries live credentials (?code=, ?nonce=, Steam's
    # signed assertion, and the login_nonce in the preferred path form
    # /auth/login/<provider>/<nonce>) and is attacker-controlled, so redact
    # query strings and UUIDs, escape control characters, and bound the length.
    def log_message(self, fmt: str, *args) -> None:
        line = _UUID_ANYWHERE_RE.sub("<redacted>", _QUERY_RE.sub("?<redacted>", fmt % args))
        _log("[auth] " + line.encode("unicode_escape").decode("ascii", "replace")[:300])

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

    def _security_headers(self) -> None:
        """Headers for every response this handler builds — JSON, HTML, and the
        /auth/login redirect. An unsupported method or a malformed request line
        never reaches this code: the stdlib's own send_error answers those, and
        that response carries none of these. The pages that do come through here
        render on the MUD's own public origin, so they must not be sniffed into
        another type and must not leak a nonce- or code-bearing URL in a
        Referer."""
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")

    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _html(self, code: int, message_html: str, title: str = "Sign-in failed") -> None:
        body = _page(title, message_html, ok=code == 200).encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
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
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()

    # ── /auth/callback ────────────────────────────────────────────────────

    def _callback(self, q: dict) -> None:
        state = q.get("state", [""])[0]
        with self.flow.lock:
            pending = self.flow.pending.pop(state, None)
        if not state or pending is None:
            # The user-facing message stays generic, but log the specific cause
            # so an operator can tell a forged/replayed state from other 400s.
            _log("[auth] callback: unknown or already-consumed state")
            self._html(400, _AUTH_FAILED_MESSAGE)
            return
        # Enforce the TTL inline so expiry is exact and does not depend on the
        # 60s janitor sweep having run between creation and callback.
        if time.time() - pending["created_at"] > PENDING_TTL:
            _log(f"[auth] {pending['provider']} callback: login state expired (TTL)")
            self._html(400, _AUTH_FAILED_MESSAGE)
            return

        provider = pending["provider"]
        cfg = self.configs.get(provider)
        if not cfg:
            _log(f"[auth] {provider} callback: provider no longer configured")
            self._html(503, f"Provider '{html.escape(provider)}' is no longer configured.")
            return

        if provider == "steam":
            # OpenID 2.0: no code exchange; verify the signed assertion and
            # carry the steamid64 into the profile step.
            if q.get("openid.mode", [""])[0] == "cancel":
                _log("[auth] steam callback: user cancelled at Steam")
                self._html(400, _DECLINED_MESSAGE, _DECLINED_TITLE)
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
                _log(
                    f"[auth] {provider} callback error: "
                    f"{repr(error)[:100]}: {repr(desc)[:200]}"
                )
                if error == "access_denied":
                    self._html(400, _DECLINED_MESSAGE, _DECLINED_TITLE)
                else:
                    self._html(400, _AUTH_FAILED_MESSAGE)
                return
            code = q.get("code", [""])[0]
            if not code:
                _log(f"[auth] {provider} callback missing the code param")
                self._html(400, _AUTH_FAILED_MESSAGE)
                return
            access = providers.exchange_code_for_token(provider, cfg, code)
        if not access:
            self._html(400, _AUTH_FAILED_MESSAGE)
            return
        user = providers.fetch_provider_user(provider, cfg, access)
        if not user:
            name = html.escape(providers.display_name(provider))
            self._html(
                502,
                f"Could not fetch your {name} profile. Go back to your MUD "
                "client and start the sign-in again.",
            )
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
        self._html(
            200,
            "Go back to your MUD client to continue. You can close this page.",
            "You're signed in",
        )

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
            # The game's own loopback poll is exempt and is checked first, so
            # that integration keeps working. Everyone else must present the
            # origin the flow was bound to. Written as an explicit reject: an
            # origin we never recorded, or a caller address we could not
            # resolve, is a reason to refuse, not a reason for the comparison
            # to evaporate and hand the identity to whoever holds the nonce.
            if not _is_trusted_loopback(self):
                recorded = entry.get("origin_ip")
                claimed = _client_ip(self)
                peer = self.client_address[0] if self.client_address else None
                if _AUTH_SERVICE_TOKEN and _is_loopback(peer) and _lacks_forwarding_headers(self):
                    _log_rejected_exemption(
                        "token-poll", peer, claimed, recorded, entry.get("provider")
                    )
                if not recorded or not claimed or claimed != recorded:
                    # A cross-IP retrieval is a hijack signal worth a trace,
                    # and a trace is only useful with the addresses in it.
                    _log(
                        "[auth][security] token-poll: origin rejected — "
                        f"peer={peer} claimed={claimed} recorded={recorded} "
                        f"provider={entry.get('provider')}"
                    )
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
        # Same shape as the poll: the loopback exemption first, then an
        # explicit reject for anything we cannot vouch for. Cancelling
        # someone else's login -- completed OR still pending -- is a denial
        # of their sign-in, so both are bound to the origin that started
        # them; a nonce is a client-generated UUID, not a secret, so leaving
        # the pending half unchecked let anyone who learned it cancel an
        # in-flight login from anywhere.
        loopback = _is_trusted_loopback(self)
        requester_ip = None if loopback else _client_ip(self)
        peer = self.client_address[0] if self.client_address else None
        cancelled = 0
        with self.flow.lock:
            entry = self.flow.completed.get(nonce)
            pending_states = [
                s for s, v in self.flow.pending.items() if v.get("login_nonce") == nonce
            ]
            if entry or pending_states:
                # The completed entry's recorded origin wins when both exist
                # (it cannot, in practice: completion pops the pending state);
                # otherwise fall back to the first pending state's -- both are
                # recorded from the same caller at /auth/login time.
                recorded = entry.get("origin_ip") if entry else None
                if recorded is None and pending_states:
                    recorded = self.flow.pending[pending_states[0]].get("origin_ip")
                provider = entry.get("provider") if entry else None
                if not loopback and _AUTH_SERVICE_TOKEN and _lacks_forwarding_headers(self):
                    _log_rejected_exemption(
                        "login-cancel", peer, requester_ip, recorded, provider
                    )
                if not loopback and (
                    not recorded or not requester_ip or requester_ip != recorded
                ):
                    _log(
                        "[auth][security] login-cancel: origin rejected — "
                        f"peer={peer} claimed={requester_ip} recorded={recorded} "
                        f"provider={provider}"
                    )
                    self._json(403, {"error": "forbidden"})
                    return
            if entry:
                self.flow.completed.pop(nonce, None)
                cancelled += 1
            for st in pending_states:
                self.flow.pending.pop(st, None)
                cancelled += 1
        self._json(200, {"cancelled": cancelled})


_DECLINED_TITLE = "Sign-in cancelled"

_DECLINED_MESSAGE = (
    "You declined the sign-in request. Go back to your MUD client to pick "
    "another way to sign in. You can close this page."
)

_AUTH_FAILED_MESSAGE = (
    "The sign-in did not complete. Go back to your MUD client and start the "
    "sign-in again."
)

# Light and dark follow the browser's setting. The page is one self-contained
# response: no web fonts or scripts, and the only external fetch is the
# operator's own AUTH_BRAND_LOGO_URL.
_PAGE_CSS = (
    ":root{color-scheme:light dark;--bg:#e8eaee;--surface:#fff;--ink:#1b1e24;"
    "--muted:#555c68;--line:#d3d7de;--ok:#23804f;--bad:#b9382f;"
    "--serif:\"Iowan Old Style\",\"Palatino Linotype\",Palatino,\"Book Antiqua\",Georgia,serif}"
    "@media (prefers-color-scheme:dark){:root{--bg:#141519;--surface:#1f2126;"
    "--ink:#eceef2;--muted:#a4aab5;--line:#353841;--ok:#4cc583;--bad:#f06d62}}"
    "*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}"
    "body{margin:0;min-height:100vh;min-height:100dvh;display:flex;"
    "flex-direction:column;align-items:center;justify-content:center;"
    "padding:max(1.5rem,env(safe-area-inset-top)) max(1rem,env(safe-area-inset-right)) "
    "max(1.5rem,env(safe-area-inset-bottom)) max(1rem,env(safe-area-inset-left));"
    "background:var(--bg);color:var(--ink);text-align:center;"
    "font:1.0625rem/1.55 system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif}"
    "main{width:100%;max-width:26rem;background:var(--surface);"
    "border:1px solid var(--line);border-radius:20px;padding:2.5rem 1.75rem 2rem}"
    ".seal{position:relative;width:6rem;height:6rem;margin:0 auto 1.25rem;"
    "border-radius:50%;border:2px solid var(--accent);display:grid;place-items:center;"
    "background:color-mix(in srgb,var(--accent) 16%,var(--surface))}"
    ".seal img{width:4.75rem;height:4.75rem;object-fit:contain;border-radius:50%}"
    ".mono{font:600 2.5rem/1 var(--serif)}"
    ".badge{position:absolute;right:-.25rem;bottom:-.25rem;width:2.25rem;"
    "height:2.25rem;border-radius:50%;display:grid;place-items:center;color:#fff;"
    "background:var(--ok);border:3px solid var(--surface)}"
    ".bad .badge{background:var(--bad)}"
    ".badge svg{width:1.1rem;height:1.1rem}"
    ".brand{margin:0 0 .25rem;color:var(--muted);font-size:.95rem}"
    "h1{margin:0 0 .75rem;font:600 1.75rem/1.2 var(--serif);text-wrap:balance}"
    ".msg{margin:0;text-wrap:pretty}"
    ".visit{display:inline-block;margin-top:1.25rem;padding:.75rem .5rem;"
    "color:var(--muted);font-size:.95rem}"
    "a:focus-visible{outline:3px solid var(--accent);outline-offset:2px;border-radius:4px}"
    "@media (max-width:30rem){body{justify-content:flex-start;"
    "padding-top:max(10vh,env(safe-area-inset-top))}"
    "main{border-radius:16px;padding:2rem 1.25rem 1.5rem}}"
    "@media (prefers-reduced-motion:no-preference){"
    ".badge{animation:stamp .45s cubic-bezier(.2,1.6,.4,1) .15s both}"
    "@keyframes stamp{from{transform:scale(0)}to{transform:scale(1)}}}"
    "@media (forced-colors:active){.seal,.badge{border-color:CanvasText}}"
)

_CHECK_SVG = (
    "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\" fill=\"none\" stroke=\"currentColor\" "
    "stroke-width=\"3.2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
    "<path d=\"M5 12.5l4.5 4.5L19 7.5\"/></svg>"
)

_CROSS_SVG = (
    "<svg viewBox=\"0 0 24 24\" aria-hidden=\"true\" fill=\"none\" stroke=\"currentColor\" "
    "stroke-width=\"3.2\" stroke-linecap=\"round\"><path d=\"M7 7l10 10M17 7L7 17\"/></svg>"
)


def _page(title: str, message_html: str, ok: bool) -> str:
    """The browser page for every HTML response. ``message_html`` is trusted
    markup: callers escape anything they interpolate into it."""
    b, _ = brand()
    name = html.escape(b["name"])
    title = html.escape(title)
    state, badge = ("ok", _CHECK_SVG) if ok else ("bad", _CROSS_SVG)
    if b["logo"]:
        logo = html.escape(b["logo"])
        mark = f"<img src=\"{logo}\" alt=\"\" width=\"76\" height=\"76\">"
        icon = f"<link rel=\"icon\" href=\"{logo}\">"
    else:
        mark = f"<span class=\"mono\" aria-hidden=\"true\">{html.escape(b['name'][:1].upper())}</span>"
        icon = ""
    visit = ""
    if b["url"]:
        visit = f"<a class=\"visit\" href=\"{html.escape(b['url'])}\">Visit the {name} website</a>"
    return (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">"
        "<meta name=\"robots\" content=\"noindex\">"
        "<meta name=\"theme-color\" content=\"#e8eaee\" media=\"(prefers-color-scheme: light)\">"
        "<meta name=\"theme-color\" content=\"#141519\" media=\"(prefers-color-scheme: dark)\">"
        f"<title>{title} – {name}</title>{icon}"
        f"<style>:root{{--accent:{b['accent']}}}{_PAGE_CSS}</style></head>"
        f"<body><main class=\"{state}\">"
        f"<div class=\"seal\">{mark}<span class=\"badge\">{badge}</span></div>"
        f"<p class=\"brand\">{name}</p><h1>{title}</h1>"
        f"<p class=\"msg\">{message_html}</p>{visit}</main></body></html>"
    )


# ── Server bootstrap ──────────────────────────────────────────────────────────


class _ThreadingHTTPServer6(ThreadingHTTPServer):
    """IPv6 variant of ThreadingHTTPServer for the ::1 loopback companion."""

    address_family = socket.AF_INET6


def _start_ipv6_loopback_companion(port: int) -> ThreadingHTTPServer | None:
    """Also listen on [::1].

    Browsers resolve ``localhost`` to both ``127.0.0.1`` and ``::1`` and often
    try IPv6 first. The primary server binds IPv4 loopback, so without this the
    browser-side ``/auth/login`` and ``/auth/callback`` would hit ``::1`` and be
    refused — breaking the OAuth round-trip even though the MUD's IPv4 polling
    works. This keeps the service loopback-only while covering both families.

    Returns the companion server (or ``None`` if the bind failed) so the
    caller can shut it down alongside the primary one -- otherwise its
    listening socket and daemon thread outlive every test that starts one.
    """
    try:
        comp = _ThreadingHTTPServer6(("::1", port), AuthHandler)
    except OSError as exc:
        _log(f"[auth] IPv6 loopback companion not started: {exc}")
        return None
    threading.Thread(target=comp.serve_forever, daemon=True).start()
    _log(f"[auth] also listening on [::1]:{port} (IPv6 loopback)")
    return comp


def make_server(host: str, port: int) -> ThreadingHTTPServer:
    # Validate before binding anything: a hop count we cannot use degrades the
    # origin binding, so it has to stop the service, not be clamped into
    # something that looks fine.
    hops = _configure_trusted_proxy_hops()
    token = _configure_auth_service_token()
    configs = _load_provider_configs()
    flow = _State()

    AuthHandler.configs = configs
    AuthHandler.flow = flow

    httpd = ThreadingHTTPServer((host, port), AuthHandler)
    # The port actually bound -- not the requested `port`, which is 0 on an
    # ephemeral bind (AUTH_BIND=127.0.0.1:0). Everything below must report
    # and reuse this, or an ephemeral bind gets a banner that names the wrong
    # port and an IPv6 companion that binds an unrelated random port of its
    # own instead of matching the primary listener.
    bound_port = httpd.server_address[1]

    # When bound to IPv4 loopback, also cover IPv6 loopback so browsers that
    # prefer ::1 for "localhost" can still reach the login/callback endpoints.
    # Stashed on httpd so a caller (tests, in particular) can shut it down
    # alongside the primary server instead of leaking its socket and thread.
    httpd.ipv6_companion = None
    if host in ("127.0.0.1", "localhost"):
        httpd.ipv6_companion = _start_ipv6_loopback_companion(bound_port)

    def _janitor() -> None:
        while True:
            time.sleep(60)
            flow.sweep()

    threading.Thread(target=_janitor, daemon=True).start()
    if not token:
        _log(
            "[auth] AUTH_SERVICE_TOKEN is not set — the game is identified only "
            "by loopback peer + absent forwarding headers. If the reverse proxy "
            "ever stops adding those headers, every internet request looks like "
            "the game and the origin check is skipped entirely. Set "
            "AUTH_SERVICE_TOKEN here and in the game's environment to close "
            "this gap; see docs/deploy.md for the migration order."
        )
    for problem in brand()[1]:
        _log(f"[auth] {problem}")
    _log(
        f"[auth] mudauth {__version__} on {host}:{bound_port} — "
        f"providers: {sorted(configs.keys()) or '(none configured)'} — "
        f"trusted proxy hops: {hops} — "
        f"auth service token: {'configured' if token else 'NOT SET'}"
    )
    return httpd
