"""Per-provider identity logic (OAuth2 / OIDC / OpenID 2.0) for mudauth.

Ports the three provider-specific operations from MUDdown's `auth.ts`
(`buildAuthorizeUrl`, `exchangeCodeForToken`, `fetchProviderUser`) using only
the Python standard library (urllib) so the service needs no third-party deps.
Steam adds a fourth, `verify_steam_assertion`, because OpenID 2.0 has no code
exchange: the callback's signed assertion is verified directly instead.

Each provider maps its profile onto a normalized ``ProviderUser``
(provider, provider_id, username, display_name).
"""

from __future__ import annotations

import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass
class ProviderUser:
    """Normalized identity returned by a provider's profile fetch."""

    provider: str
    provider_id: str
    username: str
    display_name: str


SUPPORTED_PROVIDERS = (
    "discord",
    "github",
    "microsoft",
    "google",
    "twitch",
    "facebook",
    "apple",
    "steam",
)

PROVIDER_DISPLAY_NAMES = {
    "discord": "Discord",
    "github": "GitHub",
    "microsoft": "Microsoft",
    "google": "Google",
    "twitch": "Twitch",
    "facebook": "Facebook",
    "apple": "Apple",
    "steam": "Steam",
}

_STEAM_OPENID_ENDPOINT = "https://steamcommunity.com/openid/login"
_STEAM_CLAIMED_ID_PREFIX = "https://steamcommunity.com/openid/id/"

# Apple id_token issuer, checked (alongside aud/exp) when we decode the token
# locally in the Apple profile step.
_APPLE_ISSUER = "https://appleid.apple.com"

# Pin the Graph API version so Meta's rolling deprecations cannot change
# behaviour under us; bump deliberately. The one constant feeds both the
# www.facebook.com login dialog and the graph.facebook.com endpoints.
_FACEBOOK_VERSION = "v25.0"
_FACEBOOK_GRAPH = f"https://graph.facebook.com/{_FACEBOOK_VERSION}"

# OpenID configuration discovery doc advertised via Char.Login.Default.location.
# Providers that publish a standard document are listed; the rest (Discord,
# GitHub, Facebook, Steam) fall back to the service's own metadata.
OPENID_CONFIG_URLS = {
    "google": "https://accounts.google.com/.well-known/openid-configuration",
    "microsoft": "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    "twitch": "https://id.twitch.tv/oauth2/.well-known/openid-configuration",
    "apple": "https://appleid.apple.com/.well-known/openid-configuration",
}

_FETCH_TIMEOUT = 10  # seconds


def user_agent() -> str:
    """Outbound User-Agent. Discord's Cloudflare front rejects the default
    ``Python-urllib`` agent, so every call identifies itself. Operators should
    set AUTH_USER_AGENT to something naming their own game and contact URL."""
    from . import __version__

    return os.environ.get("AUTH_USER_AGENT") or f"mudauth/{__version__}"


@dataclass
class ProviderConfig:
    client_id: str
    client_secret: str
    callback_url: str


def display_name(provider: str) -> str:
    return PROVIDER_DISPLAY_NAMES.get(provider, provider.capitalize())


# ── Authorize URL ─────────────────────────────────────────────────────────────


def build_authorize_url(provider: str, cfg: ProviderConfig, state: str) -> str:
    if provider == "discord":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            "scope": "identify",
            "state": state,
        }
        return "https://discord.com/oauth2/authorize?" + urllib.parse.urlencode(params)
    if provider == "github":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            "scope": "read:user",
            "state": state,
        }
        return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(params)
    if provider == "microsoft":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            "scope": "openid profile email User.Read",
            "state": state,
        }
        return (
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"
            + urllib.parse.urlencode(params)
        )
    if provider == "google":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
        }
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    if provider == "twitch":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            # Login-only: Twitch accepts an empty scope list, and Helix
            # /users returns the token owner's public profile without scopes.
            "scope": "",
            "state": state,
        }
        return "https://id.twitch.tv/oauth2/authorize?" + urllib.parse.urlencode(params)
    if provider == "facebook":
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            # public_profile is default-granted; email would need extra
            # portal setup and Facebook accounts often lack one anyway.
            "scope": "public_profile",
            "state": state,
        }
        return (
            f"https://www.facebook.com/{_FACEBOOK_VERSION}/dialog/oauth?"
            + urllib.parse.urlencode(params)
        )
    if provider == "apple":
        # Deliberately scope-less: requesting name/email forces
        # response_mode=form_post (a POST callback this service does not
        # accept). The id_token still carries the stable sub, and email when
        # Apple includes it.
        params = {
            "client_id": cfg.client_id,
            "redirect_uri": cfg.callback_url,
            "response_type": "code",
            "state": state,
        }
        return "https://appleid.apple.com/auth/authorize?" + urllib.parse.urlencode(params)
    if provider == "steam":
        # OpenID 2.0, not OAuth2. There is no state param: the CSRF state
        # rides inside return_to, which Steam signs and echoes back.
        cb = urllib.parse.urlparse(cfg.callback_url)
        sep = "&" if cb.query else "?"
        params = {
            "openid.ns": "http://specs.openid.net/auth/2.0",
            "openid.mode": "checkid_setup",
            "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
            "openid.return_to": cfg.callback_url + sep + "state=" + urllib.parse.quote(state),
            "openid.realm": f"{cb.scheme}://{cb.netloc}",
        }
        return _STEAM_OPENID_ENDPOINT + "?" + urllib.parse.urlencode(params)
    raise ValueError(f"Unsupported provider: {provider}")


# ── HTTP helpers (stdlib) ─────────────────────────────────────────────────────


def _post(url: str, *, data: bytes, headers: dict[str, str]) -> dict | None:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        print(f"[auth] POST {_redact_url(url)} failed: {exc.code} {detail!r}")
        return None
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[auth] POST {_redact_url(url)} error: {exc}")
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        print(f"[auth] POST {_redact_url(url)} returned non-JSON body")
        return None


def _redact_url(url: str) -> str:
    """Drop the query from a URL destined for a log line — GET queries carry
    credentials (Steam's ``key=``), and logs get pasted into issues."""
    split = urllib.parse.urlsplit(url)
    if not split.query:
        return url
    return urllib.parse.urlunsplit(split._replace(query="<redacted>"))


def _get(url: str, *, headers: dict[str, str]) -> dict | None:
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        print(f"[auth] GET {_redact_url(url)} failed: {exc.code} {detail!r}")
        return None
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[auth] GET {_redact_url(url)} error: {exc}")
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        print(f"[auth] GET {_redact_url(url)} returned non-JSON body")
        return None


def _post_text(url: str, *, data: bytes, headers: dict[str, str]) -> str | None:
    """POST like _post(), but return the raw body (Steam's OpenID verify
    endpoint answers in plain-text key:value lines, not JSON)."""
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        print(f"[auth] POST {_redact_url(url)} failed: {exc.code} {detail!r}")
        return None
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"[auth] POST {_redact_url(url)} error: {exc}")
        return None


def _decode_jwt_payload(token: str) -> dict | None:
    """Decode a JWT's payload segment without verifying the signature."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(seg))
    except (ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


# ── Token exchange ────────────────────────────────────────────────────────────


def exchange_code_for_token(
    provider: str, cfg: ProviderConfig, code: str
) -> str | None:
    form = {
        "client_id": cfg.client_id,
        "client_secret": cfg.client_secret,
        "code": code,
        "redirect_uri": cfg.callback_url,
        "grant_type": "authorization_code",
    }

    if provider == "github":
        # GitHub expects JSON and returns JSON when Accept: application/json.
        data = json.dumps(
            {
                "client_id": cfg.client_id,
                "client_secret": cfg.client_secret,
                "code": code,
                "redirect_uri": cfg.callback_url,
            }
        ).encode()
        result = _post(
            "https://github.com/login/oauth/access_token",
            data=data,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
    elif provider == "discord":
        result = _post(
            "https://discord.com/api/oauth2/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
    elif provider == "microsoft":
        result = _post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
    elif provider == "google":
        result = _post(
            "https://oauth2.googleapis.com/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
    elif provider == "twitch":
        result = _post(
            "https://id.twitch.tv/oauth2/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
    elif provider == "facebook":
        # Graph documents the exchange as a GET, but it accepts the same form
        # POST as everyone else — and a GET would put client_secret in a URL
        # that the helpers' error paths write to the log.
        result = _post(
            _FACEBOOK_GRAPH + "/oauth/access_token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
    elif provider == "apple":
        # Apple has no userinfo endpoint: identity lives in the id_token, so
        # that is the token this flow carries forward, not the access token.
        # (client_secret here is the pre-generated ES256 JWT; see
        # deploy/make_apple_secret.py.)
        result = _post(
            "https://appleid.apple.com/auth/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": user_agent(),
            },
        )
        if not result:
            return None
        id_token = result.get("id_token")
        if not id_token:
            detail = result.get("error_description") or result.get("error") or "no id_token"
            print(f"[auth] apple token error: {repr(detail)[:200]}")
            return None
        return id_token
    else:
        raise ValueError(f"Unsupported provider: {provider}")

    if not result:
        return None
    token = result.get("access_token")
    if not token:
        error = result.get("error")
        if isinstance(error, dict):
            # Facebook nests its error as {"error": {"message": ...}}; the other
            # providers use flat OAuth2 error/error_description strings.
            detail = error.get("message") or "no access_token"
        else:
            detail = result.get("error_description") or error or "no access_token"
        print(f"[auth] {provider} token error: {repr(detail)[:200]}")
        return None
    return token


# ── Steam OpenID 2.0 verification ─────────────────────────────────────────────


def verify_steam_assertion(q: dict, cfg: ProviderConfig) -> str | None:
    """Verify a Steam OpenID 2.0 positive assertion from callback params.

    ``q`` is the parse_qs-style query dict. Returns the steamid64 on success.
    The claimed_id prefix, the numeric steamid, and the return_to origin and
    embedded state are all checked before any network call; the signature
    itself is verified by echoing the assertion back to Steam with
    mode=check_authentication (direct verification).
    """
    # Only a positive assertion (id_res) is a login. Anything else -- a cancel,
    # a setup_needed, or a malformed callback -- must never reach
    # check_authentication or be treated as a sign-in by any caller.
    mode = q.get("openid.mode", [""])[0]
    if mode != "id_res":
        print(f"[auth] steam: non-assertion openid.mode rejected: {mode[:100]!r}")
        return None
    claimed = q.get("openid.claimed_id", [""])[0]
    if not claimed.startswith(_STEAM_CLAIMED_ID_PREFIX):
        print(f"[auth] steam: foreign claimed_id rejected: {claimed[:100]!r}")
        return None
    steamid = claimed[len(_STEAM_CLAIMED_ID_PREFIX):]
    if not steamid.isdigit():
        print(f"[auth] steam: non-numeric steamid rejected: {steamid[:100]!r}")
        return None
    # return_to is Steam-signed: its origin must be exactly our callback and
    # its embedded state must be the state that popped the pending login, or
    # an assertion minted for one flow could be replayed against another.
    rt = urllib.parse.urlsplit(q.get("openid.return_to", [""])[0])
    cb = urllib.parse.urlsplit(cfg.callback_url)
    rt_state = urllib.parse.parse_qs(rt.query).get("state", [""])[0]
    if (rt.scheme, rt.netloc, rt.path) != (cb.scheme, cb.netloc, cb.path) or (
        rt_state != q.get("state", [""])[0]
    ):
        print(f"[auth] steam: return_to mismatch rejected: {rt.geturl()[:100]!r}")
        return None

    form = {k: v[0] for k, v in q.items() if k.startswith("openid.")}
    form["openid.mode"] = "check_authentication"
    body = _post_text(
        _STEAM_OPENID_ENDPOINT,
        data=urllib.parse.urlencode(form).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": user_agent(),
        },
    )
    if body is None:
        print("[auth] steam: check_authentication got no response")
        return None
    if not any(line.strip() == "is_valid:true" for line in body.splitlines()):
        print(f"[auth] steam: assertion not confirmed: {body[:200]!r}")
        return None
    return steamid


# ── User profile ──────────────────────────────────────────────────────────────


def fetch_provider_user(
    provider: str, cfg: ProviderConfig, access_token: str
) -> ProviderUser | None:
    """Map the provider's profile onto a ProviderUser.

    ``access_token`` is whatever credential the provider's exchange step
    produced: an OAuth access token, Apple's id_token, or Steam's verified
    steamid64. Only the OAuth providers use the Bearer header built here.
    """
    auth = {"Authorization": f"Bearer {access_token}"}

    if provider == "discord":
        data = _get(
            "https://discord.com/api/users/@me",
            headers={**auth, "User-Agent": user_agent()},
        )
        if not data or not data.get("id") or not data.get("username"):
            print("[auth] discord: /users/@me returned no usable profile")
            return None
        return ProviderUser(
            provider="discord",
            provider_id=str(data["id"]),
            username=data["username"],
            display_name=data.get("global_name") or data["username"],
        )

    if provider == "github":
        data = _get(
            "https://api.github.com/user",
            headers={
                **auth,
                "Accept": "application/vnd.github+json",
                "User-Agent": user_agent(),
            },
        )
        if not data or not data.get("id") or not data.get("login"):
            print("[auth] github: /user returned no usable profile")
            return None
        return ProviderUser(
            provider="github",
            provider_id=str(data["id"]),
            username=data["login"],
            display_name=data.get("name") or data["login"],
        )

    if provider == "microsoft":
        data = _get(
            "https://graph.microsoft.com/v1.0/me",
            headers={**auth, "User-Agent": user_agent()},
        )
        if not data or not data.get("id"):
            print("[auth] microsoft: /v1.0/me returned no usable profile")
            return None
        username = data.get("mail") or data.get("userPrincipalName") or data["id"]
        return ProviderUser(
            provider="microsoft",
            provider_id=str(data["id"]),
            username=username,
            display_name=data.get("displayName") or username,
        )

    if provider == "google":
        data = _get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={**auth, "User-Agent": user_agent()},
        )
        if not data or not data.get("sub"):
            print("[auth] google: /userinfo returned no usable profile")
            return None
        username = data.get("email") or data["sub"]
        return ProviderUser(
            provider="google",
            provider_id=str(data["sub"]),
            username=username,
            display_name=data.get("name") or username,
        )

    if provider == "twitch":
        # Helix requires the app's Client-Id header alongside the user token.
        data = _get(
            "https://api.twitch.tv/helix/users",
            headers={**auth, "Client-Id": cfg.client_id, "User-Agent": user_agent()},
        )
        rows = (data or {}).get("data") or []
        if not rows or not rows[0].get("id") or not rows[0].get("login"):
            print("[auth] twitch: /helix/users returned no usable rows")
            return None
        row = rows[0]
        return ProviderUser(
            provider="twitch",
            provider_id=str(row["id"]),
            username=row["login"],
            display_name=row.get("display_name") or row["login"],
        )

    if provider == "facebook":
        # Facebook exposes no handle-style username; the profile name serves
        # as both username and display name.
        data = _get(
            _FACEBOOK_GRAPH + "/me?fields=id,name",
            headers={**auth, "User-Agent": user_agent()},
        )
        if not data or not data.get("id") or not data.get("name"):
            print("[auth] facebook: /me returned no usable profile")
            return None
        return ProviderUser(
            provider="facebook",
            provider_id=str(data["id"]),
            username=data["name"],
            display_name=data["name"],
        )

    if provider == "apple":
        # No HTTP call: decode the id_token payload locally. It arrived
        # directly from appleid.apple.com over TLS during the code exchange,
        # so a signature check adds nothing here -- but still validate the
        # standard claims so a token minted for another client, or a stale one,
        # is refused even if upstream behaviour changes.
        claims = _decode_jwt_payload(access_token)
        if not claims or not claims.get("sub"):
            # Never log the token itself: it is a bearer credential.
            print("[auth] apple: id_token payload undecodable or missing sub")
            return None
        # Truncate the attacker-controlled claims so a crafted token cannot
        # flood the log; repr guards against control characters.
        if claims.get("iss") != _APPLE_ISSUER:
            print(f"[auth] apple: id_token iss rejected: {repr(claims.get('iss'))[:200]}")
            return None
        aud = claims.get("aud")
        aud_ok = cfg.client_id in aud if isinstance(aud, list) else aud == cfg.client_id
        if not aud_ok:
            print(f"[auth] apple: id_token aud rejected: {repr(aud)[:200]}")
            return None
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)) or exp <= time.time():
            print("[auth] apple: id_token missing or expired exp")
            return None
        sub = str(claims["sub"])
        username = claims.get("email") or sub
        return ProviderUser(
            provider="apple",
            provider_id=sub,
            username=username,
            display_name=username,
        )

    if provider == "steam":
        # ``access_token`` is the OpenID-verified steamid64, not a token. The
        # summary lookup (server-keyed, no user token) only decorates the
        # already-proven identity, so a failed lookup must not fail the login.
        query = urllib.parse.urlencode(
            {"key": cfg.client_secret, "steamids": access_token}
        )
        data = _get(
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?" + query,
            headers={"User-Agent": user_agent()},
        )
        players = ((data or {}).get("response") or {}).get("players") or []
        name = players[0].get("personaname") if players else None
        if not name:
            print(
                f"[auth] steam: no personaname for {access_token}; "
                "using the steamid64 (check STEAM_API_KEY)"
            )
        return ProviderUser(
            provider="steam",
            provider_id=access_token,
            username=name or access_token,
            display_name=name or access_token,
        )

    raise ValueError(f"Unsupported provider: {provider}")
