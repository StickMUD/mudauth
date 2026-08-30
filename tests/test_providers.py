"""Unit tests for per-provider OAuth logic (providers.py).

These never hit the network: the profile fetch's HTTP helper is monkeypatched.
They lock in the provider-specific details that are easy to get wrong (Discord's
snowflake id must be stringified, display_name falls back through global_name).
"""

import os
import time
import unittest
import unittest.mock
from urllib.parse import parse_qs, urlparse

from mudauth import providers
from mudauth.providers import ProviderConfig

CFG = ProviderConfig(
    "client-id", "client-secret", "http://localhost:7700/auth/callback"
)


class AuthorizeUrlTest(unittest.TestCase):
    def test_discord_authorize_url(self):
        url = providers.build_authorize_url("discord", CFG, "state-123")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://discord.com/oauth2/authorize",
        )
        self.assertEqual(q["scope"], ["identify"])
        self.assertEqual(q["response_type"], ["code"])
        self.assertEqual(q["client_id"], ["client-id"])
        self.assertEqual(
            q["redirect_uri"], ["http://localhost:7700/auth/callback"]
        )
        self.assertEqual(q["state"], ["state-123"])

    def test_all_providers_build_an_authorize_url(self):
        for p in providers.SUPPORTED_PROVIDERS:
            url = providers.build_authorize_url(p, CFG, "s")
            self.assertTrue(url.startswith("https://"), p)
            if p == "steam":
                continue  # OpenID 2.0: state rides inside openid.return_to
            self.assertEqual(parse_qs(urlparse(url).query)["state"], ["s"], p)

    def test_all_providers_request_the_code_flow(self):
        # Every provider must explicitly request the authorization-code flow;
        # GitHub once relied on its default, which this guards against.
        for p in providers.SUPPORTED_PROVIDERS:
            if p == "steam":
                continue  # OpenID 2.0, not OAuth2: no response_type
            q = parse_qs(urlparse(providers.build_authorize_url(p, CFG, "s")).query)
            self.assertEqual(q.get("response_type"), ["code"], p)

    def test_steam_authorize_url_is_an_openid2_checkid_setup(self):
        url = providers.build_authorize_url("steam", CFG, "state-123")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://steamcommunity.com/openid/login",
        )
        self.assertEqual(q["openid.ns"], ["http://specs.openid.net/auth/2.0"])
        self.assertEqual(q["openid.mode"], ["checkid_setup"])
        select = "http://specs.openid.net/auth/2.0/identifier_select"
        self.assertEqual(q["openid.claimed_id"], [select])
        self.assertEqual(q["openid.identity"], [select])
        # OpenID 2.0 has no state param; the CSRF state rides in return_to.
        self.assertEqual(
            q["openid.return_to"],
            ["http://localhost:7700/auth/callback?state=state-123"],
        )
        self.assertEqual(q["openid.realm"], ["http://localhost:7700"])

    def test_steam_return_to_extends_an_existing_query(self):
        cfg = ProviderConfig(
            "steam", "key", "http://localhost:7700/auth/callback?env=dev"
        )
        url = providers.build_authorize_url("steam", cfg, "s")
        q = parse_qs(urlparse(url).query)
        self.assertEqual(
            q["openid.return_to"],
            ["http://localhost:7700/auth/callback?env=dev&state=s"],
        )

    def test_unsupported_provider_raises(self):
        with self.assertRaises(ValueError):
            providers.build_authorize_url("myspace", CFG, "s")

    def test_facebook_authorize_url(self):
        url = providers.build_authorize_url("facebook", CFG, "state-123")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://www.facebook.com/v25.0/dialog/oauth",
        )
        # public_profile is default-granted; email would add review friction.
        self.assertEqual(q["scope"], ["public_profile"])
        self.assertEqual(q["response_type"], ["code"])
        self.assertEqual(q["client_id"], ["client-id"])
        self.assertEqual(q["state"], ["state-123"])

    def test_apple_authorize_url(self):
        url = providers.build_authorize_url("apple", CFG, "state-123")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://appleid.apple.com/auth/authorize",
        )
        # No scopes: requesting name/email would force response_mode=form_post
        # (a POST callback the service does not accept). Scope-less keeps the
        # callback a plain GET redirect.
        self.assertNotIn("scope", q)
        self.assertNotIn("response_mode", q)
        self.assertEqual(q["response_type"], ["code"])
        self.assertEqual(q["client_id"], ["client-id"])
        self.assertEqual(q["state"], ["state-123"])

    def test_twitch_authorize_url(self):
        url = providers.build_authorize_url("twitch", CFG, "state-123")
        parsed = urlparse(url)
        q = parse_qs(parsed.query, keep_blank_values=True)
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://id.twitch.tv/oauth2/authorize",
        )
        # Login-only: Twitch accepts an empty scope list.
        self.assertEqual(q["scope"], [""])
        self.assertEqual(q["response_type"], ["code"])
        self.assertEqual(q["client_id"], ["client-id"])
        self.assertEqual(q["state"], ["state-123"])


class FetchProviderUserTest(unittest.TestCase):
    def setUp(self):
        self._orig_get = providers._get
        self.addCleanup(setattr, providers, "_get", self._orig_get)

    def _stub_get(self, payload, capture=None):
        def fake(url, *, headers):
            if capture is not None:
                capture["url"] = url
                capture["headers"] = headers
            return payload

        providers._get = fake

    def test_discord_maps_global_name_and_strings_id(self):
        cap = {}
        self._stub_get(
            {"id": 1234567890, "username": "gamer", "global_name": "Cool Gamer"},
            cap,
        )
        user = providers.fetch_provider_user("discord", CFG, "tok")
        self.assertEqual(cap["url"], "https://discord.com/api/users/@me")
        self.assertEqual(cap["headers"]["Authorization"], "Bearer tok")
        # Discord/Cloudflare rejects the default urllib UA (error 1010).
        self.assertIn("User-Agent", cap["headers"])
        self.assertEqual(user.provider, "discord")
        self.assertEqual(user.provider_id, "1234567890")  # stringified snowflake
        self.assertEqual(user.username, "gamer")
        self.assertEqual(user.display_name, "Cool Gamer")

    def test_discord_display_name_falls_back_to_username(self):
        self._stub_get({"id": "42", "username": "gamer", "global_name": None})
        user = providers.fetch_provider_user("discord", CFG, "tok")
        self.assertEqual(user.display_name, "gamer")

    def test_discord_missing_fields_returns_none(self):
        self._stub_get({"id": "42"})  # no username
        self.assertIsNone(providers.fetch_provider_user("discord", CFG, "tok"))

    def test_google_maps_sub_and_email(self):
        cap = {}
        self._stub_get(
            {"sub": "108234", "email": "player@gmail.com", "name": "Real Name"},
            cap,
        )
        user = providers.fetch_provider_user("google", CFG, "tok")
        self.assertEqual(
            cap["url"], "https://www.googleapis.com/oauth2/v3/userinfo"
        )
        self.assertEqual(user.provider, "google")
        self.assertEqual(user.provider_id, "108234")
        self.assertEqual(user.username, "player@gmail.com")
        self.assertEqual(user.display_name, "Real Name")

    def test_google_display_name_falls_back_to_email(self):
        self._stub_get({"sub": "108234", "email": "player@gmail.com"})
        user = providers.fetch_provider_user("google", CFG, "tok")
        self.assertEqual(user.display_name, "player@gmail.com")

    def test_google_missing_sub_returns_none(self):
        self._stub_get({"email": "x@gmail.com"})  # no sub
        self.assertIsNone(providers.fetch_provider_user("google", CFG, "tok"))

    def test_microsoft_prefers_mail_then_upn(self):
        cap = {}
        self._stub_get(
            {
                "id": "AAD-123",
                "mail": "p@contoso.com",
                "userPrincipalName": "p@contoso.onmicrosoft.com",
                "displayName": "Player One",
            },
            cap,
        )
        user = providers.fetch_provider_user("microsoft", CFG, "tok")
        self.assertEqual(cap["url"], "https://graph.microsoft.com/v1.0/me")
        self.assertEqual(user.provider, "microsoft")
        self.assertEqual(user.provider_id, "AAD-123")
        self.assertEqual(user.username, "p@contoso.com")  # mail wins over UPN
        self.assertEqual(user.display_name, "Player One")

    def test_microsoft_falls_back_to_upn_then_username(self):
        self._stub_get({"id": "AAD-123", "userPrincipalName": "p@x.com"})
        user = providers.fetch_provider_user("microsoft", CFG, "tok")
        self.assertEqual(user.username, "p@x.com")  # no mail -> UPN
        self.assertEqual(user.display_name, "p@x.com")  # no displayName -> name

    def test_microsoft_missing_id_returns_none(self):
        self._stub_get({"mail": "x@x.com"})  # no id
        self.assertIsNone(providers.fetch_provider_user("microsoft", CFG, "tok"))

    def test_twitch_maps_helix_user_and_sends_client_id(self):
        cap = {}
        self._stub_get(
            {"data": [{"id": 141981764, "login": "gamer", "display_name": "Gamer"}]},
            cap,
        )
        user = providers.fetch_provider_user("twitch", CFG, "tok")
        self.assertEqual(cap["url"], "https://api.twitch.tv/helix/users")
        self.assertEqual(cap["headers"]["Authorization"], "Bearer tok")
        # Helix rejects requests without the app's Client-Id header.
        self.assertEqual(cap["headers"]["Client-Id"], "client-id")
        self.assertEqual(user.provider, "twitch")
        self.assertEqual(user.provider_id, "141981764")
        self.assertEqual(user.username, "gamer")
        self.assertEqual(user.display_name, "Gamer")

    def test_twitch_display_name_falls_back_to_login(self):
        self._stub_get({"data": [{"id": "1", "login": "gamer"}]})
        user = providers.fetch_provider_user("twitch", CFG, "tok")
        self.assertEqual(user.display_name, "gamer")

    def test_twitch_empty_or_missing_data_returns_none(self):
        self._stub_get({"data": []})
        self.assertIsNone(providers.fetch_provider_user("twitch", CFG, "tok"))
        self._stub_get({})
        self.assertIsNone(providers.fetch_provider_user("twitch", CFG, "tok"))

    def test_facebook_maps_profile(self):
        cap = {}
        self._stub_get({"id": 10218765, "name": "Play Er"}, cap)
        user = providers.fetch_provider_user("facebook", CFG, "tok")
        parsed = urlparse(cap["url"])
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://graph.facebook.com/v25.0/me",
        )
        self.assertEqual(cap["headers"]["Authorization"], "Bearer tok")
        self.assertEqual(user.provider, "facebook")
        self.assertEqual(user.provider_id, "10218765")
        self.assertEqual(user.username, "Play Er")
        self.assertEqual(user.display_name, "Play Er")

    def test_facebook_missing_id_returns_none(self):
        self._stub_get({"name": "Play Er"})
        self.assertIsNone(providers.fetch_provider_user("facebook", CFG, "tok"))

    def test_facebook_missing_name_returns_none(self):
        self._stub_get({"id": "10218765"})
        self.assertIsNone(providers.fetch_provider_user("facebook", CFG, "tok"))

    def test_twitch_row_without_login_returns_none(self):
        self._stub_get({"data": [{"id": "1", "display_name": "Gamer"}]})
        self.assertIsNone(providers.fetch_provider_user("twitch", CFG, "tok"))


class TokenExchangeTest(unittest.TestCase):
    def setUp(self):
        for name in ("_get", "_post"):
            self.addCleanup(setattr, providers, name, getattr(providers, name))

    def _stub_post(self, payload, capture):
        def fake(url, *, data, headers):
            capture["url"] = url
            capture["data"] = data
            capture["headers"] = headers
            return payload

        providers._post = fake

    def test_twitch_token_exchange_posts_the_form(self):
        cap = {}
        self._stub_post({"access_token": "tw-tok"}, cap)
        token = providers.exchange_code_for_token("twitch", CFG, "the-code")
        self.assertEqual(token, "tw-tok")
        self.assertEqual(cap["url"], "https://id.twitch.tv/oauth2/token")
        self.assertEqual(
            cap["headers"]["Content-Type"], "application/x-www-form-urlencoded"
        )
        form = parse_qs(cap["data"].decode())
        self.assertEqual(form["client_id"], ["client-id"])
        self.assertEqual(form["code"], ["the-code"])
        self.assertEqual(form["grant_type"], ["authorization_code"])

    def test_facebook_token_exchange_posts_the_form(self):
        # The exchange must be a form POST: credentials in a GET query string
        # would be written to the log verbatim by _get's error paths.
        cap = {}
        self._stub_post({"access_token": "fb-tok", "token_type": "bearer"}, cap)
        providers._get = lambda url, *, headers: self.fail(
            f"unexpected HTTP GET {url}"
        )
        token = providers.exchange_code_for_token("facebook", CFG, "the-code")
        self.assertEqual(token, "fb-tok")
        self.assertEqual(
            cap["url"], "https://graph.facebook.com/v25.0/oauth/access_token"
        )
        self.assertEqual(
            cap["headers"]["Content-Type"], "application/x-www-form-urlencoded"
        )
        form = parse_qs(cap["data"].decode())
        self.assertEqual(form["client_id"], ["client-id"])
        self.assertEqual(form["client_secret"], ["client-secret"])
        self.assertEqual(form["code"], ["the-code"])
        self.assertEqual(
            form["redirect_uri"], ["http://localhost:7700/auth/callback"]
        )


class RedactUrlTest(unittest.TestCase):
    def test_query_string_is_redacted(self):
        # Query strings can carry secrets (Steam's key= param), so the HTTP
        # helpers must never log them.
        self.assertEqual(
            providers._redact_url("https://api.example/x/y?key=hush&steamids=1"),
            "https://api.example/x/y?<redacted>",
        )

    def test_query_less_url_is_unchanged(self):
        self.assertEqual(
            providers._redact_url("https://api.example/x/y"),
            "https://api.example/x/y",
        )


def _fake_jwt(payload: dict) -> str:
    import base64
    import json as _json

    def seg(obj):
        raw = base64.urlsafe_b64encode(_json.dumps(obj).encode()).decode()
        return raw.rstrip("=")  # real JWTs are unpadded

    return seg({"alg": "RS256", "kid": "k"}) + "." + seg(payload) + ".sig"


def _apple_jwt(**over) -> str:
    """A fake Apple id_token with valid standard claims by default; override any
    claim, or pass claim=None to drop it, for the negative-path tests."""
    claims = {
        "iss": "https://appleid.apple.com",
        "aud": "client-id",  # == CFG.client_id
        "exp": int(time.time()) + 3600,
        "sub": "001234.abcdef",
    }
    claims.update(over)
    return _fake_jwt({k: v for k, v in claims.items() if v is not None})


class AppleTest(unittest.TestCase):
    """Apple has no userinfo endpoint: the token exchange must surface the
    id_token, and the profile step decodes it locally with no HTTP call."""

    def setUp(self):
        self._orig_get = providers._get
        self._orig_post = providers._post
        self.addCleanup(setattr, providers, "_get", self._orig_get)
        self.addCleanup(setattr, providers, "_post", self._orig_post)
        # Any HTTP GET during an Apple flow is a bug.
        providers._get = lambda url, *, headers: self.fail(
            f"unexpected HTTP GET {url}"
        )

    def test_token_exchange_returns_the_id_token(self):
        cap = {}

        def fake_post(url, *, data, headers):
            cap["url"] = url
            cap["data"] = data
            cap["headers"] = headers
            return {"access_token": "useless", "id_token": "the-id-token"}

        providers._post = fake_post
        token = providers.exchange_code_for_token("apple", CFG, "the-code")
        self.assertEqual(token, "the-id-token")
        self.assertEqual(cap["url"], "https://appleid.apple.com/auth/token")
        self.assertEqual(
            cap["headers"]["Content-Type"], "application/x-www-form-urlencoded"
        )
        # Apple rejects requests without an explicit User-Agent.
        self.assertIn("User-Agent", cap["headers"])
        form = parse_qs(cap["data"].decode())
        self.assertEqual(form["client_id"], ["client-id"])
        self.assertEqual(form["code"], ["the-code"])
        self.assertEqual(form["grant_type"], ["authorization_code"])

    def test_exchange_without_id_token_returns_none(self):
        providers._post = lambda url, *, data, headers: {"access_token": "at"}
        self.assertIsNone(
            providers.exchange_code_for_token("apple", CFG, "the-code")
        )

    def test_profile_decodes_id_token_locally(self):
        jwt = _apple_jwt(email="p@example.com")
        user = providers.fetch_provider_user("apple", CFG, jwt)
        self.assertEqual(user.provider, "apple")
        self.assertEqual(user.provider_id, "001234.abcdef")
        self.assertEqual(user.username, "p@example.com")
        self.assertEqual(user.display_name, "p@example.com")

    def test_profile_without_email_falls_back_to_sub(self):
        jwt = _apple_jwt()
        user = providers.fetch_provider_user("apple", CFG, jwt)
        self.assertEqual(user.username, "001234.abcdef")
        self.assertEqual(user.display_name, "001234.abcdef")

    def test_malformed_id_token_returns_none(self):
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, "junk"))
        self.assertIsNone(
            providers.fetch_provider_user("apple", CFG, "a.!!!not-base64!!!.c")
        )

    def test_id_token_without_sub_returns_none(self):
        jwt = _fake_jwt({"email": "p@example.com"})
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_wrong_aud_returns_none(self):
        jwt = _apple_jwt(aud="some-other-client")
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_wrong_iss_returns_none(self):
        jwt = _apple_jwt(iss="https://evil.example")
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_missing_iss_returns_none(self):
        jwt = _apple_jwt(iss=None)
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_missing_aud_returns_none(self):
        jwt = _apple_jwt(aud=None)
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_aud_list_without_client_id_is_rejected(self):
        # Pins the negative half of the list branch: a token minted for a
        # different Apple app must not sign anyone in here.
        jwt = _apple_jwt(aud=["other-a", "other-b"])
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_aud_list_containing_client_id_is_accepted(self):
        jwt = _apple_jwt(aud=["client-id", "some-other-client"])
        user = providers.fetch_provider_user("apple", CFG, jwt)
        self.assertIsNotNone(user)
        self.assertEqual(user.provider_id, "001234.abcdef")

    def test_id_token_expired_returns_none(self):
        jwt = _apple_jwt(exp=int(time.time()) - 3600)
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))

    def test_id_token_missing_exp_returns_none(self):
        jwt = _apple_jwt(exp=None)
        self.assertIsNone(providers.fetch_provider_user("apple", CFG, jwt))


STEAM_CFG = ProviderConfig(
    "steam", "web-api-key", "http://localhost:7700/auth/callback"
)

_STEAMID = "76561198012345678"


class SteamTest(unittest.TestCase):
    """Steam is OpenID 2.0: the callback carries a signed assertion that must
    be echoed back to Steam (check_authentication) instead of a code that is
    exchanged for a token."""

    def setUp(self):
        for name in ("_get", "_post_text"):
            orig = getattr(providers, name, None)
            if orig is not None:
                self.addCleanup(setattr, providers, name, orig)

    def _q(self, **over):
        q = {
            "state": ["state-123"],
            "openid.ns": ["http://specs.openid.net/auth/2.0"],
            "openid.mode": ["id_res"],
            "openid.op_endpoint": ["https://steamcommunity.com/openid/login"],
            "openid.claimed_id": [
                f"https://steamcommunity.com/openid/id/{_STEAMID}"
            ],
            "openid.identity": [
                f"https://steamcommunity.com/openid/id/{_STEAMID}"
            ],
            "openid.return_to": [
                "http://localhost:7700/auth/callback?state=state-123"
            ],
            "openid.response_nonce": ["2026-07-04T00:00:00Zabc"],
            "openid.assoc_handle": ["1234567890"],
            "openid.signed": ["signed,op_endpoint,claimed_id"],
            "openid.sig": ["c2ln"],
        }
        q.update(over)
        return q

    def _stub_verify(self, body, capture=None):
        def fake(url, *, data, headers):
            if capture is not None:
                capture["url"] = url
                capture["data"] = data
                capture["headers"] = headers
            return body

        providers._post_text = fake

    def _forbid_network(self):
        providers._post_text = lambda url, *, data, headers: self.fail(
            f"unexpected HTTP POST {url}"
        )

    def test_valid_assertion_returns_the_steamid(self):
        cap = {}
        self._stub_verify("ns:http://specs.openid.net/auth/2.0\nis_valid:true\n", cap)
        steamid = providers.verify_steam_assertion(self._q(), STEAM_CFG)
        self.assertEqual(steamid, _STEAMID)
        self.assertEqual(cap["url"], "https://steamcommunity.com/openid/login")
        form = parse_qs(cap["data"].decode())
        # The assertion is echoed back verbatim, mode swapped to verify.
        self.assertEqual(form["openid.mode"], ["check_authentication"])
        self.assertEqual(form["openid.sig"], ["c2ln"])

    def test_invalid_signature_is_rejected(self):
        self._stub_verify("ns:http://specs.openid.net/auth/2.0\nis_valid:false\n")
        self.assertIsNone(providers.verify_steam_assertion(self._q(), STEAM_CFG))

    def test_foreign_claimed_id_is_rejected_before_any_network(self):
        self._forbid_network()
        q = self._q(**{
            "openid.claimed_id": [f"https://evil.example/openid/id/{_STEAMID}"]
        })
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_non_numeric_steamid_is_rejected(self):
        self._forbid_network()
        q = self._q(**{
            "openid.claimed_id": ["https://steamcommunity.com/openid/id/../4"]
        })
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_non_id_res_mode_is_rejected_before_any_network(self):
        self._forbid_network()
        q = self._q(**{"openid.mode": ["cancel"]})
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_return_to_for_another_site_is_rejected(self):
        self._forbid_network()
        q = self._q(**{
            "openid.return_to": ["https://attacker.example/auth/callback?state=state-123"]
        })
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_return_to_path_suffix_is_rejected(self):
        # A bare prefix check would accept /auth/callback.evil; the path must
        # match the configured callback exactly.
        self._forbid_network()
        q = self._q(**{
            "openid.return_to": [
                "http://localhost:7700/auth/callback.evil/x?state=state-123"
            ]
        })
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_return_to_embedded_state_mismatch_is_rejected(self):
        # The Steam-signed state inside return_to must match the top-level
        # state used to pop the pending login, or a signed assertion minted
        # for one flow could be replayed against another.
        self._forbid_network()
        q = self._q(**{
            "openid.return_to": [
                "http://localhost:7700/auth/callback?state=other-state"
            ]
        })
        self.assertIsNone(providers.verify_steam_assertion(q, STEAM_CFG))

    def test_profile_maps_personaname(self):
        cap = {}

        def fake_get(url, *, headers):
            cap["url"] = url
            return {
                "response": {
                    "players": [{"steamid": _STEAMID, "personaname": "Gamer"}]
                }
            }

        providers._get = fake_get
        user = providers.fetch_provider_user("steam", STEAM_CFG, _STEAMID)
        parsed = urlparse(cap["url"])
        self.assertEqual(
            f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/",
        )
        q = parse_qs(parsed.query)
        self.assertEqual(q["key"], ["web-api-key"])
        self.assertEqual(q["steamids"], [_STEAMID])
        self.assertEqual(user.provider, "steam")
        self.assertEqual(user.provider_id, _STEAMID)
        self.assertEqual(user.username, "Gamer")
        self.assertEqual(user.display_name, "Gamer")

    def test_profile_falls_back_to_steamid_when_summary_unavailable(self):
        # The OpenID assertion already proved the identity; the summary only
        # decorates it, so a failed lookup must not fail the login.
        providers._get = lambda url, *, headers: None
        user = providers.fetch_provider_user("steam", STEAM_CFG, _STEAMID)
        self.assertEqual(user.provider_id, _STEAMID)
        self.assertEqual(user.username, _STEAMID)


class UserAgentTest(unittest.TestCase):
    def test_default_user_agent_names_mudauth_and_version(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_USER_AGENT", None)
            from mudauth import __version__
            self.assertEqual(providers.user_agent(), f"mudauth/{__version__}")

    def test_user_agent_env_override(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_USER_AGENT": "MyMUD/2 (+https://mymud.example)"}):
            self.assertEqual(providers.user_agent(), "MyMUD/2 (+https://mymud.example)")


if __name__ == "__main__":
    unittest.main()
