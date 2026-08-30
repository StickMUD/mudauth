"""End-to-end tests for the auth-service HTTP handlers (server.py).

Runs the real ThreadingHTTPServer on an ephemeral loopback port, but
monkeypatches the provider token-exchange and profile-fetch so no external
network calls happen. The service is stateless: it verifies an identity and
hands ``(provider, provider_id, username)`` back via the nonce poll. The MUD
owns accounts, characters and the login/link/create decision, so there are no
DB-backed endpoints to test here.
"""

import contextlib
import email.message
import html
import io
import json
import os
import select
import subprocess
import sys
import threading
import time
import types
import unittest
import unittest.mock
import urllib.error
import urllib.request
from urllib.parse import parse_qs, quote, urlparse

from mudauth import providers, server
from mudauth.providers import ProviderConfig, ProviderUser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response as-is instead of following or raising on it."""

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_302


def _opener():
    return urllib.request.build_opener(_NoRedirect)


@contextlib.contextmanager
def _hops(count):
    """Set the startup-validated hop count for the duration of the block.

    The request path reads the module-level value, not the environment, so
    tests set it the same way startup does.
    """
    original = server._TRUSTED_PROXY_HOPS
    server._TRUSTED_PROXY_HOPS = count
    try:
        yield
    finally:
        server._TRUSTED_PROXY_HOPS = original


@contextlib.contextmanager
def _token(value):
    """Set the startup-validated AUTH_SERVICE_TOKEN for the duration of the
    block, the same way ``_hops`` does for the proxy hop count.
    """
    original = server._AUTH_SERVICE_TOKEN
    server._AUTH_SERVICE_TOKEN = value
    try:
        yield
    finally:
        server._AUTH_SERVICE_TOKEN = original


class HandlerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cfg = {
            "github": ProviderConfig("cid", "secret", "http://cb/auth/callback"),
            "steam": ProviderConfig("steam", "api-key", "http://cb/auth/callback"),
        }
        server.AuthHandler.configs = cfg
        server.AuthHandler.flow = server._State()

        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.AuthHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

        # Stub provider network calls.
        cls._orig_exchange = providers.exchange_code_for_token
        cls._orig_fetch = providers.fetch_provider_user
        providers.exchange_code_for_token = lambda p, c, code: "fake-access-token"
        providers.fetch_provider_user = lambda p, c, t: ProviderUser(
            p, "42", "octocat", "Octo Cat"
        )
        cls._orig_verify_steam = getattr(providers, "verify_steam_assertion", None)
        # The stub checks the parse_qs shape so a handler that flattened the
        # query dict (or passed the raw string) would fail loudly here.
        providers.verify_steam_assertion = lambda q, c: (
            "76561198000000001" if q.get("openid.mode") == ["id_res"] else None
        )

    @classmethod
    def tearDownClass(cls):
        providers.exchange_code_for_token = cls._orig_exchange
        providers.fetch_provider_user = cls._orig_fetch
        if cls._orig_verify_steam is not None:
            providers.verify_steam_assertion = cls._orig_verify_steam
        else:
            del providers.verify_steam_assertion
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path):
        return _opener().open(self.base + path)

    def _get_json(self, path):
        with self._get(path) as r:
            return r.status, json.loads(r.read().decode())

    def _post_json(self, path, payload):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        with _opener().open(req) as r:
            return r.status, json.loads(r.read().decode())

    def _post_json_with_headers(self, path, payload, headers):
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.base + path, data=data,
            headers={"Content-Type": "application/json", **headers}, method="POST",
        )
        with _opener().open(req) as r:
            return r.status, json.loads(r.read().decode())

    def _get_with_headers(self, path, headers):
        req = urllib.request.Request(self.base + path, headers=headers, method="GET")
        return _opener().open(req)

    def _get_json_with_headers(self, path, headers):
        with self._get_with_headers(path, headers) as r:
            return r.status, json.loads(r.read().decode())

    @contextlib.contextmanager
    def _non_loopback_peer(self, addr="203.0.113.99"):
        """Make requests inside the block look like they came from off-box.

        The test server binds 127.0.0.1, so every real client is a loopback
        peer and the branch that ignores forwarding headers from a stranger
        would never run. ``BaseRequestHandler.__init__`` assigns
        ``client_address`` and then calls ``setup()``, so rewriting the address
        in a patched ``setup`` gives the handler exactly the state it would
        have on a request from that address — the whole dispatch, the origin
        check and the response path are the real ones.
        """
        original = server.AuthHandler.setup

        def setup(handler):
            original(handler)
            handler.client_address = (addr, 54321)

        server.AuthHandler.setup = setup
        try:
            yield
        finally:
            server.AuthHandler.setup = original

    # ── tests ─────────────────────────────────────────────────────────────

    def test_providers_lists_configured(self):
        status, body = self._get_json("/auth/providers")
        self.assertEqual(status, 200)
        self.assertEqual(body["providers"], ["github", "steam"])

    def test_login_redirects_to_provider(self):
        nonce = "11111111-1111-1111-1111-111111111111"
        with self._get(f"/auth/login/github/{nonce}") as r:
            self.assertEqual(r.status, 302)
            loc = r.headers["Location"]
        self.assertTrue(loc.startswith("https://github.com/login/oauth/authorize"))
        self.assertIn("state=", loc)

    def test_legacy_query_login_still_works(self):
        nonce = "1a1a1a1a-1111-1111-1111-111111111111"
        with self._get(f"/auth/login?provider=github&login_nonce={nonce}") as r:
            self.assertEqual(r.status, 302)

    def test_unknown_provider_404(self):
        try:
            self._get("/auth/login/nope/1c1c1c1c-1111-1111-1111-111111111111")
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_unknown_provider_response_escapes_html(self):
        # provider is attacker-controlled (it comes straight from the URL) and
        # the 404 body is served as text/html, so a raw reflection here is
        # reflected XSS on the operator's public origin.
        payload = "<script>alert(1)</script>"
        nonce = "1d1d1d1d-1111-1111-1111-111111111111"
        try:
            self._get(f"/auth/login?provider={quote(payload)}&login_nonce={nonce}")
            self.fail("expected HTTPError 404")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)
            body = e.read().decode()
            self.assertNotIn(payload, body)
            self.assertIn(html.escape(payload), body)

    def test_full_login_flow_then_poll(self):
        nonce = "22222222-2222-2222-2222-222222222222"
        # 1. start login, capture state from the redirect
        with self._get(f"/auth/login/github/{nonce}") as r:
            loc = r.headers["Location"]
        state = parse_qs(urlparse(loc).query)["state"][0]

        # 2. before callback, poll is pending
        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 202)
        self.assertEqual(body["status"], "pending")

        # 3. simulate the provider redirect to the callback
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        # 4. poll now returns the verified identity (one-time)
        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 200)
        self.assertEqual(body["provider"], "github")
        self.assertEqual(body["provider_id"], "42")
        self.assertEqual(body["username"], "octocat")

        # 5. second poll is empty (identity already retrieved)
        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 202)

    def test_steam_login_flow_uses_openid_not_code(self):
        nonce = "66666666-6666-6666-6666-666666666666"
        # 1. login redirects to Steam's OpenID endpoint, state inside return_to
        with self._get(f"/auth/login/steam/{nonce}") as r:
            self.assertEqual(r.status, 302)
            loc = r.headers["Location"]
        self.assertTrue(loc.startswith("https://steamcommunity.com/openid/login"))
        return_to = parse_qs(urlparse(loc).query)["openid.return_to"][0]
        state = parse_qs(urlparse(return_to).query)["state"][0]

        # 2. Steam redirects back with an assertion and NO code param
        with self._get(f"/auth/callback?state={state}&openid.mode=id_res") as r:
            self.assertEqual(r.status, 200)

        # 3. the verified steamid is handed out via the poll
        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 200)
        self.assertEqual(body["provider"], "steam")

    def test_steam_callback_with_bad_assertion_is_rejected(self):
        stub = providers.verify_steam_assertion
        providers.verify_steam_assertion = lambda q, c: None
        self.addCleanup(setattr, providers, "verify_steam_assertion", stub)

        nonce = "77777777-7777-7777-7777-777777777777"
        with self._get(f"/auth/login/steam/{nonce}") as r:
            return_to = parse_qs(urlparse(r.headers["Location"]).query)[
                "openid.return_to"
            ][0]
        state = parse_qs(urlparse(return_to).query)["state"][0]
        try:
            self._get(f"/auth/callback?state={state}&openid.mode=id_res")
            self.fail("expected HTTPError 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_callback_rejects_unknown_state(self):
        try:
            self._get("/auth/callback?code=x&state=does-not-exist")
            self.fail("expected HTTPError")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_callback_rejects_expired_login_state(self):
        # The TTL is enforced inline, not left to the 60s janitor sweep.
        nonce = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with server.AuthHandler.flow.lock:
            server.AuthHandler.flow.pending[state]["created_at"] -= (
                server.PENDING_TTL + 1
            )
        try:
            self._get(f"/auth/callback?code=abc&state={state}")
            self.fail("expected HTTPError 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_oauth_callback_without_code_is_rejected(self):
        # The exchange stub always succeeds, so if this check regressed the
        # suite would otherwise report a code-less callback as a login.
        nonce = "88888888-8888-8888-8888-888888888888"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        try:
            self._get(f"/auth/callback?state={state}")
            self.fail("expected HTTPError 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)

    def test_consent_denied_callback_reports_the_decline(self):
        # A provider "Cancel" comes back with error=access_denied and no code;
        # the user must not be told their login state was invalid.
        nonce = "99999999-9999-9999-9999-999999999999"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        try:
            self._get(
                f"/auth/callback?state={state}&error=access_denied"
                "&error_description=The+user+denied+the+request"
            )
            self.fail("expected HTTPError 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            self.assertIn("declined", e.read().decode())

    def test_concurrent_polls_yield_identity_once(self):
        # The check-and-pop is meant to be atomic: many simultaneous polls of the
        # same nonce must result in exactly one 200 (identity handed out once),
        # the rest 202. This fails if the lock around get/origin-check/pop is
        # removed. (Sequential one-time retrieval is covered separately.)
        nonce = "44444444-4444-4444-4444-444444444444"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        n = 12
        barrier = threading.Barrier(n)
        statuses = []
        lock = threading.Lock()

        def poll():
            barrier.wait()  # release all pollers at once
            status, _ = self._get_json(f"/auth/token-poll?nonce={nonce}")
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=poll) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(statuses.count(200), 1, statuses)
        self.assertEqual(statuses.count(202), n - 1, statuses)

    def test_token_poll_rejects_origin_ip_mismatch(self):
        # A completed identity is bound to the IP that started the flow. Both
        # shipped proxy configs *append* to X-Forwarded-For, so the header the
        # service sees is "<whatever the client sent>, <the client's real IP>":
        # only the rightmost element was written by our own proxy. An attacker
        # therefore pins a leftmost value at login and replays it from a
        # different real IP; keying on the rightmost element defeats that.
        nonce = "55555555-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        try:
            # Same forged prefix, different real client: must not match.
            self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {"X-Forwarded-For": "198.51.100.9, 198.51.100.66"},
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        # The original origin still retrieves it once.
        status, body = self._get_json_with_headers(
            f"/auth/token-poll?nonce={nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_token_poll_rejects_x_real_ip_mismatch(self):
        # X-Real-IP is the other header the proxies set; it is honored only when
        # X-Forwarded-For is absent. Bind and enforce on it the same way.
        nonce = "5a5a5a5a-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}", {"X-Real-IP": "203.0.113.31"}
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        try:
            self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}", {"X-Real-IP": "198.51.100.31"}
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        status, body = self._get_json_with_headers(
            f"/auth/token-poll?nonce={nonce}", {"X-Real-IP": "203.0.113.31"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_forwarded_header_from_a_non_loopback_peer_is_ignored(self):
        # The recommended integration has the *game* start the flow over
        # loopback, so the recorded origin is the constant 127.0.0.1 that every
        # attacker knows. A remote caller must not be able to claim that origin
        # by asserting it in a header: forwarding headers are believable only
        # from our own proxy, which reaches us over loopback.
        nonce = "5b5b5b5b-5555-5555-5555-555555555555"
        with self._get(f"/auth/login/github/{nonce}") as r:  # game-style, no headers
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        with self._non_loopback_peer():
            try:
                self._get_json_with_headers(
                    f"/auth/token-poll?nonce={nonce}",
                    {"X-Forwarded-For": "127.0.0.1"},
                )
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

        # Still filed under the nonce afterwards: nothing was handed out.
        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_browser_login_is_still_pollable_by_the_headerless_mud(self):
        # THE CRITICAL NON-REGRESSION: pins the live path with
        # AUTH_SERVICE_TOKEN unset (today's deployment, until the migration in
        # docs/deploy.md is carried out). The player's browser starts the flow
        # through the reverse proxy (origin recorded as the real client IP),
        # and the game polls over loopback with no forwarding headers and no
        # token. That poll is exempt from the binding on header-absence alone
        # and must still retrieve the identity -- this is the deliberate,
        # required backward-compatible path.
        self.assertIsNone(server._AUTH_SERVICE_TOKEN)
        nonce = "5c5c5c5c-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        status, body = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_browser_login_headerless_poll_is_refused_once_a_token_is_configured(self):
        # The other half of the non-regression: once AUTH_SERVICE_TOKEN is
        # configured, a headerless loopback poll -- the very thing the
        # previous test proves still works today -- must NO LONGER be granted
        # the exemption. Header-absence alone stops being sufficient; that is
        # the whole point of wave 2. The identity survives the rejection and
        # is retrievable with the token, so nothing was lost, only gated.
        nonce = "5d5d5d5d-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        with _token("s3cr3t"):
            try:
                self._get_json(f"/auth/token-poll?nonce={nonce}")
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

            status, body = self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {server.AUTH_SERVICE_TOKEN_HEADER: "s3cr3t"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["provider_id"], "42")

    def test_wrong_token_is_refused_like_no_token_at_all(self):
        nonce = "5e5e5e5e-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        with _token("s3cr3t"):
            try:
                self._get_json_with_headers(
                    f"/auth/token-poll?nonce={nonce}",
                    {server.AUTH_SERVICE_TOKEN_HEADER: "not-the-secret"},
                )
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

            # The identity survived; the real origin (or the token) still gets it.
            status, body = self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["provider_id"], "42")

    def test_a_valid_token_from_a_non_loopback_peer_is_still_refused(self):
        # Defense in depth: possessing the secret is not enough on its own,
        # the peer must also be loopback. Otherwise a leaked token would let
        # anyone on the internet claim the game's exemption outright.
        nonce = "5f5f5f5f-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        with _token("s3cr3t"), self._non_loopback_peer():
            try:
                self._get_json_with_headers(
                    f"/auth/token-poll?nonce={nonce}",
                    {server.AUTH_SERVICE_TOKEN_HEADER: "s3cr3t"},
                )
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

    def test_correct_token_with_a_forwarding_header_is_refused_end_to_end(self):
        # THE FINDING-1 LIVE PROOF: the deployed topology is peer=loopback
        # (your own reverse proxy) carrying a forwarding header for every real
        # browser request. Neither shipped proxy config strips a
        # client-supplied X-Auth-Service-Token, so before the fix this exact
        # combination -- the correct token riding through the proxy alongside
        # X-Forwarded-For -- passed the loopback exemption: a net widening of
        # remote attack surface, since the legacy rule never granted the
        # exemption to a header-bearing request at all. A token-bearing,
        # headerless poll (the real game path) must still succeed.
        nonce = "5f6f7f8f-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        with _token("s3cr3t"):
            try:
                self._get_json_with_headers(
                    f"/auth/token-poll?nonce={nonce}",
                    {
                        server.AUTH_SERVICE_TOKEN_HEADER: "s3cr3t",
                        "X-Forwarded-For": "203.0.113.55",
                    },
                )
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

            # The headerless game path is untouched by the tightening.
            status, body = self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {server.AUTH_SERVICE_TOKEN_HEADER: "s3cr3t"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(body["provider_id"], "42")

    def test_login_cancel_honors_the_token_exemption(self):
        nonce = "5a5b5c5d-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        with _token("s3cr3t"):
            # Headerless (no token) loopback cancel is refused, same as a poll.
            try:
                self._post_json("/auth/login-cancel", {"nonce": nonce})
                self.fail("expected HTTPError 403")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 403)

            status, body = self._post_json_with_headers(
                "/auth/login-cancel", {"nonce": nonce},
                {server.AUTH_SERVICE_TOKEN_HEADER: "s3cr3t"},
            )
            self.assertEqual(status, 200)
            self.assertGreaterEqual(body["cancelled"], 1)

    def test_the_token_value_never_appears_in_service_output(self):
        # Exercise every rejection path a token can trigger and grep the
        # captured stdout for the secret. A bearer credential in a log line
        # is as bad as one in the request line the previous wave redacted.
        secret = "sekrit-token-should-never-be-logged-xyz123"
        nonce = "5b5c5d5e-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(
            f"/auth/callback?code=abc&state={state}",
            {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"},
        ) as r:
            self.assertEqual(r.status, 200)

        out = io.StringIO()
        with _token(secret), contextlib.redirect_stdout(out):
            # Wrong token, from loopback: hits the dedicated exemption-denied
            # log line plus the origin-mismatch line.
            try:
                self._get_json_with_headers(
                    f"/auth/token-poll?nonce={nonce}",
                    {server.AUTH_SERVICE_TOKEN_HEADER: secret + "-wrong"},
                )
            except urllib.error.HTTPError:
                pass
            # Correct token: the success path, which logs nothing at all
            # about the request.
            self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {server.AUTH_SERVICE_TOKEN_HEADER: secret},
            )
        self.assertNotIn(secret, out.getvalue())

    def test_poll_of_an_entry_with_no_recorded_origin_is_rejected(self):
        # A falsy origin used to short-circuit the whole comparison, so the
        # identity went to whoever held the nonce. An origin we cannot vouch
        # for is a reason to refuse, not a reason to skip the check.
        nonce = "7a7a7a7a-7777-7777-7777-777777777777"
        server.AuthHandler.flow.completed[nonce] = {
            "provider": "github", "provider_id": "42", "username": "octocat",
            "created_at": time.time(), "origin_ip": None,
        }
        try:
            with self._non_loopback_peer():
                try:
                    self._get_json(f"/auth/token-poll?nonce={nonce}")
                    self.fail("expected HTTPError 403")
                except urllib.error.HTTPError as e:
                    self.assertEqual(e.code, 403)
        finally:
            server.AuthHandler.flow.completed.pop(nonce, None)

    def test_poll_with_an_unusable_forwarded_chain_is_rejected(self):
        # _client_ip has no answer when the chain is not the promised shape.
        # That "no answer" must reject rather than evaporate the comparison.
        nonce = "7b7b7b7b-7777-7777-7777-777777777777"
        proxied = {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"}
        with self._get_with_headers(f"/auth/login/github/{nonce}", proxied) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get_with_headers(f"/auth/callback?code=abc&state={state}", proxied) as r:
            self.assertEqual(r.status, 200)

        try:
            self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {"X-Forwarded-For": "198.51.100.9, not-an-ip"},
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        # Nothing was handed out; the real origin can still collect it.
        status, body = self._get_json_with_headers(
            f"/auth/token-poll?nonce={nonce}", proxied
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_login_cancel(self):
        nonce = "33333333-3333-3333-3333-333333333333"
        self._get(f"/auth/login/github/{nonce}")
        status, body = self._post_json("/auth/login-cancel", {"nonce": nonce})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["cancelled"], 1)

    def test_login_cancel_of_an_entry_with_no_recorded_origin_is_rejected(self):
        # Same falsy-origin short circuit as the poll, on the cancel path.
        nonce = "7d7d7d7d-7777-7777-7777-777777777777"
        server.AuthHandler.flow.completed[nonce] = {
            "provider": "github", "provider_id": "42", "username": "octocat",
            "created_at": time.time(), "origin_ip": None,
        }
        try:
            with self._non_loopback_peer():
                try:
                    self._post_json("/auth/login-cancel", {"nonce": nonce})
                    self.fail("expected HTTPError 403")
                except urllib.error.HTTPError as e:
                    self.assertEqual(e.code, 403)
            self.assertIn(nonce, server.AuthHandler.flow.completed)
        finally:
            server.AuthHandler.flow.completed.pop(nonce, None)

    def test_login_cancel_rejects_origin_ip_mismatch(self):
        # Cancelling drops a completed identity, so it is bound to the same
        # origin as the poll: a stranger must not be able to wipe a login that
        # is on its way to somebody else's client.
        nonce = "3a3a3a3a-3333-3333-3333-333333333333"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}", {"X-Forwarded-For": "203.0.113.7"}
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        try:
            self._post_json_with_headers(
                "/auth/login-cancel", {"nonce": nonce},
                {"X-Forwarded-For": "198.51.100.9"},
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
            self.assertEqual(json.loads(e.read().decode())["error"], "forbidden")

        # The identity survived the rejected cancel.
        status, _ = self._get_json_with_headers(
            f"/auth/token-poll?nonce={nonce}", {"X-Forwarded-For": "203.0.113.7"}
        )
        self.assertEqual(status, 200)

    def test_login_cancel_rejects_origin_mismatch_for_a_still_pending_login(self):
        # The origin binding on cancel must cover a login that has not yet
        # reached the provider callback too -- a login_nonce is a
        # client-generated UUID, not a secret, so leaving this half unchecked
        # let anyone who learned (or guessed) a nonce cancel someone else's
        # in-flight login from anywhere, with the callback never completing.
        nonce = "6e6e6e6e-6666-6666-6666-666666666666"
        proxied = {"X-Forwarded-For": "198.51.100.9, 203.0.113.7"}
        with self._get_with_headers(f"/auth/login/github/{nonce}", proxied):
            pass  # deliberately no callback -- the flow stays pending

        try:
            self._post_json_with_headers(
                "/auth/login-cancel", {"nonce": nonce},
                {"X-Forwarded-For": "198.51.100.9, 198.51.100.66"},
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        # Still pending after the rejected attempt; the real origin can
        # complete or cancel it.
        status, body = self._post_json_with_headers(
            "/auth/login-cancel", {"nonce": nonce}, proxied
        )
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["cancelled"], 1)

    def test_responses_carry_the_hardening_headers(self):
        # These pages render on the operator's public MUD origin, and the URLs
        # that reach them carry live nonces, so nothing may be stored either.
        with self._get("/auth/providers") as r:  # JSON path
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(r.headers["Cache-Control"], "no-store")
        try:
            self._get("/auth/login/nope/1e1e1e1e-1111-1111-1111-111111111111")
            self.fail("expected HTTPError 404")
        except urllib.error.HTTPError as e:  # HTML path
            self.assertEqual(e.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(e.headers["Referrer-Policy"], "no-referrer")
            self.assertEqual(e.headers["Cache-Control"], "no-store")

    def test_login_redirect_carries_the_hardening_headers(self):
        # The 302's own request URL carries the login_nonce, so it must not
        # be cached, and it renders on the operator's public origin like the
        # rest.
        nonce = "1f1f1f1f-1111-1111-1111-111111111111"
        with self._get(f"/auth/login/github/{nonce}") as r:  # redirect path
            self.assertEqual(r.status, 302)
            self.assertEqual(r.headers["Cache-Control"], "no-store")
            self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")

    def test_login_with_a_malformed_nonce_is_400(self):
        try:
            self._get("/auth/login/github/not-a-uuid")
            self.fail("expected HTTPError 400")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            self.assertIn("Invalid login_nonce format.", e.read().decode())

    def test_profile_fetch_failure_is_502(self):
        stub = providers.fetch_provider_user
        providers.fetch_provider_user = lambda p, c, t: None
        self.addCleanup(setattr, providers, "fetch_provider_user", stub)

        nonce = "6a6a6a6a-6666-6666-6666-666666666666"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        try:
            self._get(f"/auth/callback?code=abc&state={state}")
            self.fail("expected HTTPError 502")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 502)
            self.assertIn("profile", e.read().decode())

        # Nothing was filed under the nonce.
        status, _ = self._get_json(f"/auth/token-poll?nonce={nonce}")
        self.assertEqual(status, 202)

    def test_callback_for_a_deconfigured_provider_is_503(self):
        # The flow started while github was configured; the process comes back
        # with a different environment before the browser returns.
        nonce = "6b6b6b6b-6666-6666-6666-666666666666"
        with self._get(f"/auth/login/github/{nonce}") as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]

        configs = server.AuthHandler.configs
        self.addCleanup(setattr, server.AuthHandler, "configs", configs)
        server.AuthHandler.configs = {
            k: v for k, v in configs.items() if k != "github"
        }
        try:
            self._get(f"/auth/callback?code=abc&state={state}")
            self.fail("expected HTTPError 503")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 503)
            self.assertIn("no longer configured", e.read().decode())

    def test_removed_endpoints_are_404(self):
        for path in ("/auth/identity?token=x", "/auth/account-identities?account_id=x"):
            try:
                self._get(path)
                self.fail(f"expected 404 for GET {path}")
            except urllib.error.HTTPError as e:
                self.assertEqual(e.code, 404)

        # /auth/unlink was a POST endpoint; identity removal now lives in the MUD.
        try:
            self._post_json("/auth/unlink", {"account_id": "x", "provider": "github"})
            self.fail("expected 404 for POST /auth/unlink")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


class ConfigTest(unittest.TestCase):
    def test_steam_registers_from_api_key_alone(self):
        # Steam has no client id/secret; the Web API key rides in the
        # client_secret slot, which fetch_provider_user("steam", ...) reads.
        env = {"STEAM_API_KEY": "web-api-key"}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            configs = server._load_provider_configs()
        self.assertEqual(list(configs), ["steam"])
        self.assertEqual(configs["steam"].client_secret, "web-api-key")

    def test_oauth_provider_needs_both_id_and_secret(self):
        env = {"GITHUB_CLIENT_ID": "cid"}  # no secret
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            configs = server._load_provider_configs()
        self.assertEqual(configs, {})


class BrandNameTest(unittest.TestCase):
    def test_done_page_defaults_to_mudauth(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_BRAND_NAME", None)
            page = server._done_page("ok")
            self.assertIn("<title>mudauth</title>", page)
            self.assertIn("<h1>mudauth</h1>", page)

    def test_done_page_uses_brand_env(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_BRAND_NAME": "Realm of Bob"}):
            page = server._done_page("ok")
            self.assertIn("<h1>Realm of Bob</h1>", page)

    def test_done_page_escapes_brand(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_BRAND_NAME": "<b>x</b>"}):
            self.assertIn("&lt;b&gt;x&lt;/b&gt;", server._done_page("ok"))


class LogRedactionTest(unittest.TestCase):
    """The request line reaches the service log; live credentials must not."""

    def _log(self, request_line):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            # log_message reads nothing off the instance.
            server.AuthHandler.log_message(None, '"%s" %s -', request_line, "200")
        return out.getvalue()

    def test_path_form_nonce_is_redacted(self):
        nonce = "12345678-1234-1234-1234-123456789abc"
        line = self._log(f"GET /auth/login/github/{nonce} HTTP/1.1")
        self.assertNotIn(nonce, line)
        self.assertIn("/auth/login/github/<redacted>", line)

    def test_uppercase_nonce_is_redacted(self):
        nonce = "12345678-1234-1234-1234-123456789ABC"
        self.assertNotIn(nonce, self._log(f"GET /auth/login/github/{nonce} HTTP/1.1"))

    def test_query_string_is_still_redacted(self):
        line = self._log("GET /auth/callback?code=live-code&state=abc HTTP/1.1")
        self.assertNotIn("live-code", line)
        self.assertIn("?<redacted>", line)


def _stub_handler(peer, *header_pairs):
    """A handler stand-in carrying only what ``_client_ip`` reads.

    ``email.message.Message`` is the same container ``BaseHTTPRequestHandler``
    puts in ``.headers``, so case-insensitive lookup and repeated header lines
    behave exactly as they do on a live request.
    """
    headers = email.message.Message()
    for name, value in header_pairs:
        headers[name] = value
    return types.SimpleNamespace(
        headers=headers, client_address=(peer, 4444) if peer else None
    )


class ClientIPTest(unittest.TestCase):
    """Unit tests for the origin-IP decision that the whole binding rests on.

    The end-to-end tests above cover the wiring; these pin the decision itself,
    including the cases a live loopback-bound test server cannot produce.
    """

    def test_ignores_forwarded_headers_from_a_non_loopback_peer(self):
        h = _stub_handler(
            "203.0.113.99",
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
        )
        self.assertEqual(server._client_ip(h), "203.0.113.99")
        self.assertFalse(server._is_trusted_loopback(h))

    def test_takes_the_rightmost_forwarded_element_from_the_proxy(self):
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", "198.51.100.9, 203.0.113.7"))
        self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_header_lookup_is_case_insensitive(self):
        h = _stub_handler("127.0.0.1", ("x-forwarded-for", "9.9.9.9, 203.0.113.7"))
        self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_repeated_forwarded_header_lines_are_one_list(self):
        # A client can send its own X-Forwarded-For line; a proxy may append a
        # second one rather than merging. The last element of the whole list is
        # still the hop our proxy wrote.
        h = _stub_handler(
            "127.0.0.1",
            ("X-Forwarded-For", "9.9.9.9"),
            ("X-Forwarded-For", "203.0.113.7"),
        )
        self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_empty_forwarded_elements_are_skipped(self):
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", " , , 203.0.113.7"))
        self.assertEqual(server._client_ip(h), "203.0.113.7")
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", " , , "))
        self.assertEqual(server._client_ip(h), "127.0.0.1")

    def test_ipv6_mapped_loopback_peer_is_loopback(self):
        h = _stub_handler("::ffff:127.0.0.1", ("X-Forwarded-For", "203.0.113.7"))
        self.assertEqual(server._client_ip(h), "203.0.113.7")
        self.assertTrue(server._is_trusted_loopback(_stub_handler("::ffff:127.0.0.1")))
        self.assertTrue(server._is_trusted_loopback(_stub_handler("::1")))

    def test_x_real_ip_is_used_only_without_forwarded_for(self):
        h = _stub_handler("127.0.0.1", ("X-Real-IP", "203.0.113.7"))
        self.assertEqual(server._client_ip(h), "203.0.113.7")
        h = _stub_handler(
            "127.0.0.1",
            ("X-Forwarded-For", "203.0.113.7"),
            ("X-Real-IP", "198.51.100.9"),
        )
        self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_repeated_real_ip_lines_take_the_last(self):
        # Same reasoning as X-Forwarded-For: if a client's own line survives
        # into the request, our proxy's line is the one that arrives after it.
        h = _stub_handler(
            "127.0.0.1",
            ("X-Real-IP", "9.9.9.9"),
            ("X-Real-IP", "203.0.113.7"),
        )
        self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_an_unusable_x_real_ip_is_rejected(self):
        # A header that is present but not an address tells us the proxy is
        # not the one we were promised. Falling back to the loopback peer here
        # would hand a browser request the origin the game itself uses.
        for value in ("not-an-ip", "   ", "203.0.113.7:443"):
            h = _stub_handler("127.0.0.1", ("X-Real-IP", value))
            self.assertIsNone(server._client_ip(h), value)

    def test_bare_loopback_peer_without_headers(self):
        h = _stub_handler("127.0.0.1")
        self.assertEqual(server._client_ip(h), "127.0.0.1")
        self.assertTrue(server._is_trusted_loopback(h))

    def test_a_forwarded_header_forfeits_the_loopback_exemption(self):
        # Our own proxy is on loopback, so a proxied request arrives from a
        # loopback peer. It still represents a remote browser and must not
        # inherit the game's exemption.
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", "203.0.113.7"))
        self.assertFalse(server._is_trusted_loopback(h))

    def test_a_remote_headerless_peer_is_not_trusted(self):
        # The address check is the whole exemption once the header check has
        # passed: a headerless request from off-box must not inherit the
        # game's pass just because it sent no forwarding headers.
        self.assertFalse(server._is_trusted_loopback(_stub_handler("203.0.113.99")))
        self.assertFalse(server._is_trusted_loopback(_stub_handler("10.0.0.4")))
        self.assertFalse(server._is_trusted_loopback(_stub_handler("2001:db8::1")))
        self.assertFalse(server._is_trusted_loopback(_stub_handler(None)))

    def test_the_whole_127_block_is_loopback(self):
        # The check is ipaddress-based rather than three literals, so anything
        # in 127.0.0.0/8 counts — a driver or health checker may source from
        # an address other than 127.0.0.1.
        h = _stub_handler("127.0.0.5")
        self.assertTrue(server._is_trusted_loopback(h))
        self.assertEqual(server._client_ip(h), "127.0.0.5")
        self.assertEqual(
            server._client_ip(_stub_handler("127.0.0.5", ("X-Real-IP", "203.0.113.7"))),
            "203.0.113.7",
        )

    def test_trusted_hop_count_selects_the_element(self):
        h = _stub_handler(
            "127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7, 10.0.0.2")
        )
        with _hops(2):
            self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_hop_count_past_the_end_of_the_list_is_rejected(self):
        # The chain is not the shape the configuration promised. Falling back
        # to the peer would resolve every browser request to 127.0.0.1 — the
        # origin the game's own flows record — so every origin would match and
        # the binding would be silently off.
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7"))
        with _hops(5):
            self.assertIsNone(server._client_ip(h))

    def test_a_forwarded_element_that_is_not_an_address_is_rejected(self):
        # Whatever sits at the configured hop has to be an address. A garbage
        # value would otherwise be recorded as an origin that an attacker can
        # reproduce by sending the same garbage back.
        for value in ("unknown", "; DROP", "203.0.113.7:443", "[203.0.113.7]"):
            h = _stub_handler("127.0.0.1", ("X-Forwarded-For", f"9.9.9.9, {value}"))
            self.assertIsNone(server._client_ip(h), value)

    def test_the_request_path_does_not_read_the_environment(self):
        # The hop count is fixed at startup, so an operator editing .env under
        # a running service cannot change the binding mid-flight.
        h = _stub_handler(
            "127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7, 10.0.0.2")
        )
        with unittest.mock.patch.dict(os.environ, {"AUTH_TRUSTED_PROXY_HOPS": "2"}):
            self.assertEqual(server._client_ip(h), "10.0.0.2")


class TrustedLoopbackTokenTest(unittest.TestCase):
    """Unit tests for the token half of the exemption decision.

    Mirrors ClientIPTest: the end-to-end tests in HandlerTest cover wiring,
    these pin _is_trusted_loopback itself, including the non-loopback-peer
    case a loopback-bound test server cannot produce directly.
    """

    def setUp(self):
        self._original = server._AUTH_SERVICE_TOKEN

    def tearDown(self):
        server._AUTH_SERVICE_TOKEN = self._original

    def test_correct_token_from_loopback_is_trusted(self):
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler("127.0.0.1", (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t"))
        self.assertTrue(server._is_trusted_loopback(h))

    def test_correct_token_is_refused_alongside_forwarding_headers(self):
        # THE FINDING-1 FIX: neither shipped proxy config strips a
        # client-supplied X-Auth-Service-Token, so a request that arrives
        # through the proxy carrying both the correct token AND a forwarding
        # header is exactly what a remote caller who has learned the token
        # can send. The token path must be strictly stronger than the legacy
        # header-absence path, never a trade against it -- so this must be
        # refused even though the token itself is correct.
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler(
            "127.0.0.1",
            (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t"),
            ("X-Forwarded-For", "203.0.113.7"),
        )
        self.assertFalse(server._is_trusted_loopback(h))

    def test_missing_token_when_configured_is_not_trusted(self):
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler("127.0.0.1")
        self.assertFalse(server._is_trusted_loopback(h))

    def test_wrong_token_when_configured_is_not_trusted(self):
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler("127.0.0.1", (server.AUTH_SERVICE_TOKEN_HEADER, "wrong"))
        self.assertFalse(server._is_trusted_loopback(h))

    def test_a_repeated_token_header_is_refused_rather_than_reading_the_first(self):
        # Every other credential-bearing header this service reads
        # (X-Forwarded-For, X-Real-IP) treats a repeated line deliberately.
        # A second X-Auth-Service-Token line is not a value to pick a winner
        # from -- it means the request does not look like what was promised,
        # so it must fail closed even when the first line is the real token.
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler(
            "127.0.0.1",
            (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t"),
            (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t"),
        )
        self.assertFalse(server._is_trusted_loopback(h))

    def test_a_non_ascii_token_header_fails_closed_instead_of_raising(self):
        # hmac.compare_digest raises TypeError on non-ASCII str input. The
        # header is attacker-controlled even on this loopback-only branch --
        # a local process or SSRF without the real token is exactly the
        # caller this token is meant to keep out -- so a malformed value must
        # fail the check, not crash the request thread.
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler("127.0.0.1", (server.AUTH_SERVICE_TOKEN_HEADER, "héllo-not-ascii"))
        self.assertFalse(server._is_trusted_loopback(h))

    def test_correct_token_from_a_non_loopback_peer_is_not_trusted(self):
        server._AUTH_SERVICE_TOKEN = "s3cr3t"
        h = _stub_handler(
            "203.0.113.99", (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t")
        )
        self.assertFalse(server._is_trusted_loopback(h))

    def test_unset_token_keeps_the_legacy_header_absence_rule(self):
        server._AUTH_SERVICE_TOKEN = None
        self.assertTrue(server._is_trusted_loopback(_stub_handler("127.0.0.1")))
        self.assertFalse(server._is_trusted_loopback(
            _stub_handler("127.0.0.1", ("X-Forwarded-For", "203.0.113.7"))
        ))
        # A stray token header does nothing when unconfigured -- there is no
        # secret to compare it against, so the legacy rule alone decides, and
        # a token header is neither X-Forwarded-For nor X-Real-IP.
        self.assertTrue(server._is_trusted_loopback(
            _stub_handler("127.0.0.1", (server.AUTH_SERVICE_TOKEN_HEADER, "s3cr3t"))
        ))


class TrustedProxyHopsConfigTest(unittest.TestCase):
    """The hop count is parsed and validated once, at startup.

    A misconfiguration here silently degrades the origin binding, so it must
    stop the service rather than be clamped into something that looks fine.
    """

    def setUp(self):
        self._original = server._TRUSTED_PROXY_HOPS

    def tearDown(self):
        server._TRUSTED_PROXY_HOPS = self._original

    def test_an_unset_value_defaults_to_one(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_TRUSTED_PROXY_HOPS", None)
            self.assertEqual(server._configure_trusted_proxy_hops(), 1)
        self.assertEqual(server._trusted_proxy_hops(), 1)

    def test_a_valid_value_is_adopted(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_TRUSTED_PROXY_HOPS": " 3 "}):
            self.assertEqual(server._configure_trusted_proxy_hops(), 3)
        self.assertEqual(server._trusted_proxy_hops(), 3)

    def test_a_non_integer_refuses_to_start(self):
        for value in ("banana", "tow", "1.5", "one"):
            with unittest.mock.patch.dict(
                os.environ, {"AUTH_TRUSTED_PROXY_HOPS": value}
            ), self.assertRaises(ValueError) as ctx:
                server._configure_trusted_proxy_hops()
            self.assertIn("AUTH_TRUSTED_PROXY_HOPS", str(ctx.exception))

    def test_a_value_below_one_refuses_to_start(self):
        # 0 used to clamp to 1 in silence, so an operator who meant to disable
        # the header got a binding that read one hop anyway.
        for value in ("0", "-3"):
            with unittest.mock.patch.dict(
                os.environ, {"AUTH_TRUSTED_PROXY_HOPS": value}
            ), self.assertRaises(ValueError) as ctx:
                server._configure_trusted_proxy_hops()
            self.assertIn("AUTH_TRUSTED_PROXY_HOPS", str(ctx.exception))

    def test_make_server_refuses_a_bad_hop_count_before_binding(self):
        with unittest.mock.patch.dict(
            os.environ, {"AUTH_TRUSTED_PROXY_HOPS": "banana"}
        ), self.assertRaises(ValueError) as ctx:
            server.make_server("127.0.0.1", 0)
        self.assertIn("AUTH_TRUSTED_PROXY_HOPS", str(ctx.exception))


class AuthServiceTokenConfigTest(unittest.TestCase):
    """AUTH_SERVICE_TOKEN is read once at startup, mirroring the hop count."""

    def setUp(self):
        self._original = server._AUTH_SERVICE_TOKEN

    def tearDown(self):
        server._AUTH_SERVICE_TOKEN = self._original

    def test_an_unset_value_is_none(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_SERVICE_TOKEN", None)
            self.assertIsNone(server._configure_auth_service_token())
        self.assertIsNone(server._AUTH_SERVICE_TOKEN)

    def test_an_empty_value_is_treated_as_unset(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_SERVICE_TOKEN": ""}):
            self.assertIsNone(server._configure_auth_service_token())

    def test_a_set_value_is_adopted(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_SERVICE_TOKEN": "s3cr3t"}):
            self.assertEqual(server._configure_auth_service_token(), "s3cr3t")
        self.assertEqual(server._AUTH_SERVICE_TOKEN, "s3cr3t")

    def test_a_value_with_surrounding_whitespace_is_stripped(self):
        # A trailing space is trivially easy to introduce in a .env file. The
        # client strips its copy before sending (client.py); if this side did
        # not also strip, the two sides would normalise to different strings
        # and never compare equal, even though both looked configured.
        with unittest.mock.patch.dict(os.environ, {"AUTH_SERVICE_TOKEN": " s3cr3t "}):
            self.assertEqual(server._configure_auth_service_token(), "s3cr3t")
        self.assertEqual(server._AUTH_SERVICE_TOKEN, "s3cr3t")

    def test_a_whitespace_only_value_is_treated_as_unset(self):
        with unittest.mock.patch.dict(os.environ, {"AUTH_SERVICE_TOKEN": "   "}):
            self.assertIsNone(server._configure_auth_service_token())
        self.assertIsNone(server._AUTH_SERVICE_TOKEN)

    def test_a_value_outside_the_clients_charset_refuses_to_start(self):
        # The client (client.py's _SAFE_TOKEN_RE) refuses to transmit
        # anything outside [A-Za-z0-9_-], so a service that accepted such a
        # token would be up but permanently unauthenticatable by the only
        # caller that matters. Refuse to start instead, mirroring the
        # hop-count validation above.
        with unittest.mock.patch.dict(
            os.environ, {"AUTH_SERVICE_TOKEN": "s3cr3t token"}
        ), self.assertRaises(ValueError) as ctx:
            server._configure_auth_service_token()
        message = str(ctx.exception)
        self.assertIn("AUTH_SERVICE_TOKEN", message)
        self.assertNotIn("s3cr3t token", message)

    def test_make_server_refuses_a_bad_charset_token_before_binding(self):
        with unittest.mock.patch.dict(
            os.environ, {"AUTH_SERVICE_TOKEN": "bad!token"}
        ), self.assertRaises(ValueError) as ctx:
            server.make_server("127.0.0.1", 0)
        message = str(ctx.exception)
        self.assertIn("AUTH_SERVICE_TOKEN", message)
        self.assertNotIn("bad!token", message)

    @staticmethod
    def _serve_and_close(httpd):
        """shutdown() waits on an event only serve_forever() sets, so a
        server that never started serving hangs forever on shutdown.

        A 127.0.0.1 bind also starts an IPv6 [::1] companion server
        (make_server stashes it as httpd.ipv6_companion); leaving that
        running is a live socket and daemon thread this test never asked
        for, so it is shut down the same way.
        """
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        httpd.shutdown()
        thread.join()
        httpd.server_close()
        companion = getattr(httpd, "ipv6_companion", None)
        if companion is not None:
            companion.shutdown()
            companion.server_close()

    def test_make_server_warns_on_startup_when_the_token_is_unset(self):
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("AUTH_SERVICE_TOKEN", None)
            with contextlib.redirect_stdout(out):
                httpd = server.make_server("127.0.0.1", 0)
        try:
            self.assertIn("AUTH_SERVICE_TOKEN is not set", out.getvalue())
            self.assertIn("NOT SET", out.getvalue())
        finally:
            self._serve_and_close(httpd)

    def test_make_server_does_not_warn_when_the_token_is_set(self):
        out = io.StringIO()
        with (
            unittest.mock.patch.dict(os.environ, {"AUTH_SERVICE_TOKEN": "s3cr3t"}),
            contextlib.redirect_stdout(out),
        ):
            httpd = server.make_server("127.0.0.1", 0)
        try:
            self.assertNotIn("AUTH_SERVICE_TOKEN is not set", out.getvalue())
            self.assertIn("configured", out.getvalue())
            self.assertNotIn("s3cr3t", out.getvalue())
        finally:
            self._serve_and_close(httpd)


class StdoutFlushTest(unittest.TestCase):
    """The production defect: Python block-buffers stdout when it is not a
    TTY -- always true under systemd -- so a print() without flush=True can
    sit unheard in that buffer indefinitely, including the [auth][security]
    lines an operator needs live during an incident. This launches the real
    service the way the shipped unit does (``mudauth serve``, via
    ``python -m mudauth.cli serve`` so it runs under this interpreter) with
    stdout attached to a pipe (never a TTY) and PYTHONUNBUFFERED explicitly
    removed from the environment, so neither the test harness's TTY nor the
    operator's workaround can mask a regression. The startup banner is the
    smallest possible amount of output -- nothing close to a 4 KB
    block-buffer's worth -- so without flush=True it would not arrive on the
    pipe within the timeout below; it would sit until the process exited or
    enough later output filled the buffer.
    """

    def test_startup_banner_arrives_promptly_on_a_piped_stdout(self):
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = os.environ.copy()
        env.pop("PYTHONUNBUFFERED", None)
        env["AUTH_BIND"] = "127.0.0.1:0"  # ephemeral port; avoid colliding with a real instance
        # A context manager, not a bare Popen(): its __exit__ closes the
        # piped stdout/stderr file objects, which a bare Popen() call leaves
        # open (and unclosed pipes are exactly what -W error::ResourceWarning
        # is there to catch).
        with subprocess.Popen(
            [sys.executable, "-m", "mudauth.cli", "serve"],
            cwd=repo_root,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        ) as proc:
            try:
                ready, _, _ = select.select([proc.stdout], [], [], 3)
                self.assertTrue(
                    ready,
                    "no output arrived on the piped stdout within 3s -- diagnostics "
                    "are sitting unflushed in the block buffer",
                )
                line = proc.stdout.readline()
                self.assertIn("[auth]", line)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
