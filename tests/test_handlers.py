"""End-to-end tests for the auth-service HTTP handlers (server.py).

Runs the real ThreadingHTTPServer on an ephemeral loopback port, but
monkeypatches the provider token-exchange and profile-fetch so no external
network calls happen. The service is stateless: it verifies an identity and
hands ``(provider, provider_id, username)`` back via the nonce poll. The MUD
owns accounts, characters and the login/link/create decision, so there are no
DB-backed endpoints to test here.
"""

import json
import os
import threading
import unittest
import unittest.mock
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse

from mudauth import providers, server
from mudauth.providers import ProviderConfig, ProviderUser


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Return the 3xx response as-is instead of following or raising on it."""

    def http_error_302(self, req, fp, code, msg, headers):
        return fp

    http_error_301 = http_error_303 = http_error_307 = http_error_302


def _opener():
    return urllib.request.build_opener(_NoRedirect)


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

    def _get_with_headers(self, path, headers):
        req = urllib.request.Request(self.base + path, headers=headers, method="GET")
        return _opener().open(req)

    def _get_json_with_headers(self, path, headers):
        with self._get_with_headers(path, headers) as r:
            return r.status, json.loads(r.read().decode())

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
        # A completed identity is bound to the IP that started the flow. Sending
        # an X-Forwarded-For disables the trusted-loopback exemption, so a poll
        # from a different IP must be forbidden. (Loopback callers stay exempt,
        # which is why the other tests, run without XFF, succeed.)
        nonce = "55555555-5555-5555-5555-555555555555"
        with self._get_with_headers(
            f"/auth/login/github/{nonce}", {"X-Forwarded-For": "203.0.113.7"}
        ) as r:
            state = parse_qs(urlparse(r.headers["Location"]).query)["state"][0]
        with self._get(f"/auth/callback?code=abc&state={state}") as r:
            self.assertEqual(r.status, 200)

        try:
            self._get_json_with_headers(
                f"/auth/token-poll?nonce={nonce}",
                {"X-Forwarded-For": "198.51.100.9"},
            )
            self.fail("expected HTTPError 403")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)

        # The original origin still retrieves it once.
        status, body = self._get_json_with_headers(
            f"/auth/token-poll?nonce={nonce}", {"X-Forwarded-For": "203.0.113.7"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["provider_id"], "42")

    def test_login_cancel(self):
        nonce = "33333333-3333-3333-3333-333333333333"
        self._get(f"/auth/login/github/{nonce}")
        status, body = self._post_json("/auth/login-cancel", {"nonce": nonce})
        self.assertEqual(status, 200)
        self.assertGreaterEqual(body["cancelled"], 1)

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


if __name__ == "__main__":
    unittest.main()
