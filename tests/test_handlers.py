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
import json
import os
import threading
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

    def test_trusted_hop_count_selects_the_element(self):
        h = _stub_handler(
            "127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7, 10.0.0.2")
        )
        with unittest.mock.patch.dict(os.environ, {"AUTH_TRUSTED_PROXY_HOPS": "2"}):
            self.assertEqual(server._client_ip(h), "203.0.113.7")

    def test_hop_count_past_the_end_of_the_list_falls_back_to_the_peer(self):
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7"))
        with unittest.mock.patch.dict(os.environ, {"AUTH_TRUSTED_PROXY_HOPS": "5"}):
            self.assertEqual(server._client_ip(h), "127.0.0.1")

    def test_unusable_hop_counts_fall_back_to_one(self):
        h = _stub_handler("127.0.0.1", ("X-Forwarded-For", "9.9.9.9, 203.0.113.7"))
        for value in ("0", "-3", "banana", ""):
            with unittest.mock.patch.dict(
                os.environ, {"AUTH_TRUSTED_PROXY_HOPS": value}
            ):
                self.assertEqual(server._client_ip(h), "203.0.113.7", value)


if __name__ == "__main__":
    unittest.main()
