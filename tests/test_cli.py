import contextlib
import io
import os
import tempfile
import unittest
import unittest.mock

from mudauth import cli


class EnvFileTest(unittest.TestCase):
    def _load(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write(text)
        try:
            return cli.load_env_file(fh.name)
        finally:
            os.unlink(fh.name)

    def test_parses_key_value_comments_and_blank_lines(self):
        env = self._load("# c\n\nAUTH_BIND=127.0.0.1:7700\nGITHUB_CLIENT_ID=abc\n")
        self.assertEqual(env, {"AUTH_BIND": "127.0.0.1:7700", "GITHUB_CLIENT_ID": "abc"})

    def test_strips_export_and_quotes(self):
        env = self._load('export A="x y"\nB=\'z\'\n')
        self.assertEqual(env, {"A": "x y", "B": "z"})

    def test_keeps_trailing_hash_inside_value(self):
        self.assertEqual(self._load("A=ab#c\n")["A"], "ab#c")


class CheckTest(unittest.TestCase):
    def test_warns_when_public_base_ends_in_auth(self):
        env = {"AUTH_PUBLIC_BASE": "https://mud.example/auth", "GITHUB_CLIENT_ID": "i", "GITHUB_CLIENT_SECRET": "s"}
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
             unittest.mock.patch("mudauth.client.request", return_value={"status": 200, "body": "{}"}):
            rc = cli.main(["check"])
        self.assertEqual(rc, 1)
        self.assertIn("ends in /auth", out.getvalue())
        self.assertIn("github", out.getvalue())

    def test_reports_unreachable_service(self):
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, {"AUTH_PUBLIC_BASE": "https://mud.example"}, clear=True), \
             contextlib.redirect_stdout(out), \
             unittest.mock.patch("mudauth.client.request", return_value={"status": 0, "body": "refused"}):
            rc = cli.main(["check"])
        self.assertEqual(rc, 1)
        self.assertIn("unreachable", out.getvalue())

    def test_ok_when_everything_is_fine(self):
        env = {"AUTH_PUBLIC_BASE": "https://mud.example", "DISCORD_CLIENT_ID": "i", "DISCORD_CLIENT_SECRET": "s"}
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
             unittest.mock.patch("mudauth.client.request", return_value={"status": 200, "body": "{}"}):
            self.assertEqual(cli.main(["check"]), 0)

    def _check(self, env):
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), \
             unittest.mock.patch("mudauth.client.request", return_value={"status": 200, "body": "{}"}):
            rc = cli.main(["check"])
        return rc, out.getvalue()

    def test_warns_when_public_base_is_not_https(self):
        env = {"AUTH_PUBLIC_BASE": "http://mud.example", "GITHUB_CLIENT_ID": "i", "GITHUB_CLIENT_SECRET": "s"}
        rc, out = self._check(env)
        self.assertEqual(rc, 1)
        self.assertIn("not https", out)

    def test_warns_about_the_unconfigured_http_localhost_default(self):
        # No AUTH_PUBLIC_BASE at all: the default is http://localhost:7700, so
        # an install nobody configured must not report itself healthy.
        env = {"GITHUB_CLIENT_ID": "i", "GITHUB_CLIENT_SECRET": "s"}
        rc, out = self._check(env)
        self.assertEqual(rc, 1)
        self.assertIn("not https", out)
        self.assertIn("local development", out)

    def test_warns_when_bind_is_not_loopback(self):
        env = {"AUTH_PUBLIC_BASE": "https://mud.example", "AUTH_BIND": "0.0.0.0:7700",
               "GITHUB_CLIENT_ID": "i", "GITHUB_CLIENT_SECRET": "s"}
        rc, out = self._check(env)
        self.assertEqual(rc, 1)
        self.assertIn("not a loopback address", out)

    def test_loopback_binds_do_not_warn(self):
        for bind in ("127.0.0.1:7700", "localhost:7700", "::1:7700", "127.0.0.2:7700"):
            env = {"AUTH_PUBLIC_BASE": "https://mud.example", "AUTH_BIND": bind,
                   "GITHUB_CLIENT_ID": "i", "GITHUB_CLIENT_SECRET": "s"}
            rc, out = self._check(env)
            self.assertEqual(rc, 0, (bind, out))

    def test_warns_when_no_provider_is_configured(self):
        rc, out = self._check({"AUTH_PUBLIC_BASE": "https://mud.example"})
        self.assertEqual(rc, 1)
        self.assertIn("no provider is configured", out)


class ServeTest(unittest.TestCase):
    def test_serve_smoke(self):
        import threading
        import urllib.request
        with unittest.mock.patch.dict(os.environ, {"AUTH_BIND": "127.0.0.1:0"}):
            httpd = cli.build_server_from_env()
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/auth/healthz", timeout=5) as r:
                self.assertEqual(r.status, 200)
        finally:
            httpd.shutdown()
            httpd.server_close()


class VersionTest(unittest.TestCase):
    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--version"])
        from mudauth import __version__
        self.assertIn(__version__, out.getvalue())
