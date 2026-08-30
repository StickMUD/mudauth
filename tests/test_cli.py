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


class VersionTest(unittest.TestCase):
    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--version"])
        from mudauth import __version__
        self.assertIn(__version__, out.getvalue())
