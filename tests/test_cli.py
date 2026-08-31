import argparse
import contextlib
import io
import os
import tempfile
import unittest
import unittest.mock

from mudauth import cli


def _running_as_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0


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


class UnusableEnvFileTest(unittest.TestCase):
    """A missing/unreadable --env-file must fail like any other bad config:

    ``[auth] configuration error: ...`` on stderr and exit 2 -- not a raw
    traceback -- for both `serve` and `check`.
    """

    def _run(self, cmd, path):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = cli.main([cmd, "--env-file", path])
        return rc, err.getvalue()

    def test_serve_reports_missing_env_file(self):
        rc, err = self._run("serve", "/nonexistent/mudauth.env")
        self.assertEqual(rc, 2)
        self.assertIn("[auth] configuration error:", err)
        self.assertIn("/nonexistent/mudauth.env", err)

    def test_check_reports_missing_env_file(self):
        rc, err = self._run("check", "/nonexistent/mudauth.env")
        self.assertEqual(rc, 2)
        self.assertIn("[auth] configuration error:", err)
        self.assertIn("/nonexistent/mudauth.env", err)

    def test_serve_reports_env_file_that_is_a_directory(self):
        with tempfile.TemporaryDirectory() as d:
            rc, err = self._run("serve", d)
        self.assertEqual(rc, 2)
        self.assertIn("[auth] configuration error:", err)
        self.assertIn(d, err)

    def test_check_reports_env_file_that_is_a_directory(self):
        with tempfile.TemporaryDirectory() as d:
            rc, err = self._run("check", d)
        self.assertEqual(rc, 2)
        self.assertIn("[auth] configuration error:", err)
        self.assertIn(d, err)

    @unittest.skipIf(_running_as_root(), "permission bits are not enforced for root")
    def test_serve_reports_unreadable_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("A=b\n")
            path = fh.name
        try:
            os.chmod(path, 0o000)
            rc, err = self._run("serve", path)
            self.assertEqual(rc, 2)
            self.assertIn("[auth] configuration error:", err)
            self.assertIn(path, err)
        finally:
            os.chmod(path, 0o644)
            os.unlink(path)

    @unittest.skipIf(_running_as_root(), "permission bits are not enforced for root")
    def test_check_reports_unreadable_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("A=b\n")
            path = fh.name
        try:
            os.chmod(path, 0o000)
            rc, err = self._run("check", path)
            self.assertEqual(rc, 2)
            self.assertIn("[auth] configuration error:", err)
            self.assertIn(path, err)
        finally:
            os.chmod(path, 0o644)
            os.unlink(path)

    def test_apply_env_file_loads_a_readable_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("MUDAUTH_TEST_VAR=hello\n")
            path = fh.name
        try:
            with unittest.mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("MUDAUTH_TEST_VAR", None)
                cli._apply_env_file(argparse.Namespace(env_file=path))
                self.assertEqual(os.environ.get("MUDAUTH_TEST_VAR"), "hello")
        finally:
            os.unlink(path)

    def test_check_still_works_with_a_readable_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("AUTH_PUBLIC_BASE=https://mud.example\nDISCORD_CLIENT_ID=i\nDISCORD_CLIENT_SECRET=s\n")
            path = fh.name
        out = io.StringIO()
        try:
            with unittest.mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out), \
                 unittest.mock.patch("mudauth.client.request", return_value={"status": 200, "body": "{}"}):
                rc = cli.main(["check", "--env-file", path])
            self.assertEqual(rc, 0)
            self.assertIn("https://mud.example", out.getvalue())
        finally:
            os.unlink(path)

    def test_serve_still_works_with_a_readable_env_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("AUTH_BIND=127.0.0.1:0\n")
            path = fh.name
        try:
            with unittest.mock.patch.dict(os.environ, {}, clear=True):
                args = argparse.Namespace(env_file=path, bind=None)
                cli._apply_env_file(args)
                httpd = cli.build_server_from_env()
            try:
                self.assertEqual(httpd.server_address[0], "127.0.0.1")
            finally:
                httpd.server_close()
                companion = getattr(httpd, "ipv6_companion", None)
                if companion is not None:
                    companion.server_close()
        finally:
            os.unlink(path)


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

    def test_reports_auth_service_token_unset(self):
        # Unset is legitimate and backward-compatible, so it must not itself
        # add to `problems` -- only surface it for visibility.
        env = {"AUTH_PUBLIC_BASE": "https://mud.example", "DISCORD_CLIENT_ID": "i",
               "DISCORD_CLIENT_SECRET": "s"}
        rc, out = self._check(env)
        self.assertEqual(rc, 0)
        self.assertIn("AUTH_SERVICE_TOKEN: not set", out)

    def test_reports_auth_service_token_configured_without_leaking_it(self):
        env = {"AUTH_PUBLIC_BASE": "https://mud.example", "DISCORD_CLIENT_ID": "i",
               "DISCORD_CLIENT_SECRET": "s", "AUTH_SERVICE_TOKEN": "s3cr3t-value"}
        rc, out = self._check(env)
        self.assertEqual(rc, 0)
        self.assertIn("AUTH_SERVICE_TOKEN: configured", out)
        self.assertNotIn("s3cr3t-value", out)


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
            # A 127.0.0.1 bind also starts an IPv6 [::1] companion server
            # (server.make_server stashes it as httpd.ipv6_companion);
            # leaving that running leaks its socket and daemon thread.
            companion = getattr(httpd, "ipv6_companion", None)
            if companion is not None:
                companion.shutdown()
                companion.server_close()


class VersionTest(unittest.TestCase):
    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            cli.main(["--version"])
        from mudauth import __version__
        self.assertIn(__version__, out.getvalue())
