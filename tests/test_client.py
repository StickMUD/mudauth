import json
import threading
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mudauth import client, ldmud


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404 if self.path == "/missing" else 200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"path": self.path}).encode())

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):
        pass


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_get_returns_status_and_body(self):
        r = client.request("GET", "/auth/healthz", base_url=self.base)
        self.assertEqual(r["status"], 200)
        self.assertEqual(json.loads(r["body"]), {"path": "/auth/healthz"})

    def test_non_2xx_is_returned_not_raised(self):
        self.assertEqual(client.request("GET", "/missing", base_url=self.base)["status"], 404)

    def test_post_sends_json_body(self):
        r = client.request("POST", "/x", '{"nonce":"n"}', base_url=self.base)
        self.assertEqual(r["body"], '{"nonce":"n"}')

    def test_leading_slash_is_added(self):
        r = client.request("GET", "auth/providers", base_url=self.base)
        self.assertEqual(json.loads(r["body"])["path"], "/auth/providers")

    def test_transport_error_is_status_zero(self):
        r = client.request("GET", "/", base_url="http://127.0.0.1:1", timeout=1)
        self.assertEqual(r["status"], 0)
        self.assertTrue(r["body"])

    def test_efun_wrapper_returns_json_string(self):
        with unittest.mock.patch.object(client, "DEFAULT_BASE_URL", self.base):
            out = ldmud.auth_service_request("GET", "/auth/healthz", "")
        self.assertEqual(json.loads(out)["status"], 200)

    def test_efun_rejects_unknown_method(self):
        out = json.loads(ldmud.auth_service_request("DELETE", "/", ""))
        self.assertEqual(out["status"], 0)
