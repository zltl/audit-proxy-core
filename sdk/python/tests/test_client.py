import io
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sshproxy import SSHProxyClient, SSHProxyError  # noqa: E402


class FakeResponse:
    def __init__(self, payload: str, status: int = 200):
        self._payload = payload.encode("utf-8")
        self.status = status

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class SSHProxyClientTests(unittest.TestCase):
    def test_invalid_base_url(self):
        with self.assertRaises(ValueError):
            SSHProxyClient("not-a-url")

    @mock.patch("urllib.request.urlopen")
    def test_list_users(self, mock_urlopen):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(
                '{"success": true, "data": [{"username": "alice", "role": "admin"}], "total": 1, "page": 1, "per_page": 50}'
            )

        mock_urlopen.side_effect = fake_urlopen

        client = SSHProxyClient("https://proxy.example.com", token="token-123")
        page = client.list_users()

        self.assertEqual(1, page.total)
        self.assertEqual("alice", page.items[0].username)
        self.assertEqual("Bearer token-123", captured["request"].headers["Authorization"])
        self.assertEqual(30.0, captured["timeout"])

    @mock.patch("urllib.request.urlopen")
    def test_list_sessions_includes_filters(self, mock_urlopen):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            return FakeResponse('{"success": true, "data": [], "total": 0, "page": 2, "per_page": 10}')

        mock_urlopen.side_effect = fake_urlopen

        client = SSHProxyClient("https://proxy.example.com")
        page = client.list_sessions(status="active", user="alice", page=2, per_page=10)

        self.assertEqual(2, page.page)
        self.assertIn("status=active", captured["url"])
        self.assertIn("user=alice", captured["url"])
        self.assertIn("page=2", captured["url"])
        self.assertIn("per_page=10", captured["url"])

    @mock.patch("urllib.request.urlopen")
    def test_sign_user_certificate(self, mock_urlopen):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["body"] = request.data.decode("utf-8")
            return FakeResponse(
                '{"success": true, "data": {"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...", "serial": 7, "key_id": "alice-7", "expires_at": "2026-04-08T12:00:00Z"}}'
            )

        mock_urlopen.side_effect = fake_urlopen

        client = SSHProxyClient("https://proxy.example.com")
        cert = client.sign_user_certificate(
            {
                "public_key": "ssh-ed25519 AAAAalice",
                "principals": ["alice"],
                "ttl": "8h",
            }
        )

        self.assertEqual(7, cert.serial)
        self.assertIn('"public_key": "ssh-ed25519 AAAAalice"', captured["body"])

    @mock.patch("urllib.request.urlopen")
    def test_api_error(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://proxy.example.com/api/v2/users",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=io.BytesIO(b'{"success": false, "error": "bad request"}'),
        )

        client = SSHProxyClient("https://proxy.example.com")
        with self.assertRaises(SSHProxyError) as ctx:
            client.list_users()

        self.assertIn("bad request", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
