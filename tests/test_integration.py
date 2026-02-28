"""
Integration tests — verify server startup, health check, and auth enforcement.

These tests start the actual FastMCP server in a subprocess and make HTTP
requests against it. They require all pip dependencies to be installed
(run inside Docker via Dockerfile.test).

Usage:
    python -m pytest tests/test_integration.py -v
    # or:
    python tests/test_integration.py
"""

import os
import signal
import socket
import subprocess
import sys
import time
import unittest

import httpx


TEST_PORT = 9876
TEST_API_KEY = "test-integration-key-abc123"
SERVER_URL = f"http://127.0.0.1:{TEST_PORT}"


def _wait_for_port(port: int, host: str = "127.0.0.1", timeout: float = 15.0) -> bool:
    """Block until a TCP port is accepting connections, or timeout."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


class TestServerIntegration(unittest.TestCase):
    """Start the MCP server and verify HTTP-level behavior."""

    proc: subprocess.Popen | None = None

    @classmethod
    def setUpClass(cls):
        """Start server.py as a subprocess with test env vars."""
        env = os.environ.copy()
        env.update({
            "PORT": str(TEST_PORT),
            "TEAM_API_KEYS": TEST_API_KEY,
            # SF credentials are intentionally invalid — we're testing
            # HTTP/auth layer only, not actual Salesforce connectivity.
            "SF_USERNAME": "test@example.com",
            "SF_PASSWORD": "not-real",
            "SF_SECURITY_TOKEN": "",
            "SF_DOMAIN": "login",
            "SF_CLIENT_ID": "",
            "SF_CLIENT_SECRET": "",
            "PARDOT_BUSINESS_UNIT_ID": "0Uv000000000001AAA",
        })

        cls.proc = subprocess.Popen(
            [sys.executable, "server.py"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        )

        if not _wait_for_port(TEST_PORT):
            # Grab whatever output the server produced before dying
            if cls.proc.poll() is not None:
                output = cls.proc.stdout.read().decode() if cls.proc.stdout else ""
                cls.proc = None
                raise RuntimeError(f"Server failed to start. Output:\n{output}")
            cls.proc.kill()
            cls.proc = None
            raise RuntimeError(f"Server did not open port {TEST_PORT} within timeout")

    @classmethod
    def tearDownClass(cls):
        """Stop the server subprocess."""
        if cls.proc is not None:
            cls.proc.send_signal(signal.SIGTERM)
            try:
                cls.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.proc.kill()
                cls.proc.wait()

    # -- Health check -------------------------------------------------------

    def test_health_endpoint_returns_ok(self):
        """GET /health should return 200 with {"status": "ok"}."""
        resp = httpx.get(f"{SERVER_URL}/health", timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")

    # -- SSE endpoint exists ------------------------------------------------

    def test_sse_endpoint_exists(self):
        """GET /sse should return 200 (SSE stream opens)."""
        # We open the stream but close immediately — just verifying 200.
        with httpx.stream("GET", f"{SERVER_URL}/sse", timeout=5) as resp:
            self.assertEqual(resp.status_code, 200)

    # -- Server responds on correct port ------------------------------------

    def test_server_binds_to_configured_port(self):
        """Server should be listening on TEST_PORT."""
        with socket.create_connection(("127.0.0.1", TEST_PORT), timeout=2):
            pass  # connection succeeded


class TestAuthEnforcement(TestServerIntegration):
    """Verify auth behavior on HTTP endpoints.

    Inherits from TestServerIntegration so the server subprocess is shared
    (setUpClass/tearDownClass run once for the parent, reused here).

    Note: MCP tool calls go through the SSE/JSON-RPC protocol, not plain HTTP.
    These tests verify the health endpoint (custom route, no MCP middleware).
    Full MCP-level auth testing requires an MCP client.
    """

    def test_health_no_auth_required(self):
        """Health check should work without any Authorization header."""
        resp = httpx.get(f"{SERVER_URL}/health", timeout=5)
        self.assertEqual(resp.status_code, 200)

    def test_health_ignores_bad_auth(self):
        """Health check should work even with an invalid token (it's not MCP)."""
        resp = httpx.get(
            f"{SERVER_URL}/health",
            headers={"Authorization": "Bearer wrong-key"},
            timeout=5,
        )
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
