"""mitmproxy addon that binds GitHub credentials to sandbox Pod source addresses."""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.fernet import Fernet, InvalidToken
from mitmproxy import http

GITHUB_HOSTS = {"github.com", "api.github.com"}
CREDENTIALS: dict[str, tuple[str, frozenset[str] | None, float]] = {}
LOCK = threading.RLock()
ADMIN_TOKEN = os.environ["PROXY_ADMIN_TOKEN"]
TOKEN_CIPHER = Fernet(base64.urlsafe_b64encode(hashlib.sha256(ADMIN_TOKEN.encode()).digest()))


def _repository(host: str, path: str) -> str | None:
    match = re.match(r"^/repos/([^/]+/[^/]+)(?:/|$)", path) if host == "api.github.com" else None
    if match:
        return match.group(1).removesuffix(".git").lower()
    if host == "github.com":
        match = re.match(r"^/([^/]+/[^/]+?)(?:\.git)?(?:/|$)", path)
        if match:
            return match.group(1).removesuffix(".git").lower()
    return None


def authorize(source_ip: str, host: str, path: str) -> str | None:
    """Return the injected upstream Authorization value when the Pod is permitted."""
    with LOCK:
        credential = CREDENTIALS.get(source_ip)
    if not credential:
        return None
    token, repositories, expires_at = credential
    if time.monotonic() >= expires_at:
        with LOCK:
            CREDENTIALS.pop(source_ip, None)
        return None
    repository = _repository(host, path)
    safe_account_route = host == "api.github.com" and path.split("?", 1)[0] == "/user"
    if (
        repositories is not None
        and not safe_account_route
        and (repository is None or repository not in repositories)
    ):
        return None
    if host == "api.github.com":
        return f"Bearer {token}"
    encoded = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return f"Basic {encoded}"


def _source_ip(flow: http.HTTPFlow) -> str:
    peer = flow.client_conn.peername
    return str(peer[0]) if peer else ""


def _public_address(host: str) -> str | None:
    if host.endswith((".cluster.local", ".svc")) or host in {"localhost", "kubernetes"}:
        return None
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
        if not addresses or not all(ipaddress.ip_address(value).is_global for value in addresses):
            return None
        return addresses[0]
    except (OSError, ValueError):
        return None


def _pin_upstream(flow: http.HTTPFlow, host: str) -> bool:
    port = flow.request.port
    if port not in {80, 443}:
        return False
    address = _public_address(host)
    if address is None:
        return False
    flow.server_conn.address = (address, port)
    return True


class CredentialProxy:
    def running(self) -> None:
        server = ThreadingHTTPServer(("0.0.0.0", 8081), AdminHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host.lower().rstrip(".")
        flow.request.headers.pop("Proxy-Authorization", None)
        if not _pin_upstream(flow, host):
            flow.response = http.Response.make(403, b"Proxy target is not permitted\n")
            return
        if host not in GITHUB_HOSTS:
            return
        with LOCK:
            valid = _source_ip(flow) in CREDENTIALS
        if not valid:
            flow.response = http.Response.make(403, b"GitHub credential unavailable\n")

    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host.lower().rstrip(".")
        flow.request.headers.pop("Proxy-Authorization", None)
        if not _pin_upstream(flow, host):
            flow.response = http.Response.make(403, b"Proxy target is not permitted\n")
            return
        if host not in GITHUB_HOSTS:
            return
        injected = authorize(_source_ip(flow), host, flow.request.path)
        if injected is None:
            flow.response = http.Response.make(
                403,
                b"GitHub credential unavailable or repository not authorized\n",
                {"Content-Type": "text/plain"},
            )
            return
        for header in ("Authorization", "Cookie", "X-Forwarded-For", "Forwarded"):
            flow.request.headers.pop(header, None)
        flow.request.headers["Authorization"] = injected


class AdminHandler(BaseHTTPRequestHandler):
    def _authorized(self) -> bool:
        supplied = self.headers.get("Authorization", "").removeprefix("Bearer ")
        return hmac.compare_digest(supplied, ADMIN_TOKEN)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._respond(200, {"status": "ok"})
            return
        if self.path == "/self-test" and self._authorized():
            source_ip, token = "127.0.0.1", "k3-proxy-self-test-sentinel"
            with LOCK:
                CREDENTIALS[source_ip] = (token, None, time.monotonic() + 60)
            status = 0
            response_body = b""
            try:
                context = ssl.create_default_context(
                    cafile="/root/.mitmproxy/mitmproxy-ca-cert.pem"
                )
                opener = urllib.request.build_opener(
                    urllib.request.ProxyHandler({"https": "http://127.0.0.1:8080"}),
                    urllib.request.HTTPSHandler(context=context),
                )
                try:
                    response_body = opener.open("https://api.github.com/user", timeout=15).read()
                    status = 200
                except urllib.error.HTTPError as exc:
                    status = exc.code
                    response_body = exc.read()
            finally:
                with LOCK:
                    CREDENTIALS.pop(source_ip, None)
            denied = authorize("127.0.0.2", "api.github.com", "/user")
            ok = status == 401 and token.encode() not in response_body and denied is None
            self._respond(200 if ok else 500, {"status": "ok" if ok else "failed"})
            return
        self._respond(404, {"error": "not found"})

    def do_DELETE(self) -> None:  # noqa: N802
        if not self._authorized():
            self._respond(401, {"error": "unauthorized"})
            return
        prefix = "/credentials/"
        source_ip = self.path.removeprefix(prefix)
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            self._respond(400, {"error": "invalid source address"})
            return
        if not self.path.startswith(prefix):
            self._respond(400, {"error": "invalid source address"})
            return
        with LOCK:
            CREDENTIALS.pop(source_ip, None)
        self._respond(204, None)

    def do_PUT(self) -> None:  # noqa: N802
        if not self._authorized():
            self._respond(401, {"error": "unauthorized"})
            return
        prefix = "/credentials/"
        source_ip = self.path.removeprefix(prefix)
        try:
            ipaddress.ip_address(source_ip)
        except ValueError:
            self._respond(400, {"error": "invalid source address"})
            return
        if not self.path.startswith(prefix):
            self._respond(400, {"error": "invalid source address"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1024 * 1024:
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            encrypted_token = payload["encrypted_token"]
            token = TOKEN_CIPHER.decrypt(encrypted_token.encode()).decode()
            repos = payload.get("repositories", [])
            if not isinstance(token, str) or not token or not isinstance(repos, list):
                raise ValueError
            normalized = frozenset(str(repo).lower().removesuffix(".git") for repo in repos)
        except (ValueError, KeyError, json.JSONDecodeError, InvalidToken, UnicodeDecodeError):
            self._respond(400, {"error": "invalid payload"})
            return
        with LOCK:
            CREDENTIALS[source_ip] = (token, normalized, time.monotonic() + 3600)
        self._respond(204, None)

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _respond(self, status: int, body: dict[str, str] | None) -> None:
        content = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


addons = [CredentialProxy()]
