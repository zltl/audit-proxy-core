from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


DEFAULT_USER_AGENT = "ssh-proxy-python-sdk/0.1"


class SSHProxyError(RuntimeError):
    def __init__(self, status_code: int, message: str = "", body: str = "") -> None:
        self.status_code = status_code
        self.message = message
        self.body = body
        detail = message or body or "unknown error"
        super().__init__(f"sshproxy API error (HTTP {status_code}): {detail}")


@dataclass
class Page:
    items: List[Any]
    total: int = 0
    page: int = 0
    per_page: int = 0


@dataclass
class User:
    username: str
    display_name: str = ""
    email: str = ""
    role: str = ""
    enabled: bool = True
    mfa_enabled: bool = False
    allowed_ips: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "User":
        return cls(
            username=payload.get("username", ""),
            display_name=payload.get("display_name", ""),
            email=payload.get("email", ""),
            role=payload.get("role", ""),
            enabled=payload.get("enabled", True),
            mfa_enabled=payload.get("mfa_enabled", False),
            allowed_ips=list(payload.get("allowed_ips", [])),
        )


@dataclass
class Server:
    id: str = ""
    name: str = ""
    host: str = ""
    port: int = 0
    group: str = ""
    status: str = ""
    healthy: bool = False

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Server":
        return cls(
            id=payload.get("id", ""),
            name=payload.get("name", ""),
            host=payload.get("host", ""),
            port=payload.get("port", 0),
            group=payload.get("group", ""),
            status=payload.get("status", ""),
            healthy=payload.get("healthy", False),
        )


@dataclass
class Session:
    id: str = ""
    username: str = ""
    source_ip: str = ""
    target_host: str = ""
    target_port: int = 0
    status: str = ""
    duration: str = ""

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Session":
        return cls(
            id=payload.get("id", ""),
            username=payload.get("username", ""),
            source_ip=payload.get("source_ip", ""),
            target_host=payload.get("target_host", ""),
            target_port=payload.get("target_port", 0),
            status=payload.get("status", ""),
            duration=payload.get("duration", ""),
        )


@dataclass
class SignedCertificate:
    certificate: str
    serial: int
    key_id: str
    expires_at: str

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SignedCertificate":
        return cls(
            certificate=payload.get("certificate", ""),
            serial=payload.get("serial", 0),
            key_id=payload.get("key_id", ""),
            expires_at=payload.get("expires_at", ""),
        )


class SSHProxyClient:
    def __init__(
        self,
        base_url: str,
        token: str = "",
        timeout: float = 30.0,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("base_url must include an http(s) scheme and host")

        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.user_agent = user_agent

    def list_users(self) -> Page:
        envelope = self._request("GET", "/api/v2/users")
        return Page(
            items=[User.from_dict(item) for item in envelope.get("data", [])],
            total=envelope.get("total", 0),
            page=envelope.get("page", 0),
            per_page=envelope.get("per_page", 0),
        )

    def create_user(self, payload: Dict[str, Any]) -> User:
        envelope = self._request("POST", "/api/v2/users", body=payload)
        return User.from_dict(envelope.get("data", {}))

    def list_servers(self) -> Page:
        envelope = self._request("GET", "/api/v2/servers")
        return Page(
            items=[Server.from_dict(item) for item in envelope.get("data", [])],
            total=envelope.get("total", 0),
            page=envelope.get("page", 0),
            per_page=envelope.get("per_page", 0),
        )

    def list_sessions(
        self,
        *,
        status: str = "",
        user: str = "",
        page: int = 0,
        per_page: int = 0,
    ) -> Page:
        query: Dict[str, Any] = {}
        if status:
            query["status"] = status
        if user:
            query["user"] = user
        if page > 0:
            query["page"] = page
        if per_page > 0:
            query["per_page"] = per_page

        envelope = self._request("GET", "/api/v2/sessions", query=query)
        return Page(
            items=[Session.from_dict(item) for item in envelope.get("data", [])],
            total=envelope.get("total", 0),
            page=envelope.get("page", 0),
            per_page=envelope.get("per_page", 0),
        )

    def get_config(self) -> Dict[str, Any]:
        envelope = self._request("GET", "/api/v2/config")
        return envelope.get("data", {})

    def sign_user_certificate(self, payload: Dict[str, Any]) -> SignedCertificate:
        envelope = self._request("POST", "/api/v2/ca/sign-user", body=payload)
        return SignedCertificate.from_dict(envelope.get("data", {}))

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)

        request_body = None
        if body is not None:
            request_body = json.dumps(body).encode("utf-8")

        request = urllib.request.Request(url=url, data=request_body, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", self.user_agent)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        if self.token:
            token = self.token if self.token.startswith("Bearer ") else f"Bearer {self.token}"
            request.add_header("Authorization", token)

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                status_code = getattr(response, "status", 200)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8")
            payload = self._parse_json(raw)
            raise SSHProxyError(exc.code, payload.get("error", ""), raw) from exc
        except urllib.error.URLError as exc:
            raise SSHProxyError(0, str(exc.reason)) from exc

        payload = self._parse_json(raw)
        if status_code >= 400 or not payload.get("success", False):
            raise SSHProxyError(status_code, payload.get("error", ""), raw)
        return payload

    @staticmethod
    def _parse_json(raw: str) -> Dict[str, Any]:
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SSHProxyError(0, "invalid JSON response", raw) from exc
        if not isinstance(payload, dict):
            raise SSHProxyError(0, "unexpected JSON response", raw)
        return payload
