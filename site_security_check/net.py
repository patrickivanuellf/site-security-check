"""Network layer.

Kept separate from the checks so the checks can be tested against local
servers and the parsing logic never touches the network.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass
from typing import List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

USER_AGENT = "site-security-check/0.1 (read-only security scan)"
REDIRECT_CODES = (301, 302, 303, 307, 308)


@dataclass
class Target:
    host: str
    https_port: int = 443
    http_port: int = 80

    @property
    def label(self) -> str:
        return self.host if self.https_port == 443 else f"{self.host}:{self.https_port}"


def parse_target(text: str) -> Target:
    """Accept 'example.com', 'https://example.com:8443' or 'http://host:8080'."""
    raw = text.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"invalid target: {text!r}")
    if parts.scheme == "http":
        return Target(parts.hostname, 443, parts.port or 80)
    return Target(parts.hostname, parts.port or 443, 80)


@dataclass
class Response:
    status: int
    headers: List[Tuple[str, str]]
    body: bytes
    url: str

    def header(self, name: str) -> Optional[str]:
        wanted = name.lower()
        for key, value in self.headers:
            if key.lower() == wanted:
                return value
        return None

    def header_all(self, name: str) -> List[str]:
        wanted = name.lower()
        return [v for k, v in self.headers if k.lower() == wanted]

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def request(scheme: str, host: str, port: int, path: str = "/",
            cafile: Optional[str] = None, timeout: float = 8.0,
            max_body: int = 65536) -> Response:
    """One GET request, never following redirects. Raises on network errors."""
    if scheme == "https":
        ctx = ssl.create_default_context(cafile=cafile)
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        resp = conn.getresponse()
        body = resp.read(max_body)
        default = 443 if scheme == "https" else 80
        netloc = host if port == default else f"{host}:{port}"
        return Response(resp.status, resp.getheaders(), body, f"{scheme}://{netloc}{path}")
    finally:
        conn.close()


def fetch_following(target: Target, cafile: Optional[str] = None,
                    timeout: float = 8.0, max_hops: int = 5) -> Response:
    """GET / over HTTPS and follow redirects, as long as they stay on HTTPS."""
    host, port, path = target.host, target.https_port, "/"
    resp = request("https", host, port, path, cafile, timeout)
    for _ in range(max_hops):
        location = resp.header("location")
        if resp.status not in REDIRECT_CODES or not location:
            break
        parts = urlsplit(urljoin(resp.url, location))
        if parts.scheme != "https" or not parts.hostname:
            break
        host, port = parts.hostname, parts.port or 443
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        resp = request("https", host, port, path, cafile, timeout)
    return resp


@dataclass
class TLSInfo:
    version: Optional[str] = None
    not_after: Optional[float] = None  # seconds since the epoch
    issuer: str = ""
    error: Optional[str] = None


def _flat_name(rdns) -> str:
    flat = {key: value for rdn in (rdns or ()) for key, value in rdn}
    return flat.get("organizationName") or flat.get("commonName") or ""


def tls_info(host: str, port: int, cafile: Optional[str] = None,
             timeout: float = 8.0) -> TLSInfo:
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                return TLSInfo(
                    version=tls.version(),
                    not_after=ssl.cert_time_to_seconds(cert["notAfter"]),
                    issuer=_flat_name(cert.get("issuer")),
                )
    except ssl.SSLCertVerificationError as exc:
        return TLSInfo(error=f"certificate verification failed: {exc.verify_message or exc}")
    except (OSError, ssl.SSLError) as exc:
        return TLSInfo(error=f"cannot establish HTTPS connection: {exc}")
