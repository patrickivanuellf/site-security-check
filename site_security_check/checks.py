"""Website security checks"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .net import REDIRECT_CODES, Response, Target, fetch_following, request, tls_info

PASS, WARN, FAIL, SKIP = "PASS", "WARN", "FAIL", "SKIP"
WEIGHTS = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Result:
    id: str
    category: str
    title: str
    status: str
    detail: str = ""
    fix: str = ""
    severity: str = "medium"


class Site:
    """Everything fetched once up front, so checks stay small and testable."""

    def __init__(self, target: Target, cafile: Optional[str] = None,
                 timeout: float = 8.0, check_ads_txt: bool = False):
        self.target = target
        self.cafile = cafile
        self.timeout = timeout
        self.check_ads_txt = check_ads_txt
        self.tls = tls_info(target.host, target.https_port, cafile, timeout)
        self.home: Optional[Response] = None
        self.home_error: Optional[str] = self.tls.error
        self.base: Tuple[str, int] = (target.host, target.https_port)
        if not self.tls.error:
            try:
                self.home = fetch_following(target, cafile, timeout)
                parts = urlsplit(self.home.url)
                self.base = (parts.hostname or target.host, parts.port or 443)
            except Exception as exc:  # network errors of any kind
                self.home_error = f"request failed: {exc}"

    def get(self, path: str) -> Optional[Response]:
        try:
            return request("https", self.base[0], self.base[1], path,
                           self.cafile, self.timeout)
        except Exception:
            return None


# --------------------------------------------------------------- TLS

def check_tls(site: Site) -> List[Result]:
    t1 = "HTTPS works with a valid certificate"
    t2 = "Certificate is not close to expiry"
    t3 = "TLS 1.3 is supported"
    fix1 = "Install a valid certificate for this exact hostname (for example with Let's Encrypt)."
    fix2 = "Renew the certificate and set up automatic renewal (certbot renew or your host's AutoSSL)."
    fix3 = "Enable TLS 1.3 in your web server or CDN settings."
    tls = site.tls
    if tls.error:
        return [Result("TLS-001", "TLS", t1, FAIL, tls.error, fix1, "high"),
                Result("TLS-002", "TLS", t2, SKIP, "no certificate to inspect", fix2, "high"),
                Result("TLS-003", "TLS", t3, SKIP, "no TLS session to inspect", fix3, "low")]
    days = int((tls.not_after - time.time()) // 86400)
    status = FAIL if days < 7 else WARN if days < 14 else PASS
    return [
        Result("TLS-001", "TLS", t1, PASS, f"issued by {tls.issuer or 'unknown'}", fix1, "high"),
        Result("TLS-002", "TLS", t2, status, f"expires in {days} days", fix2, "high"),
        Result("TLS-003", "TLS", t3, PASS if tls.version == "TLSv1.3" else WARN,
               f"negotiated {tls.version}", fix3, "low"),
    ]


def check_http_redirect(site: Site) -> Result:
    title = "Plain HTTP redirects to HTTPS"
    fix = "Add a permanent (301) redirect from http:// to https:// in your web server or CDN."
    t = site.target
    try:
        resp = request("http", t.host, t.http_port, "/", timeout=site.timeout)
    except Exception as exc:
        return Result("HTTP-001", "TLS", title, WARN,
                      f"port {t.http_port} is not reachable over HTTP ({exc.__class__.__name__}); "
                      "visitors typing http:// will fail", fix, "medium")
    location = resp.header("location") or ""
    if resp.status in REDIRECT_CODES and location.lower().startswith("https://"):
        return Result("HTTP-001", "TLS", title, PASS,
                      f"{resp.status} redirect to HTTPS", fix, "medium")
    if resp.status in REDIRECT_CODES:
        return Result("HTTP-001", "TLS", title, FAIL,
                      f"{resp.status} redirect, but not to an https:// URL", fix, "medium")
    return Result("HTTP-001", "TLS", title, FAIL,
                  f"serves content over plain HTTP (status {resp.status})", fix, "medium")


# ----------------------------------------------------------- headers

def _hsts(r: Response) -> Tuple[str, str]:
    value = r.header("strict-transport-security")
    if value is None:
        return FAIL, "header missing"
    m = re.search(r'max-age\s*=\s*"?(\d+)', value, re.I)
    if not m:
        return WARN, f"no valid max-age in '{value}'"
    age = int(m.group(1))
    if age >= 15552000:
        extra = ", includeSubDomains" if "includesubdomains" in value.lower() else ""
        return PASS, f"max-age={age}{extra}"
    return WARN, f"max-age={age} is below 15552000 (180 days)"


def csp_directives(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), " ".join(bits[1:]))
    return out


def _csp(r: Response) -> Tuple[str, str]:
    value = r.header("content-security-policy")
    if value is None:
        return FAIL, "header missing"
    directives = csp_directives(value)
    tokens = (directives.get("script-src") or directives.get("default-src") or "").split()
    issues = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in tokens]
    if "*" in tokens:
        issues.append("wildcard source")
    if issues:
        return WARN, "script policy allows " + ", ".join(issues)
    return PASS, "policy present"


def _nosniff(r: Response) -> Tuple[str, str]:
    value = r.header("x-content-type-options")
    if value is None:
        return FAIL, "header missing"
    return (PASS, "nosniff") if value.strip().lower() == "nosniff" else (WARN, f"unexpected value '{value}'")


def _frames(r: Response) -> Tuple[str, str]:
    csp = r.header("content-security-policy") or ""
    if "frame-ancestors" in csp_directives(csp):
        return PASS, "CSP frame-ancestors is set"
    xfo = (r.header("x-frame-options") or "").strip().upper()
    if xfo in ("DENY", "SAMEORIGIN"):
        return PASS, f"X-Frame-Options {xfo}"
    return FAIL, "neither X-Frame-Options nor CSP frame-ancestors is set"


def _referrer(r: Response) -> Tuple[str, str]:
    value = r.header("referrer-policy")
    if value is None:
        return WARN, "header missing"
    last = value.split(",")[-1].strip().lower()
    return (WARN, "unsafe-url leaks full URLs") if last == "unsafe-url" else (PASS, last)


def _permissions(r: Response) -> Tuple[str, str]:
    return (PASS, "header present") if r.header("permissions-policy") else (WARN, "header missing")


def _server(r: Response) -> Tuple[str, str]:
    value = r.header("server")
    if value is None:
        return PASS, "not disclosed"
    if re.search(r"\d+\.\d+", value):
        return WARN, f"reveals a version: '{value}'"
    return PASS, f"'{value}' (no version)"


def _powered_by(r: Response) -> Tuple[str, str]:
    value = r.header("x-powered-by")
    return (WARN, f"present: '{value}'") if value else (PASS, "not disclosed")


HEADER_RULES = [
    ("HDR-001", "Strict-Transport-Security tells browsers to always use HTTPS", "high", _hsts,
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("HDR-002", "Content-Security-Policy limits where scripts can load from", "medium", _csp,
     "Add a Content-Security-Policy, starting with: default-src 'self'"),
    ("HDR-003", "X-Content-Type-Options stops MIME sniffing", "medium", _nosniff,
     "Add: X-Content-Type-Options: nosniff"),
    ("HDR-004", "Clickjacking protection is set", "medium", _frames,
     "Add: X-Frame-Options: SAMEORIGIN, or CSP frame-ancestors 'self'"),
    ("HDR-005", "Referrer-Policy limits what is leaked to other sites", "low", _referrer,
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("HDR-006", "Permissions-Policy restricts browser features", "low", _permissions,
     "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"),
    ("HDR-007", "Server header does not reveal a software version", "low", _server,
     "Hide the version (nginx: server_tokens off; Apache: ServerTokens Prod)."),
    ("HDR-008", "X-Powered-By header is not exposed", "low", _powered_by,
     "Remove it (PHP: expose_php = Off; Express: app.disable('x-powered-by'))."),
]


def check_headers(site: Site) -> List[Result]:
    results = []
    for rid, title, sev, fn, fix in HEADER_RULES:
        if site.home is None:
            results.append(Result(rid, "Headers", title, SKIP, "no HTTPS response to inspect", fix, sev))
            continue
        status, detail = fn(site.home)
        results.append(Result(rid, "Headers", title, status, detail, fix, sev))
    return results


# ----------------------------------------------------------- cookies

def parse_cookie(header_value: str) -> Tuple[str, Dict[str, bool]]:
    """Return (cookie name, flags). The cookie value is never kept."""
    parts = [p.strip() for p in header_value.split(";")]
    name = parts[0].split("=", 1)[0].strip()
    attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:]}
    return name, {"secure": "secure" in attrs, "httponly": "httponly" in attrs,
                  "samesite": "samesite" in attrs}


def check_cookies(site: Site) -> Result:
    title = "Cookies are set with Secure, HttpOnly and SameSite"
    fix = "Add the missing attributes, for example: Set-Cookie: id=...; Secure; HttpOnly; SameSite=Lax"
    if site.home is None:
        return Result("CKE-001", "Cookies", title, SKIP, "no HTTPS response to inspect", fix, "medium")
    cookies = [parse_cookie(v) for v in site.home.header_all("set-cookie")]
    if not cookies:
        return Result("CKE-001", "Cookies", title, PASS, "no cookies set on the home page", fix, "medium")
    missing_secure = [n for n, f in cookies if not f["secure"]]
    other = [f"{n} ({', '.join(k for k in ('httponly', 'samesite') if not f[k])})"
             for n, f in cookies if not (f["httponly"] and f["samesite"])]
    if missing_secure:
        return Result("CKE-001", "Cookies", title, FAIL,
                      "missing Secure: " + ", ".join(missing_secure), fix, "medium")
    if other:
        return Result("CKE-001", "Cookies", title, WARN,
                      "missing flags: " + "; ".join(other), fix, "medium")
    return Result("CKE-001", "Cookies", title, PASS,
                  f"{len(cookies)} cookie(s), all with the recommended flags", fix, "medium")


# ------------------------------------------------------------- files

def check_security_txt(site: Site) -> Result:
    title = "security.txt tells researchers how to report problems"
    fix = "Publish /.well-known/security.txt with a Contact: line (see securitytxt.org)."
    resp = site.get("/.well-known/security.txt")
    if resp and resp.status == 200 and "contact:" in resp.text.lower():
        return Result("FIL-001", "Files", title, PASS, "found", fix, "low")
    return Result("FIL-001", "Files", title, WARN, "not found", fix, "low")


def _looks_like_env(r: Response) -> bool:
    return (r.status == 200 and "<html" not in r.text.lower()
            and re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", r.text, re.M) is not None)


def _looks_like_sql(r: Response) -> bool:
    return (r.status == 200 and "<html" not in r.text.lower()
            and re.search(r"CREATE TABLE|INSERT INTO", r.text, re.I) is not None)


SENSITIVE_FILES = [
    ("/.git/HEAD", lambda r: r.status == 200 and r.text.startswith("ref:")),
    ("/.env", _looks_like_env),
    ("/backup.sql", _looks_like_sql),
]


def check_sensitive_files(site: Site) -> Result:
    title = "Common sensitive files are not publicly readable"
    fix = "Block these paths in the web server and remove the files from the web root."
    if site.home is None:
        return Result("FIL-002", "Files", title, SKIP, "no HTTPS response to inspect", fix, "high")
    exposed = []
    for path, looks_real in SENSITIVE_FILES:
        resp = site.get(path)
        if resp is not None and looks_real(resp):
            exposed.append(path)
    if exposed:
        return Result("FIL-002", "Files", title, FAIL, "exposed: " + ", ".join(exposed), fix, "high")
    return Result("FIL-002", "Files", title, PASS, "none of the probed paths is readable", fix, "high")


def check_ads_txt(site: Site) -> List[Result]:
    """Optional (--check-ads-txt) for ad-supported sites."""
    if not site.check_ads_txt:
        return []
    title = "ads.txt is published with valid entries"
    fix = "Publish /ads.txt with one 'domain, publisher-id, DIRECT|RESELLER' line per ad partner."
    resp = site.get("/ads.txt")
    if resp is None or resp.status != 200:
        status = "not reachable" if resp is None else f"status {resp.status}"
        return [Result("ADS-001", "Ads", title, WARN, status, fix, "low")]
    entries = 0
    for line in resp.text.splitlines():
        fields = [f.strip() for f in line.split("#", 1)[0].split(",")]
        if len(fields) >= 3 and fields[2].upper() in ("DIRECT", "RESELLER") \
                and "=" not in fields[0]:
            entries += 1
    if entries:
        return [Result("ADS-001", "Ads", title, PASS, f"{entries} valid entries", fix, "low")]
    return [Result("ADS-001", "Ads", title, WARN, "file found but no valid entries", fix, "low")]


# ------------------------------------------------------------ runner

CHECKS = [check_tls, check_http_redirect, check_headers, check_cookies,
          check_security_txt, check_sensitive_files, check_ads_txt]


def run_all(site: Site) -> List[Result]:
    results: List[Result] = []
    for fn in CHECKS:
        try:
            out = fn(site)
        except Exception as exc:  # one broken check must not kill the report
            results.append(Result(fn.__name__, "Internal", fn.__name__, SKIP,
                                  f"check crashed: {exc}", "", "low"))
            continue
        results.extend(out if isinstance(out, list) else [out])
    return results


def scan(target: Target, cafile: Optional[str] = None, timeout: float = 8.0,
         check_ads_txt: bool = False) -> List[Result]:
    return run_all(Site(target, cafile, timeout, check_ads_txt))
