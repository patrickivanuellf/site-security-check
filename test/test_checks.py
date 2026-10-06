import json

import pytest

from site_security_check.checks import FAIL, PASS, SKIP, WARN, Result, Site, run_all
from site_security_check.cli import main
from site_security_check.net import Target, parse_target
from site_security_check.report import render_markdown, render_text, score

from tests.conftest import free_port

GOOD = [
    ("Content-Type", "text/html"),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "strict-origin-when-cross-origin"),
    ("Permissions-Policy", "geolocation=()"),
]
SECURITY_TXT = (200, [("Content-Type", "text/plain")], b"Contact: mailto:security@example.com\n")


def scan(start_server, routes, tls_days=90, http_server=None, ads=False):
    https = start_server(routes, tls_days=tls_days)
    target = Target("127.0.0.1", https.port, http_server.port if http_server else free_port())
    site = Site(target, cafile=https.cert_path, timeout=3, check_ads_txt=ads)
    return {r.id: r for r in run_all(site)}


def home(headers, status=200):
    return {"/": (status, headers, b"<html>hello</html>")}


# ------------------------------------------------------------ parsing

def test_parse_target_variants():
    assert parse_target("example.com") == Target("example.com", 443, 80)
    assert parse_target("https://example.com:8443/x") == Target("example.com", 8443, 80)
    assert parse_target("http://localhost:8080") == Target("localhost", 443, 8080)
    with pytest.raises(ValueError):
        parse_target("ftp://example.com")


# ---------------------------------------------------------------- TLS

def test_good_site_passes_tls_and_headers(start_server):
    r = scan(start_server, {**home(GOOD), "/.well-known/security.txt": SECURITY_TXT})
    for rid in ("TLS-001", "TLS-002", "HDR-001", "HDR-002", "HDR-003", "HDR-004",
                "HDR-005", "HDR-006", "HDR-007", "HDR-008", "CKE-001", "FIL-001", "FIL-002"):
        assert r[rid].status == PASS, (rid, r[rid].detail)


def test_untrusted_certificate_fails_and_skips_the_rest(start_server):
    https = start_server(home(GOOD), tls_days=90)
    site = Site(Target("127.0.0.1", https.port, free_port()), cafile=None, timeout=3)
    r = {x.id: x for x in run_all(site)}
    assert r["TLS-001"].status == FAIL
    assert "verification failed" in r["TLS-001"].detail
    assert r["HDR-001"].status == SKIP
    assert r["FIL-002"].status == SKIP


def test_certificate_close_to_expiry_fails(start_server):
    assert scan(start_server, home(GOOD), tls_days=1)["TLS-002"].status == FAIL


def test_certificate_in_warning_window(start_server):
    assert scan(start_server, home(GOOD), tls_days=10)["TLS-002"].status == WARN


def test_tls13_is_reported(start_server):
    assert scan(start_server, home(GOOD))["TLS-003"].status == PASS


def test_http_redirect_pass_and_fail(start_server):
    https = start_server(home(GOOD), tls_days=90)
    redirect = start_server({"*": (301, [("Location", f"https://127.0.0.1:{https.port}/")], b"")})
    plain = start_server({"*": (200, [("Content-Type", "text/html")], b"<html>hi</html>")})
    bad_redirect = start_server({"*": (302, [("Location", "http://other.example/")], b"")})

    def check(http_server):
        site = Site(Target("127.0.0.1", https.port, http_server.port), https.cert_path, 3)
        return {x.id: x for x in run_all(site)}["HTTP-001"]

    assert check(redirect).status == PASS
    assert check(plain).status == FAIL
    assert check(bad_redirect).status == FAIL


def test_closed_http_port_is_a_warning(start_server):
    assert scan(start_server, home(GOOD))["HTTP-001"].status == WARN


def test_https_redirects_are_followed(start_server):
    routes = {"/": (301, [("Location", "/home")], b""), "/home": (200, GOOD, b"<html>ok</html>")}
    assert scan(start_server, routes)["HDR-001"].status == PASS


# ------------------------------------------------------------ headers

def test_missing_headers_fail(start_server):
    r = scan(start_server, home([("Content-Type", "text/html")]))
    for rid in ("HDR-001", "HDR-002", "HDR-003", "HDR-004"):
        assert r[rid].status == FAIL, rid
    assert r["HDR-005"].status == WARN
    assert r["HDR-006"].status == WARN


def test_short_hsts_is_a_warning(start_server):
    r = scan(start_server, home([("Strict-Transport-Security", "max-age=3600")]))
    assert r["HDR-001"].status == WARN


def test_unsafe_csp_is_a_warning(start_server):
    r = scan(start_server, home([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")]))
    assert r["HDR-002"].status == WARN
    assert "unsafe-inline" in r["HDR-002"].detail


def test_clickjacking_accepts_xfo_or_csp(start_server):
    assert scan(start_server, home([("X-Frame-Options", "DENY")]))["HDR-004"].status == PASS


def test_version_leaks_are_flagged(start_server):
    r = scan(start_server, home([("Server", "Apache/2.4.41 (Ubuntu)"), ("X-Powered-By", "PHP/8.1.2")]))
    assert r["HDR-007"].status == WARN
    assert r["HDR-008"].status == WARN


def test_server_without_version_is_fine(start_server):
    assert scan(start_server, home([("Server", "nginx")]))["HDR-007"].status == PASS


# ------------------------------------------------------------ cookies

def test_cookie_flags(start_server):
    good = home(GOOD + [("Set-Cookie", "sid=abc; Secure; HttpOnly; SameSite=Lax")])
    assert scan(start_server, good)["CKE-001"].status == PASS
    no_secure = home(GOOD + [("Set-Cookie", "sid=abc; HttpOnly; SameSite=Lax")])
    result = scan(start_server, no_secure)["CKE-001"]
    assert result.status == FAIL and "sid" in result.detail and "abc" not in result.detail
    no_samesite = home(GOOD + [("Set-Cookie", "sid=abc; Secure; HttpOnly")])
    assert scan(start_server, no_samesite)["CKE-001"].status == WARN


# -------------------------------------------------------------- files

def test_exposed_git_and_env_are_detected(start_server):
    routes = {**home(GOOD),
              "/.git/HEAD": (200, [("Content-Type", "text/plain")], b"ref: refs/heads/main\n"),
              "/.env": (200, [("Content-Type", "text/plain")], b"DB_PASSWORD=hunter2\n")}
    result = scan(start_server, routes)["FIL-002"]
    assert result.status == FAIL
    assert "/.git/HEAD" in result.detail and "/.env" in result.detail
    assert "hunter2" not in result.detail


def test_soft_404_pages_are_not_false_positives(start_server):
    soft = (200, [("Content-Type", "text/html")], b"<html>DB_PASSWORD=oops</html>")
    assert scan(start_server, {**home(GOOD), "*": soft})["FIL-002"].status == PASS


def test_security_txt_missing_is_a_warning(start_server):
    assert scan(start_server, home(GOOD))["FIL-001"].status == WARN


def test_ads_txt_is_optional_and_validated(start_server):
    assert "ADS-001" not in scan(start_server, home(GOOD))
    valid = (200, [("Content-Type", "text/plain")],
             b"# comment\ngoogle.com, pub-123, DIRECT, f08c47fec0942fa0\nexample.net, 55, RESELLER\n")
    assert scan(start_server, {**home(GOOD), "/ads.txt": valid}, ads=True)["ADS-001"].status == PASS
    junk = (200, [("Content-Type", "text/html")], b"<html>nope</html>")
    assert scan(start_server, {**home(GOOD), "/ads.txt": junk}, ads=True)["ADS-001"].status == WARN
    assert scan(start_server, home(GOOD), ads=True)["ADS-001"].status == WARN


# ------------------------------------------------- score and reports

def test_score_weights():
    rs = [Result("a", "x", "t", PASS, severity="high"),
          Result("b", "x", "t", FAIL, severity="high"),
          Result("c", "x", "t", WARN, severity="low"),
          Result("d", "x", "t", SKIP, severity="high")]
    assert score(rs) == round(100 * (3 + 0.5) / (3 + 3 + 1))


def test_good_site_scores_higher_than_bare_site(start_server):
    good = scan(start_server, {**home(GOOD), "/.well-known/security.txt": SECURITY_TXT})
    bare = scan(start_server, home([("Content-Type", "text/html")]))
    assert score(list(good.values())) > score(list(bare.values())) + 20


def test_reports_render(start_server):
    r = list(scan(start_server, home([("Content-Type", "text/html")])).values())
    text = render_text([("demo", r)], generated_at="T")
    assert "=== demo ===" in text and "fix:" in text and "Score:" in text
    md = render_markdown([("demo", r)], generated_at="T")
    assert "## demo" in md and "Recommendations" in md


def test_cli_end_to_end(start_server, tmp_path):
    https = start_server({**home(GOOD), "/.well-known/security.txt": SECURITY_TXT}, tls_days=90)
    out = tmp_path / "r.json"
    code = main([f"https://127.0.0.1:{https.port}", "--cafile", https.cert_path,
                 "--format", "json", "-o", str(out), "--fail-under", "50", "--timeout", "3"])
    data = json.loads(out.read_text())
    assert code == 0
    assert data["sites"][0]["score"] >= 50
    bad = main([f"https://127.0.0.1:{https.port}", "--format", "json", "-o", str(out),
                "--fail-under", "50", "--timeout", "3"])  # untrusted cert, no --cafile
    assert bad == 1


def test_cli_rejects_missing_targets_and_bad_input(tmp_path):
    assert main([]) == 2
    assert main(["ftp://nope"]) == 2
    targets = tmp_path / "t.txt"
    targets.write_text("# only a comment\n")
    assert main(["--file", str(targets)]) == 2
