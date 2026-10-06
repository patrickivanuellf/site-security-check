# site-security-check

A small, **read-only** command line tool that checks the security configuration of a website (TLS certificate, HTTP security headers, cookies, exposed files) and produces a scored report with a concrete fix for every finding.

It uses only the Python standard library and only sends plain `GET` requests, so it is safe to run against your own sites at any time.

> **Only scan sites you own or have written permission to test.**

## Why I built it

I run several live websites, and every one of them needs the same checks: is the certificate about to expire, are the security headers set, does the server leak its version, is a `.env` file accidentally public? This tool turns that routine into code, so the result is repeatable, scored, and easy to run on many sites at once or from a CI job.

## Features

- 15 checks across TLS, HTTP redirect, security headers, cookies and exposed files, plus an optional `ads.txt` validation for ad-supported sites
- Weighted score from 0 to 100 (high, medium and low severity checks)
- A suggested fix for every warning and failure
- Scan one site or a whole list (`--file sites.txt`) with an overview of all scores
- Text, JSON and Markdown reports
- `--fail-under` exit code for CI pipelines
- `--cafile` to trust an internal or self-signed certificate
- Cookie values and file contents are never printed, only names and paths
- 25 tests that run against local HTTP and HTTPS servers, no internet needed

## Quick start

```bash
git clone https://github.com/patrickivanuellf/site-security-check.git
cd site-security-check

python3 -m site_security_check example.com
python3 -m site_security_check example.com example.org --format md -o report.md
python3 -m site_security_check --file sites.txt --check-ads-txt
python3 -m site_security_check example.com --format json --fail-under 80
```

`sites.txt` has one domain or URL per line. Lines starting with `#` are ignored.

Options:

| Option | Meaning |
|---|---|
| `targets` | One or more domains or URLs |
| `-f, --file FILE` | Read targets from a file |
| `--format text\|json\|md` | Report format. Default `text` |
| `-o, --output FILE` | Write the report to a file |
| `--fail-under N` | Exit with status 1 if any site scores below N |
| `--timeout SECONDS` | Network timeout. Default 8 |
| `--cafile FILE` | Extra CA certificate to trust |
| `--check-ads-txt` | Also validate `/ads.txt` |

## What it checks

| ID | Area | Check | Severity |
|---|---|---|---|
| TLS-001 | TLS | HTTPS works with a valid certificate for this hostname | high |
| TLS-002 | TLS | Certificate is not close to expiry (warn under 14 days, fail under 7) | high |
| TLS-003 | TLS | TLS 1.3 is supported | low |
| HTTP-001 | TLS | Plain HTTP redirects to HTTPS | medium |
| HDR-001 | Headers | Strict-Transport-Security with a long `max-age` | high |
| HDR-002 | Headers | Content-Security-Policy present, without `unsafe-inline`, `unsafe-eval` or wildcards in script sources | medium |
| HDR-003 | Headers | `X-Content-Type-Options: nosniff` | medium |
| HDR-004 | Headers | Clickjacking protection (`X-Frame-Options` or CSP `frame-ancestors`) | medium |
| HDR-005 | Headers | Referrer-Policy is set and not `unsafe-url` | low |
| HDR-006 | Headers | Permissions-Policy is set | low |
| HDR-007 | Headers | `Server` header does not reveal a version | low |
| HDR-008 | Headers | `X-Powered-By` is not exposed | low |
| CKE-001 | Cookies | Cookies have `Secure`, `HttpOnly` and `SameSite` | medium |
| FIL-001 | Files | `/.well-known/security.txt` is published | low |
| FIL-002 | Files | `/.git/HEAD`, `/.env` and `/backup.sql` are not readable | high |
| ADS-001 | Ads | `/ads.txt` has valid entries (optional) | low |

Header checks look at the final HTTPS response after following up to five redirects that stay on HTTPS.

## Scoring

Each check has a weight: high = 3, medium = 2, low = 1. A `PASS` earns the full weight, a `WARN` half, a `FAIL` nothing. `SKIP` checks (for example, header checks when HTTPS is unreachable) are ignored. The score is the earned weight divided by the total weight, as a percentage.

## Sample output

An excerpt from a deliberately weak local test server (headers, cookies and files only):

```text
=== demo-site.local ===
[Headers]
  WARN  HDR-001  Strict-Transport-Security tells browsers to always use HTTPS
            max-age=300 is below 15552000 (180 days)
            fix: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  FAIL  HDR-002  Content-Security-Policy limits where scripts can load from
            header missing
            fix: Add a Content-Security-Policy, starting with: default-src 'self'
  WARN  HDR-007  Server header does not reveal a software version
            reveals a version: 'Apache/2.4.41 (Ubuntu)'
            fix: Hide the version (nginx: server_tokens off; Apache: ServerTokens Prod).
[Cookies]
  FAIL  CKE-001  Cookies are set with Secure, HttpOnly and SameSite
            missing Secure: PHPSESSID
[Files]
  FAIL  FIL-002  Common sensitive files are not publicly readable
            exposed: /.env

Summary: 3 passed, 8 warnings, 5 failed, 0 skipped
Score:   43/100
```

## Design notes

- **Read-only by design.** Only `GET` requests and one TLS handshake. Nothing is sent that could change state on a site.
- **Network and logic are separate.** `net.py` does the I/O, `checks.py` holds the rules, `report.py` renders. That is what makes the tests possible with local servers instead of the real internet.
- **Soft 404s do not cause false alarms.** A "sensitive file" is only reported when the content really looks like that file (for example a `ref:` line for `.git/HEAD`, or `KEY=value` lines for `.env`), not when a site answers 200 to everything.
- **One broken check never kills the report.** A check that crashes is reported as `SKIP` with the error.

## Limitations

- This is a learning and portfolio project, not a replacement for full scanners such as Mozilla Observatory, SSL Labs or OWASP ZAP.
- TLS checks cover the certificate and the negotiated protocol version. They do not enumerate cipher suites or detect old protocol versions.
- Only the home page and a few well-known paths are inspected, not the whole site.
- Header checks flag the presence and obvious weaknesses of a policy. They do not judge whether a Content-Security-Policy is complete for your application.

## Roadmap

- Cipher suite and legacy protocol detection
- Subresource Integrity and mixed-content checks
- HTML report
- Crawl a few internal pages instead of only the home page

## Development

```bash
pip install pytest
python3 -m pytest
```

The tests start local HTTP and HTTPS servers (with a throw-away self-signed certificate made by `openssl`) on random ports. Tested on Python 3.12.

## License

MIT. See [LICENSE](LICENSE).

Author: Patrick Ivanuell Firstyanto
