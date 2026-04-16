"""
scanner/web_scanner.py
──────────────────────
HTTP/HTTPS header analysis and basic web vulnerability checks.

Checks performed
────────────────
1. HTTPS availability / HTTP-to-HTTPS redirect
2. Security response headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options,
   Referrer-Policy, Permissions-Policy)
3. Server banner disclosure
4. Cookies without Secure / HttpOnly flags (if Set-Cookie header present)
"""

import logging
import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10          # seconds
USER_AGENT = "MiniVulnScanner/1.0 (security-audit; contact=admin@example.com)"

# ── Security header definitions ───────────────────────────────────────────────

SECURITY_HEADERS: list[dict] = [
    {
        "header": "Strict-Transport-Security",
        "short": "HSTS",
        "severity": "high",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "description": "HSTS tells browsers to always use HTTPS, preventing downgrade attacks.",
    },
    {
        "header": "Content-Security-Policy",
        "short": "CSP",
        "severity": "high",
        "recommendation": "Define a Content-Security-Policy to restrict resource origins.",
        "description": "CSP mitigates XSS by whitelisting trusted content sources.",
    },
    {
        "header": "X-Frame-Options",
        "short": "X-Frame-Options",
        "severity": "medium",
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN)",
        "description": "Prevents clickjacking by disallowing iframe embedding.",
    },
    {
        "header": "X-Content-Type-Options",
        "short": "X-Content-Type-Options",
        "severity": "medium",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "description": "Stops browsers from MIME-sniffing a response away from the declared content-type.",
    },
    {
        "header": "Referrer-Policy",
        "short": "Referrer-Policy",
        "severity": "low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "description": "Controls how much referrer information is included with requests.",
    },
    {
        "header": "Permissions-Policy",
        "short": "Permissions-Policy",
        "severity": "low",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "description": "Restricts which browser features the page is allowed to use.",
    },
]


def _fetch(url: str) -> requests.Response | None:
    """Make a GET request and return the response, or None on failure."""
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            verify=True,
        )
        return resp
    except RequestException as exc:
        logger.warning("Request to %s failed: %s", url, exc)
        return None


def _check_https(host: str) -> dict:
    """Check whether HTTPS is available and HTTP redirects to HTTPS."""
    result = {
        "https_available": False,
        "http_redirects_to_https": False,
        "vulnerabilities": [],
    }

    # Try HTTPS first
    https_resp = _fetch(f"https://{host}")
    if https_resp and https_resp.status_code < 500:
        result["https_available"] = True
    else:
        result["vulnerabilities"].append({
            "type": "NO_HTTPS",
            "severity": "high",
            "title": "HTTPS not available",
            "detail": "The server does not respond on HTTPS. All traffic is transmitted in plaintext.",
            "recommendation": "Install a TLS certificate (free via Let's Encrypt) and enable HTTPS.",
        })

    # Try HTTP and check for redirect
    http_resp = _fetch(f"http://{host}")
    if http_resp:
        final_url = http_resp.url
        if final_url.startswith("https://"):
            result["http_redirects_to_https"] = True
        else:
            result["vulnerabilities"].append({
                "type": "NO_HTTPS_REDIRECT",
                "severity": "medium",
                "title": "HTTP does not redirect to HTTPS",
                "detail": "Plain HTTP requests are served without redirection to HTTPS.",
                "recommendation": "Configure a 301 redirect from HTTP to HTTPS.",
            })

    return result


def _analyze_headers(host: str) -> tuple[dict, list[dict], requests.Response | None]:
    """
    Fetch headers from the target (prefers HTTPS) and check for missing security headers.
    Returns (headers_dict, vulnerabilities, response).
    """
    resp = _fetch(f"https://{host}") or _fetch(f"http://{host}")
    if resp is None:
        return {}, [], None

    headers = dict(resp.headers)
    vulns = []

    for hdef in SECURITY_HEADERS:
        hname = hdef["header"]
        # Case-insensitive lookup
        present = any(k.lower() == hname.lower() for k in headers)
        if not present:
            vulns.append({
                "type": f"MISSING_{hdef['short'].upper().replace('-', '_')}",
                "severity": hdef["severity"],
                "title": f"Missing header: {hname}",
                "detail": hdef["description"],
                "recommendation": hdef["recommendation"],
            })

    return headers, vulns, resp


def _check_server_banner(headers: dict) -> list[dict]:
    """Flag if the Server header reveals version info."""
    vulns = []
    server = headers.get("Server") or headers.get("server", "")
    if server:
        # Version numbers in server banner are a risk
        import re
        if re.search(r"\d+\.\d+", server):
            vulns.append({
                "type": "SERVER_BANNER_DISCLOSURE",
                "severity": "low",
                "title": "Server version disclosed",
                "detail": f"Server header reveals: '{server}'",
                "recommendation": "Configure your web server to omit or obscure the Server header.",
            })
    return vulns


def _check_cookies(headers: dict) -> list[dict]:
    """Basic check for insecure Set-Cookie flags."""
    vulns = []
    # headers can have multiple Set-Cookie (requests merges them sometimes)
    set_cookie = headers.get("Set-Cookie") or headers.get("set-cookie", "")
    if not set_cookie:
        return vulns

    cookie_lower = set_cookie.lower()
    if "secure" not in cookie_lower:
        vulns.append({
            "type": "COOKIE_NO_SECURE",
            "severity": "medium",
            "title": "Cookie missing Secure flag",
            "detail": "A Set-Cookie header without the Secure flag may be sent over HTTP.",
            "recommendation": "Add the Secure attribute to all cookies.",
        })
    if "httponly" not in cookie_lower:
        vulns.append({
            "type": "COOKIE_NO_HTTPONLY",
            "severity": "medium",
            "title": "Cookie missing HttpOnly flag",
            "detail": "Cookies without HttpOnly can be accessed by JavaScript, increasing XSS risk.",
            "recommendation": "Add the HttpOnly attribute to session cookies.",
        })
    return vulns


def scan_web(host: str) -> dict:
    """
    Run all web checks against *host* (bare hostname or IP, no scheme).

    Returns a structured result dict.
    """
    logger.info("Web scan starting for %s", host)

    https_result = _check_https(host)
    headers, header_vulns, resp = _analyze_headers(host)
    banner_vulns = _check_server_banner(headers)
    cookie_vulns = _check_cookies(headers)

    all_vulns = (
        https_result["vulnerabilities"]
        + header_vulns
        + banner_vulns
        + cookie_vulns
    )

    status_code = resp.status_code if resp else None
    final_url   = resp.url        if resp else None

    result = {
        "host": host,
        "status_code": status_code,
        "final_url": final_url,
        "https_available": https_result["https_available"],
        "http_redirects_to_https": https_result["http_redirects_to_https"],
        "response_headers": {k: v for k, v in headers.items()},
        "vulnerabilities": all_vulns,
        "total_issues": len(all_vulns),
    }

    logger.info("Web scan complete for %s: %d issues found", host, len(all_vulns))
    return result
