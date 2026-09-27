"""
scanner.py
----------
Core checks for the Automated Web Application Security Assessment & Reporting Platform.

IMPORTANT / RESPONSIBLE USE
This tool only performs passive / non-intrusive checks against a target:
  - reading HTTP response headers
  - reading the TLS certificate a server presents
  - requesting a small set of well-known, publicly-served paths (robots.txt, etc.)
  - attempting TCP connections to common ports to see if they accept connections

It does NOT attempt to exploit anything, brute-force credentials, fuzz parameters,
or send attack payloads. Only run this against systems you own or are explicitly
authorized to test. Running security scans against systems without permission is
illegal in most jurisdictions.
"""

from __future__ import annotations

import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

requests.packages.urllib3.disable_warnings()  # we intentionally allow self-signed certs for inspection


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


@dataclass
class Finding:
    category: str
    title: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW / INFO
    detail: str
    recommendation: str = ""


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    findings: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, category, title, severity, detail, recommendation=""):
        self.findings.append(Finding(category, title, severity.upper(), detail, recommendation))

    def score(self) -> int:
        """Simple 0-100 risk score. 100 = clean, 0 = terrible."""
        weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3, "INFO": 0}
        penalty = sum(weights.get(f.severity, 0) for f in self.findings)
        return max(0, 100 - penalty)

    def counts(self) -> dict:
        c = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c


# --------------------------------------------------------------------------- #
# Individual checks
# --------------------------------------------------------------------------- #

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "HIGH",
        "No Content-Security-Policy header. This weakens defenses against XSS and data-injection attacks.",
    ),
    "Strict-Transport-Security": (
        "HIGH",
        "No HSTS header. Browsers may be tricked into using plain HTTP, enabling downgrade/MITM attacks.",
    ),
    "X-Content-Type-Options": (
        "MEDIUM",
        "No X-Content-Type-Options header. Browsers may MIME-sniff responses, enabling certain attacks.",
    ),
    "X-Frame-Options": (
        "MEDIUM",
        "No X-Frame-Options header. Page may be vulnerable to clickjacking via iframe embedding.",
    ),
    "Referrer-Policy": (
        "LOW",
        "No Referrer-Policy header. Full URLs (possibly with sensitive query params) may leak via the Referer header.",
    ),
    "Permissions-Policy": (
        "LOW",
        "No Permissions-Policy header. Browser features (camera, geolocation, etc.) are not explicitly restricted.",
    ),
}

SENSITIVE_PATHS = [
    ("/.git/config", "CRITICAL", "Exposed .git directory can leak full source code and history."),
    ("/.env", "CRITICAL", "Exposed .env file may leak secrets, API keys, or database credentials."),
    ("/backup.zip", "HIGH", "Exposed backup archive may contain sensitive site data."),
    ("/wp-config.php.bak", "HIGH", "Exposed backup of a config file may leak credentials."),
    ("/.DS_Store", "LOW", "Exposed .DS_Store can reveal directory structure."),
    ("/server-status", "MEDIUM", "Apache server-status page may expose internal request info."),
    ("/phpinfo.php", "MEDIUM", "phpinfo() page exposes detailed server/environment configuration."),
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 27017: "MongoDB",
}


def check_headers(result: ScanResult, resp: requests.Response):
    headers = resp.headers
    for name, (severity, msg) in SECURITY_HEADERS.items():
        if name not in headers:
            result.add("HTTP Headers", f"Missing {name}", severity, msg,
                       f"Add a `{name}` header with an appropriate policy.")
        else:
            result.add("HTTP Headers", f"{name} present", "INFO", f"Value: {headers[name][:120]}")

    server = headers.get("Server")
    if server:
        result.add("Information Disclosure", "Server banner exposed", "LOW",
                   f"Server header reveals: {server}",
                   "Suppress or genericize the Server header.")
    powered_by = headers.get("X-Powered-By")
    if powered_by:
        result.add("Information Disclosure", "X-Powered-By exposed", "LOW",
                   f"X-Powered-By reveals: {powered_by}",
                   "Remove the X-Powered-By header.")


def check_cookies(result: ScanResult, resp: requests.Response):
    cookies_hdr = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else None
    if not cookies_hdr:
        cookies_hdr = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"] if resp.raw.headers else []
    if not cookies_hdr:
        return
    for raw_cookie in cookies_hdr:
        name = raw_cookie.split("=", 1)[0]
        lower = raw_cookie.lower()
        issues = []
        if "secure" not in lower:
            issues.append("missing Secure flag")
        if "httponly" not in lower:
            issues.append("missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append("missing SameSite attribute")
        if issues:
            result.add("Cookies", f"Cookie '{name}' misconfigured", "MEDIUM",
                       f"{name}: {', '.join(issues)}.",
                       "Set Secure, HttpOnly and SameSite=Strict/Lax on all session cookies.")
        else:
            result.add("Cookies", f"Cookie '{name}' looks properly configured", "INFO",
                       "Secure, HttpOnly and SameSite all present.")


def check_tls(result: ScanResult, hostname: str, port: int = 443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                if not cert:
                    result.add("TLS/SSL", "Certificate unreadable", "MEDIUM",
                               "Could not parse peer certificate.")
                    return
                not_after = cert.get("notAfter")
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result.add("TLS/SSL", "Certificate details", "INFO",
                           f"Issuer: {issuer.get('organizationName', 'Unknown')} | "
                           f"Expires: {expiry.date()} ({days_left} days left) | Protocol: {proto}")
                if days_left < 0:
                    result.add("TLS/SSL", "Certificate expired", "CRITICAL",
                               f"Certificate expired on {expiry.date()}.",
                               "Renew the TLS certificate immediately.")
                elif days_left < 14:
                    result.add("TLS/SSL", "Certificate expiring soon", "HIGH",
                               f"Certificate expires in {days_left} days.",
                               "Renew the TLS certificate before it expires.")
                if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    result.add("TLS/SSL", "Outdated TLS protocol in use", "HIGH",
                               f"Negotiated protocol: {proto}.",
                               "Disable legacy protocols; require TLS 1.2+ (ideally 1.3).")
    except Exception as e:
        result.add("TLS/SSL", "TLS check failed", "MEDIUM", f"Could not establish TLS session: {e}")


def check_sensitive_paths(result: ScanResult, base_url: str, session: requests.Session):
    for path, severity, msg in SENSITIVE_PATHS:
        try:
            r = session.get(base_url.rstrip("/") + path, timeout=6, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                result.add("Exposed Files", f"Potentially exposed: {path}", severity, msg,
                           f"Remove public access to `{path}` or block it at the web server / proxy layer.")
        except requests.RequestException:
            continue


def check_robots(result: ScanResult, base_url: str, session: requests.Session):
    try:
        r = session.get(base_url.rstrip("/") + "/robots.txt", timeout=6, verify=False)
        if r.status_code == 200 and r.text.strip():
            disallowed = [l for l in r.text.splitlines() if l.lower().startswith("disallow")]
            if disallowed:
                result.add("Information Disclosure", "robots.txt reveals hidden paths", "LOW",
                           f"{len(disallowed)} Disallow entries found, e.g. {disallowed[:3]}",
                           "Avoid listing sensitive paths in robots.txt; rely on access control instead.")
    except requests.RequestException:
        pass


def check_ports(result: ScanResult, hostname: str, ports=None, timeout: float = 1.0):
    ports = ports or COMMON_PORTS
    open_ports = []
    for port, service in ports.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((hostname, port)) == 0:
                    open_ports.append((port, service))
        except socket.error:
            continue
    if open_ports:
        for port, service in open_ports:
            sev = "MEDIUM" if port not in (80, 443) else "INFO"
            result.add("Network Exposure", f"Port {port} ({service}) open", sev,
                       f"TCP port {port} accepted a connection.",
                       "Confirm this service should be internet-facing; firewall it off if not.")
    else:
        result.add("Network Exposure", "No common ports found open (besides web)", "INFO",
                   "Scanned a standard list of common service ports.")


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

def run_scan(target: str, do_port_scan: bool = True) -> ScanResult:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    parsed = urlparse(target)
    hostname = parsed.hostname

    result = ScanResult(target=target, started_at=datetime.datetime.utcnow().isoformat() + "Z")
    session = requests.Session()
    session.headers.update({"User-Agent": "WebSecAssess/1.0 (authorized-scan)"})

    try:
        resp = session.get(target, timeout=10, verify=False, allow_redirects=True)
        result.meta["status_code"] = resp.status_code
        result.meta["final_url"] = resp.url
        check_headers(result, resp)
        check_cookies(result, resp)
    except requests.RequestException as e:
        result.add("Connectivity", "Could not reach target", "CRITICAL", str(e))
        result.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
        return result

    if parsed.scheme == "https" or True:
        check_tls(result, hostname, parsed.port or 443)

    check_sensitive_paths(result, target, session)
    check_robots(result, target, session)

    if do_port_scan and hostname:
        check_ports(result, hostname)

    result.findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 0))
    result.finished_at = datetime.datetime.utcnow().isoformat() + "Z"
    return result
