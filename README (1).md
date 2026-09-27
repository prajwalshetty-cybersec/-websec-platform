# Automated Web Application Security Assessment & Reporting Platform

A lightweight, self-contained tool that runs a set of **passive, non-intrusive**
security checks against a web application and renders the results as a
dark/red "hacker terminal" styled HTML report.

> ⚠️ **Authorized use only.** Only scan systems you own or have explicit
> written permission to test. Unauthorized scanning of third-party systems
> may be illegal in your jurisdiction.

## What it checks

| Category | Checks |
|---|---|
| HTTP Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Information Disclosure | `Server` / `X-Powered-By` banners, `robots.txt` contents |
| Cookies | `Secure`, `HttpOnly`, `SameSite` flags |
| TLS/SSL | Certificate issuer, expiry date, negotiated protocol version |
| Exposed Files | Common sensitive paths (`.git/config`, `.env`, backups, `phpinfo.php`, etc.) |
| Network Exposure | Optional TCP connect scan of common service ports |

Each finding is tagged with a severity (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`)
and rolled into a 0–100 risk score.

## Install

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py https://example.com
# -> writes report.html in the current directory

python main.py example.com -o my_report.html --json findings.json
python main.py example.com --no-port-scan     # skip the port scan step
```

Open the generated `report.html` in a browser — findings are filterable by
severity, and the raw JSON is available in a collapsible section at the bottom.

## Project structure

```
websec_platform/
├── main.py               # CLI entry point
├── scanner.py             # All scan logic + data model
├── report_generator.py    # Red/black themed HTML report renderer
├── requirements.txt
└── README.md
```

## Extending it

- Add new checks as functions in `scanner.py` that call `result.add(...)`.
- Add new severities/colors in `SEVERITY_COLORS` in `report_generator.py`.
- Swap `run_scan()`'s target loop to iterate a list of URLs for bulk scanning.
