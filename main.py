"""
main.py
-------
CLI entry point for the Automated Web Application Security Assessment &
Reporting Platform.

Usage:
    python main.py https://example.com
    python main.py example.com --no-port-scan -o report.html
"""

import argparse
import sys
import json

from scanner import run_scan
from report_generator import generate_html_report


def main():
    parser = argparse.ArgumentParser(
        description="Automated Web Application Security Assessment & Reporting Platform "
                    "(authorized security testing only)."
    )
    parser.add_argument("target", help="Target URL or hostname, e.g. https://example.com")
    parser.add_argument("-o", "--output", default="report.html", help="Output HTML report path")
    parser.add_argument("--json", dest="json_out", default=None, help="Also write raw findings as JSON")
    parser.add_argument("--no-port-scan", action="store_true", help="Skip the TCP port scan step")
    args = parser.parse_args()

    print(f"[*] Starting scan of {args.target} ...")
    result = run_scan(args.target, do_port_scan=not args.no_port_scan)

    print(f"[*] Scan complete. {len(result.findings)} findings. Risk score: {result.score()}/100")

    html_report = generate_html_report(result)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f"[+] HTML report written to {args.output}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "target": result.target,
                    "started_at": result.started_at,
                    "finished_at": result.finished_at,
                    "score": result.score(),
                    "counts": result.counts(),
                    "findings": [f.__dict__ for f in result.findings],
                },
                f,
                indent=2,
            )
        print(f"[+] JSON findings written to {args.json_out}")


if __name__ == "__main__":
    sys.exit(main())
