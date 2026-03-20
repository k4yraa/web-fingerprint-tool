from __future__ import annotations

import argparse
import sys

from modules.detector import fingerprint
from modules.formatter import (
    print_banner,
    print_cookies,
    print_fingerprint,
    print_redirects,
    print_security,
    print_summary,
)
from modules.http_client import fetch_target


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Passive web fingerprinting tool for owned or authorized targets."
    )
    parser.add_argument("target", help="Domain or URL, e.g. github.com or https://example.com")
    parser.add_argument("--timeout", type=int, default=6, help="Request timeout in seconds")
    args = parser.parse_args()

    print_banner()

    result = fetch_target(args.target, timeout=args.timeout)
    if result is None:
        print("Could not fetch target.")
        return 1

    fp = fingerprint(result.headers, result.body_sample, result.cookies)

    print_summary(args.target, result.final_url, result.status_code, result.reason, result.elapsed_ms)
    print_fingerprint(fp.server, fp.powered_by, fp.technologies, fp.confidence)
    print_security(fp.security_headers)
    print_cookies(fp.cookie_names)
    print_redirects(result.redirect_chain)

    return 0


if __name__ == "__main__":
    sys.exit(main())