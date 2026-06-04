#!/usr/bin/env python3
"""
Nagios check script for Let's Encrypt certificate expiry.

Runs `certbot certificates` to discover all managed certs, then checks
each certificate's expiry date via openssl.  Returns the worst state
found across all certificates.

Exit codes (Nagios convention):
  0 – OK
  1 – WARNING  (expiry within --warn days, default 28)
  2 – CRITICAL (expiry within --crit days, default 14)
  3 – UNKNOWN  (could not determine state)
"""

import argparse
import re
import subprocess
import sys
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Nagios exit codes
# ---------------------------------------------------------------------------
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

STATE_LABEL = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}


def nagios_exit(state: int, message: str) -> None:
    """Print a Nagios-compatible status line and exit."""
    print(f"CERT {STATE_LABEL[state]}: {message}")
    sys.exit(state)


# ---------------------------------------------------------------------------
# certbot helpers
# ---------------------------------------------------------------------------
def get_certbot_cert_paths(certbot_bin: str) -> list[dict]:
    """
    Run `certbot certificates` and return a list of dicts:
      { "name": <cert name>, "cert_path": <path to cert.pem> }
    """
    try:
        result = subprocess.run(
            [certbot_bin, "certificates"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        nagios_exit(UNKNOWN, f"certbot binary not found: {certbot_bin}")
    except subprocess.TimeoutExpired:
        nagios_exit(UNKNOWN, "certbot timed out")

    output = result.stdout + result.stderr  # certbot sometimes writes to stderr

    certs = []
    current: dict | None = None

    for line in output.splitlines():
        # New certificate block
        name_match = re.match(r"\s*Certificate Name:\s+(.+)", line)
        if name_match:
            current = {"name": name_match.group(1).strip(), "cert_path": None}
            certs.append(current)
            continue

        # Certificate path line
        path_match = re.match(r"\s*Certificate Path:\s+(.+)", line)
        if path_match and current is not None:
            current["cert_path"] = path_match.group(1).strip()

    if not certs:
        nagios_exit(UNKNOWN, "certbot returned no certificates (or parse failed)")

    return certs


# ---------------------------------------------------------------------------
# openssl helpers
# ---------------------------------------------------------------------------
def get_expiry_date(cert_path: str, openssl_bin: str) -> datetime:
    """
    Run `openssl x509 -in <cert> -noout -enddate` and return a timezone-aware
    datetime (UTC).
    """
    try:
        result = subprocess.run(
            [openssl_bin, "x509", "-in", cert_path, "-noout", "-enddate"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except FileNotFoundError:
        nagios_exit(UNKNOWN, f"openssl binary not found: {openssl_bin}")
    except subprocess.TimeoutExpired:
        nagios_exit(UNKNOWN, f"openssl timed out reading {cert_path}")

    if result.returncode != 0:
        raise RuntimeError(
            f"openssl failed for {cert_path}: {result.stderr.strip()}"
        )

    # Expected format: notAfter=May 20 12:34:56 2026 GMT
    match = re.search(r"notAfter=(.+)", result.stdout)
    if not match:
        raise ValueError(f"Could not parse notAfter from openssl output: {result.stdout!r}")

    date_str = match.group(1).strip()
    # Parse: "May 20 12:34:56 2026 GMT"
    expiry = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
    return expiry.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------
def check_certificates(args: argparse.Namespace) -> None:
    certs = get_certbot_cert_paths(args.certbot)

    now = datetime.now(tz=timezone.utc)

    results = []  # list of (days_remaining, cert_name, state)
    errors = []

    for cert in certs:
        name = cert["name"]
        path = cert["cert_path"]

        if path is None:
            errors.append(f"{name}: no certificate path found")
            continue

        try:
            expiry = get_expiry_date(path, args.openssl)
        except Exception as exc:
            errors.append(f"{name}: {exc}")
            continue

        days_remaining = (expiry - now).days

        if days_remaining < args.crit:
            state = CRITICAL
        elif days_remaining < args.warn:
            state = WARNING
        else:
            state = OK

        results.append((days_remaining, name, state, expiry))

    # -----------------------------------------------------------------------
    # Build output
    # -----------------------------------------------------------------------
    if not results and errors:
        nagios_exit(UNKNOWN, "; ".join(errors))

    # Determine overall (worst) state
    overall = OK
    for _, _, state, _ in results:
        if state > overall:
            overall = state

    # Build summary lines sorted worst-first, then by days remaining
    results.sort(key=lambda r: (r[2], r[0]), reverse=True)

    detail_parts = []
    perf_parts = []

    for days, name, state, expiry in results:
        label = STATE_LABEL[state]
        expiry_str = expiry.strftime("%Y-%m-%d")
        detail_parts.append(f"{name} expires {expiry_str} ({days}d) [{label}]")
        # Nagios performance data
        perf_parts.append(
            f"'{name}'={days}d;{args.warn};{args.crit};0;"
        )

    if errors:
        detail_parts.extend([f"ERROR: {e}" for e in errors])
        if overall < UNKNOWN:
            overall = UNKNOWN

    summary = ", ".join(detail_parts)
    perf_data = " ".join(perf_parts)

    print(f"CERT {STATE_LABEL[overall]}: {summary} | {perf_data}")
    sys.exit(overall)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Nagios check for Let's Encrypt certificate expiry via certbot + openssl",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-w", "--warn",
        type=int,
        default=28,
        metavar="DAYS",
        help="WARNING threshold: days before expiry",
    )
    parser.add_argument(
        "-c", "--crit",
        type=int,
        default=14,
        metavar="DAYS",
        help="CRITICAL threshold: days before expiry",
    )
    parser.add_argument(
        "--certbot",
        default="certbot",
        metavar="PATH",
        help="Path to the certbot binary",
    )
    parser.add_argument(
        "--openssl",
        default="openssl",
        metavar="PATH",
        help="Path to the openssl binary",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.crit >= args.warn:
        nagios_exit(
            UNKNOWN,
            f"--crit ({args.crit}) must be less than --warn ({args.warn})",
        )

    check_certificates(args)
