#!/usr/bin/env python3
"""
check_ips.py — Bulk-check IP addresses against AbuseIPDB.

A small SOC triage helper: given a list of IPs (from a file or the command line),
query the AbuseIPDB v2 API and print each IP's abuse confidence score, country,
ISP, and recent report count. IPs at or above a threshold are flagged.

The API key is read from a .env file (ABUSEIPDB_API_KEY) and is NEVER committed.
See .env.example and README.md.

Usage:
    python check_ips.py 8.8.8.8 1.1.1.1
    python check_ips.py --file ips.txt
    python check_ips.py --file ips.txt --threshold 50 --csv results.csv
"""

import argparse
import csv
import ipaddress
import os
import sys
import time

import requests
from dotenv import load_dotenv

API_URL = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_MAX_AGE_DAYS = 90


def load_api_key() -> str:
    """Load the AbuseIPDB key from the environment (.env), or exit with guidance."""
    load_dotenv()
    key = os.getenv("ABUSEIPDB_API_KEY")
    if not key:
        sys.exit(
            "Error: ABUSEIPDB_API_KEY is not set.\n"
            "Copy .env.example to .env and paste your key into it "
            "(get a free key at https://www.abuseipdb.com/account/api)."
        )
    return key


def read_ips(args) -> list[str]:
    """Collect IPs from --file and/or positional args, de-duplicated, order-preserved."""
    ips: list[str] = []
    if args.file:
        try:
            with open(args.file, encoding="utf-8") as fh:
                ips.extend(line.strip() for line in fh if line.strip() and not line.startswith("#"))
        except FileNotFoundError:
            sys.exit(f"Error: file not found: {args.file}")
    ips.extend(args.ips)
    # de-duplicate while preserving order
    seen, unique = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    if not unique:
        sys.exit("Error: no IPs provided. Pass IPs as arguments or use --file.")
    return unique


def valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_ip(ip: str, key: str, max_age: int) -> dict:
    """Query AbuseIPDB for one IP. Returns a result dict (never raises for a single IP)."""
    headers = {"Key": key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": str(max_age)}
    try:
        resp = requests.get(API_URL, headers=headers, params=params, timeout=15)
    except requests.RequestException as exc:
        return {"ipAddress": ip, "error": f"request failed: {exc}"}

    if resp.status_code == 429:
        return {"ipAddress": ip, "error": "rate limited (HTTP 429) — slow down or check your plan"}
    if resp.status_code == 401:
        sys.exit("Error: HTTP 401 Unauthorized — your API key is missing or invalid.")
    if resp.status_code != 200:
        return {"ipAddress": ip, "error": f"HTTP {resp.status_code}"}

    data = resp.json().get("data", {})
    return {
        "ipAddress": data.get("ipAddress", ip),
        "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
        "countryCode": data.get("countryCode") or "?",
        "isp": data.get("isp") or "?",
        "totalReports": data.get("totalReports", 0),
        "error": None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Bulk-check IPs against AbuseIPDB.")
    parser.add_argument("ips", nargs="*", help="IP addresses to check")
    parser.add_argument("-f", "--file", help="file with one IP per line (# comments allowed)")
    parser.add_argument("-t", "--threshold", type=int, default=25,
                        help="flag IPs with an abuse score >= this (default: 25)")
    parser.add_argument("--max-age", type=int, default=DEFAULT_MAX_AGE_DAYS,
                        help=f"report age window in days (default: {DEFAULT_MAX_AGE_DAYS})")
    parser.add_argument("--csv", help="also write results to this CSV file")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds to wait between requests (helps avoid rate limits)")
    args = parser.parse_args()

    key = load_api_key()
    ips = read_ips(args)
    results = []

    print(f"{'IP':<18} {'Score':>5}  {'Country':<7} {'Reports':>7}  ISP")
    print("-" * 70)

    for ip in ips:
        if not valid_ip(ip):
            print(f"{ip:<18} {'--':>5}  invalid IP, skipped")
            continue
        res = check_ip(ip, key, args.max_age)
        results.append(res)
        if res.get("error"):
            print(f"{res['ipAddress']:<18} {'ERR':>5}  {res['error']}")
        else:
            flag = "  ⚠" if res["abuseConfidenceScore"] >= args.threshold else ""
            print(f"{res['ipAddress']:<18} {res['abuseConfidenceScore']:>5}  "
                  f"{res['countryCode']:<7} {res['totalReports']:>7}  {res['isp']}{flag}")
        if args.delay:
            time.sleep(args.delay)

    flagged = [r for r in results if not r.get("error") and r["abuseConfidenceScore"] >= args.threshold]
    print("-" * 70)
    print(f"Checked {len(results)} IP(s); {len(flagged)} at or above threshold {args.threshold}.")

    if args.csv and results:
        clean = [r for r in results if not r.get("error")]
        if clean:
            with open(args.csv, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(
                    fh, fieldnames=["ipAddress", "abuseConfidenceScore", "countryCode", "totalReports", "isp"])
                writer.writeheader()
                for r in clean:
                    writer.writerow({k: r.get(k) for k in writer.fieldnames})
            print(f"Wrote {len(clean)} row(s) to {args.csv}")


if __name__ == "__main__":
    main()
