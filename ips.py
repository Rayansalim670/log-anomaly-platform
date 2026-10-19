"""IPS decision engine: turns detections into block recommendations.

Default behavior is dry-run: commands are printed, nothing is applied.
Use --apply only on a machine you control, as root, with an allowlist
that contains your own IP address.
"""
import argparse
import ipaddress
import os
import subprocess
import sys

import pandas as pd

from detect import (
    parse, brute_force, incidents, invalid_users, suspicious_success
)

COLUMNS = ["ip", "score", "action", "ttl_hours", "reasons"]


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_protected(ip, allowlist, protect_private):
    if not _is_ip(ip):
        return True
    addr = ipaddress.ip_address(ip)
    if protect_private and not addr.is_global:
        return True
    for entry in allowlist:
        entry = entry.strip()
        if not entry:
            continue
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


def build_blocklist(df, allowlist=(), threshold=10, min_users=3,
                    min_score=40, protect_private=True,
                    sustained_min=30, success_threshold=15,
                    recovery_max=20):
    scores, reasons = {}, {}

    def add(ip, points, why):
        scores[ip] = scores.get(ip, 0) + points
        reasons.setdefault(ip, []).append(why)

    failed = df[df["status"] == "Failed"]
    total_failed = failed.groupby("ip").size()

    inc = incidents(brute_force(df, threshold))
    if not inc.empty:
        for ip, total in inc.groupby("ip")["total_failures"].sum().items():
            add(ip, 40, f"brute force ({int(total)} failures)")
            if total >= 100:
                add(ip, 20, "high volume")

    for ip, total in total_failed.items():
        if total >= sustained_min:
            add(ip, 40, f"sustained failures ({int(total)})")

    guessing = invalid_users(df, min_users)
    for _, row in guessing.iterrows():
        add(row["ip"], 30, f"username guessing ({int(row['distinct_users'])} names)")

    success = suspicious_success(df, success_threshold)
    if not success.empty:
        for ip in success["ip"].unique():
            add(ip, 50, "successful login after attack")

    accepted_ips = set(df[df["status"] == "Accepted"]["ip"])
    for ip in list(scores):
        if ip in accepted_ips and total_failed.get(ip, 0) < recovery_max:
            add(ip, -40, "likely legitimate user (login succeeded, few failures)")

    rows = []
    for ip, score in scores.items():
        if _is_protected(ip, allowlist, protect_private):
            action = "protected"
        elif score >= min_score:
            action = "block"
        else:
            action = "monitor"
        rows.append({
            "ip": ip,
            "score": score,
            "action": action,
            "ttl_hours": 24 if score >= 80 else 6,
            "reasons": "; ".join(reasons[ip]),
        })
    result = pd.DataFrame(rows, columns=COLUMNS)
    return result.sort_values("score", ascending=False).reset_index(drop=True)


def _to_block(blocklist):
    return blocklist[blocklist["action"] == "block"]


def to_iptables(blocklist):
    return [f"iptables -I INPUT -s {ip} -j DROP"
            for ip in _to_block(blocklist)["ip"]]


def to_nft(blocklist):
    return [f"nft add element inet filter blocklist {{ {r.ip} timeout {r.ttl_hours}h }}"
            for r in _to_block(blocklist).itertuples()]


def to_ufw(blocklist):
    return [f"ufw deny from {ip}" for ip in _to_block(blocklist)["ip"]]


FORMATS = {"iptables": to_iptables, "nft": to_nft, "ufw": to_ufw}


def apply_iptables(blocklist):
    for ip in _to_block(blocklist)["ip"]:
        subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True)


def main():
    parser = argparse.ArgumentParser(description="IPS recommendations (dry-run by default)")
    parser.add_argument("log")
    parser.add_argument("--year", type=int, default=2015)
    parser.add_argument("--allow", action="append", default=[],
                        help="IP or CIDR that must never be blocked (repeatable)")
    parser.add_argument("--threshold", type=int, default=10)
    parser.add_argument("--min-score", type=int, default=40)
    parser.add_argument("--format", choices=FORMATS, default="iptables")
    parser.add_argument("--apply", action="store_true",
                        help="apply iptables rules (Linux, root only)")
    args = parser.parse_args()

    df = parse(args.log, args.year)
    blocklist = build_blocklist(df, args.allow, args.threshold,
                                min_score=args.min_score)
    print(blocklist.to_string(index=False))
    print("\nCommands (dry-run):")
    for line in FORMATS[args.format](blocklist):
        print(line)

    if args.apply:
        if args.format != "iptables":
            sys.exit("--apply supports the iptables format only")
        if os.name != "posix" or os.geteuid() != 0:
            sys.exit("--apply requires root on Linux")
        if input("Type 'yes' to apply these rules: ") != "yes":
            sys.exit("Aborted, nothing applied")
        apply_iptables(blocklist)
        print("Applied.")


if __name__ == "__main__":
    main()