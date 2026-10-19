import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detect import parse_text
from ips import build_blocklist, to_iptables

PUBLIC = "45.33.32.156"


def attack(ip, n=30):
    lines = [
        f"2026-10-14 08:45:{i:02d} sshd Failed password for root from {ip}"
        for i in range(n)
    ]
    return "\n".join(lines)


def test_public_attacker_is_blocked():
    bl = build_blocklist(parse_text(attack(PUBLIC)))
    row = bl[bl["ip"] == PUBLIC].iloc[0]
    assert row["action"] == "block"
    assert row["score"] >= 40


def test_private_address_is_never_blocked():
    bl = build_blocklist(parse_text(attack("10.0.0.99")))
    assert (bl["action"] == "protected").all()
    assert to_iptables(bl) == []


def test_allowlist_cidr_protects_address():
    bl = build_blocklist(parse_text(attack(PUBLIC)), allowlist=["45.33.32.0/24"])
    assert bl.iloc[0]["action"] == "protected"


def test_commands_are_generated_for_blocked_only():
    bl = build_blocklist(parse_text(attack(PUBLIC)))
    assert to_iptables(bl) == [f"iptables -I INPUT -s {PUBLIC} -j DROP"]


def test_below_min_score_is_monitor_only():
    bl = build_blocklist(parse_text(attack(PUBLIC, n=12)), min_score=100)
    assert bl.iloc[0]["action"] == "monitor"


def test_forgetful_user_is_not_blocked():
    lines = [
        f"2026-10-14 08:45:{i:02d} sshd Failed password for ali from {PUBLIC}"
        for i in range(12)
    ]
    lines.append(f"2026-10-14 08:45:30 sshd Accepted password for ali from {PUBLIC}")
    bl = build_blocklist(parse_text("\n".join(lines)))
    assert (bl["action"] != "block").all()


def test_slow_attacker_is_blocked():
    lines = [
        f"2026-10-14 09:{(i * 30) // 60:02d}:{(i * 30) % 60:02d} "
        f"sshd Failed password for root from {PUBLIC}"
        for i in range(40)
    ]
    bl = build_blocklist(parse_text("\n".join(lines)))
    assert bl.iloc[0]["action"] == "block"