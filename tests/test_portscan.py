import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detect import parse_text, port_scan, brute_force
from ips import build_blocklist

IP = "45.33.32.156"


def ufw_line(sec, port, ip=IP):
    return (
        f"Oct 14 08:45:{sec:02d} host kernel: [123.4] [UFW BLOCK] IN=eth0 OUT= "
        f"MAC=aa:bb SRC={ip} DST=10.0.0.5 LEN=44 PROTO=TCP SPT=4444 "
        f"DPT={port} WINDOW=1024 SYN"
    )


def scan_log(n=20):
    return "\n".join(ufw_line(i, 1000 + i) for i in range(n))


def test_ufw_line_is_parsed_as_blocked_with_port():
    df = parse_text(ufw_line(1, 22))
    assert len(df) == 1
    row = df.iloc[0]
    assert row["status"] == "Blocked"
    assert row["ip"] == IP
    assert row["port"] == 22
    assert row["method"] == "firewall"


def test_scan_of_many_ports_is_detected():
    scans = port_scan(parse_text(scan_log(20)), min_ports=10)
    assert len(scans) == 1
    assert scans.iloc[0]["ip"] == IP
    assert scans.iloc[0]["distinct_ports"] == 20


def test_repeated_hits_on_one_port_are_not_a_scan():
    text = "\n".join(ufw_line(i, 22) for i in range(30))
    assert port_scan(parse_text(text), min_ports=10).empty


def test_blocked_packets_are_not_failed_logins():
    df = parse_text(scan_log(30))
    assert brute_force(df, threshold=5).empty


def test_scanner_is_recommended_for_blocking():
    bl = build_blocklist(parse_text(scan_log(20)))
    row = bl[bl["ip"] == IP].iloc[0]
    assert row["action"] == "block"
    assert "port scan" in row["reasons"]


def test_iso_timestamp_firewall_line():
    line = (
        "2026-10-14T08:45:01 host kernel: [UFW BLOCK] SRC=45.33.32.156 "
        "DST=10.0.0.5 PROTO=TCP DPT=3389"
    )
    df = parse_text(line)
    assert len(df) == 1
    assert df.iloc[0]["time"].year == 2026
    assert df.iloc[0]["port"] == 3389


def test_port_scan_on_empty_frame():
    assert port_scan(parse_text("garbage")).empty