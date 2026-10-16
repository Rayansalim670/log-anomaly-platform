import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd
from detect import parse_text, brute_force, incidents, suspicious_success

SYSLOG = (
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user "
    "webmaster from 173.234.31.186 port 38926 ssh2\n"
    "Dec 10 09:32:20 LabSZ sshd[24680]: Accepted password for fztu from "
    "119.137.62.142 port 49116 ssh2\n"
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from "
    "173.234.31.186\n"
)


def make_attack(n=10):
    lines = [
        f"2026-10-14 08:45:{i:02d} sshd Failed password for root from 10.0.0.99"
        for i in range(n)
    ]
    lines.append("2026-10-14 08:45:30 sshd Accepted password for root from 10.0.0.99")
    return "\n".join(lines)


def test_parse_syslog_keeps_only_password_events():
    df = parse_text(SYSLOG, year=2015)
    assert len(df) == 2
    assert set(df["status"]) == {"Failed", "Accepted"}


def test_parse_syslog_marks_invalid_user():
    df = parse_text(SYSLOG, year=2015)
    failed = df[df["status"] == "Failed"].iloc[0]
    assert failed["invalid"] is True or failed["invalid"] == True
    assert failed["user"] == "webmaster"
    assert failed["time"].year == 2015


def test_parse_custom_format():
    df = parse_text(make_attack(3))
    assert len(df) == 4
    assert (df["ip"] == "10.0.0.99").all()


def test_parse_empty_text_returns_empty_frame():
    assert parse_text("garbage line\nanother").empty


def test_brute_force_detects_attacker():
    df = parse_text(make_attack(10))
    alerts = brute_force(df, threshold=5)
    assert len(alerts) == 1
    assert alerts.iloc[0]["ip"] == "10.0.0.99"
    assert alerts.iloc[0]["failures"] == 10


def test_brute_force_respects_threshold():
    df = parse_text(make_attack(10))
    assert brute_force(df, threshold=10).empty


def test_incidents_groups_consecutive_minutes():
    alerts = pd.DataFrame({
        "ip": ["1.1.1.1"] * 3,
        "time": pd.to_datetime(
            ["2026-01-01 10:00", "2026-01-01 10:01", "2026-01-01 10:02"]
        ),
        "failures": [10, 12, 9],
    })
    inc = incidents(alerts)
    assert len(inc) == 1
    assert inc.iloc[0]["total_failures"] == 31


def test_suspicious_success_after_attack():
    df = parse_text(make_attack(10))
    result = suspicious_success(df, threshold=5)
    assert len(result) == 1
    assert result.iloc[0]["ip"] == "10.0.0.99"


def test_no_suspicious_success_without_failures():
    text = "2026-10-14 08:45:30 sshd Accepted password for ali from 192.168.1.5"
    assert suspicious_success(parse_text(text)).empty