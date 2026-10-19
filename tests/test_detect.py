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
    assert bool(failed["invalid"]) is True
    assert failed["user"] == "webmaster"
    assert failed["time"].year == 2015


def test_parse_custom_format():
    df = parse_text(make_attack(3))
    assert len(df) == 4
    assert (df["ip"] == "10.0.0.99").all()


def test_parse_empty_text_returns_empty_frame():
    assert parse_text("garbage line\nanother").empty


def test_empty_frame_keeps_columns_and_detectors_run():
    df = parse_text("garbage")
    assert list(df.columns) == ["time", "status", "user", "ip", "invalid", "method", "port"]
    assert brute_force(df).empty


def test_invalid_ip_is_rejected():
    text = "Dec 10 06:55:48 LabSZ sshd[1]: Failed password for root from 1.2.3."
    assert parse_text(text).empty


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


def test_publickey_login_is_parsed():
    text = (
        "Dec 10 09:32:20 LabSZ sshd[1]: Accepted publickey for deploy "
        "from 203.0.113.5 port 50022 ssh2"
    )
    df = parse_text(text, year=2015)
    assert len(df) == 1
    assert df.iloc[0]["status"] == "Accepted"
    assert df.iloc[0]["method"] == "publickey"


def test_apache_401_is_failed_and_200_is_ignored():
    text = (
        '203.0.113.7 - - [10/Oct/2026:13:55:36 +0000] "POST /login HTTP/1.1" 401 512\n'
        '203.0.113.7 - - [10/Oct/2026:13:55:40 +0000] "GET /index.html HTTP/1.1" 200 900\n'
    )
    df = parse_text(text)
    assert len(df) == 1
    assert df.iloc[0]["status"] == "Failed"
    assert df.iloc[0]["method"] == "http"
    assert df.iloc[0]["time"].year == 2026


def test_apache_burst_triggers_brute_force():
    lines = "\n".join(
        f'203.0.113.7 - - [10/Oct/2026:13:55:{i:02d} +0000] "POST /login HTTP/1.1" 401 512'
        for i in range(1, 31)
    )
    alerts = brute_force(parse_text(lines), threshold=5)
    assert len(alerts) == 1
    assert alerts.iloc[0]["failures"] == 30