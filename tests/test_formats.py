import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json

from detect import parse_text, brute_force, invalid_users

IP = "45.33.32.156"


def win_event(sec, event_id=4625, user="admin", ip=IP, sub="0xC0000064"):
    return {
        "TimeCreated": f"2026-10-14T08:45:{sec:02d}",
        "EventID": event_id,
        "TargetUserName": user,
        "IpAddress": ip,
        "SubStatus": sub,
    }


def test_jsonl_failed_events_are_parsed():
    text = "\n".join(json.dumps(win_event(i)) for i in range(3))
    df = parse_text(text)
    assert len(df) == 3
    assert (df["status"] == "Failed").all()
    assert (df["method"] == "structured").all()


def test_json_array_with_bom_is_parsed():
    text = "\ufeff" + json.dumps([win_event(1), win_event(2, event_id=4624)])
    df = parse_text(text)
    assert list(df["status"]) == ["Failed", "Accepted"]


def test_csv_is_parsed():
    text = (
        "TimeCreated,EventID,TargetUserName,IpAddress\n"
        f"2026-10-14T08:45:01,4625,root,{IP}\n"
        f"2026-10-14T08:45:02,4624,root,{IP}\n"
    )
    df = parse_text(text)
    assert len(df) == 2
    assert set(df["status"]) == {"Failed", "Accepted"}


def test_no_such_user_substatus_marks_invalid_user():
    text = "\n".join(
        json.dumps(win_event(i, user=f"user{i}")) for i in range(4)
    )
    df = parse_text(text)
    assert df["invalid"].all()
    assert len(invalid_users(df, min_users=3)) == 1


def test_events_without_a_real_ip_are_dropped():
    text = "\n".join([
        json.dumps(win_event(1, ip="-")),
        json.dumps(win_event(2, ip="")),
        json.dumps(win_event(3)),
    ])
    assert len(parse_text(text)) == 1


def test_malformed_json_lines_are_ignored():
    text = "{not json\n" + json.dumps(win_event(5)) + "\n{\"broken\": "
    assert len(parse_text(text)) == 1


def test_generic_json_fields_and_timezone():
    text = json.dumps({
        "timestamp": "2026-10-14T08:45:01Z",
        "ip": IP, "status": "failed", "user": "svc",
    })
    df = parse_text(text)
    assert len(df) == 1
    assert df.iloc[0]["status"] == "Failed"
    assert df.iloc[0]["time"].tzinfo is None


def test_windows_burst_triggers_brute_force():
    text = "\n".join(json.dumps(win_event(i)) for i in range(30))
    alerts = brute_force(parse_text(text), threshold=5)
    assert len(alerts) == 1
    assert alerts.iloc[0]["failures"] == 30


def test_unrecognized_csv_returns_empty_frame():
    df = parse_text("name,age\nali,30\nsara,25\n")
    assert df.empty
    assert list(df.columns) == ["time", "status", "user", "ip", "invalid", "method"]