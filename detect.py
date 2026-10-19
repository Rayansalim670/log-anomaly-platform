import csv
import io
import ipaddress
import json
import os
import re
from datetime import datetime

import pandas as pd
import requests
from sklearn.ensemble import IsolationForest

COLUMNS = ["time", "status", "user", "ip", "invalid", "method", "port"]
GEO_DB = "data/GeoLite2-City.mmdb"

# Custom format: 2026-10-14 08:00:19 sshd Failed password for root from 1.2.3.4
pattern = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sshd "
    r"(?P<status>Accepted|Failed) (?P<method>password|publickey) "
    r"for (?P<user>\w+) from (?P<ip>[\d.]+)"
)

# Syslog format: Dec 10 06:55:48 host sshd[24200]: Failed password for ...
syslog_pattern = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"(?P<status>Accepted|Failed) (?P<method>password|publickey) "
    r"for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)

# Apache/Nginx common or combined access log
apache_pattern = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) '
    r'\[(?P<time>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [+-]\d{4}\] '
    r'"[^"]*" (?P<code>\d{3})'
)
HTTP_FAILED_CODES = {"401", "403"}

# Firewall logs (UFW / iptables LOG): syslog or ISO timestamp, SRC= and DPT=
fw_time = re.compile(
    r"^(?:(?P<syslog>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}))"
)
fw_src = re.compile(r"SRC=([\d.]+)")
fw_dpt = re.compile(r"DPT=(\d{1,5})")

# Structured formats (JSON Lines, JSON array, CSV): field-name aliases
ALIASES = {
    "time": ["timecreated", "time", "timestamp", "@timestamp", "datetime",
             "date", "date and time"],
    "event": ["eventid", "event_id", "event id", "id"],
    "status": ["status", "result", "outcome", "action"],
    "user": ["targetusername", "username", "user", "account", "account name"],
    "ip": ["ipaddress", "sourcenetworkaddress", "source network address",
           "src_ip", "source_ip", "client_ip", "remote_ip", "ip"],
    "substatus": ["substatus"],
}
FAILED_WORDS = {"failed", "failure", "fail", "denied", "4625"}
OK_WORDS = {"accepted", "success", "succeeded", "ok", "allowed", "4624"}
WIN_NO_SUCH_USER = "0xc0000064"


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def _apache_row(m):
    """Convert an Apache match to a row, or None if it is not a failure."""
    if m.group("code") not in HTTP_FAILED_CODES:
        return None
    try:
        t = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    return {
        "time": t.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "Failed",
        "user": m.group("user"),
        "ip": m.group("ip"),
        "method": "http",
    }


def _firewall_row(line, year):
    """Convert a UFW/iptables LOG line to a row, or None if it does not match."""
    src = fw_src.search(line)
    dpt = fw_dpt.search(line)
    stamp = fw_time.match(line)
    if not (src and dpt and stamp):
        return None
    if stamp.group("syslog"):
        when = f"{year} {' '.join(stamp.group('syslog').split())}"
    else:
        when = stamp.group("iso")
    return {
        "time": when,
        "status": "Blocked",
        "user": "-",
        "ip": src.group(1),
        "method": "firewall",
        "port": dpt.group(1),
    }


def _pick(rec, names):
    for name in names:
        value = rec.get(name)
        if value not in (None, ""):
            return value
    return None


def _structured_status(rec):
    event = _pick(rec, ALIASES["event"])
    if event is not None:
        value = str(event).strip()
        if value == "4625":
            return "Failed"
        if value == "4624":
            return "Accepted"
    word = _pick(rec, ALIASES["status"])
    if word is not None:
        value = str(word).strip().lower()
        if value in FAILED_WORDS:
            return "Failed"
        if value in OK_WORDS:
            return "Accepted"
    return None


def _structured_row(raw):
    if not isinstance(raw, dict):
        return None
    rec = {str(k).strip().lower(): v for k, v in raw.items()}
    status = _structured_status(rec)
    ip = _pick(rec, ALIASES["ip"])
    stamp = _pick(rec, ALIASES["time"])
    if status is None or ip is None or stamp is None:
        return None
    if isinstance(stamp, (int, float)):
        return None
    ts = pd.to_datetime(str(stamp), errors="coerce", utc=True)
    if pd.isna(ts):
        return None
    user = _pick(rec, ALIASES["user"])
    substatus = str(_pick(rec, ALIASES["substatus"]) or "").strip().lower()
    invalid = (
        "invalid user " if status == "Failed" and substatus == WIN_NO_SUCH_USER
        else None
    )
    return {
        "time": ts.tz_localize(None).strftime("%Y-%m-%d %H:%M:%S"),
        "status": status,
        "user": str(user) if user is not None else "-",
        "ip": str(ip).strip(),
        "invalid": invalid,
        "method": "structured",
    }


def _parse_structured(text):
    """Return rows for JSON / JSON Lines / CSV input, or None if not structured."""
    body = text.lstrip("\ufeff").lstrip()
    if not body:
        return None
    records = None
    if body[0] in "[{":
        try:
            data = json.loads(body)
            records = data if isinstance(data, list) else [data]
        except ValueError:
            records = []
            for line in body.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
    else:
        first_line = body.splitlines()[0]
        if "," not in first_line:
            return None
        header = [h.strip().lower() for h in next(csv.reader([first_line]))]
        if not any(h in ALIASES["ip"] for h in header):
            return None
        try:
            records = list(csv.DictReader(io.StringIO(body)))
        except csv.Error:
            return []
    rows = []
    for rec in records:
        row = _structured_row(rec)
        if row:
            rows.append(row)
    return rows


def parse_text(text, year=2015):
    rows = _parse_structured(text)
    if rows is None:
        rows = []
        for line in text.splitlines():
            m = pattern.search(line)
            if m:
                rows.append(m.groupdict())
                continue
            m = syslog_pattern.search(line)
            if m:
                d = m.groupdict()
                d["time"] = f"{year} {' '.join(d['time'].split())}"
                rows.append(d)
                continue
            if "SRC=" in line and "DPT=" in line:
                row = _firewall_row(line, year)
                if row:
                    rows.append(row)
                continue
            m = apache_pattern.search(line)
            if m:
                row = _apache_row(m)
                if row:
                    rows.append(row)
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["invalid"] = df["invalid"].notna()
    df["port"] = pd.to_numeric(df["port"], errors="coerce")
    df["time"] = pd.to_datetime(df["time"], format="mixed", errors="coerce")
    df = df.dropna(subset=["time"])
    mask = df["ip"].map(_valid_ip).astype(bool)
    return df[mask]


def parse(path, year=2015):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return parse_text(f.read(), year)


def brute_force(df, threshold=5):
    failed = df[df["status"] == "Failed"]
    per_min = (
        failed.groupby(["ip", pd.Grouper(key="time", freq="1min")])
        .size().reset_index(name="failures")
    )
    return per_min[per_min["failures"] > threshold]


def port_scan(df, min_ports=10):
    """IPs that hit many distinct destination ports within one minute (T1046)."""
    cols = ["ip", "time", "distinct_ports", "packets"]
    hits = df[df["port"].notna()]
    if hits.empty:
        return pd.DataFrame(columns=cols)
    per_min = (
        hits.groupby(["ip", pd.Grouper(key="time", freq="1min")])
        .agg(distinct_ports=("port", "nunique"), packets=("port", "size"))
        .reset_index()
    )
    result = per_min[per_min["distinct_ports"] >= min_ports]
    return result.sort_values("distinct_ports", ascending=False)


def incidents(alerts, gap="3min"):
    if alerts.empty:
        return alerts
    alerts = alerts.sort_values(["ip", "time"])
    new_group = (
        (alerts["ip"] != alerts["ip"].shift())
        | (alerts["time"] - alerts["time"].shift() > pd.Timedelta(gap))
    )
    alerts = alerts.assign(group=new_group.cumsum())
    return (
        alerts.groupby("group")
        .agg(ip=("ip", "first"), start=("time", "min"),
             end=("time", "max"), total_failures=("failures", "sum"))
        .reset_index(drop=True)
        .sort_values("total_failures", ascending=False)
    )


def invalid_users(df, min_users=3):
    bad = df[(df["status"] == "Failed") & (df["invalid"])]
    if bad.empty:
        return pd.DataFrame(
            columns=["ip", "attempts", "distinct_users", "first_seen", "last_seen"]
        )
    result = (
        bad.groupby("ip")
        .agg(attempts=("user", "count"),
             distinct_users=("user", "nunique"),
             first_seen=("time", "min"),
             last_seen=("time", "max"))
        .reset_index()
    )
    result = result[result["distinct_users"] >= min_users]
    return result.sort_values("distinct_users", ascending=False)


def suspicious_success(df, threshold=5, window="2min"):
    df = df.sort_values("time")
    alerts = []
    for _, row in df[df["status"] == "Accepted"].iterrows():
        recent = df[
            (df["ip"] == row["ip"])
            & (df["status"] == "Failed")
            & (df["time"] < row["time"])
            & (df["time"] >= row["time"] - pd.Timedelta(window))
        ]
        if len(recent) > threshold:
            alerts.append(row)
    return pd.DataFrame(alerts)


def ml_anomalies(df, contamination=0.05):
    df = df.copy()
    df["failed"] = (df["status"] == "Failed").astype(int)
    features = (
        df.groupby(["ip", pd.Grouper(key="time", freq="1min")])
        .agg(events=("status", "count"), failures=("failed", "sum"))
        .reset_index()
    )
    features["fail_ratio"] = features["failures"] / features["events"]

    model = IsolationForest(contamination=contamination, random_state=42)
    X = features[["events", "failures", "fail_ratio"]]
    features["anomaly"] = model.fit_predict(X) == -1
    features["score"] = -model.score_samples(X)
    flagged = features[features["anomaly"] & (features["failures"] > 0)]
    return flagged.sort_values("score", ascending=False)


def _is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _geolocate_online(ips):
    rows = []
    for ip in ips:
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}"
                "?fields=status,country,city,lat,lon",
                timeout=5,
            )
            d = r.json()
            if d.get("status") == "success":
                rows.append({
                    "ip": ip,
                    "country": d.get("country") or "Unknown",
                    "city": d.get("city") or "",
                    "lat": d.get("lat"),
                    "lon": d.get("lon"),
                })
        except Exception:
            continue
    return pd.DataFrame(rows)


def geolocate(ips, limit=40):
    ips = [ip for ip in ips if not _is_private(ip)][:limit]
    if not ips:
        return pd.DataFrame()

    if os.path.exists(GEO_DB):
        try:
            import geoip2.database
            rows = []
            with geoip2.database.Reader(GEO_DB) as reader:
                for ip in ips:
                    try:
                        r = reader.city(ip)
                        rows.append({
                            "ip": ip,
                            "country": r.country.name or "Unknown",
                            "city": r.city.name or "",
                            "lat": r.location.latitude,
                            "lon": r.location.longitude,
                        })
                    except Exception:
                        continue
            return pd.DataFrame(rows)
        except ImportError:
            pass

    return _geolocate_online(ips)


if __name__ == "__main__":
    sample = "data/sample.log" if os.path.exists("data/sample.log") else "data/auth.log"
    df = parse(sample, 2015)
    print(brute_force(df))
    print(incidents(brute_force(df)))
    print(invalid_users(df))
    print(port_scan(df))
    print(suspicious_success(df))
    print(ml_anomalies(df))