import ipaddress
import os
import re

import pandas as pd
import requests
from sklearn.ensemble import IsolationForest

COLUMNS = ["time", "status", "user", "ip", "invalid"]
GEO_DB = "data/GeoLite2-City.mmdb"

pattern = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) sshd "
    r"(?P<status>Accepted|Failed) password for (?P<user>\w+) from (?P<ip>[\d.]+)"
)

syslog_pattern = re.compile(
    r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: "
    r"(?P<status>Accepted|Failed) password for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[\d.]+)"
)


def _valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def parse_text(text, year=2015):
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
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["invalid"] = df["invalid"].notna()
    df["time"] = pd.to_datetime(df["time"], format="mixed", errors="coerce")
    df = df.dropna(subset=["time"])
    mask = df["ip"].map(_valid_ip).astype(bool)
    return df[mask]


def parse(path, year=2015):
    with open(path) as f:
        return parse_text(f.read(), year)


def brute_force(df, threshold=5):
    failed = df[df["status"] == "Failed"]
    per_min = (
        failed.groupby(["ip", pd.Grouper(key="time", freq="1min")])
        .size().reset_index(name="failures")
    )
    return per_min[per_min["failures"] > threshold]


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
    print(suspicious_success(df))
    print(ml_anomalies(df))