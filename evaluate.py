import random
from datetime import datetime, timedelta

from detect import parse_text, brute_force, invalid_users

random.seed(7)
START = datetime(2026, 1, 1, 8, 0, 0)
users = ["admin", "ali", "sara", "root", "omar"]
lines, attackers = [], set()


def add(ts, status, user, ip):
    lines.append(f"{ts:%Y-%m-%d %H:%M:%S} sshd {status} password for {user} from {ip}")


# Benign traffic: 30 normal users, occasional typos
benign = [f"192.168.1.{i}" for i in range(10, 40)]
for ip in benign:
    for _ in range(random.randint(20, 40)):
        t = START + timedelta(seconds=random.randint(0, 6 * 3600))
        add(t, random.choices(["Accepted", "Failed"], weights=[9, 1])[0],
            random.choice(users), ip)

# Fast attackers: 10 IPs, bursts of 15-60 failures in a minute
for i in range(10):
    ip = f"203.0.113.{i + 1}"
    attackers.add(ip)
    t0 = START + timedelta(minutes=random.randint(10, 300))
    for s in range(random.randint(15, 60)):
        add(t0 + timedelta(seconds=s), "Failed", random.choice(users), ip)

# Hard case 1: forgetful legitimate users (burst of failures, then success)
forgetful = [f"192.168.2.{i}" for i in range(1, 6)]
for ip in forgetful:
    t0 = START + timedelta(minutes=random.randint(10, 300))
    for s in range(random.randint(6, 12)):
        add(t0 + timedelta(seconds=s * 4), "Failed", "ali", ip)
    add(t0 + timedelta(seconds=60), "Accepted", "ali", ip)

# Hard case 2: slow attackers (1 failure every 30s for 40 minutes)
slow = [f"198.51.100.{i}" for i in range(1, 6)]
for ip in slow:
    attackers.add(ip)
    t0 = START + timedelta(minutes=random.randint(10, 200))
    for s in range(80):
        add(t0 + timedelta(seconds=s * 30), "Failed", random.choice(users), ip)

df = parse_text("\n".join(lines))
all_ips = set(df["ip"])


def score(detected, label):
    tp = len(detected & attackers)
    fp = len(detected - attackers)
    fn = len(attackers - detected)
    tn = len(all_ips - attackers - detected)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"{label:34s} TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={precision:.2f} recall={recall:.2f} FPR={fpr:.2f}")


def slow_rule(data, min_failures=30):
    failed = data[data["status"] == "Failed"].groupby("ip").size()
    return set(failed[failed >= min_failures].index)


for th in (3, 5, 10, 20):
    score(set(brute_force(df, th)["ip"]), f"brute_force threshold={th}")

score(slow_rule(df), "total failures >= 30 (any speed)")
score(set(brute_force(df, 10)["ip"]) | slow_rule(df),
      "combined (per-minute>10 OR total)")