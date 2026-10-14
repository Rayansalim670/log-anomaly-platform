import os
import random
from datetime import datetime, timedelta

os.makedirs("data", exist_ok=True)

users = ["admin", "ali", "sara", "root"]
ips = [f"192.168.1.{i}" for i in range(10, 30)]
attacker = "10.0.0.99"

start = datetime(2026, 10, 14, 8, 0, 0)
lines = []

# normal activity
for i in range(500):
    t = start + timedelta(seconds=random.randint(0, 7200))
    ip, user = random.choice(ips), random.choice(users)
    status = random.choices(["Accepted", "Failed"], weights=[9, 1])[0]
    lines.append((t, f"{t:%Y-%m-%d %H:%M:%S} sshd {status} password for {user} from {ip}"))

# brute force attack
t0 = start + timedelta(minutes=45)
for i in range(40):
    t = t0 + timedelta(seconds=i)
    lines.append((t, f"{t:%Y-%m-%d %H:%M:%S} sshd Failed password for root from {attacker}"))

# attacker finally succeeds
t_success = t0 + timedelta(seconds=45)
lines.append((t_success, f"{t_success:%Y-%m-%d %H:%M:%S} sshd Accepted password for root from {attacker}"))

lines.sort()
with open("data/auth.log", "w") as f:
    f.write("\n".join(l for _, l in lines))

print("Done: data/auth.log created")