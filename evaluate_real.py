"""Evaluate detectors on real SSH logs (LogHub OpenSSH_2k).

Ground truth is a simple labeling rule: an IP with at least LABEL_MIN failed
logins in the file is labeled an attacker. This is an approximate label.
"""
import os

from detect import (
    parse, brute_force, invalid_users, suspicious_success, ml_anomalies
)

PATH = "data/sample.log"
LABEL_MIN = 20

df = parse(PATH, 2015)
failed = df[df["status"] == "Failed"].groupby("ip").size()
attackers = set(failed[failed >= LABEL_MIN].index)
all_ips = set(df["ip"])

print(f"events={len(df)} ips={len(all_ips)} "
      f"labeled attackers (>= {LABEL_MIN} failures)={len(attackers)}")


def score(detected, label):
    tp = len(detected & attackers)
    fp = len(detected - attackers)
    fn = len(attackers - detected)
    tn = len(all_ips - attackers - detected)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"{label:36s} TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={precision:.2f} recall={recall:.2f} FPR={fpr:.2f}")


for th in (3, 5, 10, 20):
    score(set(brute_force(df, th)["ip"]), f"brute_force threshold={th}")

for mu in (2, 3, 5):
    score(set(invalid_users(df, mu)["ip"]), f"invalid_users min={mu}")

score(set(ml_anomalies(df)["ip"]), "isolation forest")

combined = (set(brute_force(df, 5)["ip"]) | set(invalid_users(df, 3)["ip"]))
score(combined, "combined (brute_force 5 or users 3)")

print("\nLabeled attackers and their failures:")
print(failed[failed.index.isin(attackers)].sort_values(ascending=False))