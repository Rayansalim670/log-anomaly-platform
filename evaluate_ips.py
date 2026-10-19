"""Evaluate IPS block decisions on synthetic and real data."""
import io
from contextlib import redirect_stdout

from detect import parse
from ips import build_blocklist

# Synthetic ground truth (evaluate.py runs on import; silence its output)
with redirect_stdout(io.StringIO()):
    import evaluate as ev


def score(blocked, attackers, all_ips, label):
    tp = len(blocked & attackers)
    fp = len(blocked - attackers)
    fn = len(attackers - blocked)
    tn = len(all_ips - attackers - blocked)
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    print(f"{label:30s} TP={tp} FP={fp} FN={fn} TN={tn} "
          f"precision={precision:.2f} recall={recall:.2f} FPR={fpr:.2f}")


def blocked_ips(df, min_score, protect_private):
    bl = build_blocklist(df, min_score=min_score, protect_private=protect_private)
    return set(bl[bl["action"] == "block"]["ip"])


print("Synthetic data (private/documentation ranges, so protection is off)")
for ms in (30, 40, 50, 70, 90):
    score(blocked_ips(ev.df, ms, False), ev.attackers, ev.all_ips, f"min_score={ms}")

print("\nReal data: OpenSSH_2k (label: >= 20 failures)")
real = parse("data/sample.log", 2015)
failed = real[real["status"] == "Failed"].groupby("ip").size()
real_attackers = set(failed[failed >= 20].index)
for ms in (30, 40, 50, 70, 90):
    score(blocked_ips(real, ms, True), real_attackers, set(real["ip"]), f"min_score={ms}")