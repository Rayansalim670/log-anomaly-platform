"""Security and robustness tests for the log parser.

Run locally only (isolated lab). Each case feeds hostile or malformed input
to the parser and checks that it neither crashes nor executes content.
"""
import time

from detect import parse_text, brute_force

CASES = {}


def case(name):
    def register(fn):
        CASES[name] = fn
        return fn
    return register


@case("empty input")
def _():
    return ""


@case("binary garbage")
def _():
    return "".join(chr(i) for i in range(1, 256)) * 200


@case("very long line (1 MB)")
def _():
    return "A" * 1_000_000


@case("long line mimicking sshd (regex stress)")
def _():
    return "Dec 10 06:55:48 LabSZ sshd[1]: Failed password for " + "a" * 200_000 + " from"


@case("repeated near-matches (backtracking)")
def _():
    return ("Dec 10 06:55:48 LabSZ sshd[1]: Failed password for invalid user x from 1.2.3.\n") * 20_000


@case("injection strings in username")
def _():
    payloads = ["<script>alert(1)</script>", "'; DROP TABLE users;--",
                "$(rm-rf)", "{{7*7}}", "../../etc/passwd"]
    return "\n".join(
        f"2026-01-01 10:00:0{i} sshd Failed password for {p} from 8.8.8.8"
        for i, p in enumerate(payloads)
    )


@case("huge valid file (200k lines)")
def _():
    return "\n".join(
        f"2026-01-01 10:00:00 sshd Failed password for root from 10.0.{i % 250}.{i % 200}"
        for i in range(200_000)
    )


@case("invalid dates and ips")
def _():
    return ("2026-99-99 99:99:99 sshd Failed password for root from 999.999.999.999\n"
            "Foo 99 99:99:99 LabSZ sshd[1]: Failed password for root from 1.2.3.4")


def run():
    print(f"{'case':44s} {'result':14s} {'rows':>7s} {'seconds':>8s}")
    for name, build in CASES.items():
        text = build()
        start = time.time()
        try:
            df = parse_text(text)
            brute_force(df)
            result, rows = "OK", len(df)
        except Exception as exc:  # any crash is a finding
            result, rows = f"CRASH:{type(exc).__name__}", 0
        print(f"{name:44s} {result:14s} {rows:7d} {time.time() - start:8.2f}")


if __name__ == "__main__":
    run()
    