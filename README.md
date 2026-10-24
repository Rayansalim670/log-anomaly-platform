Log Anomaly Detection Platform

A lightweight platform that parses authentication and firewall logs, detects suspicious activity with explainable rules and machine learning, recommends safe blocks, and visualizes everything in an interactive dashboard.

Live demo: https://log-anomaly-platform.streamlit.app

Do not upload sensitive logs to the public demo: public IPs found in a log are sent to ip-api.com for geolocation.

Features
Multi-format parser (see Supported log formats).
Brute-force detection with an adjustable per-minute threshold.
Incident grouping: merges consecutive per-minute alerts into one incident.
Username guessing detection: many distinct invalid usernames from one IP.
Suspicious success detection: a login that succeeds right after many failures.
Port-scan detection (MITRE T1046): many distinct destination ports from one IP within a minute, from firewall logs.
Isolation Forest anomaly detection (exploratory complement to the rules).
IPS recommendations: a multi-signal score per IP produces block, monitor, or protected decisions and exports iptables, nftables, and ufw rules.
GeoIP attack map: failed logins and blocked packets by source country.
Interactive dashboard: file upload, adjustable thresholds, allowlist, timeline, top attackers, and alert tables.
Supported log formats
Source	Format	How events are read
SSH sshd	custom YYYY-MM-DD HH:MM:SS sshd ... or standard syslog	Accepted / Failed for password and public-key
Apache / Nginx	common or combined access log	HTTP 401 and 403 count as failed attempts
Windows security events	JSON, JSON Lines, or CSV	EventID 4625 failed, 4624 accepted; SubStatus 0xC0000064 marks a nonexistent user
UFW / iptables	kernel log lines with SRC= and DPT=	recorded as Blocked with the destination port

General system logs (for example macOS or kernel logs) are not supported and are rejected with a clear message.

Architecture
Log file --> Parser --> Structured DataFrame --> Detectors --> IPS engine --> Dashboard
(upload)     (multi-     time, status, user,     rules + ML     scored        (Streamlit
              format)    ip, invalid, method,                   block list     + Plotly)
                         port
File	Role
detect.py	Parsers, detectors, and GeoIP lookup
ips.py	IPS decision engine and rule export (dry-run by default)
dashboard.py	Streamlit UI and charts
generate_logs.py	Synthetic SSH log with an injected attack
evaluate.py, evaluate_real.py, evaluate_ips.py	Quantitative evaluation
security_tests.py	Robustness tests with hostile and malformed input
tests/	37 pytest tests
data/sample.log	Bundled real SSH sample (OpenSSH_2k from LogHub)
Installation

Requires Python 3.12.

bash
git clone https://github.com/Rayansalim670/log-anomaly-platform.git
cd log-anomaly-platform
python3.12 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt

On Windows, activate the environment with venv\Scripts\activate.

Usage

Run the dashboard locally (recommended for real logs):

bash
streamlit run dashboard.py --server.address localhost

The dashboard opens with the bundled sample. Upload your own log from the sidebar. For syslog files without a year, set the year in the sidebar.

Run the detectors from the command line:

bash
python detect.py
IPS recommendations
bash
python ips.py data/sample.log --allow 203.0.113.0/24

This prints scored decisions and the matching firewall commands. It is dry-run by default and blocks nothing. Private addresses and anything in the allowlist are never recommended for blocking. --apply exists for Linux (iptables, root only) and asks for a typed confirmation; always allowlist your own address first or you may lock yourself out.

How the score works: brute force +40 (+20 for high volume), sustained failures (30 or more) +40, username guessing +30, port scan +40, successful login after a real attack +50, and a discount of 40 for likely legitimate users. An IP scoring 40 or more is recommended for blocking.

Optional: GeoIP database

The attack map works out of the box through the free ip-api.com service (public IPs only, up to 40 per run). For faster, offline lookups, download GeoLite2 City from maxmind.com (free account) and place GeoLite2-City.mmdb in data/. Do not commit it: the license forbids redistribution (data/*.mmdb is in .gitignore).

Tests and evaluation
bash
python -m pytest -v          # 37 tests
python evaluate.py           # synthetic data with known ground truth
python evaluate_real.py      # real OpenSSH log, approximate labels
python evaluate_ips.py       # IPS block decisions
python security_tests.py     # hostile and malformed inputs (run locally)
Results

Real SSH log (OpenSSH_2k, 518 events, 24 IPs; an IP with 20 or more failures is labeled an attacker, an approximate label):

Detector	Precision	Recall
Brute force, threshold 10	0.80	1.00
IPS block decisions, min score 40	0.80	1.00
Isolation Forest	1.00	0.25
99.8% of events were failures; the top attacker made 286 failed logins in about 10 minutes; per-minute alerts group into 7 incidents.
Isolation Forest finds only one of four labeled attackers because attacks dominate this log, so it is an exploratory complement, not a primary detector.
Security tests: 8 hostile or malformed inputs, no crash, slowest 0.85 s for 200,000 lines.
Limitations
Parsers cover only the formats listed above.
Thresholds are static and tuned manually.
IPS rules were tuned on the same datasets used to evaluate them, so the synthetic scores are optimistic; the real-data result is the better indicator.
Windows and firewall support was tested on synthetic samples, not real exports.
GeoIP shows where an IP is registered, which can be a VPN, proxy, or compromised host rather than the real attacker.
Distributed attacks across many IPs are not detected.
The platform recommends blocks; the hosted demo cannot enforce anything.
Future work
Email or webhook alerts (for example Telegram)
Validation on real Windows and firewall exports
Evaluation on a separate, unseen labeled log
Adaptive thresholds and distributed-attack correlation
License

MIT License. See LICENSE.