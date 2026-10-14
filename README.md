# Log Anomaly Detection Platform

A lightweight platform that parses SSH authentication logs, detects suspicious
activity using rule-based and machine-learning methods, and visualizes the
results in an interactive dashboard.

## Features

- **Multi-format parser**: supports a custom `YYYY-MM-DD HH:MM:SS sshd ...`
  format and standard syslog (e.g. OpenSSH logs from LogHub).
- **Brute-force detection**: flags IPs with many failed logins per minute,
  with a configurable threshold.
- **Incident grouping**: merges consecutive per-minute alerts into a single
  attack incident (start, end, total failures) to reduce alert noise.
- **Username guessing detection**: flags IPs that try many distinct invalid
  usernames, catching slow attackers that stay under the per-minute threshold.
- **Suspicious success detection**: flags a successful login that follows
  many failed attempts from the same IP within a short time window.
- **Machine learning**: Isolation Forest over per-IP, per-minute features
  (events, failures, failure ratio) to surface unusual behavior.
- **Interactive dashboard**: file upload, adjustable thresholds, KPI metrics,
  timeline, top attackers, and alert tables.

## Architecture

```
Raw logs --> Parser --> Structured DataFrame --> Detectors --> Dashboard
(file upload)  (regex)   (time, status,          (rules + ML)   (Streamlit
                          user, ip, invalid)                      + Plotly)
```

| File | Role |
|---|---|
| `detect.py` | Parsing and all detection logic |
| `dashboard.py` | Streamlit UI and charts |
| `generate_logs.py` | Generates synthetic logs with an injected attack |
| `data/` | Log files |

## Installation

Requires Python 3.12.

```bash
git clone <your-repo-url>
cd log-anomaly-platform
python3.12 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

Generate sample logs (optional):

```bash
python generate_logs.py
```

Run the detectors from the command line:

```bash
python detect.py
```

Launch the dashboard:

```bash
streamlit run dashboard.py
```

Then upload a log file from the sidebar. For logs without a year
(syslog format), set the year in the sidebar.

## Tested on

- Synthetic logs from `generate_logs.py` (injected brute-force attack).
- Real SSH logs: `OpenSSH_2k.log` from the
  [LogHub](https://github.com/logpai/loghub) dataset.

## Detection results (OpenSSH_2k sample)

- 99.8% of authentication events were failures, a typical brute-force pattern.
- The top attacker produced 286 failed logins over about 10 minutes.
- Per-minute alerts were grouped into 7 attack incidents.

## Limitations

- Supports `sshd` password authentication events only.
- Thresholds are static and tuned manually per dataset.
- Isolation Forest flags unusual behavior relative to the uploaded data, so
  results depend on the data mix. It is not a measure of severity.
- No labeled ground truth, so precision and recall were not measured.

## Future work

- GeoIP enrichment and attacker map
- Email or webhook alerts
- Support for more log sources (Apache, Windows Event Log)
- Evaluation against labeled attack datasets