# LogScout-SH — SOC Log Analyzer

LogScout-SH is an educational defensive cybersecurity application that analyzes authentication-style CSV logs, identifies suspicious patterns using transparent rules, and creates investigation reports.

## Features

- CSV upload and included sample authentication logs
- Heuristic detection rules for possible brute-force activity, multiple-account targeting, successful login after repeated failures, and high event volume
- Severity-prioritized alerts with evidence and recommended response actions
- Dashboard metrics, severity charts, event timeline, and top source IPs
- Alert investigation details and related events
- Event filtering and CSV export
- Downloadable text investigation report and alert CSV
- No API key required; no claim of trained AI predictions

## Requirements

- Windows 10/11
- Python 3.10 or newer (Python 3.11 or 3.12 recommended)
- Internet connection for the initial package installation

## Quick start (Windows)

1. Extract the project folder.
2. Double-click `run.bat`.
3. Wait for the package installation to finish.
4. Streamlit opens the app in your browser. If it does not, open the URL printed in the terminal (usually `http://localhost:8501`).

### Manual start

```bat
py -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Automated checks

Run the offline regression suite from the project folder (pandas must be installed):

```bat
python -m unittest discover -s tests -v
```

The suite covers all four detection rules, the bundled sample dataset, multi-account related-event matching, invalid CSV columns, empty CSVs, invalid timestamps, and report contents. It tests the data/detection functions without launching the Streamlit UI.

## CSV format

Your CSV must include these columns (case-insensitive):

- `timestamp` — parseable date/time; UTC is recommended
- `username` — account name
- `source_ip` — source address
- `event_type` — for example `login`
- `status` — for example `success` or `failed`

A sample file is provided at `data/sample_auth_logs.csv`. Documentation includes synthetic/reserved example IP addresses; these are not intended to identify real attackers.

## Detection rules

| ID | Rule | Default severity |
|---|---|---|
| SL-001 | 5 or more failed logins from one IP in a 10-minute window | High |
| SL-002 | Failed logins against 3 or more usernames from one IP | High |
| SL-003 | Successful login after 3 or more failures for the same user and IP within 15 minutes | Critical |
| SL-004 | 20 or more events from one IP in the loaded dataset | Medium |

## Architecture

```text
CSV logs / sample dataset
          |
          v
Validation and normalization (pandas)
          |
          v
Rule-based detection engine
          |
          v
Alert records (severity, rule, evidence, recommendation)
          |
          v
Streamlit dashboard / investigation / exports
```

## Limitations and responsible use

- Alerts are heuristic signals that require analyst validation; they do not prove compromise.
- The application analyzes uploaded or bundled CSV data. It is not a live endpoint agent or full SIEM.
- The current version focuses on authentication-style logs and does not inspect packet captures.
- Uploaded files are processed in the local app session and are not intentionally sent to a third-party API.
- Analyze only logs and systems you own or are authorized to investigate. Treat real logs as sensitive data.

## Suggested demo

1. Open the app with the sample dataset.
2. Show the overview metrics and severity chart.
3. Open Alerts & Investigation and select the successful-login-after-failures alert.
4. Explain the evidence and recommended response.
5. Open Event Explorer and export events.
6. Download the investigation report.
7. Explain the rules and limitations in the About & Rules tab.

## Project objective

Demonstrate core defensive security workflow: ingest logs, detect suspicious patterns, prioritize alerts, investigate evidence, and document findings.
