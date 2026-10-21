# LogScout-SH — Cyberpunk SOC Log Analyzer

LogScout-SH is an educational, local Streamlit application for analyzing authentication-style CSV logs, surfacing explainable heuristic alerts, prioritizing source IPs, and recording triage notes during an investigation session.

## Features

- Cyberpunk SOC interface with animated grid, neon styling, and hover interactions.
- CSV upload and validation for `timestamp`, `username`, `source_ip`, `event_type`, and `status`.
- **Windows auto-scan mode:** polls the local Windows Security log for logon events 4624 (success) and 4625 (failure) while the Streamlit app is running. Events are normalized and fed into the existing detection rules.
- Four explainable, time-bounded rules with false-positive mitigations:
  - **SL-001:** 5 or more failed authentication events from one non-placeholder source IP within a 10-minute window.
  - **SL-002:** Failed authentication attempts against 3 or more distinct non-placeholder usernames from one source IP within a 10-minute window.
  - **SL-003:** Successful login after 3 or more failures for the same non-placeholder username and source IP within 15 minutes; High severity (not automatically Critical).
  - **SL-004:** 20 or more events from one source IP within 5 minutes; Low severity because event volume alone is weak evidence.
- Overview charts and dashboard metrics.
- Alert triage with evidence and recommended response guidance.
- Event explorer with CSV export.
- Source IP risk center with a transparent 0–100 heuristic score and CSV export.
- Case workspace with status tracking, analyst notes, individual text case reports, and case-register export.
- Downloadable investigation report and alert CSV.

## Requirements

- Python 3.10 or newer recommended.
- Packages listed in `requirements.txt`.

## Run on Windows

1. Extract the project folder.
2. Open a terminal in the extracted `LogScout-SH-Final` folder.
3. (Recommended) Create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\\Scripts\\activate
   ```

4. Install dependencies:

   ```powershell
   py -m pip install -r requirements.txt
   ```

5. Start the application:

   ```powershell
   py -m streamlit run app.py
   ```

   Or double-click `run.bat`.

The app normally opens at `http://localhost:8501`.

## Enable Windows Security auto-scanning

1. Run the app on the Windows machine whose local Security log you want to inspect. This feature does not read logs from another computer.
2. Open PowerShell or Command Prompt in the project folder and start the app. If Security-log access is denied, close the app and reopen the terminal using **Run as administrator**, then start it again. Use administrator access only if needed and only on a system you are authorized to administer.
3. In the sidebar, choose **Windows Security event log (auto-scan)**. Keep **Enable continuous scanning** turned on and select a polling interval (default 15 seconds).
4. The first scan checks the most recent five minutes of matching events; later scans overlap briefly and deduplicate by Windows event record ID. Up to 5,000 events are kept in the current Streamlit session.
5. Generate a test failed or successful logon only on a system/account you control, then watch the event count and alerts update. You can switch back to CSV mode at any time.

**What “continuous” means here:** while the Streamlit app remains open, it periodically polls the local Windows Security log. This is near-real-time polling, not a Windows service, not a kernel-level sensor, and not packet/network monitoring. Closing the app stops polling. Events that are older than the retained window or unavailable due to Windows audit policy/permissions may not be collected. Windows may not record all successful logons unless the relevant audit policy is enabled.

## CSV format

The CSV must include these columns (case-insensitive):

```csv
timestamp,username,source_ip,event_type,status
2026-10-19T09:00:00Z,alex,192.0.2.10,login,failed
2026-10-19T09:01:00Z,alex,192.0.2.10,login,success
```

A sample file is included at `data/sample_auth_logs.csv`.

## Risk score notes

The Risk Center score is a transparent local prioritization heuristic based on triggered alerts, failed authentication events, distinct usernames, and a failure-followed-by-success pattern. It is **not** a threat-intelligence reputation score and does not prove malicious activity.

## Case workspace notes

Investigation status and analyst notes are stored locally in `data/logscout_cases.db` using SQLite. Changes are recorded in an audit history table and remain available after restarting Streamlit. The database is local to this project and is not encrypted by the app.

## Limitations and safe use

- Windows mode performs periodic local Security-log polling for Event IDs 4624 and 4625; it does not monitor a live network or guarantee capture of every event.
- Detection rules can still produce false positives and false negatives. Mitigations include short time windows for multi-account and volume rules, ignoring placeholder source IPs/usernames, and lowering volume-only alerts to Low severity. These changes reduce some false positives but do not eliminate them.
- Validate alerts against other telemetry and organizational incident-response procedures.
- Use only logs and systems you are authorized to access.
- Do not upload sensitive production logs to an environment unless its data-handling requirements permit it.

## Tests

Run the detection tests with:

```powershell
py -m pytest -q
```


## Persistent case management update

Case statuses and analyst notes are stored locally in `data/logscout_cases.db` using SQLite. Changes are recorded in a case audit history table and remain available after restarting Streamlit. Back up this database if you need to preserve investigation records. The database is local to this project and is not encrypted by the app.

## Live network monitoring with Wireshark/TShark (Windows)

The **NETWORK MONITOR** tab supports both the Wireshark desktop GUI and an embedded TShark packet-metadata view. It does not replace the authentication-log detector and does not treat packets as login events.

### Install prerequisites

1. Install Wireshark from the official Wireshark website: <https://www.wireshark.org/download.html>.
2. During setup, include **TShark** and **Npcap**. Npcap supplies the Windows packet-capture driver.
3. Finish the installation and reopen the terminal/VS Code so PATH changes are picked up.
4. Start LogScout-SH as usual:

   ```powershell
   py -m streamlit run app.py
   ```

5. Open **NETWORK MONITOR** and select **Check TShark & discover interfaces**. If it cannot find TShark, enter the full path to `tshark.exe` (commonly under `C:\Program Files\Wireshark\tshark.exe`). Select the adapter you are authorized to monitor.
6. To use the **Wireshark desktop GUI**, select **Open Wireshark GUI on selected interface**. Wireshark opens and starts a capture on that adapter; stop it from Wireshark itself. This requires `Wireshark.exe` to be installed.
7. To use the embedded metadata view, press **Start live capture** in LogScout-SH and press **Stop live capture** when finished. Do not run both capture modes on the same adapter at once unless you intentionally want two captures.

### What this integration collects

- Frame number, timestamp, packet length, protocol stack, source/destination IP, TCP/UDP ports, and DNS query names when present.
- The current view is capped at 2,000 packet-metadata rows; a CSV export is available. The Network Monitor can also launch the installed Wireshark GUI for interactive packet inspection.
- TShark is launched as a local child process with argument lists (not through a shell). The module does not write a PCAP file or request packet payload fields. Protocol/endpoint/DNS metadata can still be sensitive.
- The capture only runs after you explicitly press Start. Use only on networks and interfaces you own or have explicit permission to monitor. Windows may require appropriate Npcap/capture permissions; do not run as Administrator unless needed and authorized.
- If the app is interrupted unexpectedly, check that the TShark process has stopped. Use the in-app Stop button for normal shutdown.

### Troubleshooting

- **TShark not found:** install Wireshark with TShark, restart your terminal, or provide the full `tshark.exe` path in the Network Monitor tab.
- **No interfaces:** confirm Npcap was installed and the adapter is enabled.
- **Permission/access error:** check Npcap and Windows capture permissions. Use elevated access only if necessary and authorized.
- **No packets:** choose the active adapter, start capture, then generate ordinary traffic on that adapter (for example, load a website). VPNs and virtual machines may use a different adapter.
- **App still works without Wireshark:** CSV analysis and Windows Security-log scanning remain separate from this module.

This is a local metadata viewer, not a full packet-forensics suite, network IDS, or guarantee that all traffic is visible. Capture availability depends on the selected adapter, Npcap, permissions, and network topology.


## False-positive reduction update

- SL-002 now requires 3 or more distinct non-placeholder usernames to be targeted by failed authentication attempts from the same source IP within 10 minutes; attempts spread across unrelated hours are not combined.
- SL-004 now requires a burst of 20 or more events within 5 minutes, rather than a large total across the entire uploaded dataset. It is Low severity because volume alone is weak evidence.
- Placeholder source IPs (for example, `unknown`, blank, `null`, and `n/a`) are excluded from grouping so unrelated records do not get treated as one source.
- SL-003 is High severity rather than Critical because a success after repeated failures is suspicious but not proof of compromise.
- False positives are reduced, not eliminated. Tune thresholds against representative, labeled logs before using the tool for operational decisions.

## Wireshark desktop GUI

The Network Monitor includes a button to open `Wireshark.exe` and request capture on the selected interface. It uses a subprocess argument list with `shell=False`. If the GUI cannot be found, install Wireshark or provide a valid `Wireshark.exe` path through the standard installation location/PATH. The button is disabled while LogScout-SH's embedded TShark capture is active to reduce accidental simultaneous capture sessions. Stop a GUI capture inside Wireshark.
