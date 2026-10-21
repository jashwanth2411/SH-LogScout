# Changelog

## Complete interface and workflow bundle

- Consolidated the cyberpunk SOC interface into one `app.py`.
- Added the source IP Risk Center and transparent heuristic scoring.
- Added the Case Workspace for session-level investigation status and notes.
- Added individual case report and case register downloads.
- Retained overview charts, alert triage, event explorer, detection rules, and investigation report downloads.
- Included sample CSV, detection tests, dependency list, Windows launcher, and setup documentation.


## Next update — Persistent case management
- Store case status and analyst notes in a local SQLite database.
- Record status and note changes in an audit history.
- Display and export persisted cases.

## Windows auto-scan upgrade

- Added opt-in continuous polling of local Windows Security Event IDs 4624 and 4625.
- Normalizes event timestamps, usernames, source IPs, and success/failure outcomes into the existing detection pipeline.
- Uses record-ID deduplication and a bounded in-session event buffer; configurable 5–60 second polling interval.
- Added explicit permission/platform errors and documented that this is local event-log polling, not network monitoring.
- Fixed the missing `sqlite3` import in the persistent case-management version.

## Wireshark/TShark live network monitor

- Added an opt-in Network Monitor tab with TShark executable/version checks and interface discovery.
- Added explicit start/stop controls for local live capture and readable dependency/permission errors.
- Displays packet metadata, protocol counts, endpoints, DNS query names, and supports metadata CSV export.
- Captures metadata fields only; no PCAP file or payload fields are saved by this integration.
- Kept packet observations separate from the existing authentication detection rules.
- Added offline tests for packet parsing, interface discovery, and missing-dependency errors.


## Update — Wireshark GUI and false-positive mitigation

- Added a safe launcher for the Wireshark desktop GUI that opens a capture on the selected interface; the embedded TShark metadata viewer remains available.
- Tightened SL-002 to a 10-minute multi-account window and SL-004 to a 5-minute event burst.
- Lowered volume-only SL-004 to Low severity and SL-003 to High severity.
- Excluded placeholder source IPs from rule grouping and placeholder usernames from multi-account/success-after-failure detections.
- Added regression tests for time-window scoping, placeholder handling, low-confidence volume signals, and safe Wireshark launch arguments.
