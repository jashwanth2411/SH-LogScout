from __future__ import annotations

from datetime import datetime, timedelta, timezone
import platform
from pathlib import Path
import sqlite3

import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from windows_event_scanner import scan_security_events, WindowsEventScanError
from tshark_capture import TSharkError, LiveCapture, get_tshark_version, list_interfaces
from wireshark_gui import WiresharkGUIError, launch_wireshark_gui
import streamlit as st

APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"
SAMPLE_FILE = DATA_DIR / "sample_auth_logs.csv"
REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]

st.set_page_config(page_title="LogScout-SH | SOC Log Analyzer", page_icon="🛡️", layout="wide")

# ---------- LogScout-SH | Cyberpunk SOC Theme ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&family=Share+Tech+Mono&display=swap');
:root{--bg:#050610;--panel:#0d1226;--cyan:#00f5ff;--pink:#ff2bd6;--purple:#8b5cf6;--green:#00ff9c;--red:#ff3864;--orange:#ffb020;--text:#e8f2ff;--muted:#8493b4;--edge:rgba(0,245,255,.22)}
.stApp{background:radial-gradient(ellipse at 12% 0%,rgba(0,245,255,.10),transparent 34%),radial-gradient(ellipse at 92% 8%,rgba(255,43,214,.09),transparent 32%),linear-gradient(145deg,#050610,#080b19 55%,#090616);color:var(--text);font-family:Inter,sans-serif}
.stApp:before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(0,245,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,.035) 1px,transparent 1px);background-size:42px 42px;animation:gridScroll 24s linear infinite;mask-image:linear-gradient(to bottom,black,transparent 85%)}
@keyframes gridScroll{from{background-position:0 0}to{background-position:42px 42px}}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
@keyframes statusPulse{0%,100%{opacity:1}50%{opacity:.35}}
[data-testid="stAppViewContainer"],[data-testid="stHeader"],[data-testid="stSidebar"],.main{position:relative}
[data-testid="stHeader"]{background:rgba(5,6,16,.9)}
.block-container{padding-top:1.8rem;padding-bottom:3rem;max-width:1500px}
[data-testid="stSidebar"]{background:linear-gradient(180deg,#0b1021,#080a17)!important;border-right:1px solid var(--edge)}
[data-testid="stSidebar"] h1,[data-testid="stSidebar"] h2,[data-testid="stSidebar"] h3{font-family:Orbitron,sans-serif!important;color:var(--cyan)!important}
h1,h2,h3{font-family:Orbitron,sans-serif!important;letter-spacing:.025em;color:var(--text)!important}h1{text-shadow:0 0 18px rgba(0,245,255,.22)}p,label{color:var(--text)}
[data-testid="stMetric"]{background:linear-gradient(145deg,rgba(17,26,49,.97),rgba(9,13,29,.97));border:1px solid var(--edge);border-radius:12px;padding:18px 20px;min-height:112px;animation:fadeUp .5s ease both;transition:transform .22s,border-color .22s,box-shadow .22s}
[data-testid="stMetric"]:hover{transform:translateY(-5px);border-color:var(--cyan);box-shadow:0 0 22px rgba(0,245,255,.14)}
[data-testid="stMetricLabel"]{color:var(--muted)!important;font-size:12px!important;text-transform:uppercase;letter-spacing:1.2px}[data-testid="stMetricValue"]{color:var(--cyan)!important;font-family:'Share Tech Mono',monospace!important;font-size:29px!important;text-shadow:0 0 12px rgba(0,245,255,.25)}
.stButton>button,.stDownloadButton>button,[data-testid="stFormSubmitButton"]>button{background:linear-gradient(105deg,rgba(0,245,255,.12),rgba(139,92,246,.16))!important;color:var(--cyan)!important;border:1px solid rgba(0,245,255,.55)!important;border-radius:7px!important;font-family:'Share Tech Mono',monospace!important;transition:all .22s ease!important}
.stButton>button:hover,.stDownloadButton>button:hover,[data-testid="stFormSubmitButton"]>button:hover{background:linear-gradient(105deg,rgba(0,245,255,.25),rgba(255,43,214,.2))!important;border-color:var(--pink)!important;color:white!important;transform:translateY(-2px);box-shadow:0 0 18px rgba(0,245,255,.18)}
[data-testid="stTabs"] [data-baseweb="tab-list"]{gap:7px;background:rgba(9,13,29,.8);padding:8px;border:1px solid rgba(139,92,246,.22);border-radius:10px}
[data-testid="stTabs"] button[data-baseweb="tab"]{color:var(--muted);font-family:'Share Tech Mono',monospace;transition:all .2s ease;border-radius:6px;padding:10px 13px}
[data-testid="stTabs"] button[data-baseweb="tab"]:hover{color:var(--cyan);background:rgba(0,245,255,.06)}
[data-testid="stTabs"] button[aria-selected="true"]{color:var(--cyan)!important;background:rgba(0,245,255,.09)!important}
[data-testid="stTabs"] [data-baseweb="tab-highlight"]{background:var(--cyan)!important;box-shadow:0 0 9px var(--cyan)}
.stTextInput input,.stNumberInput input,.stDateInput input,.stTimeInput input,.stTextArea textarea{background:#090e20!important;color:var(--text)!important;border:1px solid rgba(0,245,255,.25)!important;border-radius:7px!important}
[data-baseweb="select"]>div{background:#090e20!important;border-color:rgba(0,245,255,.25)!important;color:var(--text)!important}
[data-testid="stFileUploader"]{background:rgba(13,18,38,.7);border:1px dashed rgba(0,245,255,.4);border-radius:10px;padding:8px}
[data-testid="stDataFrame"],[data-testid="stTable"]{border:1px solid rgba(0,245,255,.17);border-radius:9px;overflow:hidden}
[data-testid="stPlotlyChart"]{background:rgba(13,18,38,.55);border:1px solid rgba(139,92,246,.2);border-radius:10px;padding:6px}
[data-testid="stExpander"]{background:rgba(13,18,38,.7);border:1px solid rgba(0,245,255,.17);border-radius:9px}
[data-testid="stAlert"]{background:rgba(13,18,38,.85);border-radius:8px}
hr{border-color:rgba(0,245,255,.18)!important}
.ls-eyebrow{font-family:'Share Tech Mono',monospace;color:var(--cyan);font-size:11px;letter-spacing:1.8px;text-transform:uppercase}
.ls-panel{background:linear-gradient(145deg,rgba(13,18,38,.97),rgba(8,11,25,.97));border:1px solid rgba(0,245,255,.24);border-radius:13px;padding:22px;box-shadow:0 0 24px rgba(0,245,255,.045);animation:fadeUp .55s ease-out;transition:border-color .25s,box-shadow .25s}
.ls-panel:hover{border-color:rgba(0,245,255,.5);box-shadow:0 0 25px rgba(0,245,255,.09)}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
</style>
""", unsafe_allow_html=True)

# ---------- Cyberpunk SOC Header ----------
local_clock = datetime.now().astimezone().strftime("%H:%M:%S %Z")
st.markdown(
    f"""
    <div class="ls-panel" style="margin-bottom:22px;border-color:rgba(0,245,255,.38);background:linear-gradient(115deg,rgba(0,245,255,.07),rgba(13,18,38,.96) 50%,rgba(255,43,214,.07));">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:20px;flex-wrap:wrap;">
        <div>
          <div class="ls-eyebrow">◈ SH-01 // SECURITY OPERATIONS CENTER</div>
          <div style="font-family:Orbitron,sans-serif;font-size:clamp(25px,4vw,38px);font-weight:800;letter-spacing:2px;margin-top:12px;color:#e8f2ff;text-shadow:0 0 18px rgba(0,245,255,.35);">LOGSCOUT<span style="color:#00f5ff;">-SH</span></div>
          <div style="color:#8493b4;font-family:'Share Tech Mono',monospace;font-size:12px;margin-top:8px;">LOG INTELLIGENCE // THREAT DETECTION // INVESTIGATION</div>
        </div>
        <div style="min-width:205px;padding:15px 18px;border:1px solid rgba(0,245,255,.3);border-radius:8px;background:rgba(5,6,16,.65);">
          <div class="ls-eyebrow">● SYSTEM INTERFACE</div>
          <div style="color:#00ff9c;font-family:'Share Tech Mono',monospace;font-size:17px;margin-top:9px;"><span style="animation:statusPulse 1.4s infinite;">●</span> ANALYZER READY</div>
          <div style="color:#8493b4;font:11px 'Share Tech Mono',monospace;margin-top:7px;">LOCAL CLOCK // {local_clock}</div>
        </div>
      </div>
      <div style="height:2px;margin-top:22px;background:linear-gradient(90deg,#00f5ff,#8b5cf6,#ff2bd6,transparent);box-shadow:0 0 12px rgba(0,245,255,.25);"></div>
      <div style="display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;color:#8493b4;font:11px 'Share Tech Mono',monospace;margin-top:13px;"><span>TELEMETRY INGESTION</span><span>RULE-BASED DETECTION</span><span>BUILD // SH-01</span></div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------- Data and detection ----------
def load_logs(uploaded_file=None) -> pd.DataFrame:
    """Load and validate sample or uploaded CSV logs with clear input errors."""
    try:
        if uploaded_file is not None:
            df = pd.read_csv(uploaded_file)
            source_label = getattr(uploaded_file, "name", "Uploaded CSV")
        else:
            df = pd.read_csv(SAMPLE_FILE)
            source_label = "Included sample dataset"
    except pd.errors.EmptyDataError as exc:
        raise ValueError("The uploaded CSV is empty. Add a header row and log records, then try again.") from exc
    except pd.errors.ParserError as exc:
        raise ValueError("The CSV could not be parsed. Check that it is a valid comma-separated file.") from exc

    if df.empty and len(df.columns) == 0:
        raise ValueError("The CSV is empty. Include the required column headers and log records.")

    df.columns = [str(c).strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError("Missing required column(s): " + ", ".join(missing))

    df = df[REQUIRED_COLUMNS].copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    df["username"] = df["username"].fillna("unknown").astype(str).str.strip()
    df["source_ip"] = df["source_ip"].fillna("unknown").astype(str).str.strip()
    df["event_type"] = df["event_type"].fillna("unknown").astype(str).str.strip().str.lower()
    df["status"] = df["status"].fillna("unknown").astype(str).str.strip().str.lower()
    df = df.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
    if df.empty:
        raise ValueError("No valid log timestamps were found. Check the timestamp column format.")
    df.attrs["source_label"] = source_label
    return df


def detect_threats(logs: pd.DataFrame) -> pd.DataFrame:
    """Apply explainable, time-bounded rules with conservative handling of weak signals."""
    columns = ["timestamp", "severity", "rule_id", "alert", "source_ip", "username", "evidence", "recommendation", "event_count"]
    if logs.empty:
        return pd.DataFrame(columns=columns)

    work = logs.copy()
    work["timestamp"] = pd.to_datetime(work["timestamp"], errors="coerce", utc=True)
    work["source_ip"] = work["source_ip"].fillna("").astype(str).str.strip()
    work["username"] = work["username"].fillna("unknown").astype(str).str.strip()
    work["status"] = work["status"].fillna("").astype(str).str.strip().str.lower()
    work["event_type"] = work["event_type"].fillna("").astype(str).str.strip().str.lower()
    work = work.dropna(subset=["timestamp"])
    # Missing/placeholder IPs are not grouped together: doing so creates artificial bursts.
    placeholders = {"", "unknown", "none", "null", "nan", "n/a", "na", "-", "—"}
    work = work[~work["source_ip"].str.lower().isin(placeholders)].copy()
    if work.empty:
        return pd.DataFrame(columns=columns)

    failed_mask = work["status"].isin(["failed", "failure", "denied", "blocked"]) | work["event_type"].str.contains(r"fail|denied|blocked", na=False)
    success_mask = work["status"].isin(["success", "succeeded", "accepted"]) | work["event_type"].str.contains(r"success|accepted", na=False)
    failed = work[failed_mask].copy()
    successes = work[success_mask].copy()
    alerts = []

    def user_list(frame: pd.DataFrame, limit: int = 8) -> list[str]:
        users = sorted({u for u in frame["username"].astype(str).str.strip() if u and u.lower() not in placeholders})
        return users[:limit]

    # SL-001: count failed events in a bounded 10-minute window, once per source.
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        for i, start_time in enumerate(times):
            matching = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= start_time + pd.Timedelta(minutes=10))]
            if len(matching) >= 5:
                users = user_list(matching)
                alerts.append({
                    "timestamp": start_time, "severity": "High", "rule_id": "SL-001",
                    "alert": "Possible brute-force login", "source_ip": ip,
                    "username": ", ".join(users) if users else "(username unavailable)",
                    "evidence": f"{len(matching)} failed authentication events within 10 minutes; {len(set(matching['username']))} username value(s).",
                    "recommendation": "Validate whether the source is expected; check account lockout/MFA and surrounding endpoint or identity logs before taking action.",
                    "event_count": len(matching),
                })
                break

    # SL-002: require distinct real usernames in the same 10-minute window.
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        for start_time in times:
            matching = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= start_time + pd.Timedelta(minutes=10))]
            users = user_list(matching, limit=10000)
            if len(users) >= 3:
                alerts.append({
                    "timestamp": start_time, "severity": "High", "rule_id": "SL-002",
                    "alert": "Multiple accounts targeted from one IP", "source_ip": ip,
                    "username": ", ".join(users[:8]),
                    "evidence": f"Failed authentication events targeted {len(users)} distinct non-placeholder usernames within 10 minutes.",
                    "recommendation": "Review whether this source is a known identity provider, proxy, or test system; correlate with endpoint/network telemetry before concluding password spraying.",
                    "event_count": len(matching),
                })
                break

    # SL-003: same real username and source IP, 3+ prior failures in 15 minutes.
    for _, success in successes.sort_values("timestamp").iterrows():
        username = str(success["username"]).strip()
        if not username or username.lower() in placeholders:
            continue
        prior = failed[(failed["source_ip"] == success["source_ip"]) &
                       (failed["username"] == username) &
                       (failed["timestamp"] < success["timestamp"]) &
                       (failed["timestamp"] >= success["timestamp"] - pd.Timedelta(minutes=15))]
        if len(prior) >= 3:
            alerts.append({
                "timestamp": success["timestamp"], "severity": "High", "rule_id": "SL-003",
                "alert": "Successful login after repeated failures", "source_ip": success["source_ip"],
                "username": username,
                "evidence": f"A successful authentication followed {len(prior)} failures for this username and source IP within 15 minutes.",
                "recommendation": "Verify the login and MFA context with the account owner; review session activity and surrounding identity events. Treat this as suspicious, not confirmed compromise.",
                "event_count": len(prior) + 1,
            })

    # SL-004: volume is weak evidence, so require a short burst and use Low severity.
    for ip, group in work.groupby("source_ip"):
        group = group.sort_values("timestamp")
        for start_time in group["timestamp"].tolist():
            matching = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= start_time + pd.Timedelta(minutes=5))]
            if len(matching) >= 20:
                alerts.append({
                    "timestamp": start_time, "severity": "Low", "rule_id": "SL-004",
                    "alert": "High event volume from one source (context needed)", "source_ip": ip,
                    "username": ", ".join(user_list(matching, limit=5)) or "(username unavailable)",
                    "evidence": f"{len(matching)} events within 5 minutes. Volume alone is a low-confidence signal and may reflect legitimate automation or a busy service.",
                    "recommendation": "Check known scanners, proxies, service accounts, scheduled jobs, and baseline traffic before escalating. Do not block based on this rule alone.",
                    "event_count": len(matching),
                })
                break

    if not alerts:
        return pd.DataFrame(columns=columns)
    out = pd.DataFrame(alerts, columns=columns).drop_duplicates(subset=["rule_id", "source_ip", "username", "alert"])
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    out["_order"] = out["severity"].map(severity_order)
    out = out.sort_values(["_order", "timestamp"], ascending=[True, False]).drop(columns="_order").reset_index(drop=True)
    return out


def severity_color(value: str) -> str:
    return {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(value, "⚪")


def build_report(logs: pd.DataFrame, alerts: pd.DataFrame, source_label: str) -> str:
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    lines = [
        "LOGSCOUT-SH SECURITY INVESTIGATION REPORT",
        "=" * 44,
        f"Generated: {generated}",
        f"Log source: {source_label}",
        f"Events analyzed: {len(logs)}",
        f"Alerts identified: {len(alerts)}",
        "",
        "SCOPE AND LIMITATIONS",
        "This report is based on heuristic rules applied to the supplied log dataset. Alerts indicate patterns worth investigating; they do not prove compromise. Validate findings with additional telemetry and organizational procedures.",
        "",
        "SUMMARY BY SEVERITY",
    ]
    if alerts.empty:
        lines.append("No configured detection rules triggered for this dataset.")
    else:
        for severity in ["Critical", "High", "Medium", "Low"]:
            count = int((alerts["severity"] == severity).sum())
            lines.append(f"{severity}: {count}")
        lines += ["", "ALERT DETAILS", "-" * 44]
        for i, alert in alerts.iterrows():
            lines += [
                f"{i + 1}. [{alert['severity']}] {alert['alert']} ({alert['rule_id']})",
                f"   Timestamp: {alert['timestamp']}",
                f"   Source IP: {alert['source_ip']}",
                f"   Username(s): {alert['username']}",
                f"   Evidence: {alert['evidence']}",
                f"   Recommended action: {alert['recommendation']}",
                "",
            ]
    lines += ["", "DETECTION RULES", "SL-001: 5 or more failed authentication events from one non-placeholder source IP in a 10-minute window.", "SL-002: Failed logins against 3 or more distinct non-placeholder usernames from one IP within 10 minutes.", "SL-003: Successful login after 3 or more failures for the same user and IP within 15 minutes (High severity; investigate context).", "SL-004: 20 or more events from one IP within 5 minutes (Low severity; weak signal).", "", "LogScout-SH — defensive triage aid"]
    return "\n".join(lines)

# ---------- Persistent SQLite case storage ----------
CASE_DB = APP_DIR / "data" / "logscout_cases.db"
CASE_DB.parent.mkdir(parents=True, exist_ok=True)

def init_case_db() -> None:
    """Create persistent case and audit tables if they do not exist."""
    with sqlite3.connect(CASE_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cases (
                case_key TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                alert TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                username TEXT NOT NULL,
                alert_timestamp TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'New',
                analyst_notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS case_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_key TEXT NOT NULL,
                action TEXT NOT NULL,
                old_value TEXT,
                new_value TEXT,
                changed_at TEXT NOT NULL
            )
            """
        )

def save_case_record(alert_row, status: str, notes: str) -> None:
    """Persist case fields and record changes in the audit history."""
    key = case_key(alert_row)
    now = datetime.now().astimezone().isoformat(timespec="seconds")
    with sqlite3.connect(CASE_DB) as conn:
        existing = conn.execute(
            "SELECT status, analyst_notes FROM cases WHERE case_key = ?", (key,)
        ).fetchone()
        old_status, old_notes = existing if existing else (None, None)
        conn.execute(
            """
            INSERT INTO cases (
                case_key, rule_id, alert, severity, source_ip, username,
                alert_timestamp, status, analyst_notes, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_key) DO UPDATE SET
                status=excluded.status,
                analyst_notes=excluded.analyst_notes,
                updated_at=excluded.updated_at
            """,
            (
                key, str(alert_row["rule_id"]), str(alert_row["alert"]),
                str(alert_row["severity"]), str(alert_row["source_ip"]),
                str(alert_row["username"]), str(alert_row["timestamp"]),
                status, notes, now,
            ),
        )
        if old_status != status:
            conn.execute(
                "INSERT INTO case_audit (case_key, action, old_value, new_value, changed_at) VALUES (?, ?, ?, ?, ?)",
                (key, "status_changed", old_status, status, now),
            )
        if old_notes != notes:
            conn.execute(
                "INSERT INTO case_audit (case_key, action, old_value, new_value, changed_at) VALUES (?, ?, ?, ?, ?)",
                (key, "notes_updated", old_notes, notes, now),
            )

def load_case_record(alert_row):
    key = case_key(alert_row)
    with sqlite3.connect(CASE_DB) as conn:
        return conn.execute(
            "SELECT status, analyst_notes FROM cases WHERE case_key = ?", (key,)
        ).fetchone()

def load_all_cases():
    with sqlite3.connect(CASE_DB) as conn:
        return pd.read_sql_query(
            "SELECT rule_id, alert, severity, source_ip, username, alert_timestamp, status, analyst_notes, updated_at FROM cases ORDER BY updated_at DESC",
            conn,
        )

def load_case_audit(case_key_value: str):
    with sqlite3.connect(CASE_DB) as conn:
        return pd.read_sql_query(
            "SELECT action, old_value, new_value, changed_at FROM case_audit WHERE case_key = ? ORDER BY id DESC",
            conn, params=(case_key_value,),
        )

init_case_db()

# ---------- Sidebar / data source ----------
st.sidebar.title("🛡️ LogScout-SH")
st.sidebar.caption("SOC Log Analyzer")
st.sidebar.markdown("---")
data_mode = st.sidebar.radio(
    "Log source",
    ["Sample / uploaded CSV", "Windows Security event log (auto-scan)"],
    help="Windows mode reads local Security events 4624 (successful logon) and 4625 (failed logon). It does not monitor network traffic.",
)
upload = None
scan_enabled = False
scan_interval = 15
if data_mode == "Sample / uploaded CSV":
    upload = st.sidebar.file_uploader(
        "Upload authentication logs (CSV)", type=["csv"],
        help="Required columns: timestamp, username, source_ip, event_type, status",
    )
    st.sidebar.markdown("**Expected CSV columns**")
    st.sidebar.code(", ".join(REQUIRED_COLUMNS), language="text")
else:
    st.sidebar.warning("Windows only. Access to the Security log may require running the terminal as Administrator.")
    scan_enabled = st.sidebar.toggle("Enable continuous scanning", value=True, help="Poll the local Windows Security event log while this Streamlit app is running.")
    scan_interval = st.sidebar.select_slider("Scan interval", options=[5, 10, 15, 30, 60], value=15, format_func=lambda n: f"{n} seconds")
    st.sidebar.caption("Scans run while this app is open. Closing the app stops scanning. First scan loads up to the most recent 5 minutes of matching events.")
st.sidebar.markdown("---")
st.sidebar.caption("Rule-based detections are triage signals, not proof of an attack.")

# ---------- Load dataset ----------
if data_mode == "Windows Security event log (auto-scan)":
    if "ls_windows_events" not in st.session_state:
        st.session_state["ls_windows_events"] = []
    if "ls_windows_record_ids" not in st.session_state:
        st.session_state["ls_windows_record_ids"] = set()
    if "ls_windows_last_timestamp" not in st.session_state:
        st.session_state["ls_windows_last_timestamp"] = None
    if scan_enabled:
        st_autorefresh(interval=int(scan_interval * 1000), key="ls_windows_autorefresh")
        try:
            last_ts = st.session_state["ls_windows_last_timestamp"]
            scan_from = (pd.Timestamp(last_ts).to_pydatetime() - timedelta(seconds=2)) if last_ts else (datetime.now(timezone.utc) - timedelta(minutes=5))
            fresh_events = scan_security_events(scan_from=scan_from, max_events=1000)
            for event in fresh_events:
                record_id = event["record_id"]
                if record_id not in st.session_state["ls_windows_record_ids"]:
                    st.session_state["ls_windows_record_ids"].add(record_id)
                    st.session_state["ls_windows_events"].append(event)
            st.session_state["ls_windows_events"] = st.session_state["ls_windows_events"][-5000:]
            if fresh_events:
                latest = max(pd.Timestamp(e["timestamp"]) for e in fresh_events)
                previous = st.session_state["ls_windows_last_timestamp"]
                if previous is None or latest > pd.Timestamp(previous):
                    st.session_state["ls_windows_last_timestamp"] = latest.isoformat()
            st.sidebar.success(f"Scanner active · {len(st.session_state['ls_windows_events']):,} events collected")
        except WindowsEventScanError as exc:
            st.sidebar.error("Windows event scan unavailable")
            st.error(str(exc))
            st.info("Try opening PowerShell as Administrator, then restart LogScout-SH. CSV mode remains available.")
    else:
        st.sidebar.info("Auto-scanning paused. Existing collected events remain in this app session.")
    rows = st.session_state["ls_windows_events"]
    if rows:
        logs = pd.DataFrame([{k: e[k] for k in REQUIRED_COLUMNS} for e in rows])
        logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce", utc=True)
        logs = logs.dropna(subset=["timestamp"]).sort_values("timestamp").reset_index(drop=True)
        logs.attrs["source_label"] = "Local Windows Security event log (4624/4625)"
    else:
        logs = pd.DataFrame(columns=REQUIRED_COLUMNS)
        logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
        logs.attrs["source_label"] = "Local Windows Security event log (waiting for events)"
        st.info("Waiting for matching Windows Security events. If the log is empty, try a test login or check Windows Security log permissions.")
    source_label = logs.attrs["source_label"]
else:
    try:
        logs = load_logs(upload)
    except Exception as exc:
        st.error(f"Could not load logs: {exc}")
        st.info("Use the included sample dataset or upload a CSV containing: " + ", ".join(REQUIRED_COLUMNS))
        st.stop()
    source_label = logs.attrs.get("source_label", "Dataset")

if not logs.empty:
    alerts = detect_threats(logs)
else:
    alerts = pd.DataFrame(columns=["timestamp", "severity", "rule_id", "alert", "source_ip", "username", "evidence", "recommendation", "event_count"])

# ---------- Investigation case workspace state ----------
if "ls_case_status" not in st.session_state:
    st.session_state["ls_case_status"] = {}
if "ls_case_notes" not in st.session_state:
    st.session_state["ls_case_notes"] = {}

def case_key(alert_row) -> str:
    """Build a stable key for a detected alert in the current dataset."""
    return "|".join([
        str(alert_row.get("rule_id", "")),
        str(alert_row.get("source_ip", "")),
        str(alert_row.get("username", "")),
        str(alert_row.get("alert", "")),
        str(alert_row.get("timestamp", "")),
    ])



# ---------- Cyberpunk SOC Status Panel ----------
last_event = logs["timestamp"].max().strftime("%Y-%m-%d %H:%M UTC") if not logs.empty else "N/A"
total_events = len(logs)
total_alerts = len(alerts)
critical_alerts = int((alerts["severity"] == "Critical").sum()) if not alerts.empty else 0
high_alerts = int((alerts["severity"] == "High").sum()) if not alerts.empty else 0
system_state = "REVIEW REQUIRED" if total_alerts else "NO RULES TRIGGERED"
state_color = "#ff3864" if critical_alerts else "#ffb020" if total_alerts else "#00ff9c"
st.markdown(
    f"""
    <div class="ls-panel" style="margin-bottom:20px;">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;">
        <div><div class="ls-eyebrow">◈ OPERATIONS STATUS // SH-01</div><div style="font-family:Orbitron,sans-serif;font-size:19px;font-weight:700;margin-top:10px;">SECURITY TELEMETRY</div><div style="color:#8493b4;font-size:12px;margin-top:6px;">SOURCE // {source_label}</div></div>
        <div style="font-family:'Share Tech Mono',monospace;color:{state_color};border:1px solid {state_color};padding:10px 14px;border-radius:5px;box-shadow:0 0 14px {state_color}22;"><span style="animation:statusPulse 1.5s infinite;">●</span> {system_state}</div>
      </div>
      <div style="height:1px;background:linear-gradient(90deg,#00f5ff,#8b5cf6,#ff2bd6,transparent);margin:18px 0;"></div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:18px;">
        <div><div class="ls-eyebrow">EVENTS INGESTED</div><div style="font:24px 'Share Tech Mono',monospace;color:#00f5ff;margin-top:6px;">{total_events:,}</div></div>
        <div><div class="ls-eyebrow">ALERTS GENERATED</div><div style="font:24px 'Share Tech Mono',monospace;color:#ff2bd6;margin-top:6px;">{total_alerts:,}</div></div>
        <div><div class="ls-eyebrow">CRITICAL FINDINGS</div><div style="font:24px 'Share Tech Mono',monospace;color:#ff3864;margin-top:6px;">{critical_alerts:,}</div></div>
        <div><div class="ls-eyebrow">HIGH PRIORITY</div><div style="font:24px 'Share Tech Mono',monospace;color:#ffb020;margin-top:6px;">{high_alerts:,}</div></div>
      </div>
      <div style="color:#8493b4;font:12px 'Share Tech Mono',monospace;margin-top:20px;">DATA SOURCE // {source_label} &nbsp; | &nbsp; LAST EVENT // {last_event}</div>
    </div>
    """,
    unsafe_allow_html=True,
)
st.markdown("---")


# ---------- Filters ----------
with st.expander("Filter dashboard", expanded=False):
    f1, f2, f3 = st.columns(3)
    severities = ["Critical", "High", "Medium", "Low"]
    chosen_severities = f1.multiselect("Alert severity", severities, default=severities)
    ip_options = sorted(logs["source_ip"].unique().tolist())
    chosen_ips = f2.multiselect("Source IP", ip_options, default=[])
    user_options = sorted(logs["username"].unique().tolist())
    chosen_users = f3.multiselect("Username", user_options, default=[])

filtered_alerts = alerts[alerts["severity"].isin(chosen_severities)] if not alerts.empty else alerts.copy()
if chosen_ips:
    filtered_alerts = filtered_alerts[filtered_alerts["source_ip"].isin(chosen_ips)]
if chosen_users:
    filtered_alerts = filtered_alerts[filtered_alerts["username"].apply(lambda x: any(u in str(x).split(", ") for u in chosen_users))]

critical_count = int((filtered_alerts["severity"] == "Critical").sum()) if not filtered_alerts.empty else 0
high_count = int((filtered_alerts["severity"] == "High").sum()) if not filtered_alerts.empty else 0
failed_count = int(((logs["status"].isin(["failed", "failure", "denied"])) | logs["event_type"].str.contains("fail|denied", na=False)).sum())

m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", f"{len(logs):,}")
m2.metric("Alerts detected", f"{len(alerts):,}")
m3.metric("Critical alerts", f"{critical_count:,}")
m4.metric("Failed login events", f"{failed_count:,}")


# ---------- Main dashboard navigation ----------
st.markdown(
    '<div class="ls-eyebrow">◈ COMMAND INTERFACE // SELECT MODULE</div>',
    unsafe_allow_html=True,
)

tab_overview, tab_alerts, tab_events, tab_risk, tab_cases, tab_report, tab_network, tab_about = st.tabs(
    [
        "◈ OVERVIEW",
        "⚠ ALERT TRIAGE",
        "⌕ EVENT EXPLORER",
        "◎ RISK CENTER",
        "▣ CASE WORKSPACE",
        "▤ REPORTS",
        "⌁ NETWORK MONITOR",
        "ℹ DETECTION RULES",
    ]
)

with tab_overview:
    left, right = st.columns(2)
    with left:
        st.subheader("Alerts by severity")
        if alerts.empty:
            st.success("No configured rules triggered for the loaded dataset.")
        else:
            sev_df = alerts.groupby("severity").size().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).rename("count").reset_index()
            fig = px.bar(sev_df, x="severity", y="count", color="severity", category_orders={"severity": ["Critical", "High", "Medium", "Low"]}, title="Detected alert severity")
            fig.update_layout(showlegend=False, margin=dict(l=10, r=10, t=45, b=10), xaxis_title="Severity", yaxis_title="Alerts")
            st.plotly_chart(fig, use_container_width=True)
    with right:
        st.subheader("Events over time")
        if not logs.empty:
            timeline = logs.assign(hour=logs["timestamp"].dt.floor("h")).groupby("hour").size().rename("events").reset_index()
            fig2 = px.line(timeline, x="hour", y="events", markers=True, title="Log volume by hour")
            fig2.update_layout(margin=dict(l=10, r=10, t=45, b=10), xaxis_title="Time (UTC)", yaxis_title="Events")
            st.plotly_chart(fig2, use_container_width=True)
    st.subheader("Top source IPs by event count")
    top_ips = logs.groupby("source_ip").size().sort_values(ascending=False).head(10).rename("events").reset_index()
    fig3 = px.bar(top_ips, x="source_ip", y="events", title="Top 10 source IPs")
    fig3.update_layout(margin=dict(l=10, r=10, t=45, b=10), xaxis_title="Source IP", yaxis_title="Events")
    st.plotly_chart(fig3, use_container_width=True)
    st.caption("Charts summarize the loaded dataset. Source IPs and timestamps are sample data unless you upload your own logs.")

with tab_alerts:
    st.subheader("Detected alerts")
    if filtered_alerts.empty:
        st.success("No alerts match the current filters.")
    else:
        display_alerts = filtered_alerts[["timestamp", "severity", "rule_id", "alert", "source_ip", "username", "evidence"]].copy()
        display_alerts["timestamp"] = display_alerts["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        st.dataframe(display_alerts, use_container_width=True, hide_index=True)
        choices = {f"{r['severity']} | {r['alert']} | {r['source_ip']} | {r['rule_id']}": idx for idx, r in filtered_alerts.iterrows()}
        selected_label = st.selectbox("Investigate an alert", list(choices.keys()))
        selected = filtered_alerts.loc[choices[selected_label]]
        st.markdown("### Investigation details")
        d1, d2, d3 = st.columns(3)
        d1.metric("Severity", f"{severity_color(selected['severity'])} {selected['severity']}")
        d2.metric("Rule", selected["rule_id"])
        d3.metric("Related events", int(selected["event_count"]))
        st.write("**Evidence**")
        st.write(selected["evidence"])
        st.write("**Source IP**", selected["source_ip"])
        st.write("**Username(s)**", selected["username"])
        st.write("**Recommended response**")
        st.info(selected["recommendation"])
        # Match every username associated with the selected alert. The previous
        # implementation only matched the first username, hiding useful evidence
        # for multi-account alerts such as SL-002.
        selected_users = {
            user.strip()
            for user in str(selected["username"]).split(",")
            if user.strip()
        }
        related = logs[
            (logs["source_ip"] == selected["source_ip"])
            & (logs["username"].isin(selected_users))
        ].copy()
        if not related.empty:
            st.write(f"**Related log events ({len(related)})**")
            related["timestamp"] = related["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            st.dataframe(related, use_container_width=True, hide_index=True)
        else:
            st.info("No matching source-IP and username events were found in the loaded dataset.")

with tab_events:
    st.subheader("Event explorer")
    status_filter = st.multiselect("Authentication status", sorted(logs["status"].unique()), default=sorted(logs["status"].unique()))
    event_filter = st.multiselect("Event type", sorted(logs["event_type"].unique()), default=sorted(logs["event_type"].unique()))
    event_view = logs[logs["status"].isin(status_filter) & logs["event_type"].isin(event_filter)].copy()
    event_view["timestamp"] = event_view["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    st.dataframe(event_view, use_container_width=True, hide_index=True)
    st.download_button("Download filtered events (CSV)", event_view.to_csv(index=False).encode("utf-8"), file_name="logscout_sh_filtered_events.csv", mime="text/csv")

with tab_risk:
    st.markdown(
        '<div class="ls-eyebrow">◈ SOURCE ANALYTICS // HEURISTIC RISK RANKING</div>',
        unsafe_allow_html=True,
    )
    st.subheader("Source IP risk center")
    st.caption(
        "This is a local, explainable triage score calculated from the loaded logs. "
        "It is not an external threat-intelligence reputation score."
    )

    failed_mask = (
        logs["status"].isin(["failed", "failure", "denied"])
        | logs["event_type"].str.contains("fail|denied", na=False)
    )
    success_mask = (
        logs["status"].isin(["success", "succeeded", "accepted"])
        | logs["event_type"].str.contains("success|accepted", na=False)
    )
    risk_rows = []
    for ip, group in logs.groupby("source_ip"):
        ip_alerts = alerts[alerts["source_ip"] == ip] if not alerts.empty else alerts
        failures = int(failed_mask.loc[group.index].sum())
        successes = int(success_mask.loc[group.index].sum())
        users_targeted = int(group["username"].nunique())
        event_total = int(len(group))
        critical_hits = int((ip_alerts["severity"] == "Critical").sum()) if not ip_alerts.empty else 0
        high_hits = int((ip_alerts["severity"] == "High").sum()) if not ip_alerts.empty else 0
        medium_hits = int((ip_alerts["severity"] == "Medium").sum()) if not ip_alerts.empty else 0

        # Transparent weighted score for prioritization, capped at 100.
        score = min(
            100,
            critical_hits * 45
            + high_hits * 25
            + medium_hits * 10
            + min(failures, 10) * 2
            + min(max(users_targeted - 1, 0), 5) * 3
            + (10 if failures >= 5 and successes >= 1 else 0),
        )
        band = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "GUARDED" if score >= 15 else "LOW"
        risk_rows.append({
            "source_ip": ip,
            "risk_score": score,
            "risk_band": band,
            "events": event_total,
            "failed_events": failures,
            "successful_events": successes,
            "unique_users": users_targeted,
            "critical_alerts": critical_hits,
            "high_alerts": high_hits,
            "medium_alerts": medium_hits,
        })

    risk_df = pd.DataFrame(risk_rows)
    if not risk_df.empty:
        risk_df = risk_df.sort_values(
            ["risk_score", "failed_events", "events"],
            ascending=[False, False, False],
        ).reset_index(drop=True)

    highest_score = int(risk_df["risk_score"].max()) if not risk_df.empty else 0
    high_risk_sources = int((risk_df["risk_score"] >= 40).sum()) if not risk_df.empty else 0
    total_failed = int(risk_df["failed_events"].sum()) if not risk_df.empty else 0

    r1, r2, r3 = st.columns(3)
    r1.metric("Highest source risk", f"{highest_score}/100")
    r2.metric("High-priority sources", high_risk_sources)
    r3.metric("Failed events", f"{total_failed:,}")

    st.markdown("#### Source prioritization")
    if risk_df.empty:
        st.info("No source IP data is available to rank.")
    else:
        chart_df = risk_df.head(12).sort_values("risk_score", ascending=True)
        risk_fig = px.bar(
            chart_df,
            x="risk_score",
            y="source_ip",
            color="risk_band",
            orientation="h",
            range_x=[0, 100],
            title="Highest-risk source IPs",
            color_discrete_map={
                "CRITICAL": "#ff3864",
                "HIGH": "#ffb020",
                "GUARDED": "#8b5cf6",
                "LOW": "#00f5ff",
            },
        )
        risk_fig.update_layout(
            margin=dict(l=10, r=10, t=45, b=10),
            xaxis_title="Heuristic risk score (0–100)",
            yaxis_title="Source IP",
            legend_title="Risk band",
        )
        st.plotly_chart(risk_fig, use_container_width=True)

        st.markdown("#### Risk-ranked source table")
        st.dataframe(risk_df, use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Export risk assessment (CSV)",
            risk_df.to_csv(index=False).encode("utf-8"),
            file_name="logscout_sh_source_risk.csv",
            mime="text/csv",
        )

    with st.expander("How the score is calculated"):
        st.markdown(
            """
            - **Critical alert:** +45 points per alert.
            - **High alert:** +25 points per alert.
            - **Medium alert:** +10 points per alert.
            - **Failed authentication:** +2 points per event, capped at 10 events.
            - **Distinct usernames:** +3 points for each additional username, capped at 5.
            - **Failures followed by a success:** +10 points when the source has at least 5 failures and 1 success.
            - The final score is capped at 100.

            Bands: **Critical** (70–100), **High** (40–69), **Guarded** (15–39), **Low** (0–14).

            This score is a prioritization aid, not proof of malicious activity. Validate results with other logs and your incident-response process.
            """
        )

with tab_cases:
    st.markdown(
        '<div class="ls-eyebrow">◈ INCIDENT HANDLING // ANALYST WORKSPACE</div>',
        unsafe_allow_html=True,
    )
    st.subheader("Investigation case workspace")
    st.caption(
        "Track triage progress and save analyst notes in the local SQLite case database."
    )

    if alerts.empty:
        st.info("No alerts were generated from the current dataset. Load logs that trigger a detection rule to create a case.")
    else:
        case_options = {
            f"{row['severity']} | {row['rule_id']} | {row['source_ip']} | {row['alert']}": idx
            for idx, row in alerts.iterrows()
        }
        chosen_case_label = st.selectbox(
            "Select an alert to investigate",
            list(case_options.keys()),
            key="ls_case_selector",
        )
        chosen_case = alerts.loc[case_options[chosen_case_label]]
        chosen_key = case_key(chosen_case)

        left_case, right_case = st.columns(2)
        with left_case:
            st.markdown("#### Case evidence")
            st.write(f"**Rule:** {chosen_case['rule_id']}")
            st.write(f"**Alert:** {chosen_case['alert']}")
            st.write(f"**Severity:** {severity_color(chosen_case['severity'])} {chosen_case['severity']}")
            st.write(f"**Source IP:** `{chosen_case['source_ip']}`")
            st.write(f"**Username(s):** {chosen_case['username']}")
            st.write(f"**Timestamp:** {chosen_case['timestamp']}")
            st.write(f"**Evidence:** {chosen_case['evidence']}")
            st.info(chosen_case["recommendation"])

        with right_case:
            st.markdown("#### Analyst workflow")
            status_options = ["New", "Investigating", "Escalated", "False positive", "Resolved"]
            stored_case = load_case_record(chosen_case)
            current_status = (stored_case[0] if stored_case else st.session_state["ls_case_status"].get(chosen_key, "New"))
            selected_status = st.selectbox(
                "Investigation status",
                status_options,
                index=status_options.index(current_status) if current_status in status_options else 0,
                key=f"ls_status_{chosen_key}",
            )
            existing_notes = (stored_case[1] if stored_case else st.session_state["ls_case_notes"].get(chosen_key, ""))
            notes_value = st.text_area(
                "Analyst notes",
                value=existing_notes,
                height=180,
                placeholder="Record validation steps, correlated evidence, and next actions...",
                key=f"ls_notes_{chosen_key}",
            )
            if st.button("Save case updates", type="primary", key="ls_save_case"):
                st.session_state["ls_case_status"][chosen_key] = selected_status
                st.session_state["ls_case_notes"][chosen_key] = notes_value
                save_case_record(chosen_case, selected_status, notes_value)
                st.success("Case updates saved to the local SQLite database.")

        st.markdown("---")
        st.markdown("#### Case summary")
        stored_case = load_case_record(chosen_case)
        case_status = stored_case[0] if stored_case else st.session_state["ls_case_status"].get(chosen_key, "New")
        case_notes = stored_case[1] if stored_case else st.session_state["ls_case_notes"].get(chosen_key, "")
        s1, s2, s3 = st.columns(3)
        s1.metric("Current status", case_status)
        s2.metric("Severity", str(chosen_case["severity"]))
        s3.metric("Evidence event count", int(chosen_case["event_count"]))

        case_report = "\\n".join([
            "LOGSCOUT-SH INVESTIGATION CASE",
            "=" * 36,
            f"Generated: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
            f"Dataset: {source_label}",
            f"Rule ID: {chosen_case['rule_id']}",
            f"Alert: {chosen_case['alert']}",
            f"Severity: {chosen_case['severity']}",
            f"Status: {case_status}",
            f"Timestamp: {chosen_case['timestamp']}",
            f"Source IP: {chosen_case['source_ip']}",
            f"Username(s): {chosen_case['username']}",
            f"Evidence: {chosen_case['evidence']}",
            f"Recommended action: {chosen_case['recommendation']}",
            "",
            "ANALYST NOTES",
            case_notes if case_notes.strip() else "No analyst notes recorded.",
            "",
            "SCOPE NOTE",
            "This case is based on heuristic rules applied to the loaded dataset. It is not proof of compromise.",
        ])
        st.download_button(
            "⬇️ Download this case report (.txt)",
            case_report,
            file_name=f"logscout_case_{str(chosen_case['rule_id']).lower()}.txt",
            mime="text/plain",
            key="ls_download_case_report",
        )

        st.markdown("#### All alert case statuses")
        status_rows = []
        for _, alert_row in alerts.iterrows():
            key = case_key(alert_row)
            status_rows.append({
                "severity": alert_row["severity"],
                "rule_id": alert_row["rule_id"],
                "alert": alert_row["alert"],
                "source_ip": alert_row["source_ip"],
                "username": alert_row["username"],
                "status": (load_case_record(alert_row)[0] if load_case_record(alert_row) else st.session_state["ls_case_status"].get(key, "New")),
                "analyst_notes_saved": bool(((load_case_record(alert_row)[1] if load_case_record(alert_row) else st.session_state["ls_case_notes"].get(key, ""))).strip()),
            })
        persisted_cases = load_all_cases()
        if not persisted_cases.empty:
            st.markdown("#### Persisted case register")
            st.dataframe(persisted_cases, use_container_width=True, hide_index=True)
            st.download_button(
                "⬇️ Export all saved cases (CSV)",
                persisted_cases.to_csv(index=False).encode("utf-8"),
                file_name="logscout_sh_persisted_cases.csv",
                mime="text/csv",
                key="ls_export_persisted_cases",
            )

        st.markdown("#### Selected case audit history")
        audit_df = load_case_audit(chosen_key)
        if audit_df.empty:
            st.caption("No saved changes yet. Save a case update to begin the audit history.")
        else:
            st.dataframe(audit_df, use_container_width=True, hide_index=True)

        st.dataframe(pd.DataFrame(status_rows), use_container_width=True, hide_index=True)
        st.download_button(
            "⬇️ Export case register (CSV)",
            pd.DataFrame(status_rows).to_csv(index=False).encode("utf-8"),
            file_name="logscout_sh_case_register.csv",
            mime="text/csv",
            key="ls_download_case_register",
        )

with tab_report:
    st.subheader("Investigation report")
    report = build_report(logs, alerts, source_label)
    st.markdown("Create a text report for the complete loaded dataset, including rule explanations and recommended actions.")
    st.download_button("⬇️ Download investigation report (.txt)", report, file_name="logscout_sh_investigation_report.txt", mime="text/plain", type="primary")
    st.download_button("⬇️ Download detected alerts (.csv)", alerts.to_csv(index=False).encode("utf-8"), file_name="logscout_sh_alerts.csv", mime="text/csv")
    with st.expander("Preview report"):
        st.text(report)

with tab_network:
    st.subheader("Wireshark Network Monitor · GUI + TShark")
    st.caption("Use the Wireshark desktop GUI for full interactive packet inspection, or TShark for the embedded metadata view. These network findings remain separate from authentication-log rules.")
    st.warning("Use only on a network/interface you own or have explicit permission to monitor. Metadata can still reveal sensitive endpoints and DNS queries.")

    if "ls_tshark_path" not in st.session_state:
        st.session_state["ls_tshark_path"] = "tshark"
    if "ls_tshark_interfaces" not in st.session_state:
        st.session_state["ls_tshark_interfaces"] = []
    if "ls_tshark_capture" not in st.session_state:
        st.session_state["ls_tshark_capture"] = None
    if "ls_network_packets" not in st.session_state:
        st.session_state["ls_network_packets"] = []
    if "ls_tshark_error" not in st.session_state:
        st.session_state["ls_tshark_error"] = ""

    st.text_input(
        "TShark executable (command or full path to tshark.exe)",
        key="ls_tshark_path",
        help=r"Default is tshark. Example: C:\Program Files\Wireshark\tshark.exe",
    )
    check_col, clear_col = st.columns([2, 1])
    with check_col:
        if st.button("Check TShark & discover interfaces", key="ls_tshark_check"):
            try:
                version = get_tshark_version(st.session_state["ls_tshark_path"])
                interfaces = list_interfaces(st.session_state["ls_tshark_path"])
                st.session_state["ls_tshark_interfaces"] = interfaces
                st.session_state["ls_tshark_error"] = ""
                st.success(f"{version} · {len(interfaces)} interface(s) found")
            except TSharkError as exc:
                st.session_state["ls_tshark_error"] = str(exc)
    with clear_col:
        if st.button("Clear packet view", key="ls_tshark_clear"):
            st.session_state["ls_network_packets"] = []

    if st.session_state["ls_tshark_error"]:
        st.error(st.session_state["ls_tshark_error"])

    interfaces = st.session_state["ls_tshark_interfaces"]
    active_capture = st.session_state["ls_tshark_capture"]
    if interfaces:
        interface_labels = {f"{item['id']}. {item['label']}": item for item in interfaces}
        selected_label = st.selectbox(
            "Capture interface", list(interface_labels.keys()), key="ls_tshark_interface_select",
            help="Choose the network adapter whose traffic you are authorized to inspect.",
        )
        selected_interface = interface_labels[selected_label]
    else:
        selected_interface = None
        st.info("Check TShark and discover interfaces first. Install Wireshark with TShark and Npcap if needed.")

    gui_col, gui_help_col = st.columns([1, 2])
    with gui_col:
        if st.button("Open Wireshark GUI on selected interface", key="ls_open_wireshark", disabled=(selected_interface is None or (active_capture is not None and active_capture.running))):
            try:
                gui_path = launch_wireshark_gui(
                    st.session_state["ls_tshark_path"],
                    selected_interface["identifier"],
                )
                st.success(f"Opened Wireshark GUI and requested capture on {selected_interface['label']} ({gui_path}). Stop capture in Wireshark when finished.")
            except WiresharkGUIError as exc:
                st.error(str(exc))
    with gui_help_col:
        st.caption("Opens the installed Wireshark desktop application and starts capture on the selected adapter. Stop it from Wireshark. This is separate from the embedded TShark capture below.")

    start_col, stop_col = st.columns(2)
    with start_col:
        if st.button("▶ Start live capture", key="ls_tshark_start", disabled=(selected_interface is None or (active_capture is not None and active_capture.running))):
            try:
                capture = LiveCapture(st.session_state["ls_tshark_path"], selected_interface["id"])
                capture.start()
                st.session_state["ls_tshark_capture"] = capture
                st.session_state["ls_tshark_error"] = ""
                st.session_state["ls_network_packets"] = []
                st.rerun()
            except TSharkError as exc:
                st.session_state["ls_tshark_error"] = str(exc)
                st.error(str(exc))
    with stop_col:
        if st.button("■ Stop live capture", key="ls_tshark_stop", disabled=(active_capture is None or not active_capture.running)):
            active_capture.stop()
            st.session_state["ls_tshark_capture"] = None
            st.info("Capture stopped.")
            st.rerun()
    if active_capture is not None and not active_capture.running:
        if st.button("Clear stopped capture", key="ls_tshark_clear_stopped"):
            active_capture.stop()
            st.session_state["ls_tshark_capture"] = None
            st.rerun()

    active_capture = st.session_state["ls_tshark_capture"]
    if active_capture is not None:
        st_autorefresh(interval=1000, key="ls_tshark_autorefresh")
    if active_capture is not None and active_capture.running:
        for item in active_capture.drain(limit=1500):
            if item.get("kind") == "packet":
                st.session_state["ls_network_packets"].append(item["packet"])
            elif item.get("kind") == "error":
                st.session_state["ls_tshark_error"] = item.get("message", "TShark capture stopped unexpectedly.")
        st.session_state["ls_network_packets"] = st.session_state["ls_network_packets"][-2000:]
        st.success(f"Capture running · {len(st.session_state['ls_network_packets']):,} packet metadata rows in this view")
    elif active_capture is not None:
        for item in active_capture.drain(limit=1500):
            if item.get("kind") == "packet":
                st.session_state["ls_network_packets"].append(item["packet"])
            elif item.get("kind") == "error":
                st.session_state["ls_tshark_error"] = item.get("message", "TShark capture stopped unexpectedly.")
        st.session_state["ls_network_packets"] = st.session_state["ls_network_packets"][-2000:]
        st.warning("Capture process is no longer running. Check the error details and restart if appropriate.")

    if st.session_state["ls_tshark_error"]:
        st.error(st.session_state["ls_tshark_error"])

    packets = st.session_state["ls_network_packets"]
    if packets:
        packet_df = pd.DataFrame(packets)
        m1, m2, m3 = st.columns(3)
        m1.metric("Packets observed", f"{len(packet_df):,}")
        m2.metric("Bytes represented", f"{int(pd.to_numeric(packet_df['length_bytes'], errors='coerce').fillna(0).sum()):,}")
        m3.metric("Distinct endpoints", f"{len(set(packet_df['source'].dropna()) | set(packet_df['destination'].dropna()) - {'—'}):,}")
        left, right = st.columns(2)
        with left:
            st.markdown("**Observed protocols**")
            protocol_counts = packet_df["protocols"].fillna("unknown").value_counts().head(12).rename_axis("protocol stack").reset_index(name="packets")
            st.dataframe(protocol_counts, use_container_width=True, hide_index=True)
        with right:
            st.markdown("**DNS queries observed**")
            dns_rows = packet_df[packet_df["dns_query"].fillna("").astype(str).str.len() > 0][["timestamp", "source", "destination", "dns_query"]].tail(100)
            if dns_rows.empty:
                st.caption("No DNS query names observed in the current packet view.")
            else:
                st.dataframe(dns_rows, use_container_width=True, hide_index=True)
        st.markdown("**Recent packet metadata**")
        st.dataframe(packet_df.tail(250), use_container_width=True, hide_index=True)
        st.download_button(
            "⬇ Export packet metadata (CSV)", packet_df.to_csv(index=False).encode("utf-8"),
            file_name="logscout_sh_packet_metadata.csv", mime="text/csv", key="ls_tshark_export",
        )
    else:
        st.caption("No packet metadata collected in this session yet. Start a capture and generate ordinary traffic, such as opening a website, on the selected interface.")

with tab_about:
    st.subheader("Detection rules")
    rules = pd.DataFrame([
        {"Rule": "SL-001", "Name": "Possible brute-force login", "Logic": "5+ failed authentication events from one non-placeholder source IP in a 10-minute window", "Default severity": "High"},
        {"Rule": "SL-002", "Name": "Multiple accounts targeted", "Logic": "3+ distinct non-placeholder usernames failed from one IP within 10 minutes", "Default severity": "High"},
        {"Rule": "SL-003", "Name": "Success after repeated failures", "Logic": "Successful login after 3+ failures for the same non-placeholder username and IP within 15 minutes", "Default severity": "High"},
        {"Rule": "SL-004", "Name": "High source event volume", "Logic": "20+ events from one IP within 5 minutes; volume alone is weak evidence", "Default severity": "Low"},
    ])
    st.dataframe(rules, use_container_width=True, hide_index=True)
    st.subheader("CSV format")
    st.code("timestamp,username,source_ip,event_type,status\n2026-10-19T09:00:00Z,alex,192.0.2.10,login,failed\n2026-10-19T09:01:00Z,alex,192.0.2.10,login,success", language="csv")
    st.subheader("Project information")
    st.markdown("""
- **Purpose:** Defensive security log triage and incident investigation.
- **Approach:** Explainable detection heuristics and a transparent source-IP risk-prioritization score; no model is trained and no compromise is automatically confirmed.
- **Privacy:** Uploaded logs are processed by this local application session and are not intentionally sent to an external service.
- **Limitations:** Results depend on log quality and the rules above. The authentication rules focus on login-style logs. The separate Network Monitor can open the Wireshark desktop GUI or use TShark for local live packet metadata; packet rows are not merged into login detections.
- **Recommended workflow:** Review the alert, validate evidence, correlate other sources, and follow your organization's incident response process.
""")

st.markdown("---")
st.caption("LogScout-SH · Educational defensive security project · Windows Security polling and Wireshark/TShark network analysis are separate modules. Live capture requires TShark/Npcap and appropriate permissions. Use only on systems and networks you are authorized to monitor.")
