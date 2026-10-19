from __future__ import annotations

from datetime import datetime
from io import StringIO
from pathlib import Path
import hashlib
import json

import pandas as pd
import plotly.express as px
import streamlit as st

APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "data"
SAMPLE_FILE = DATA_DIR / "sample_auth_logs.csv"
REQUIRED_COLUMNS = ["timestamp", "username", "source_ip", "event_type", "status"]

st.set_page_config(page_title="LogScout-SH | SOC Log Analyzer", page_icon="🛡️", layout="wide")

# ---------- Styling ----------
st.markdown("""
<style>
.block-container {padding-top: 1.5rem; padding-bottom: 2rem;}
[data-testid="stMetric"] {background: rgba(100,116,139,.09); padding: 14px 16px; border-radius: 12px; border: 1px solid rgba(100,116,139,.18);}
div[data-testid="stDataFrame"] {border-radius: 10px;}
.small-muted {color: #8b95a7; font-size: .9rem;}
</style>
""", unsafe_allow_html=True)

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
    """Transparent heuristic detections; these are alerts, not proof of compromise."""
    alerts = []
    failed = logs[(logs["status"].isin(["failed", "failure", "denied"])) |
                  (logs["event_type"].str.contains("fail|denied", na=False))].copy()

    # Brute-force: at least 5 failed authentication events from an IP in any 10-minute window.
    for ip, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        for i, start in enumerate(times):
            end = start + pd.Timedelta(minutes=10)
            count = sum(start <= t <= end for t in times[i:])
            if count >= 5:
                matching = group[(group["timestamp"] >= start) & (group["timestamp"] <= end)]
                alerts.append({
                    "timestamp": start, "severity": "High", "rule_id": "SL-001",
                    "alert": "Possible brute-force login", "source_ip": ip,
                    "username": ", ".join(sorted(matching["username"].unique())[:5]),
                    "evidence": f"{len(matching)} failed login events within 10 minutes.",
                    "recommendation": "Validate whether the source is expected; review authentication logs, enforce MFA, and consider temporary rate limiting or blocking according to policy.",
                    "event_count": len(matching),
                })
                break

    # Password spraying / account probing: same IP fails against 3+ distinct usernames.
    for ip, group in failed.groupby("source_ip"):
        unique_users = sorted(set(group["username"]))
        if len(unique_users) >= 3:
            alerts.append({
                "timestamp": group["timestamp"].min(), "severity": "High", "rule_id": "SL-002",
                "alert": "Multiple accounts targeted from one IP", "source_ip": ip,
                "username": ", ".join(unique_users[:8]),
                "evidence": f"Failed authentication events involve {len(unique_users)} distinct usernames.",
                "recommendation": "Check for password spraying or account enumeration; review affected accounts and correlate with other telemetry.",
                "event_count": len(group),
            })

    # Success following repeated failures from same IP and user.
    successes = logs[(logs["status"].isin(["success", "succeeded", "accepted"])) |
                     (logs["event_type"].str.contains("success|accepted", na=False))]
    for _, success in successes.iterrows():
        prior = failed[(failed["source_ip"] == success["source_ip"]) &
                       (failed["username"] == success["username"]) &
                       (failed["timestamp"] <= success["timestamp"]) &
                       (failed["timestamp"] >= success["timestamp"] - pd.Timedelta(minutes=15))]
        if len(prior) >= 3:
            alerts.append({
                "timestamp": success["timestamp"], "severity": "Critical", "rule_id": "SL-003",
                "alert": "Successful login after repeated failures", "source_ip": success["source_ip"],
                "username": success["username"],
                "evidence": f"Successful authentication followed {len(prior)} failed attempts within 15 minutes.",
                "recommendation": "Verify the login with the account owner, inspect session activity and MFA logs, and follow incident-response procedures if unauthorized.",
                "event_count": len(prior) + 1,
            })

    # Unusual event volume: 20+ events from one IP.
    for ip, group in logs.groupby("source_ip"):
        if len(group) >= 20:
            alerts.append({
                "timestamp": group["timestamp"].min(), "severity": "Medium", "rule_id": "SL-004",
                "alert": "High event volume from one source", "source_ip": ip,
                "username": ", ".join(sorted(group["username"].unique())[:5]),
                "evidence": f"{len(group)} events from this source in the loaded dataset.",
                "recommendation": "Check whether this volume matches expected application or user behavior; correlate with network and endpoint logs.",
                "event_count": len(group),
            })

    columns = ["timestamp", "severity", "rule_id", "alert", "source_ip", "username", "evidence", "recommendation", "event_count"]
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
    lines += ["", "DETECTION RULES", "SL-001: 5 or more failed logins from an IP in a 10-minute window.", "SL-002: Failed logins against 3 or more distinct usernames from one IP.", "SL-003: Successful login after 3 or more failures for the same user and IP within 15 minutes.", "SL-004: 20 or more events from one IP in the loaded dataset.", "", "LogScout-SH — defensive triage aid"]
    return "\n".join(lines)

# ---------- Sidebar ----------
st.sidebar.title("🛡️ LogScout-SH")
st.sidebar.caption("SOC Log Analyzer")
st.sidebar.markdown("---")
upload = st.sidebar.file_uploader("Upload authentication logs (CSV)", type=["csv"], help="Required columns: timestamp, username, source_ip, event_type, status")
st.sidebar.markdown("**Expected CSV columns**")
st.sidebar.code(", ".join(REQUIRED_COLUMNS), language="text")
st.sidebar.markdown("---")
st.sidebar.caption("Rule-based detections are triage signals, not proof of an attack.")

# ---------- Load dataset ----------
try:
    logs = load_logs(upload)
except Exception as exc:
    st.error(f"Could not load logs: {exc}")
    st.info("Use the included sample dataset or upload a CSV containing: " + ", ".join(REQUIRED_COLUMNS))
    st.stop()

source_label = logs.attrs.get("source_label", "Dataset")
alerts = detect_threats(logs)

# ---------- Header ----------
st.title("🛡️ LogScout-SH")
st.markdown("**Security Operations Center (SOC) Log Analysis & Incident Triage**")
st.markdown(f"<div class='small-muted'>Data source: {source_label} · Last event: {logs['timestamp'].max().strftime('%Y-%m-%d %H:%M UTC') if not logs.empty else 'N/A'}</div>", unsafe_allow_html=True)
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

# ---------- Main dashboard ----------
tab_overview, tab_alerts, tab_events, tab_report, tab_about = st.tabs(["📊 Overview", "🚨 Alerts & Investigation", "🧾 Event Explorer", "📄 Reports", "ℹ️ About & Rules"])

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

with tab_report:
    st.subheader("Investigation report")
    report = build_report(logs, alerts, source_label)
    st.markdown("Create a text report for the complete loaded dataset, including rule explanations and recommended actions.")
    st.download_button("⬇️ Download investigation report (.txt)", report, file_name="logscout_sh_investigation_report.txt", mime="text/plain", type="primary")
    st.download_button("⬇️ Download detected alerts (.csv)", alerts.to_csv(index=False).encode("utf-8"), file_name="logscout_sh_alerts.csv", mime="text/csv")
    with st.expander("Preview report"):
        st.text(report)

with tab_about:
    st.subheader("Detection rules")
    rules = pd.DataFrame([
        {"Rule": "SL-001", "Name": "Possible brute-force login", "Logic": "5+ failed login events from one IP in a 10-minute window", "Default severity": "High"},
        {"Rule": "SL-002", "Name": "Multiple accounts targeted", "Logic": "Failed logins against 3+ distinct usernames from one IP", "Default severity": "High"},
        {"Rule": "SL-003", "Name": "Success after repeated failures", "Logic": "Successful login after 3+ failures for the same username and IP within 15 minutes", "Default severity": "Critical"},
        {"Rule": "SL-004", "Name": "High source event volume", "Logic": "20+ events from one IP in the loaded dataset", "Default severity": "Medium"},
    ])
    st.dataframe(rules, use_container_width=True, hide_index=True)
    st.subheader("CSV format")
    st.code("timestamp,username,source_ip,event_type,status\n2026-10-19T09:00:00Z,alex,192.0.2.10,login,failed\n2026-10-19T09:01:00Z,alex,192.0.2.10,login,success", language="csv")
    st.subheader("Project information")
    st.markdown("""
- **Purpose:** Defensive security log triage and incident investigation.
- **Approach:** Explainable heuristics; no model is trained and no compromise is automatically confirmed.
- **Privacy:** Uploaded logs are processed by this local application session and are not intentionally sent to an external service.
- **Limitations:** Results depend on log quality and the rules above. The current version focuses on authentication-style CSV data, not full packet inspection or live monitoring.
- **Recommended workflow:** Review the alert, validate evidence, correlate other sources, and follow your organization's incident response process.
""")

st.markdown("---")
st.caption("LogScout-SH · Educational defensive security project · Use only on systems and data you are authorized to analyze.")
