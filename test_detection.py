"""Offline regression tests for LogScout-SH's log loader and detection rules."""
import ast
import io
import unittest
from datetime import datetime
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "app.py"
TREE = ast.parse(APP_PATH.read_text(encoding="utf-8"))
FUNCTIONS = {"load_logs", "detect_threats", "build_report"}
NODES = [n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name in FUNCTIONS]
NAMESPACE = {
    "pd": pd,
    "datetime": datetime,
    "Path": Path,
    "APP_DIR": ROOT,
    "DATA_DIR": ROOT / "data",
    "SAMPLE_FILE": ROOT / "data" / "sample_auth_logs.csv",
    "REQUIRED_COLUMNS": ["timestamp", "username", "source_ip", "event_type", "status"],
}
exec(compile(ast.Module(body=NODES, type_ignores=[]), str(APP_PATH), "exec"), NAMESPACE)
load_logs = NAMESPACE["load_logs"]
detect_threats = NAMESPACE["detect_threats"]
build_report = NAMESPACE["build_report"]

class NamedStringIO(io.StringIO):
    name = "test.csv"

class LogScoutSHTests(unittest.TestCase):
    def make_logs(self):
        base = pd.Timestamp("2026-10-19T10:00:00Z")
        rows = []
        def add(minutes, username, ip, status):
            rows.append({"timestamp": base + pd.Timedelta(minutes=minutes), "username": username,
                         "source_ip": ip, "event_type": "login", "status": status})
        for m in range(5): add(m, "brute", "198.51.100.10", "failed")
        for m, user in enumerate(["spray1", "spray2", "spray3"]): add(m, user, "198.51.100.20", "failed")
        for m in range(3): add(m, "compromised", "198.51.100.30", "failed")
        add(4, "compromised", "198.51.100.30", "success")
        for m in range(20): add(m, "volume", "198.51.100.40", "success")
        return pd.DataFrame(rows)

    def test_sample_dataset_loads_and_triggers_expected_rules(self):
        logs = load_logs()
        alerts = detect_threats(logs)
        self.assertEqual(len(logs), 38)
        self.assertEqual(set(alerts["rule_id"]), {"SL-001", "SL-002", "SL-003", "SL-004"})

    def test_all_four_rules_trigger_on_controlled_synthetic_data(self):
        alerts = detect_threats(self.make_logs())
        self.assertTrue({"SL-001", "SL-002", "SL-003", "SL-004"}.issubset(set(alerts["rule_id"])))

    def test_multi_user_alert_related_rows_include_all_accounts(self):
        logs = self.make_logs()
        alert = detect_threats(logs).query("rule_id == 'SL-002'").iloc[0]
        users = {u.strip() for u in alert["username"].split(",") if u.strip()}
        related = logs[(logs["source_ip"] == alert["source_ip"]) & logs["username"].isin(users)]
        self.assertEqual(len(users), 3)
        self.assertEqual(len(related), 3)

    def test_bad_columns_produce_clear_validation_error(self):
        data = NamedStringIO("foo,bar\n1,2\n")
        with self.assertRaisesRegex(ValueError, "Missing required column"):
            load_logs(data)

    def test_empty_csv_produces_clear_validation_error(self):
        data = NamedStringIO("")
        with self.assertRaisesRegex(ValueError, "CSV is empty"):
            load_logs(data)

    def test_invalid_timestamps_produce_clear_validation_error(self):
        data = NamedStringIO("timestamp,username,source_ip,event_type,status\nnot-a-date,a,192.0.2.1,login,failed\n")
        with self.assertRaisesRegex(ValueError, "No valid log timestamps"):
            load_logs(data)

    def test_report_includes_rule_details_and_limitations(self):
        logs = self.make_logs()
        alerts = detect_threats(logs)
        report = build_report(logs, alerts, "synthetic test")
        self.assertIn("SCOPE AND LIMITATIONS", report)
        self.assertIn("SL-001", report)
        self.assertIn("Recommended action", report)

if __name__ == "__main__":
    unittest.main(verbosity=2)
