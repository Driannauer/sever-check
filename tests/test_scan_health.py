"""Regression checks for misleading health results and report publication."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import mock_open, patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/scan_health.py"
spec = importlib.util.spec_from_file_location("scan_health", SCRIPT)
scan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan)


def result(stdout="", ok=True, **extra):
    return {"available": True, "ok": ok, "returncode": 0 if ok else 1,
            "stdout": stdout, "stderr": "", **extra}


def healthy_data():
    return {"metrics": {
        "cpu": {"usage_percent": 20.0, "load_1m": 0.2, "logical_cpus": 4},
        "memory": {"used_percent": 20.0, "swap_total_bytes": 0, "swap_used_percent": None},
        "disks": [{"mount": "/", "used_percent": 20.0, "inode_used_percent": 2.0}],
        "disk_commands": {}, "processes": {"zombie_count": 0},
        "services": {"systemd_manager_available": True, "system_state": "running", "failed_count": 0},
        "network": {}, "journal": {"available": True, "observed_count": 0},
    }}


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.args = scan.parse_args([])
        self.data = healthy_data()

    def findings(self):
        return scan.classify(self.data, self.args)

    def test_measured_healthy_metrics(self):
        self.assertEqual(self.findings(), [])

    def test_missing_core_metrics_warn(self):
        for section, key in (("cpu", "usage_percent"), ("cpu", "load_1m"), ("memory", "used_percent"), ("processes", "zombie_count")):
            with self.subTest(section=section, key=key):
                self.data = healthy_data()
                self.data["metrics"][section][key] = None
                self.assertTrue(any(f["category"] == "coverage" for f in self.findings()))

    def test_threshold_boundaries(self):
        for value, severity in ((84.9, None), (85, "warning"), (95, "critical")):
            with self.subTest(value=value):
                self.data["metrics"]["cpu"]["usage_percent"] = value
                self.assertEqual([f["severity"] for f in self.findings()], [severity] if severity else [])

    def test_inode_unavailable_is_not_not_applicable(self):
        self.data["metrics"]["disks"][0]["inode_used_percent"] = None
        self.assertTrue(self.findings())
        self.data["metrics"]["disks"][0]["inode_applicable"] = False
        self.assertEqual(self.findings(), [])

    def test_failed_and_truncated_disk_collection_warn(self):
        for status in ({"ok": False}, {"ok": True, "truncated": True}):
            self.data["metrics"]["disk_commands"] = {"inode": status}
            self.assertTrue(any(f["category"] == "coverage" for f in self.findings()))

    def test_user_service_failure_is_detected(self):
        self.data["metrics"]["services"]["user"] = {"failed_count": 1}
        self.assertTrue(any(f["category"] == "service" for f in self.findings()))

    def test_inactive_openclaw_unit_warns(self):
        self.data["metrics"]["services"]["user"] = {"openclaw_units": ["openclaw-gateway.service loaded inactive dead Gateway"]}
        self.assertTrue(any(f["evidence"].get("unit") == "openclaw-gateway.service" for f in self.findings()))

    def test_unknown_systemd_state_does_not_prove_outage(self):
        self.data["metrics"]["services"]["system_state"] = "unknown"
        self.assertFalse(any(f["severity"] == "critical" for f in self.findings()))

    def test_high_priority_single_log_needs_review(self):
        self.data["metrics"]["journal"].update(observed_count=1, sample_by_priority={"0": 1})
        self.assertEqual([f["severity"] for f in self.findings()], ["warning"])

    def test_failed_journal_is_not_healthy(self):
        self.data["metrics"]["journal"].update(available=False, observed_count=None, coverage_note="unavailable")
        self.assertTrue(any(f["category"] == "coverage" for f in self.findings()))

    def test_deliberate_skip_retains_coverage_without_outage(self):
        self.data["metrics"]["journal"].update(available=False, observed_count=None, coverage_note="skipped", skipped=True)
        self.assertEqual(self.findings(), [])
        coverage = scan.collect_coverage(self.data["metrics"])
        self.assertEqual(coverage["status"], "partial")

    def test_primary_metric_failure_makes_coverage_partial(self):
        self.data["metrics"]["cpu"]["usage_percent"] = None
        coverage = scan.collect_coverage(self.data["metrics"], self.findings())
        self.assertEqual(coverage["status"], "partial")


class CollectorTests(unittest.TestCase):
    def test_cpu_does_not_double_count_guest_time(self):
        with patch("builtins.open", mock_open(read_data="cpu 100 20 30 400 10 5 5 0 60 10\n")):
            self.assertEqual(scan.parse_proc_stat_cpu(), (570, 410))

    def test_missing_memavailable_is_unknown(self):
        metrics = scan.memory_metrics({"MemTotal": 100, "MemFree": 1})
        self.assertIsNone(metrics["used_percent"])
        self.assertIsNone(metrics["swap_used_percent"])

    def test_memory_uses_available_and_no_swap_is_not_applicable(self):
        metrics = scan.memory_metrics({"MemTotal": 1000, "MemAvailable": 700, "MemFree": 10, "SwapTotal": 0, "SwapFree": 0})
        self.assertEqual(metrics["used_percent"], 30.0)
        self.assertIsNone(metrics["swap_used_percent"])

    def test_df_keeps_space_units_and_non_inode_filesystem(self):
        def fake(cmd, **kwargs):
            if "-Pk" in cmd:
                return result("Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/a 1000 100 900 10% /\n/dev/b 1000 100 900 10% /boot/efi\n")
            return result("Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/a 1000 10 990 1% /\n/dev/b 0 0 0 - /boot/efi\n")
        with patch.object(scan, "run_cmd", side_effect=fake):
            rows = scan.merge_disk_rows({})
        self.assertEqual(rows[0]["total_bytes"], 1024000)
        self.assertEqual(rows[0]["inode_used_percent"], 1.0)
        self.assertFalse(rows[1]["inode_applicable"])

    def test_unparseable_disk_rows_cannot_disappear_silently(self):
        statuses = {}
        with patch.object(scan, "run_cmd", return_value=result("Filesystem header\n/dev/a 100 10 90 10% /\n/dev/b 100 99 1 ? /data\n")):
            rows = scan.parse_df("space", statuses)
        self.assertEqual(len(rows), 1)
        self.assertEqual(statuses["space"]["parse_errors"], 1)

    def test_proc_permission_errors_are_unknown(self):
        with patch.object(scan.Path, "iterdir", side_effect=PermissionError("denied")), patch.object(scan, "top_processes", return_value=[]):
            state = scan.process_state()
        self.assertIsNone(state["zombie_count"])
        self.assertIn("coverage_note", state)

    def test_user_manager_is_checked(self):
        calls = []
        def fake(cmd, **kwargs):
            calls.append(cmd)
            if "is-system-running" in cmd:
                return result("running\n")
            if "--user" in cmd and "list-units" in cmd:
                return result("openclaw-gateway.service loaded active running OpenClaw Gateway\n")
            return result()
        with patch.object(scan.shutil, "which", return_value="/bin/systemctl"), patch.object(scan.os.path, "isdir", return_value=True), patch.object(scan.Path, "exists", return_value=True), patch.object(scan, "run_cmd", side_effect=fake):
            services = scan.get_services()
        self.assertTrue(services["user"]["openclaw_units"])
        self.assertTrue(any("--user" in cmd for cmd in calls))

    def test_degraded_nonzero_exit_is_valid_evidence(self):
        metrics = healthy_data()["metrics"]
        metrics["services"].update(system_state="degraded", commands={"system_state": {"ok": False, "returncode": 1}})
        self.assertEqual(scan.collect_coverage(metrics)["status"], "complete")

    def test_listener_scopes_handle_ipv4_ipv6_and_wildcards(self):
        lines = [f"tcp LISTEN 0 128 {address} *:*" for address in ("127.0.0.1:22", "[::1]:22", "[::ffff:127.0.0.1]:23", "0.0.0.0:80", "[::]:443", "*:111", "10.0.0.2:8080")]
        summary = scan.summarize_listeners(lines)
        self.assertEqual(summary["counts_by_bind_scope"], {"loopback": 3, "wildcard": 3, "interface": 1})
        self.assertEqual(len(summary["non_loopback_bindings"]), 4)
        self.assertIn("not_tested", summary["reachability"])

    def test_failed_listener_collection_is_unknown(self):
        with patch.object(scan, "run_cmd", return_value=result(ok=False)):
            network = scan.get_network(False, 80)
        self.assertIsNone(network["listening_ports_total_observed"])
        self.assertIsNone(network["listener_summary"])


class JournalTests(unittest.TestCase):
    def record(self, message="error", priority="3"):
        return json.dumps({"MESSAGE": message, "PRIORITY": priority, "_SYSTEMD_UNIT": "demo.service", "__REALTIME_TIMESTAMP": "123"})

    def collect(self, output, limit=20, **extra):
        with patch.object(scan, "run_cmd", return_value=result(output, **extra)) as runner:
            data = scan.get_journal("24 hours ago", limit)
        self.assertIn("0..3", runner.call_args.args[0])
        return data

    def test_multiline_messages_are_one_record(self):
        data = self.collect(self.record("first\nsecond\nthird"))
        self.assertEqual(data["observed_count"], 1)
        self.assertEqual(data["sample_by_unit"], {"demo.service": 1})
        self.assertFalse(data["count_is_lower_bound"])

    def test_exact_cap_and_overflow_differ(self):
        exact = self.collect("\n".join([self.record()] * 20))
        overflow = self.collect("\n".join([self.record()] * 21))
        self.assertFalse(exact["count_is_lower_bound"])
        self.assertTrue(overflow["count_is_lower_bound"])
        self.assertEqual(overflow["observed_count"], 21)
        self.assertEqual(overflow["sample_count"], 20)

    def test_empty_success_differs_from_denied_or_failed(self):
        self.assertEqual(self.collect("")["observed_count"], 0)
        for status in ({"ok": False, "stderr": "denied"}, {"stderr": "No journal files were found."}):
            with self.subTest(status=status):
                data = self.collect("", **status)
                self.assertIsNone(data["observed_count"])
                self.assertIn("coverage_note", data)

    def test_malformed_and_bounded_output_are_partial(self):
        for output, extra in (("not json", {}), (self.record() + "\n{", {"truncated": True})):
            data = self.collect(output, **extra)
            self.assertFalse(data["coverage_complete"])
            self.assertTrue(data["count_is_lower_bound"])

    def test_log_secret_is_removed_before_excerpt_truncation(self):
        data = self.collect(self.record('password="' + 'SECRET' * 1000 + '"'))
        self.assertNotIn("SECRET", data["entries"][0])


class CommandTests(unittest.TestCase):
    def test_output_is_bounded_on_both_pipes(self):
        res = scan.run_cmd([sys.executable, "-c", "import os; os.write(1,b'x'*300000); os.write(2,b'e'*30000)"], max_chars=128)
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["stdout"]), 128)
        self.assertTrue(res["truncated"])
        self.assertEqual(len(res["stderr"]), 20000)
        self.assertTrue(res["stderr_truncated"])

    def test_timeout_keeps_partial_output_and_stops_collector(self):
        started = time.monotonic()
        res = scan.run_cmd([sys.executable, "-c", "import time; print('partial',flush=True); time.sleep(5)"], timeout=0.2)
        self.assertTrue(res["timed_out"])
        self.assertFalse(res["ok"])
        self.assertIn("partial", res["stdout"])
        self.assertLess(time.monotonic() - started, 2)

    def test_missing_command_is_unavailable(self):
        self.assertFalse(scan.run_cmd(["/nonexistent/scan-collector"])["available"])

    def test_machine_readable_locale(self):
        res = scan.run_cmd([sys.executable, "-c", "import os; print(os.environ['LC_ALL'])"])
        self.assertEqual(res["stdout"].strip(), "C")


class PublicationTests(unittest.TestCase):
    def test_private_atomic_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            target.write_text("old")
            target.chmod(0o644)
            scan.write_report(str(target), '{"fresh":true}')
            self.assertTrue(json.loads(target.read_text())["fresh"])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_symlink_is_rejected_and_target_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_text("keep")
            link = Path(directory) / "link"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                scan.write_report(str(link), "new")
            self.assertEqual(target.read_text(), "keep")

    def test_publish_failure_keeps_old_file_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "report.json"
            target.write_text("old")
            with patch.object(scan.os, "replace", side_effect=OSError("failure")), self.assertRaises(OSError):
                scan.write_report(str(target), "new")
            self.assertEqual(target.read_text(), "old")
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_redaction_covers_credentials_in_nested_metrics(self):
        value = {"a": ["Authorization: Basic aGVsbG86d29ybGQ=", "OPENCLAW_GATEWAY_TOKEN=secretvalue", 'password="space secret"', "https://bob:secretvalue@example.test"], "b": "-----BEGIN PRIVATE KEY-----\nsecretvalue\n-----END PRIVATE KEY-----"}
        rendered = json.dumps(scan.redact_tree(value))
        for secret in ("aGVsbG86d29ybGQ=", "secretvalue", "space secret"):
            self.assertNotIn(secret, rendered)


class ArgumentTests(unittest.TestCase):
    def test_daily_default(self):
        self.assertEqual(scan.parse_args([]).journal_since, "24 hours ago")

    def test_invalid_values_are_rejected_before_collection(self):
        options = [
            ["--disk-warning", "95", "--disk-critical", "90"],
            ["--cpu-warning", "nan"], ["--mem-critical", "101"],
            ["--load-critical-per-cpu", "inf"], ["--cpu-sample-seconds", "0"],
            ["--zombie-warning-count", "0"], ["--max-ports", "0"],
            ["--journal-lines", "0"], ["--journal-lines", "501"],
            ["--journal-warning-count", "101"], ["--journal-since", " "],
        ]
        for args in options:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                scan.parse_args(args)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
