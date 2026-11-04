import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from network_monitor.alerts import HostAlertTracker
from network_monitor.models import Host, HostSummary, ProbeResult
from network_monitor.notifications import notify
from network_monitor.preferences import (
    Preferences,
    load_preferences,
    save_preferences,
)
from network_monitor.probes import probe_host
from network_monitor.reporting import export_pdf
from network_monitor.scanner import parse_scan_network, reverse_lookup, scan_network
from network_monitor.storage import MonitorDatabase
from network_monitor.ui import MonitorApp, validate_address


class AddressValidationTests(unittest.TestCase):
    def test_accepts_ip_addresses_and_hostnames(self) -> None:
        for address in ("127.0.0.1", "::1", "example.com", "nas.home."):
            with self.subTest(address=address):
                self.assertTrue(validate_address(address))

    def test_rejects_urls_and_invalid_hostnames(self) -> None:
        for address in ("", "https://example.com", "bad host", "-bad.example"):
            with self.subTest(address=address):
                self.assertFalse(validate_address(address))

    def test_host_latency_formats_minimum_average_and_maximum(self) -> None:
        summary = HostSummary(
            "router.local",
            443,
            samples=8,
            successes=7,
            loss_percent=12.5,
            average_ms=3.45,
            minimum_ms=1.2,
            maximum_ms=9.8,
        )

        self.assertEqual(MonitorApp._format_latency_range(summary), "1.2 / 3.5 / 9.8 ms")


class AlertTests(unittest.TestCase):
    def test_alerts_only_emit_on_down_and_recovery_transitions(self) -> None:
        tracker = HostAlertTracker(failure_threshold=2)
        self.assertIsNone(tracker.record(1, False))
        self.assertEqual(tracker.record(1, False), "offline")
        self.assertIsNone(tracker.record(1, False))
        self.assertEqual(tracker.record(1, True), "recovered")
        self.assertIsNone(tracker.record(1, True))

    def test_windows_notification_uses_toast_backend(self) -> None:
        with (
            patch("network_monitor.notifications.sys.platform", "win32"),
            patch("winotify.Notification") as toast,
        ):
            notify("Host is offline", "No response")

        toast.assert_called_once_with(
            app_id="Network Monitor",
            title="Host is offline",
            msg="No response",
        )
        toast.return_value.show.assert_called_once_with()


class PreferencesTests(unittest.TestCase):
    def test_preferences_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "settings.json"
            preferences = Preferences(
                poll_interval_seconds=7,
                stats_window_hours=12,
                graph_window_hours=48,
                report_window_hours=72,
                graph_host_ids=[2, 4],
                alerts_enabled=False,
                alert_failure_threshold=3,
            )

            save_preferences(path, preferences)

            self.assertEqual(load_preferences(path), preferences)

    def test_preferences_reject_out_of_range_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "settings.json"
            path.write_text('{"poll_interval_seconds": 0}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_preferences(path)


class ProbeTests(unittest.TestCase):
    def test_automatic_mode_falls_back_to_tcp(self) -> None:
        host = Host(1, "example.com", 443)
        with (
            patch("network_monitor.probes._icmp_probe", return_value=(False, None, "blocked")),
            patch("network_monitor.probes._tcp_probe", return_value=(True, 12.5, "connected")),
        ):
            result = probe_host(host)
        self.assertTrue(result.success)
        self.assertEqual(result.method, "TCP fallback")
        self.assertEqual(result.latency_ms, 12.5)

    def test_icmp_mode_does_not_fall_back(self) -> None:
        host = Host(1, "example.com", 443)
        with (
            patch("network_monitor.probes._icmp_probe", return_value=(False, None, "blocked")),
            patch("network_monitor.probes._tcp_probe") as tcp_probe,
        ):
            result = probe_host(host, mode="icmp")
        tcp_probe.assert_not_called()
        self.assertFalse(result.success)
        self.assertEqual(result.method, "ICMP")


class ScannerTests(unittest.TestCase):
    def test_scanner_accepts_bounded_rfc1918_networks(self) -> None:
        network = parse_scan_network("192.168.1.17/24")
        self.assertEqual(str(network), "192.168.1.0/24")

    def test_scanner_rejects_public_and_oversized_networks(self) -> None:
        for value in ("8.8.8.0/24", "10.0.0.0/16", "2001:db8::/64"):
            with self.subTest(network=value):
                with self.assertRaises(ValueError):
                    parse_scan_network(value)

    def test_scanner_lists_only_icmp_responders(self) -> None:
        def fake_probe(address: str, _timeout: float) -> tuple[bool, float | None, str]:
            return address.endswith(".1"), 2.0, "test"

        with patch("network_monitor.scanner._icmp_probe", side_effect=fake_probe):
            results = scan_network("192.168.1.0/30", max_workers=1)
        self.assertEqual([result.address for result in results], ["192.168.1.1"])

    def test_reverse_lookup_resolves_ip_address(self) -> None:
        with patch("network_monitor.scanner.gethostbyaddr", return_value=("router.local.", [], [])):
            self.assertEqual(reverse_lookup("192.168.1.1"), "router.local")


class StorageTests(unittest.TestCase):
    def test_add_hosts_adds_multiple_and_skips_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            database.add_host("192.168.1.1", 443)

            added, skipped = database.add_hosts(
                ["192.168.1.1", "192.168.1.2", "192.168.1.3"], 443
            )

            self.assertEqual([host.address for host in added], ["192.168.1.2", "192.168.1.3"])
            self.assertEqual(skipped, 1)
            self.assertEqual(len(database.list_hosts()), 3)
            database.close()

    def test_persists_samples_and_summarizes_availability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            host = database.add_host("example.com", 443)
            now = datetime.now(timezone.utc)
            database.record_sample(
                host, ProbeResult(True, 10.0, "ICMP", "reply", now)
            )
            database.record_sample(
                host, ProbeResult(False, None, "ICMP + TCP", "timeout", now)
            )

            samples = database.recent_samples(host_id=host.id)
            summary = database.summaries()[0]

            self.assertEqual(len(samples), 2)
            self.assertEqual(summary.samples, 2)
            self.assertEqual(summary.successes, 1)
            self.assertEqual(summary.loss_percent, 50.0)
            self.assertEqual(summary.average_ms, 10.0)
            self.assertEqual(database.packet_loss(host.id), 50.0)
            database.close()

    def test_summaries_respect_selected_time_window(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            host = database.add_host("example.com", 443)
            now = datetime.now(timezone.utc)
            database.record_sample(
                host,
                ProbeResult(
                    False,
                    None,
                    "ICMP",
                    "older failure",
                    now - timedelta(hours=2),
                ),
            )
            database.record_sample(
                host, ProbeResult(True, 12.0, "ICMP", "reply", now)
            )

            summary = database.summaries(now - timedelta(hours=1))[0]

            self.assertEqual(summary.samples, 1)
            self.assertEqual(summary.successes, 1)
            self.assertEqual(summary.loss_percent, 0.0)
            self.assertEqual(summary.average_ms, 12.0)
            database.close()

    def test_chart_samples_are_grouped_per_host(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            first = database.add_host("192.168.1.1", 443)
            second = database.add_host("192.168.1.2", 443)
            now = datetime.now(timezone.utc)
            database.record_sample(
                first, ProbeResult(True, 10.0, "ICMP", "reply", now)
            )
            database.record_sample(
                second, ProbeResult(True, 20.0, "ICMP", "reply", now)
            )

            samples = database.chart_samples()

            self.assertEqual(set(samples), {first.id, second.id})
            self.assertEqual(samples[first.id][0].latency_ms, 10.0)
            self.assertEqual(samples[second.id][0].latency_ms, 20.0)
            database.close()

    def test_chart_samples_respect_selected_period(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            host = database.add_host("192.168.1.1", 443)
            now = datetime.now(timezone.utc)
            database.record_sample(
                host,
                ProbeResult(
                    True,
                    5.0,
                    "ICMP",
                    "old",
                    now - timedelta(hours=3),
                ),
            )
            database.record_sample(
                host, ProbeResult(True, 10.0, "ICMP", "recent", now)
            )

            samples = database.chart_samples(since=now - timedelta(hours=1))

            self.assertEqual([sample.latency_ms for sample in samples[host.id]], [10.0])
            database.close()

    def test_chart_downsampling_preserves_full_time_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            host = database.add_host("192.168.1.1", 443)
            now = datetime.now(timezone.utc)
            for index in range(100):
                database.record_sample(
                    host,
                    ProbeResult(
                        True,
                        float(index),
                        "ICMP",
                        "reply",
                        now - timedelta(minutes=99 - index),
                    ),
                )

            samples = database.chart_samples(limit_per_host=10)[host.id]

            self.assertLessEqual(len(samples), 11)
            self.assertEqual(samples[0].latency_ms, 0.0)
            self.assertEqual(samples[-1].latency_ms, 99.0)
            database.close()

    def test_exports_pdf_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            database = MonitorDatabase(Path(temporary_directory) / "history.sqlite3")
            database.add_host("example.com", 443)
            output_path = Path(temporary_directory) / "report.pdf"
            export_pdf(database.summaries(), output_path, period_hours=12)
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))
            with self.assertRaises(ValueError):
                export_pdf(database.summaries(), output_path, period_hours=0)
            database.close()


if __name__ == "__main__":
    unittest.main()
