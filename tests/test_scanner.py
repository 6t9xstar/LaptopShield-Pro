"""Unit tests for scanner & telemetry classification."""

from __future__ import annotations

from laptopshield.core.scanner import _classify_connection, scan_hosts_file


def test_classify_connection_flags_remote_tool():
    assert _classify_connection("RustDesk.exe", r"C:\Program Files\RustDesk\rustdesk.exe", "1.2.3.4", 443) == "HIGH"


def test_classify_connection_flags_temp_binary():
    assert _classify_connection("updater.exe", r"C:\Users\dell\AppData\Local\Temp\updater.exe", "8.8.8.8", 443) == "HIGH"


def test_classify_connection_medium_nonstandard_port():
    assert _classify_connection("python.exe", r"C:\Python311\python.exe", "45.33.32.156", 4444) == "MEDIUM"


def test_classify_connection_low_standard_https():
    assert _classify_connection("chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe", "142.250.1.1", 443) == "LOW"


def test_scan_hosts_file_ignores_comments(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("# comment\n\n127.0.0.1 evil.local\n", encoding="utf-8")
    entries = scan_hosts_file(str(hosts))
    assert entries == ["127.0.0.1 evil.local"]
