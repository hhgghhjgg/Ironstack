#!/usr/bin/env python3
"""
Unit tests for IronStack Scanner module (ironstack/attack/scanner.py).
Covers PortScanner, WebVulnerabilityScanner, SQLInjectionScanner, and the main Scanner class.
"""

import sys
import os
import pytest
import json
import socket
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ironstack.attack.scanner import (
    Scanner,
    PortScanner,
    WebVulnerabilityScanner,
    SQLInjectionScanner,
    ScanResult,
    Vulnerability,
    COMMON_PORTS,
    WEB_VULNERABILITY_CHECKS,
)
from ironstack.exceptions import IronStackScanError, ScanFailedError


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def scanner():
    """Return a Scanner instance with short timeouts for testing."""
    return Scanner(timeout=5, threads=2, max_depth=1, rate_limit=100)


@pytest.fixture
def port_scanner():
    return PortScanner(timeout=0.5, threads=5)


@pytest.fixture
def web_scanner():
    return WebVulnerabilityScanner(timeout=5, max_depth=1, rate_limit=100)


@pytest.fixture
def sample_scan_result():
    result = ScanResult("https://example.com", "web")
    result.add_vulnerability(Vulnerability(
        vuln_type="xss",
        severity="high",
        title="Test XSS",
        description="A test vulnerability",
        location="https://example.com/search?q=<script>",
        evidence="<script> reflected",
        remediation="Sanitize input",
    ))
    result.finalize()
    return result


# ============================================================
# Vulnerability Class Tests
# ============================================================

class TestVulnerability:
    def test_create_vulnerability(self):
        vuln = Vulnerability(
            vuln_type="sql_injection",
            severity="critical",
            title="SQLi Found",
            description="SQL injection in login form",
            location="https://example.com/login",
            evidence="Error: SQL syntax",
            remediation="Use prepared statements",
            cvss_score=9.8,
        )
        assert vuln.vuln_type == "sql_injection"
        assert vuln.severity == "critical"
        assert vuln.cvss_score == 9.8

    def test_to_dict(self):
        vuln = Vulnerability(
            vuln_type="xss",
            severity="medium",
            title="XSS",
            description="Reflected XSS",
            location="/search",
        )
        d = vuln.to_dict()
        assert d["type"] == "xss"
        assert d["severity"] == "medium"
        assert "timestamp" in d


# ============================================================
# ScanResult Class Tests
# ============================================================

class TestScanResult:
    def test_initialization(self):
        result = ScanResult("https://example.com", "web")
        assert result.target == "https://example.com"
        assert result.risk_score == 0
        assert len(result.vulnerabilities) == 0

    def test_add_vulnerability_updates_risk(self):
        result = ScanResult("target", "web")
        result.add_vulnerability(Vulnerability(
            vuln_type="critical_vuln", severity="critical", title="C", description="...", location="/"
        ))
        assert result.risk_score > 0
        assert result.risk_score == 25  # critical = 25

    def test_severity_counts(self):
        result = ScanResult("target", "web")
        result.add_vulnerability(Vulnerability("t", "critical", "C", "d", "/"))
        result.add_vulnerability(Vulnerability("t", "high", "H", "d", "/"))
        result.add_vulnerability(Vulnerability("t", "high", "H2", "d", "/"))
        result.finalize()
        data = result.to_dict()
        assert data["severity_counts"]["critical"] == 1
        assert data["severity_counts"]["high"] == 2
        assert data["severity_counts"]["medium"] == 0

    def test_duration_calculated(self):
        result = ScanResult("target", "web")
        result.finalize()
        assert result.end_time is not None
        assert result.to_dict()["duration_seconds"] is not None


# ============================================================
# PortScanner Tests
# ============================================================

class TestPortScanner:
    def test_scan_closed_port(self, port_scanner):
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1  # non-zero = closed
            mock_socket.return_value = mock_sock
            results = port_scanner.scan("127.0.0.1", ports=[54321])
            assert len(results) == 0

    def test_scan_open_port(self, port_scanner):
        with patch("socket.socket") as mock_socket:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0 