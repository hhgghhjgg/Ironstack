#!/usr/bin/env python3
"""
Unit tests for IronStack WAF module (ironstack/defense/waf.py).
Covers Python engine, BunkerWeb connector, and auto‑selection logic.
"""

import sys
import os
import pytest
import time
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ironstack.defense.waf import (
    WAF,
    WAFRule,
    WAFRateLimiter,
    WAFRequestChecker,
    BunkerWebConnector,
    DEFAULT_WAF_RULES,
)
from ironstack.exceptions import WAFConfigurationError, WAFError


# ============================================================
# Helper – build a minimal request dict
# ============================================================
def req(**kwargs):
    """Return a minimal HTTP request dictionary with defaults."""
    base = {
        "method": "GET",
        "path": "/",
        "headers": {"User-Agent": "Mozilla/5.0"},
        "body": "",
        "query_params": {},
        "ip": "192.168.1.10",
    }
    base.update(kwargs)
    return base


# ============================================================
# Python Engine – Request Checking
# ============================================================
class TestPythonEngine:
    """Tests for the built‑in Python WAF engine."""

    @pytest.fixture
    def waf(self):
        return WAF(engine="python", mode="normal")

    def test_normal_request_allowed(self, waf):
        result = waf.check_request(req(method="GET", path="/home"))
        assert result["allowed"] is True
        assert result["action"] == "allow"

    def test_sql_injection_blocked(self, waf):
        result = waf.check_request(
            req(method="POST", path="/login", body="username=admin' OR '1'='1 --")
        )
        assert result["allowed"] is False
        assert any(
            "sql_injection" in r["category"] for r in result["matched_rules"]
        )

    def test_xss_blocked(self, waf):
        result = waf.check_request(
            req(method="POST", path="/comment", body="<script>alert(1)</script>")
        )
        assert result["allowed"] is False
        assert any("xss" in r["category"] for r in result["matched_rules"])

    def test_path_traversal_blocked(self, waf):
        result = waf.check_request(
            req(method="GET", path="/download", query_params={"file": "../../../etc/passwd"})
        )
        assert result["allowed"] is False

    def test_command_injection_blocked(self, waf):
        result = waf.check_request(
            req(method="GET", path="/ping", query_params={"host": "127.0.0.1; ls -la"})
        )
        assert result["allowed"] is False

    def test_scanner_user_agent_blocked(self, waf):
        result = waf.check_request(
            req(method="GET", path="/", headers={"User-Agent": "sqlmap/1.6#stable"})
        )
        assert result["allowed"] is False

    def test_ip_whitelist(self, waf):
        waf.config["ip_whitelist"] = ["10.0.0.1"]
        # Even with a malicious payload, whitelisted IP should be allowed
        result = waf.check_request(
            req(method="POST", path="/login", body="' OR 1=1 --", ip="10.0.0.1")
        )
        assert result["allowed"] is True

    def test_ip_blacklist(self, waf):
        waf.config["ip_blacklist"] = ["10.0.0.2"]
        result = waf.check_request(req(ip="10.0.0.2"))
        assert result["allowed"] is False

    def test_http_method_not_allowed(self, waf):
        result = waf.check_request(req(method="TRACE"))
        assert result["allowed"] is False

    def test_rate_limiting(self, waf):
        waf.config["rate_limiting"]["enabled"] = True
        waf.config["rate_limiting"]["max_requests"] = 5
        waf.config["rate_limiting"]["time_window"] = 1  # 1 second
        waf.config["rate_limiting"]["burst"] = 2
        ip = "192.168.1.100"
        for _ in range(8):
            r = waf.check_request(req(ip=ip))
        # The 8th should be blocked because 5+2 burst exceeded
        assert r["allowed"] is False

    def test_body_too_large(self, waf):
        waf.config["max_body_size"] = 10
        result = waf.check_request(req(body="A" * 100))
        assert result["allowed"] is False

    def test_missing_required_fields_raises(self, waf):
        with pytest.raises(WAFError):
            waf.check_request({"method": "GET"})  # no path, headers

    def test_disabled_waf(self, waf):
        waf.config["enabled"] = False
        result = waf.check_request(req(body="<script>"))
        assert result["allowed"] is True


# ============================================================
# Python Engine – Rule Management
# ============================================================
class TestRuleManagement:
    """Tests for adding/removing rules."""

    @pytest.fixture
    def waf(self):
        return WAF(engine="python")

    def test_add_custom_rule(self, waf):
        initial_count = len(waf.rules)
        waf.add_rule("TEST", r"test_patte