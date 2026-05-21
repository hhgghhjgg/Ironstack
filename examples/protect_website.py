#!/usr/bin/env python3
"""
IronStack – Website Protection Example
========================================
Shows how to protect a live web application with IronStack.

Two engines are demonstrated:
  1. Python WAF  (no external dependencies, ~100 built‑in rules)
  2. BunkerWeb    (Docker‑based, 200+ OWASP CRS v4 rules)

Run from the project root:
    python examples/protect_website.py
"""

import os
import sys
import json
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import IronStack
from ironstack.defense import WAF, Crypto, Monitor
from ironstack.exceptions import WAFConfigurationError


def banner(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


# ============================================================
# Configuration – adjust these to match your real backend
# ============================================================
TARGET_URL = "http://localhost:8000"   # your application (Flask, Django, etc.)
WAF_PORT = 8080                         # port that the WAF will listen on

# ============================================================
# 1. Python WAF engine (lightweight, ~100 regex rules)
# ============================================================
banner("1. Python WAF Engine")

print(f"Starting Python WAF on port {WAF_PORT} …")
print(f"Protecting backend: {TARGET_URL}")

waf_py = WAF(engine="python", mode="normal")
waf_py.start(port=WAF_PORT)

# Simulate a few requests to show the WAF in action
print("\nSimulating traffic …")
normal = {
    "method": "GET",
    "path": "/",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "body": "",
    "query_params": {},
    "ip": "192.168.1.10",
}
sqli = {
    "method": "POST",
    "path": "/login",
    "headers": {},
    "body": "user=admin' OR '1'='1 --",
    "query_params": {},
    "ip": "10.0.0.5",
}
xss = {
    "method": "POST",
    "path": "/search",
    "headers": {},
    "body": "<script>alert('xss')</script>",
    "query_params": {},
    "ip": "10.0.0.6",
}

for req, label in [(normal, "Normal GET /"), (sqli, "SQL Injection"), (xss, "XSS attempt")]:
    r = waf_py.check_request(req)
    status = "ALLOWED" if r["allowed"] else "BLOCKED"
    print(f"  {label:20s} → {status}   (score: {r['score']})")

# Show WAF statistics
stats = waf_py.get_stats()
print(f"\nPython WAF stats: {json.dumps(stats, indent=2, default=str)[:500]}")

waf_py.stop()
print("✅ Python WAF example completed.\n")


# ============================================================
# 2. BunkerWeb engine (200+ OWASP CRS rules, requires Docker)
# ============================================================
banner("2. BunkerWeb WAF Engine (OWASP CRS v4)")

try:
    from ironstack.defense.bunkerweb_connector import BunkerWebConnector
    BUNKERWEB_AVAILABLE = True
except ImportError:
    BUNKERWEB_AVAILABLE = False

if BUNKERWEB_AVAILABLE:
    bw = BunkerWebConnector(target_url=TARGET_URL, listen_port=WAF_PORT)
    if bw.is_available():
        print("Docker detected. Launching BunkerWeb …")
        print(f"  Listen: 0.0.0.0:{WAF_PORT}")
        print(f"  Backend: {TARGET_URL}")
        print(f"  Rules:   OWASP CRS v4 (200+ rules)")
        print(f"  Features: ModSecurity + Rate Limiting + Bad Behavior detection")

        bw.start()

        print("\nBunkerWeb is running.")
        print("All HTTP traffic reaching port 8080 will be filtered by the full OWASP CRS.")
        print("Press Ctrl+C to stop …")

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down BunkerWeb …")
        finally:
            bw.stop()
    else:
        print("Docker is not running or not installed.")
        print("Please start Docker and run:  pip install docker")
else:
    print("The 'docker' Python package is not installed.")
    print("Install it with:  pip install docker")
print("✅ BunkerWeb example completed.\n")


# ============================================================
# 3. Additional layers you can enable
# ============================================================
banner("3. Additional Security Layers")

print("IronStack can also enable:")
print("  • Crypto      – encrypt API responses, pin certificates")
print("  • Monitor     – auto‑block attackers via Fail2ban integration")
print("  • Rate Limiting – already built into the WAF")
print()
print("Example: enabling Crypto + Monitor alongside WAF")

# Create a full-stack IronStack instance
full_stack = IronStack(mode="defense")

# Crypto layer
crypto = Crypto()
api_key = crypto.generate_api_key()
print(f"  Generated API key: {api_key}")

# Monitor layer
monitor = Monitor()
monitor.block_ip("10.99.99.99", duration=3600)
blocked = monitor.get_blocked_ips()
print(f"  Manually blocked IPs: {[b['ip'] for b in blocked]}")

print("\n✅ Full-stack protection ready!\n")


# ============================================================
# 4. Quick summary
