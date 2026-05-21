#!/usr/bin/env python3
"""
IronStack – Basic Usage Examples
=================================
This script demonstrates the most common use‑cases of IronStack.
Run it from the project root:

    python examples/basic_usage.py

Sections:
    1. Protecting a web endpoint (WAF – Python engine)
    2. Protecting Python source code
    3. Quick security scan
    4. Cryptographic operations
    5. [Optional] BunkerWeb (200+ OWASP rules)
    6. [Optional] Game Anti‑Cheat
"""

import os
import sys
import json
from pathlib import Path

# Allow running from the project root without installing the package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import IronStack
from ironstack.defense import WAF, CodeProtector, Crypto
from ironstack.attack import Scanner

# Optional – only work when Docker / extra deps are available
try:
    from ironstack.defense import AntiCheat
    ANTI_CHEAT_AVAILABLE = True
except ImportError:
    ANTI_CHEAT_AVAILABLE = False

try:
    from ironstack.defense.bunkerweb_connector import BunkerWebConnector
    BUNKERWEB_AVAILABLE = True
except ImportError:
    BUNKERWEB_AVAILABLE = False


def banner(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


# ============================================================
# 1. Web Application Firewall (Python engine)
# ============================================================
banner("1. Web Application Firewall (Python engine)")

waf = WAF(engine="python", mode="normal")

# Simulate a normal request
normal = {
    "method": "GET",
    "path": "/home",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "body": "",
    "query_params": {},
    "ip": "192.168.1.10",
}
result = waf.check_request(normal)
print(f" Normal request → allowed: {result['allowed']}")

# Simulate an SQL injection attempt
malicious = {
    "method": "POST",
    "path": "/login",
    "headers": {"User-Agent": "Mozilla/5.0"},
    "body": "user=admin' OR '1'='1 --",
    "query_params": {},
    "ip": "10.0.0.5",
}
result = waf.check_request(malicious)
print(f" SQLi attempt → allowed: {result['allowed']}")
if not result["allowed"]:
    print(f"   Matched rules: {result['matched_rules'][:2]}")

print("✅ WAF example completed.\n")


# ============================================================
# 2. Code Protection
# ============================================================
banner("2. Code Protection (PyArmor / built‑in)")

# Create a temporary Python file for demo purposes
demo_dir = Path("demo_project")
demo_dir.mkdir(exist_ok=True)
demo_file = demo_dir / "hello.py"
demo_file.write_text("print('Hello from protected code!')")

protector = CodeProtector(mode="normal")
result = protector.protect(str(demo_dir), output_dir="demo_protected")
print(f" Files protected: {result.get('files_protected', 0)}")
print(f" Output: demo_protected/")

# Cleanup
import shutil
shutil.rmtree(demo_dir, ignore_errors=True)
shutil.rmtree("demo_protected", ignore_errors=True)

print("✅ Code protection example completed.\n")


# ============================================================
# 3. Quick Security Scan
# ============================================================
banner("3. Quick Security Scan")

scanner = Scanner(timeout=10, threads=2, max_depth=1)
summary = scanner.quick_scan("https://example.com")
print(f" Target: {summary['target']}")
print(f" Risk score: {summary['risk_score']}/100")
print(f" Vulnerabilities found: {summary['vulnerabilities_count']}")
print(f" Open ports: {summary['open_ports_count']}")
print("✅ Scan example completed.\n")


# ============================================================
# 4. Cryptography
# ============================================================
banner("4. Cryptographic Operations")

crypto = Crypto()

# Hash a message
hashed = crypto.hash_data("IronStack is awesome!")
print(f" SHA-256 hash: {hashed[:32]}...")

# Encrypt / decrypt
encrypted = crypto.encrypt("Secret message")
decrypted = crypto.decrypt(encrypted["ciphertext"], encrypted["nonce"], encrypted.get("tag"))
print(f" Decrypted: {decrypted.decode()}")

print("✅ Crypto example completed.\n")


# ============================================================
# 5. BunkerWeb (200+ OWASP CRS) – Optional
# ============================================================
banner("5. BunkerWeb WAF (requires Docker)")

if BUNKERWEB_AVAILABLE:
    bw = BunkerWebConnector(target_url="http://localhost:8000", listen_port=8080)
    if bw.is_available():
        print("BunkerWeb is available! Starting container...")
        bw.start()
        print(f" BunkerWeb running on http://0.0.0.0:8080")
        print(f" Protecting → http://localhost:8000")
        bw.stop()
    else:
        print("Docker is not running. Please start Docker and re‑run this script.")
else:
    print("BunkerWeb connector requires the 'docker' Python package.")
    print("Install it with:  pip install docker")
print("✅ BunkerWeb example completed.\n")


# =============