#!/usr/bin/env python3
"""
IronStack – API Protection Example
====================================
Demonstrates how to protect a REST / GraphQL API with IronStack.

Key techniques shown:
  • WAF (Python engine) – blocks SQLi, XSS, command injection, scanners …
  • HMAC request signing – prevents request tampering & replay attacks
  • Response obfuscation – makes data harder to reverse‑engineer
  • Rate limiting – stops brute‑force and mass scraping
  • Certificate pinning – hardens HTTPS connections

Run from the project root:
    python examples/protect_api.py
"""

import os
import sys
import json
import time
import hashlib
import hmac
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import IronStack
from ironstack.defense import WAF, Crypto


def banner(title: str):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


# ============================================================
# 1. Start the WAF layer
# ============================================================
banner("1. WAF Layer – Filter malicious requests")

waf = WAF(engine="python", mode="normal")
waf.start()  # configures the WAF for request checking

# Simulate various API requests
print("Checking incoming API requests …")
requests_to_check = [
    # Normal requests that should pass
    {
        "method": "GET",
        "path": "/api/v1/users/42",
        "headers": {"Authorization": "Bearer valid-token"},
        "body": "",
        "query_params": {},
        "ip": "203.0.113.1",
    },
    {
        "method": "POST",
        "path": "/api/v1/comments",
        "headers": {"Content-Type": "application/json"},
        "body": '{"text": "Nice article!"}',
        "query_params": {},
        "ip": "203.0.113.2",
    },
    # Attack attempts – should be blocked
    {
        "method": "GET",
        "path": "/api/v1/users/1",
        "headers": {},
        "body": "",
        "query_params": {"id": "1' UNION SELECT NULL --"},
        "ip": "10.0.0.5",
    },
    {
        "method": "POST",
        "path": "/api/v1/upload",
        "headers": {},
        "body": '<img src=x onerror="alert(1)">',
        "query_params": {},
        "ip": "10.0.0.6",
    },
    {
        "method": "GET",
        "path": "/api/v1/download",
        "headers": {},
        "body": "",
        "query_params": {"file": "../../../etc/passwd"},
        "ip": "10.0.0.7",
    },
]

for req in requests_to_check:
    result = waf.check_request(req)
    status = "✅ ALLOWED" if result["allowed"] else "❌ BLOCKED"
    extra = ""
    if not result["allowed"]:
        extra = f" (score: {result['score']}, rules: {result['matched_rules'][:2]})"
    print(f"  {req['method']:6s} {req['path']:20s} → {status}{extra}")

waf.stop()
print("\n✅ WAF layer demonstrated.\n")


# ============================================================
# 2. Request Signing (HMAC) – prevent tampering & replay
# ============================================================
banner("2. Request Signing (HMAC)")

crypto = Crypto()

# Create a signer with a secret key
# In real code, this key would be shared only with trusted clients
secret = b"super-secret-api-key-32bytes!!"  # 32 bytes
signer = crypto.signer  # already configured in crypto, but we can override
# For demo, create a fresh signer
from ironstack.defense.crypto import HMACSigner
api_signer = HMACSigner(secret_key=secret)

# --- Client side (e.g., mobile app) ---
client_method = "POST"
client_path = "/api/v1/order"
client_body = '{"item": "book", "price": 19.95}'

signed = api_signer.sign_request(client_method, client_path, client_body)
print(f"Client sends headers:")
print(f"  X-Signature: {signed['X-Signature'][:32]}...")
print(f"  X-Timestamp: {signed['X-Timestamp']}")

# --- Server side (your API) ---
is_valid, msg = api_signer.verify_request(
    client_method,
    client_path,
    client_body,
    int(signed["X-Timestamp"]),
    signed["X-Signature"],
    max_age=300,  # 5 minutes
)
print(f"\nServer verification: {'✅ Valid' if is_valid else '❌ Invalid'} – {msg}")

# Simulate a replay (old timestamp)
old_signed = api_signer.sign_request("GET", "/api/v1/users", "", timestamp=1)
is_valid, msg = api_signer.verify_request(
    "GET", "/api/v1/users", "", 1, old_signed["X-Signature"], max_age=300
)
print(f"Old request verification: {'✅ Valid' if is_valid else '❌ Invalid'} – {msg}")

print("\n✅ Request signing demonstrated.\n")


# ============================================================
# 3. Response Obfuscation – harder to reverse‑engineer
# ============================================================
banner("3. Response Obfuscation")

# The server obfuscates the response body
original_data = {
    "order_id": 12345,
    "status": "confirmed",
    "total": 19.95,
    "currency": "USD",
}
print(f"Original response: {json.dumps(original_data)}")

obfuscated = crypto.obfuscate(original_data)
print(f"Obfuscated (what the client receives): {obfuscated[:60]}...")

# The client deobfuscates
restored = crypto.deobfuscate(obfuscated)
print(f"After deobfuscation: {json.dumps(restored)}")

print("\n✅ Response obfuscation demonstrated.\n")


# ============================================================
# 4. Rate Limiting (built into WAF)
# ============================================================
banner("4. Rate Limiting (WAF built‑in)")

rate_waf = WAF(engine="python", mode="normal")
# Tighten limits for demo
rate_waf.config["rate_limiting"]["max_requests"] = 3
rate_waf.config["rate_limiting"]["time_window"] = 10  # 10 seconds
rate_waf.config["rate_limiting"]["burst"] = 1

ip = "192.0.2.100"
print(f"Sending 10 rapid requests from IP {ip} …")
blocked = False
for i in range(10):
    result = rate_waf.check_request({
        "method": "GET",
        "path": "/api/v1/data",
        "headers": {},
        "body": "",
        "query_params": {},
        "ip": ip,
    })
    if not result["allowed"]:
        print(f"  Request {i+1}: ❌ BLOCKED (rate limit exceeded)")
        blocked = True
        break
    else:
        print(f"  Request {i+1}: allowed")

if not blocked:
    print("(limits not triggered – try lowering max_requests)")

print("\n✅ Rate limiting demonstrated.\n")


# ============================================================
# 5. Certificate Pinning (conceptual)
# ============================================================
banner("5. Certificate Pinning (conceptual)")

# Pin a certificate hash (in real code you would extract the cert from a file or URL)
import hashlib
fake_cert_data = b"-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
cert_hash = hashlib.sha256(fake_cert_data).hexdigest()

crypto.pin_certificate_from_bytes = lambda data: crypto.cert_pinner.add_pin(
    hashlib.sha256(data).hexdigest()
)
crypto.pin_certificate_from_bytes(fake_cert_data)

pinned_hash = crypto.cert_pinner.allowed_hashes[0]
print(f"Pinned certificate SHA‑256: {pinned_hash[:16]}...")

# Verify the same certificate
assert crypto.cert_pinner.verify_certificate(fake_cert_data)
print("✅ Known certificate → accepted")

# Verify a different certificate
fake_cert2 = b"-----BEGIN CERTIFICATE-----\nEVIL_CERT\n-----END CERTIFICATE-----"
print(f"Unknown certificate → {'accepted' if crypto.cert_pinner.verify_certificate(fake_cert2) else 'rejected'}")

print("\n✅ Certificate pinning demonstrated.\n")


# ============================================================
# 6. Putting it all together – a protected API endpoint
# ============================================================
banner("6. Simulating a Protected API Endpoint")

print("Combining WAF, request signing, rate limiting, and response obfuscation.\n")

# Configuration for the "server"
api_secret = b"api-secret-32bytes-long-key!!"
api_signer = HMACSigner(secret_key=api_secret)
api_waf = WAF(engine="python", mode="normal")
api_crypto = Crypto()

def handle_api_request(method, path, body, headers, ip):
    """Simulate a real API handler protected by IronStack."""
    
    # 1. WAF check (always first)
    waf_result = api_waf.check_request({
        "method": method,
        "path": path,
        "headers": headers,
        "body": body,
        "query_params": {},
        "ip": ip,
    })
    if not waf_result["allowed"]:
        return 403, {"error": "Request blocked by WAF", "reason": waf_result["message"]}

    # 2. Verify request signature (if required)
    sig = headers.get("X-Signature")
    ts = headers.get("X-Timestamp")
    if sig and ts:
        valid, msg = api_signer.verify_request(method, path, body, int(ts), sig)
        if not valid:
            return 401, {"error": msg}

    # 3. Process the request (mock logic)
    if path == "/api/v1/data" and method == "GET":
        response_data = {"data": [1, 2, 3], "status": "ok"}
    elif path == "/api/v1/data" and method == "POST":
        response_data = {"created": True, "id": 42}
    else:
        return 404, {"error": "Not found"}

    # 4. Obfuscate the response before sending back
    obfuscated_body = api_crypto.obfuscate(response_data)
    return 200, obfuscated_body


# Test the mock endpoint
print("→ Legitimate GET request (signed)")
headers = api_signer.sign_request("GET", "/api/v1/data", "")
code, resp = handle_api_request(
    "GET", "/api/v1/data", "",
    {"X-Signature": headers["X-Signature"], "X-Timestamp": headers["X-Timestamp"]},
    "192.168.1.1",
)
print(f"   HTTP {code} – response: {str(resp)[:50]}...")

print("\n→ Malicious SQL injection in request body")
code, resp = handle_api_request(
    "POST", "/api/v1/data",
    "x' OR 1=1 --",
    {},
    "10.0.0.5",
)
print(f"   HTTP {code} – {resp}")

print("\n→ Unsigned request (if signature is mandatory)")
code, resp = handle_api_request(
    "GET", "/api/v1/data", "",
    {},
    "192.168.1.1",
)
print(f"   HTTP {code} – {resp}")

print("\n✅ Full API protection workflow demonstrated.\n")


# ============================================================
# Summary
# ============================================================
banner("Summary")

print("To protect your API with IronStack:")
print("  1. WAF:             WAF(engine='python' | 'bunkerweb')")
print("  2. Sign requests:   crypto.signer.sign_request(method, path, body)")
print("  3. Obfuscate:       crypto.obfuscate(response_data)")
print("  4. Rate limit:      WAF.config['rate_limiting'] (built‑in)")
print("  5. Pin certificates: crypto.cert_pinner.pin_certificate_from_file(path)")
print()
print("These layers work together to provide defense‑in‑depth for your API.")