#!/usr/bin/env python3
"""
Pytest configuration and shared fixtures for IronStack tests.
"""

import os
import sys
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Generator

import pytest

# Ensure ironstack package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import IronStack
from ironstack.config import IronStackConfig
from ironstack.defense import WAF, CodeProtector, Crypto, Monitor, AntiCheat
from ironstack.attack import Scanner, Hooker, Disassembler, Emulator


# ==========================================
# Pytest Configuration
# ==========================================

def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "defense: tests for defense layer"
    )
    config.addinivalue_line(
        "markers", "attack: tests for attack layer"
    )
    config.addinivalue_line(
        "markers", "waf: tests for WAF module"
    )
    config.addinivalue_line(
        "markers", "protector: tests for code protection module"
    )
    config.addinivalue_line(
        "markers", "crypto: tests for crypto module"
    )
    config.addinivalue_line(
        "markers", "monitor: tests for monitor module"
    )
    config.addinivalue_line(
        "markers", "anticheat: tests for anti-cheat module"
    )
    config.addinivalue_line(
        "markers", "scanner: tests for scanner module"
    )
    config.addinivalue_line(
        "markers", "hooker: tests for hooker module (requires Frida)"
    )
    config.addinivalue_line(
        "markers", "disassembler: tests for disassembler module (requires Capstone)"
    )
    config.addinivalue_line(
        "markers", "emulator: tests for emulator module (requires Unicorn)"
    )


# ==========================================
# Core Fixtures
# ==========================================

@pytest.fixture
def ironstack_defense() -> IronStack:
    """Create a basic IronStack instance in defense mode."""
    return IronStack(mode="defense")


@pytest.fixture
def ironstack_attack() -> IronStack:
    """Create a basic IronStack instance in attack mode."""
    return IronStack(mode="attack")


@pytest.fixture
def ironstack_full() -> IronStack:
    """Create a basic IronStack instance in full mode."""
    return IronStack(mode="full")


@pytest.fixture
def default_config() -> IronStackConfig:
    """Return a default IronStackConfig instance."""
    return IronStackConfig()


# ==========================================
# Defense Layer Fixtures
# ==========================================

@pytest.fixture
def waf_normal() -> WAF:
    """Create a WAF instance in normal mode."""
    return WAF(mode="normal")


@pytest.fixture
def waf_strict() -> WAF:
    """Create a WAF instance in strict mode."""
    return WAF(mode="strict")


@pytest.fixture
def waf_permissive() -> WAF:
    """Create a WAF instance in permissive mode."""
    return WAF(mode="permissive")


@pytest.fixture
def code_protector() -> CodeProtector:
    """Create a CodeProtector instance."""
    return CodeProtector(mode="normal")


@pytest.fixture
def crypto_module() -> Crypto:
    """Create a Crypto instance."""
    return Crypto()


@pytest.fixture
def monitor_module() -> Monitor:
    """Create a Monitor instance."""
    return Monitor()


@pytest.fixture
def anti_cheat_fps() -> AntiCheat:
    """Create an AntiCheat instance for FPS games."""
    return AntiCheat(game_type="fps")


# ==========================================
# Attack Layer Fixtures
# ==========================================

@pytest.fixture
def scanner() -> Scanner:
    """Create a Scanner instance."""
    return Scanner()


@pytest.fixture
def hooker():
    """Create a Hooker instance (requires Frida)."""
    try:
        return Hooker()
    except ImportError:
        pytest.skip("Frida not installed")


@pytest.fixture
def disassembler():
    """Create a Disassembler instance (requires Capstone)."""
    try:
        return Disassembler()
    except ImportError:
        pytest.skip("Capstone not installed")


@pytest.fixture
def emulator():
    """Create an Emulator instance (requires Unicorn)."""
    try:
        return Emulator()
    except ImportError:
        pytest.skip("Unicorn not installed")


# ==========================================
# File System Fixtures
# ==========================================

@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    tmp = Path(tempfile.mkdtemp(prefix="ironstack_test_"))
    yield tmp
    shutil.rmtree(tmp, ignore_errors=True)


@pytest.fixture
def sample_python_file(temp_dir: Path) -> Path:
    """Create a sample Python file for testing code protection."""
    file_path = temp_dir / "sample.py"
    file_path.write_text("""
#!/usr/bin/env python3
\"\"\"Sample Python script for testing.\"\"\"

def hello():
    print("Hello, World!")

if __name__ == "__main__":
    hello()
""")
    return file_path


@pytest.fixture
def sample_python_project(temp_dir: Path) -> Path:
    """Create a small Python project directory."""
    project_dir = temp_dir / "myproject"
    project_dir.mkdir()
    (project_dir / "main.py").write_text("print('main')")
    (project_dir / "utils.py").write_text("def add(a, b): return a + b")
    sub_dir = project_dir / "sub"
    sub_dir.mkdir()
    (sub_dir / "helper.py").write_text("def greet(name): return f'Hello {name}'")
    return project_dir


# ==========================================
# Request Fixtures (for WAF testing)
# ==========================================

@pytest.fixture
def normal_request() -> Dict[str, Any]:
    """A normal HTTP request that should pass WAF."""
    return {
        "method": "GET",
        "path": "/home",
        "headers": {"User-Agent": "Mozilla/5.0", "Host": "example.com"},
        "body": "",
        "query_params": {},
        "ip": "192.168.1.100",
    }


@pytest.fixture
def sql_injection_request() -> Dict[str, Any]:
    """A request containing SQL injection payload."""
    return {
        "method": "POST",
        "path": "/login",
        "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
        "body": "username=admin' OR '1'='1' --",
        "query_params": {},
        "ip": "10.0.0.5",
    }


@pytest.fixture
def xss_request() -> Dict[str, Any]:
    """A request containing XSS payload."""
    return {
        "method": "POST",
        "path": "/comment",
        "headers": {"User-Agent": "Mozilla/5.0"},
        "body": "<script>alert('XSS')</script>",
        "query_params": {},
        "ip": "10.0.0.6",
    }


@pytest.fixture
def path_traversal_request() -> Dict[str, Any]:
    """A request containing path traversal attempt."""
    return {
        "method": "GET",
        "path": "/download",
        "headers": {},
        "body": "",
        "query_params": {"file": "../../../etc/passwd"},
        "ip": "10.0.0.7",
    }


@pytest.fixture
def command_injection_request() -> Dict[str, Any]:
    """A request containing command injection attempt."""
    return {
        "method": "GET",
        "path": "/ping",
        "headers": {},
        "body": "",
        "query_params": {"host": "127.0.0.1; cat /etc/passwd"},
        "ip": "10.0.0.8",
    }


@pytest.fixture
def scanner_request() -> Dict[str, Any]:
    """A request mimicking a vulnerability scanner."""
    return {
        "method": "GET",
        "path": "/",
        "headers": {"User-Agent": "sqlmap/1.6#stable (http://sqlmap.org)"},
        "body": "",
        "query_params": {},
        "ip": "10.0.0.9",
    }


# ==========================================
# Payload Collections
# ==========================================

@pytest.fixture
def malicious_payloads() -> Dict[str, list]:
    """Collection of various attack payloads for testing."""
    return {
        "sql_injection": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' ORDER BY 1--",
            "' OR 1=1#",
            "1; DROP TABLE users--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
        ],
        "command_injection": [
            "; ls",
            "| cat /etc/passwd",
            "`id`",
            "$(whoami)",
        ],
    }


# ==========================================
# Anti-Cheat Fixtures
# ==========================================

@pytest.fixture
def clean_player_action() -> Dict[str, Any]:
    """A normal player action (no cheating)."""
    return {
        "aim_angle_x": 1.5,
        "aim_angle_y": 0.3,
        "aim_speed": 120.0,
        "target_position": (100.0, 200.0, 50.0),
        "player_position": (50.0, 100.0, 25.0),
        "shot_fired": False,
        "hit_target": False,
        "target_id": "player2",
        "target_visible": True,
        "line_of_sight": True,
        "obstacles": [],
    }


@pytest.fixture
def suspicious_aim_action() -> Dict[str, Any]:
    """A suspicious aim action (potential aimbot)."""
    return {
        "aim_angle_x": 0.02,
        "aim_angle_y": 0.01,
        "aim_speed": 1500.0,
        "target_position": (101.0, 199.0, 49.0),
        "player_position": (50.0, 100.0, 25.0),
        "shot_fired": True,
        "hit_target": True,
        "target_id": "player2",
        "target_visible": True,
        "line_of_sight": True,
        "obstacles": [],
    }


# ==========================================
# Crypto Fixtures
# ==========================================

@pytest.fixture
def sample_plaintext() -> str:
    """Sample plaintext for encryption tests."""
    return "This is a secret message for IronStack testing."


@pytest.fixture
def sample_password() -> str:
    """Sample password for hashing tests."""
    return "IronStackSecurePass123!@#"


@pytest.fixture
def sample_file_content() -> bytes:
    """Sample file content for file encryption tests."""
    return b"Binary file content for testing file encryption with IronStack."


# ==========================================
# Scanner Fixtures
# ==========================================

@pytest.fixture
def local_test_server():
    """Start a local test HTTP server for scanner tests (integration)."""
    import http.server
    import threading
    import socket

    # Find a free port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 0))
    port = sock.getsockname()[1]
    sock.close()

    server_addr = ('127.0.0.1', port)

    class QuietHandler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # Suppress logs

    httpd = http.server.HTTPServer(server_addr, QuietHandler)
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    yield f"http://127.0.0.1:{port}"

    httpd.shutdown()
    server_thread.join(timeout=1)


# ==========================================
# Helper Functions
# ==========================================

def load_json_fixture(filename: str) -> Dict[str, Any]:
    """Load a JSON fixture file from the fixtures directory."""
    fixtures_dir = Path(__file__).parent / "fixtures"
    with open(fixtures_dir / filename, "r") as f:
        return json.load(f)


def skip_if_module_missing(module_name: str):
    """Decorator to skip a test if a module is not installed."""
    import importlib
    try:
        importlib.import_module(module_name)
        return lambda func: func
    except ImportError:
        return pytest.mark.skip(reason=f"{module_name} not installed")