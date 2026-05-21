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
    """Create a sample Python file for testing cod