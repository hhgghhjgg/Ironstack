#!/usr/bin/env python3
"""
Unit tests for IronStack core module (ironstack/core.py).
Tests the main IronStack class and quick access functions.
"""

import os
import sys
import pytest
from pathlib import Path

# Ensure package is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ironstack import (
    IronStack,
    protect,
    scan,
    status,
    version_info,
    get_instance,
    reset_instance,
    IronStackError,
    IronStackConfigError,
    IronStackProtectionError,
    IronStackScanError,
    LayerNotAvailableError,
    __version__,
)


# ==========================================
# Fixtures (reuse from conftest.py)
# ==========================================

@pytest.fixture(autouse=True)
def reset_default_instance():
    """Reset the default instance before each test."""
    reset_instance()
    yield
    reset_instance()


# ==========================================
# Initialization Tests
# ==========================================

class TestIronStackInit:
    """Tests for IronStack initialization."""

    def test_default_init(self):
        """Test creating IronStack with default parameters."""
        is_stack = IronStack()
        assert is_stack is not None
        assert is_stack._mode == "defense"
        assert is_stack.version_info() == f"IronStack v0.1.0"

    def test_init_defense_mode(self, ironstack_defense):
        """Test creating IronStack in defense mode."""
        assert ironstack_defense._mode == "defense"

    def test_init_attack_mode(self, ironstack_attack):
        """Test creating IronStack in attack mode."""
        assert ironstack_attack._mode == "attack"

    def test_init_full_mode(self, ironstack_full):
        """Test creating IronStack in full mode."""
        assert ironstack_full._mode == "full"

    def test_init_with_config_dict(self):
        """Test initialization with a configuration dictionary."""
        config = {"core": {"mode": "defense"}}
        is_stack = IronStack(config=config)
        assert is_stack._mode == "defense"

    def test_init_invalid_mode_raises_error(self):
        """Test that an invalid mode raises IronStackConfigError."""
        with pytest.raises(IronStackConfigError):
            IronStack(mode="invalid")

    def test_init_with_verbose(self):
        """Test initialization with verbose flag."""
        is_stack = IronStack(verbose=True)
        assert is_stack._verbose is True

    def test_init_with_debug(self):
        """Test initialization with debug flag."""
        is_stack = IronStack(debug=True)
        assert is_stack._debug is True


# ==========================================
# Mode Tests
# ==========================================

class TestIronStackModes:
    """Tests for different operation modes."""

    @pytest.mark.defense
    def test_defense_mode_has_defense_layers(self, ironstack_defense):
        """Test defense mode enables defense layers."""
        status = ironstack_defense.status()
        assert status["mode"] == "defense"

    @pytest.mark.attack
    def test_attack_mode_has_attack_layers(self, ironstack_attack):
        """Test attack mode enables attack layers."""
        status = ironstack_attack.status()
        assert status["mode"] == "attack"

    @pytest.mark.defense
    def test_full_mode_has_all_layers(self, ironstack_full):
        """Test full mode enables all layers."""
        status = ironstack_full.status()
        assert status["mode"] == "full"


# ==========================================
# Status Tests
# ==========================================

class TestStatus:
    """Tests for the status() method."""

    def test_status_returns_dict(self, ironstack_defense):
        """Test status returns a dictionary with required keys."""
        result = ironstack_defense.status()
        assert isinstance(result, dict)
        assert "version" in result
        assert "mode" in result
        assert "active_layers" in result
        assert "layers" in result
        assert "stats" in result

    def test_status_version(self, ironstack_defense):
        """Test status shows correct version."""
        result = ironstack_defense.status()
        assert result["version"] == "0.1.0"

    def test_status_mode(self, ironstack_defense):
        """Test status shows correct mode."""
        result = ironstack_defense.status()
        assert result["mode"] == "defense"


# ==========================================
# Protect Tests
# ==========================================

class TestProtect:
    """Tests for the protect() method."""

    def test_protect_project_directory(self, ironstack_defense, sample_python_project):
        """Test protecting a project directory."""
        result = ironstack_defense.protect(str(sample_python_project))
        assert result["status"] == "success"
        assert result["target_type"] == "project"

    def test_protect_python_file(self, ironstack_defense, sample_python_file):
        """Test protect