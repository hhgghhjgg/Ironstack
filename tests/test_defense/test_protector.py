#!/usr/bin/env python3
"""
Unit tests for IronStack Code Protection module (ironstack/defense/protector.py).
"""

import sys
import os
import pytest
import shutil
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ironstack.defense.protector import (
    CodeProtector,
    FileHasher,
    PROTECTION_MODES,
    SUPPORTED_EXTENSIONS,
)
from ironstack.exceptions import CodeProtectionError, ObfuscationError, FileNotFoundError


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def tmp_workdir(tmp_path):
    """Change to a temporary directory for file operations."""
    old = os.getcwd()
    os.chdir(tmp_path)
    yield tmp_path
    os.chdir(old)


@pytest.fixture
def sample_python_file(tmp_workdir):
    """Create a simple Python file."""
    filepath = tmp_workdir / "sample.py"
    filepath.write_text("""
def hello():
    print("Hello, World!")

if __name__ == "__main__":
    hello()
""")
    return filepath


@pytest.fixture
def sample_python_project(tmp_workdir):
    """Create a minimal Python project directory."""
    proj = tmp_workdir / "myproject"
    proj.mkdir()
    (proj / "main.py").write_text("print('main')")
    (proj / "utils.py").write_text("def add(a, b): return a + b")
    sub = proj / "sub"
    sub.mkdir()
    (sub / "helper.py").write_text("def greet(name): return f'Hello {name}'")
    return proj


@pytest.fixture
def protector_normal():
    """Return a CodeProtector in normal mode."""
    return CodeProtector(mode="normal")


# ============================================================
# Initialization
# ============================================================

class TestInit:
    def test_default_mode(self):
        cp = CodeProtector()
        assert cp.mode == "normal"

    def test_invalid_mode_raises(self):
        with pytest.raises(CodeProtectionError):
            CodeProtector(mode="invalid")

    def test_mode_config_loaded(self):
        cp = CodeProtector(mode="max")
        assert cp.config["encrypt_strings"] is True
        assert cp.config["anti_debug"] is True


# ============================================================
# FileHasher
# ============================================================

class TestFileHasher:
    def test_hash_file_sha256(self, sample_python_file):
        result = FileHasher.hash_file(sample_python_file, "sha256")
        assert "hash" in result
        assert len(result["hash"]) == 64

    def test_hash_file_md5(self, sample_python_file):
        result = FileHasher.hash_file(sample_python_file, "md5")
        assert len(result["hash"]) == 32

    def test_hash_directory(self, sample_python_project):
        hashes = FileHasher.hash_directory(sample_python_project, "sha256")
        assert len(hashes) >= 3

    def test_verify_integrity(self, sample_python_project):
        expected = FileHasher.hash_directory(sample_python_project)
        result = FileHasher.verify_integrity(sample_python_project, expected)
        assert result["verified"] is True

    def test_verify_integrity_fails_on_mismatch(self, sample_python_project):
        expected = FileHasher.hash_directory(sample_python_project)
        # Corrupt one expected hash
        some_key = next(iter(expected))
        expected[some_key] = "deadbeef" * 8
        result = FileHasher.verify_integrity(sample_python_project, expected)
        assert result["verified"] is False


# ============================================================
# Single File Protection
# ============================================================

class TestProtectFile:
    def test_basic_protection(self, protector_normal, sample_python_file):
        result = protector_normal.protect_file(sample_python_file)
        assert result["status"] == "protected"
        output_dir = Path(result["output_dir"])
        protected_file = output_dir / sample_python_file.name
        assert protected_file.exists()

    def test_protected_file_is_not_empty(self, protector_normal, sample_python_file):
        result = protector_normal.protect_file(sample_python_file)
        output_dir = Path(result["output_dir"])
        content = (output_dir / sample_python_file.name).read_text()
        assert len(content) > 0

    def test_non_existent_file_raises(self, protector_normal, tmp_path):
        with pytest.raises(FileNotFoundError):
            protector_normal.protect_file(tmp_path / "missing.py")

    def test_unsupported_extension_skipped(self, protector_normal, tmp_workdir):
        file = tmp_workdir / "data.txt"
        file.write_text("not python")
        result = protector_normal.protect_file(file)
        assert result["status"] == "skipped"

    def test_max_mode_adds_anti_debug(self, sample_python_file):
        cp = CodeProtector(mode="max")
        result = cp.protect_file(sample_python_file)
        assert result["status"] == "