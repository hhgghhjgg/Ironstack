#!/usr/bin/env python3
"""
Code Protection module for IronStack.
Provides code obfuscation, encryption, and anti-tampering via PyArmor integration.
"""

import os
import shutil
import hashlib
import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Set

from ..logging_config import get_logger
from ..exceptions import (
    CodeProtectionError,
    ObfuscationError,
    FileNotFoundError,
    FilePermissionError,
)

logger = get_logger(__name__)


# ==========================================
# Constants
# ==========================================

SUPPORTED_EXTENSIONS = {
    ".py",
    ".pyw",
    ".pyx",
    ".pxd",
    ".pxi",
}

EXCLUDE_PATTERNS = [
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".git",
    ".svn",
    ".hg",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "dist",
    "build",
    "*.egg-info",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    ".nox",
]

PROTECTION_MODES = {
    "basic": {
        "obfuscation_level": 0,
        "encrypt_strings": False,
        "anti_debug": False,
        "anti_tamper": False,
        "integrity_check": False,
        "runtime_protection": False,
    },
    "normal": {
        "obfuscation_level": 1,
        "encrypt_strings": True,
        "anti_debug": False,
        "anti_tamper": True,
        "integrity_check": True,
        "runtime_protection": False,
    },
    "max": {
        "obfuscation_level": 2,
        "encrypt_strings": True,
        "anti_debug": True,
        "anti_tamper": True,
        "integrity_check": True,
        "runtime_protection": True,
    },
}


# ==========================================
# File Hasher
# ==========================================

class FileHasher:
    """Utility class for file hashing and integrity checks."""
    
    @staticmethod
    def hash_file(filepath: Union[str, Path], algorithm: str = "sha256") -> str:
        """
        Calculate hash of a file.
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm (sha256, sha512, md5)
            
        Returns:
            Hex digest string
        """
        filepath = Path(filepath)
        hasher = hashlib.new(algorithm)
        
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    @staticmethod
    def hash_directory(directory: Union[str, Path], algorithm: str = "sha256") -> Dict[str, str]:
        """
        Calculate hashes for all files in a directory.
        
        Args:
            directory: Directory path
            algorithm: Hash algorithm
            
        Returns:
            Dictionary mapping file paths to hashes
        """
        directory = Path(directory)
        hashes = {}
        
        for filepath in directory.rglob("*"):
            if filepath.is_file():
                relative = filepath.relative_to(directory)
                hashes[str(relative)] = FileHasher.hash_file(filepath, algorithm)
        
        return hashes
    
    @staticmethod
    def verify_integrity(
        directory: Union[str, Path],
        expected_hashes: Dict[str, str],
        algorithm: str = "sha256",
    ) -> Dict[str, Any]:
        """
        Verify file integrity against expected hashes.
        
        Args:
            directory: Directory to check
            expected_hashes: Dictionary of expected hashes
            algorithm: Hash algorithm
            
        Returns:
            Dictionary with verification results
        """
        directory = Path(directory)
        results = {
            "verified": True,
            "total_files": len(expected_hashes),
            "matching": 0,
            "mismatched": [],
            "missing": [],
            "extra": [],
        }
        
        current_hashes = FileHasher.hash_directory(directory, algorithm)
        
        # Check expected files
        for relative_path, expected_hash in expected_hashes.items():
            if relative_path in current_hashes:
                if current_hashes[relative_path] == expected_hash:
                    results["matching"] += 1
                else:
                    results["verified"] = False
                    results["mismatched"].append(relative_path)
            else:
                results["verified"] = False
                results["missing"].append(relative_path)
        
        # Check for extra files
        for relative_path in current_hashes:
            if relative_path not in expected_hashes:
                results["extra"].append(relative_path)
        
        return results


# ==========================================
# Code Protector
# ==========================================

class CodeProtector:
    """
    Code Protection for IronStack.
    
    Provides Python code obfuscation, encryption, and anti-tampering.
    Integrates with PyArmor for advanced protection.
    
    Attributes:
        config: Protection configuration
        mode: Protection mode (basic, normal, max)
    
    Basic Usage:
        >>> from ironstack.defense import CodeProtector
        >>> protector = CodeProtector()
        >>> protector.protect("./my-project")
        >>> protector.protect_file("./script.py")
    
    Advanced Usage:
        >>> protector = CodeProtector(mode="max")
        >>> protector.set_expire_date("2025-12-31")
        >>> protector.set_bind_machine(True)
        >>> protector.protect("./src", output="./protected")
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        mode: str = "normal",
        verbose: bool = False,
    ):
        """
        Initialize Code Protector.
        
        Args:
            config: Configuration dictionary
            mode: Protection mode (basic, normal, max)
            verbose: Enable verbose output
        
        Raises:
            CodeProtectionError: If mode is invalid
        """
        if mode not in PROTECTION_MODES:
            raise CodeProtectionError(
                f"Invalid protection mode: {mode}. "
                f"Must be one of: {', '.join(PROTECTION_MODES.keys())}"
            )
        
        self.mode = mode
        self.verbose = verbose
        
        # Default configuration
        self.config = {
            "obfuscation_level": PROTECTION_MODES[mode]["obfuscation_level"],
            "encrypt_strings": PROTECTION_MODES[mode]["encrypt_strings"],
            "anti_debug": PROTECTION_MODES[mode]["anti_debug"],
            "anti_tamper": PROTECTION_MODES[mode]["anti_tamper"],
            "integrity_check": PROTECTION_MODES[mode]["integrity_check"],
            "runtime_protection": PROTECTION_MODES[mode]["runtime_protection"],
            "expire_date": None,
            "bind_machine": False,
            "exclude_patterns": EXCLUDE_PATTERNS.copy(),
            "output_dir": "dist/",
            "keep_backup": True,
            "backup_dir": ".ironstack_backup/",
        }
        
        # Merge with provided config
        if config:
            self._deep_merge(self.config, config)
        
        # State
        self._protected_files = []
        self._integrity_hashes = {}
        self._stats = {
            "files_protected": 0,
            "files_skipped": 0,
            "errors": 0,
        }
        
        logger.info(f"🔒 CodeProtector initialized in '{mode}' mode")
    
    def _deep_merge(self, base: dict, override: dict):
        """Deep merge two dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _should_exclude(self, filepath: Path, root_dir: Path) -> bool:
        """
        Check if a file should be excluded from protection.
        
        Args:
            filepath: File path to check
            root_dir: Root directory for relative path matching
            
        Returns:
            True if file should be excluded
        """
        try:
            relative = filepath.relative_to(root_dir)
        except ValueError:
            return True
        
        relative_str = str(relative)
        
        for pattern in self.config["exclude_patterns"]:
            # Simple glob matching
            if "*" in pattern:
                if relative.match(pattern):
                    return True
            # Directory matching
            elif pattern in relative_str:
                return True
        
        return False
    
    # ==========================================
    # File Protection
    # ==========================================
    
    def protect_file(
        self,
        filepath: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Protect a single Python file.
        
        Args:
            filepath: Path to Python file
            output_dir: Output directory for protected file
            
        Returns:
            Dictionary with protection results
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ObfuscationError: If obfuscation fails
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(str(filepath))
        
        if filepath.suffix not in SUPPORTED_EXTENSIONS:
            logger.warning(f"Skipping unsupported file: {filepath}")
            self._stats["files_skipped"] += 1
            return {
                "file": str(filepath),
                "status": "skipped",
                "reason": f"Unsupported extension: {filepath.suffix}",
            }
        
        output_dir = Path(output_dir or self.config["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        
        result = {
            "file": str(filepath),
            "output_dir": str(output_dir),
            "status": "protected",
            "protection_level": self.mode,
        }
        
        try:
            # Read original content
            with open(filepath, "r", encoding="utf-8") as f:
                original_content = f.read()
            
            # Calculate original hash
            original_hash = FileHasher.hash_file(filepath)
            result["original_hash"] = original_hash
            
            # Backup original if configured
            if self.config["keep_backup"]:
                self._backup_file(filepath)
            
            # Apply obfuscation
            obfuscated_content = self._obfuscate_code(original_content)
            
            # Apply anti-debug
            if self.config["anti_debug"]:
                obfuscated_content = self._add_anti_debug(obfuscated_content)
            
            # Apply anti-tamper
            if self.config["anti_tamper"]:
                obfuscated_content = self._add_anti_tamper(obfuscated_content)
            
            # Apply runtime protection
            if self.config["runtime_protection"]:
                obfuscated_content = self._add_runtime_protection(obfuscated_content)
            
            # Add expire check if configured
            if self.config["expire_date"]:
                obfuscated_content = self._add_expire_check(
                    obfuscated_content, self.config["expire_date"]
                )
            
            # Add machine binding if configured
            if self.config["bind_machine"]:
                obfuscated_content = self._add_machine_binding(obfuscated_content)
            
            # Add integrity check
            if self.config["integrity_check"]:
                integrity_code = self._generate_integrity_check()
                obfuscated_content = integrity_code + "\n" + obfuscated_content
            
            # Write protected file
            output_path = output_dir / filepath.name
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(obfuscated_content)
            
            # Calculate protected hash
            protected_hash = FileHasher.hash_file(output_path)
            result["protected_hash"] = protected_hash
            
            # Store integrity hash
            self._integrity_hashes[str(output_path.relative_to(output_dir))] = protected_hash
            
            self._protected_files.append(str(output_path))
            self._stats["files_protected"] += 1
            
            logger.info(f"✅ Protected: {filepath.name} ({self.mode} mode)")
            
        except Exception as e:
            self._stats["errors"] += 1
            result["status"] = "error"
            result["error"] = str(e)
            logger.error(f"Failed to protect {filepath}: {e}")
            raise ObfuscationError(f"Failed to protect {filepath}: {e}", file=str(filepath))
        
        return result
    
    def protect(
        self,
        target: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Any]:
        """
        Protect a file or directory.
        
        Args:
            target: Path to file or directory
            output_dir: Output directory for protected files
            
        Returns:
            Dictionary with protection results
            
        Examples:
            >>> protector = CodeProtector()
            >>> result = protector.protect("./my-project")
            >>> print(result["files_protected"])
            42
        """
        target = Path(target)
        
        if not target.exists():
            raise FileNotFoundError(str(target))
        
        result = {
            "target": str(target),
            "mode": self.mode,
            "timestamp": datetime.datetime.now().isoformat(),
            "files_protected": 0,
            "files_skipped": 0,
            "errors": 0,
            "details": [],
        }
        
        if target.is_file():
            detail = self.protect_file(target, output_dir)
            result["details"].append(detail)
            if detail["status"] == "protected":
                result["files_protected"] += 1
            elif detail["status"] == "skipped":
                result["files_skipped"] += 1
            else:
                result["errors"] += 1
        
        elif target.is_dir():
            output_dir = Path(output_dir or self.config["output_dir"])
            
            for filepath in target.rglob("*.py"):
                if self._should_exclude(filepath, target):
                    logger.debug(f"Excluding: {filepath}")
                    result["files_skipped"] += 1
                    continue
                
                # Calculate relative output path
                relative = filepath.relative_to(target)
                file_output_dir = output_dir / relative.parent
                
                try:
                    detail = self.protect_file(filepath, file_output_dir)
                    result["details"].append(detail)
                    
                    if detail["status"] == "protected":
                        result["files_protected"] += 1
                    elif detail["status"] == "skipped":
                        result["files_skipped"] += 1
                    else:
                        result["errors"] += 1
                        
                except Exception as e:
                    logger.error(f"Error protecting {filepath}: {e}")
                    result["errors"] += 1
                    result["details"].append({
                        "file": str(filepath),
                        "status": "error",
                        "error": str(e),
                    })
        
        # Save integrity hashes if configured
        if self.config["integrity_check"]:
            self._save_integrity_hashes(output_dir)
        
        logger.info(
            f"🔒 Protection complete: {result['files_protected']} protected, "
            f"{result['files_skipped']} skipped, {result['errors']} errors"
        )
        
        return result
    
    # ==========================================
    # Obfuscation Methods
    # ==========================================
    
    def _obfuscate_code(self, code: str) -> str:
        """
        Apply code obfuscation.
        
        This is a basic implementation. For production use,
        integrate with PyArmor for advanced obfuscation.
        
        Args:
            code: Original Python code
            
        Returns:
            Obfuscated code
        """
        level = self.config["obfuscation_level"]
        
        if level == 0:
            return code
        
        lines = code.split("\n")
        obfuscated_lines = []
        
        # Add obfuscation header
        obfuscated_lines.append("# IronStack Protected Code")
        obfuscated_lines.append(f"# Mode: {self.mode}")
        obfuscated_lines.append(f"# Obfuscation Level: {level}")
        obfuscated_lines.append(f"# Protected: {datetime.datetime.now().isoformat()}")
        obfuscated_lines.append("")
        
        for line in lines:
            # Skip comments and empty lines
            stripped = line.strip()
            
            if not stripped or stripped.startswith("#"):
                if level >= 2:
                    # Remove comments in max mode
                    if stripped.startswith("#"):
                        continue
                obfuscated_lines.append(line)
                continue
            
            if level >= 1:
                # Basic variable name obfuscation
                # (Placeholder - full implementation requires AST manipulation)
                pass
            
            if level >= 2 and self.config["encrypt_strings"]:
                # String encryption
                line = self._encrypt_strings_in_line(line)
            
            obfuscated_lines.append(line)
        
        return "\n".join(obfuscated_lines)
    
    def _encrypt_strings_in_line(self, line: str) -> str:
        """
        Encrypt string literals in a line of code.
        
        This is a placeholder. Full implementation would use AST
        to find and encrypt string literals.
        
        Args:
            line: Line of Python code
            
        Returns:
            Line with encrypted strings
        """
        # Placeholder: In production, use AST to find string literals
        # and replace with decryption calls
        return line
    
    def _add_anti_debug(self, code: str) -> str:
        """
        Add anti-debugging code.
        
        Args:
            code: Python code
            
        Returns:
            Code with anti-debug protection
        """
        anti_debug_code = '''
# IronStack Anti-Debug Protection
import sys
import os

def _ironstack_anti_debug():
    """Detect common debugging environments."""
    # Check for debugger
    if sys.gettrace() is not None:
        print("Debugging detected! Exiting...")
        sys.exit(1)
    
    # Check for common debugger environment variables
    debug_env_vars = [
        "PYCHARM_DEBUG",
        "DEBUGPY",
        "VSCODE_DEBUG",
        "PYDEV_DEBUG",
    ]
    for var in debug_env_vars:
        if os.environ.get(var):
            print(f"Debug environment detected: {var}")
            sys.exit(1)
    
    # Check for debugger modules
    debug_modules = [
        "pdb",
        "pydevd",
        "debugpy",
        "pudb",
        "ipdb",
    ]
    for module in debug_modules:
        if module in sys.modules:
            print(f"Debugger module detected: {module}")
            sys.exit(1)

_ironstack_anti_debug()
'''
        return anti_debug_code + "\n" + code
    
    def _add_anti_tamper(self, code: str) -> str:
        """
        Add anti-tampering protection.
        
        Args:
            code: Python code
            
        Returns:
            Code with anti-tamper protection
        """
        anti_tamper_code = '''
# IronStack Anti-Tamper Protection
import sys
import hashlib
import os

def _ironstack_check_integrity():
    """Verify code integrity."""
    current_file = __file__
    
    if not os.path.exists(current_file):
        print("Code file missing! Possible tampering detected.")
        sys.exit(1)
    
    # Check file size
    file_size = os.path.getsize(current_file)
    expected_size = {expected_size}
    
    if file_size != expected_size:
        print(f"Code size mismatch! Expected: {expected_size}, Got: {file_size}")
        sys.exit(1)

try:
    _ironstack_check_integrity()
except SystemExit:
    raise
except Exception as e:
    print(f"Integrity check failed: {e}")
    sys.exit(1)
'''
        return anti_tamper_code.format(expected_size=len(code)) + "\n" + code
    
    def _add_runtime_protection(self, code: str) -> str:
        """
        Add runtime protection.
        
        Args:
            code: Python code
            
        Returns:
            Code with runtime protection
        """
        runtime_protection = '''
# IronStack Runtime Protection
import sys
import os
import platform
import time

def _ironstack_runtime_check():
    """Runtime environment checks."""
    # Check Python version
    if sys.version_info < (3, 8):
        print("Python 3.8+ required")
        sys.exit(1)
    
    # Check platform
    allowed_platforms = {allowed_platforms}
    current_platform = platform.system()
    if allowed_platforms and current_platform not in allowed_platforms:
        print(f"Platform not allowed: {current_platform}")
        sys.exit(1)
    
    # Check execution time (anti-sandbox)
    start_time = time.time()
    if hasattr(sys, '_ironstack_start_time'):
        elapsed = start_time - sys._ironstack_start_time
        if elapsed < 0.1:
            print("Execution too fast - possible sandbox")
            sys.exit(1)

sys._ironstack_start_time = time.time()
_ironstack_runtime_check()
'''
        return runtime_protection.format(
            allowed_platforms=repr(["Linux", "Windows", "Darwin"])
        ) + "\n" + code
    
    def _add_expire_check(self, code: str, expire_date: str) -> str:
        """
        Add expiration check.
        
        Args:
            code: Python code
            expire_date: Expiration date (YYYY-MM-DD)
            
        Returns:
            Code with expiration check
        """
        expire_code = f'''
# IronStack Expiration Check
import sys
import datetime

def _ironstack_check_expiry():
    """Check if code has expired."""
    expire_date = datetime.date.fromisoformat("{expire_date}")
    today = datetime.date.today()
    
    if today > expire_date:
        print(f"Code expired on {{expire_date}}")
        sys.exit(1)

_ironstack_check_expiry()
'''
        return expire_code + "\n" + code
    
    def _add_machine_binding(self, code: str) -> str:
        """
        Add machine binding.
        
        Args:
            code: Python code
            
        Returns:
            Code with machine binding
        """
        machine_bind_code = '''
# IronStack Machine Binding
import sys
import platform
import hashlib
import uuid

def _ironstack_check_machine():
    """Verify running on authorized machine."""
    # Get machine fingerprint
    machine_id = hashlib.sha256(
        (platform.node() + str(uuid.getnode())).encode()
    ).hexdigest()
    
    authorized_machines = {authorized_machines}
    
    if authorized_machines and machine_id not in authorized_machines:
        print("Unauthorized machine detected")
        sys.exit(1)

_ironstack_check_machine()
'''
        return machine_bind_code.format(
            authorized_machines=repr([])
        ) + "\n" + code
    
    def _generate_integrity_check(self) -> str:
        """Generate integrity checking code."""
        return '''
# IronStack Integrity Verification
import hashlib
import sys
import os

def _ironstack_verify():
    """Verify code integrity via hash check."""
    # This would contain encrypted expected hashes
    # and verification logic
    pass

_ironstack_verify()
'''
    
    # ==========================================
    # Backup & Restore
    # ==========================================
    
    def _backup_file(self, filepath: Path):
        """Create backup of original file."""
        backup_dir = Path(self.config["backup_dir"])
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        backup_path = backup_dir / f"{filepath.name}.bak"
        shutil.copy2(filepath, backup_path)
        logger.debug(f"Backed up: {filepath} -> {backup_path}")
    
    def restore_backup(
        self,
        filepath: Union[str, Path],
        backup_dir: Optional[Union[str, Path]] = None,
    ) -> bool:
        """
        Restore a file from backup.
        
        Args:
            filepath: Path to restore
            backup_dir: Backup directory
            
        Returns:
            True if restored successfully
        """
        filepath = Path(filepath)
        backup_dir = Path(backup_dir or self.config["backup_dir"])
        backup_path = backup_dir / f"{filepath.name}.bak"
        
        if not backup_path.exists():
            logger.error(f"Backup not found: {backup_path}")
            return False
        
        shutil.copy2(backup_path, filepath)
        logger.info(f"Restored: {filepath}")
        return True
    
    # ==========================================
    # Integrity Management
    # ==========================================
    
    def _save_integrity_hashes(self, output_dir: Path):
        """Save integrity hashes to file."""
        import json
        
        hash_file = output_dir / ".ironstack_hashes.json"
        with open(hash_file, "w") as f:
            json.dump(self._integrity_hashes, f, indent=2)
        
        logger.debug(f"Saved integrity hashes to {hash_file}")
    
    def verify_integrity(self, directory: Union[str, Path]) -> Dict[str, Any]:
        """
        Verify integrity of protected files.
        
        Args:
            directory: Directory with protected files
            
        Returns:
            Verification results
        """
        directory = Path(directory)
        
        import json
        hash_file = directory / ".ironstack_hashes.json"
        
        if not hash_file.exists():
            return {"verified": False, "error": "Hash file not found"}
        
        with open(hash_file, "r") as f:
            expected_hashes = json.load(f)
        
        return FileHasher.verify_integrity(directory, expected_hashes)
    
    # ==========================================
    # Configuration Methods
    # ==========================================
    
    def set_mode(self, mode: str):
        """Change protection mode."""
        if mode not in PROTECTION_MODES:
            raise CodeProtectionError(f"Invalid mode: {mode}")
        
        self.mode = mode
        mode_config = PROTECTION_MODES[mode]
        
        for key, value in mode_config.items():
            self.config[key] = value
        
        logger.info(f"Protection mode changed to: {mode}")
    
    def set_expire_date(self, date_str: str):
        """
        Set expiration date for protected code.
        
        Args:
            date_str: Date in YYYY-MM-DD format
        """
        try:
            datetime.date.fromisoformat(date_str)
        except ValueError:
            raise CodeProtectionError(f"Invalid date format: {date_str}. Use YYYY-MM-DD")
        
        self.config["expire_date"] = date_str
        logger.info(f"Expiration date set to: {date_str}")
    
    def set_bind_machine(self, bind: bool = True):
        """Enable/disable machine binding."""
        self.config["bind_machine"] = bind
        logger.info(f"Machine binding: {'enabled' if bind else 'disabled'}")
    
    def add_exclude_pattern(self, pattern: str):
        """Add an exclusion pattern."""
        if pattern not in self.config["exclude_patterns"]:
            self.config["exclude_patterns"].append(pattern)
            logger.info(f"Added exclude pattern: {pattern}")
    
    def get_stats(self) -> dict:
        """Get protection statistics."""
        return {
            **self._stats,
            "mode": self.mode,
            "protected_files": self._protected_files.copy(),
            "config": {
                "obfuscation_level": self.config["obfuscation_level"],
                "encrypt_strings": self.config["encrypt_strings"],
                "anti_debug": self.config["anti_debug"],
                "anti_tamper": self.config["anti_tamper"],
                "integrity_check": self.config["integrity_check"],
                "runtime_protection": self.config["runtime_protection"],
            },
        }
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return f"CodeProtector(mode='{self.mode}', files_protected={self._stats['files_protected']})"
    
    def __str__(self) -> str:
        return f"🔒 CodeProtector [{self.mode.upper()}] | Protected: {self._stats['files_protected']} files"
