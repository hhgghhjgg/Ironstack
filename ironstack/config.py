#!/usr/bin/env python3
"""
Configuration module for IronStack.
Handles loading, saving, and managing configuration settings.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field, asdict
from copy import deepcopy

from .exceptions import ConfigurationError


# ==========================================
# Default Configuration
# ==========================================

DEFAULT_CONFIG = {
    # Core settings
    "core": {
        "mode": "defense",           # defense, attack, full
        "verbose": False,
        "debug": False,
        "log_level": "INFO",         # DEBUG, INFO, WARNING, ERROR, CRITICAL
        "log_file": None,            # Path to log file (None = stderr)
        "temp_dir": None,            # Temporary directory (None = system default)
    },

    # WAF (Web Application Firewall) settings
    "waf": {
        "enabled": False,
        "engine": "auto",            # auto, python, bunkerweb
        "mode": "normal",            # strict, normal, permissive (python engine)
        "port": 8080,
        "listen_address": "127.0.0.1",
        "ruleset": "builtin",        # builtin, owasp-crs (via BunkerWeb)
        "paranoia_level": 1,         # 1-4 (python engine)
        "anomaly_threshold": 5,      # Inbound threshold
        "outbound_threshold": 4,     # Outbound threshold
        "block_on_attack": True,
        "audit_log": True,
        "audit_log_path": None,
        "rate_limiting": {
            "enabled": True,
            "max_requests": 100,
            "time_window": 60,       # seconds
            "burst": 20,
        },
        "ip_whitelist": [],
        "ip_blacklist": [],
        "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
        "max_body_size": 10485760,   # 10MB
        "max_headers_size": 8192,    # 8KB
        "response_obfuscation": False,
        "certificate_pinning": False,

        # BunkerWeb-specific settings (engine=bunkerweb)
        "bunkerweb": {
            "enabled": False,
            "target_url": "http://localhost:8000",
            "listen_port": 8080,
            "api_port": 5000,
            "docker_image": "bunkerity/bunkerweb:latest",
        },
    },

    # Code Protection settings
    "code_protection": {
        "enabled": False,
        "engine": "pyarmor",         # pyarmor, custom
        "mode": "normal",            # basic, normal, max
        "obfuscation_level": 2,      # 0-3
        "encrypt_strings": True,
        "anti_debug": True,
        "anti_tamper": True,
        "integrity_check": True,
        "runtime_protection": True,
        "expire_date": None,         # YYYY-MM-DD format
        "bind_machine": False,       # Bind to specific hardware
        "exclude_patterns": [
            "tests/*",
            "venv/*",
            ".git/*",
            "__pycache__/*",
            "*.pyc",
        ],
        "output_dir": "dist/",
        "keep_backup": True,
    },

    # Cryptography settings
    "crypto": {
        "enabled": False,
        "algorithm": "AES-256-GCM",
        "key_size": 256,
        "hash_algorithm": "SHA-256",
        "signing_algorithm": "HMAC-SHA256",
        "salt_size": 32,
        "iterations": 100000,
        "key_derivation": "PBKDF2",
    },

    # Monitoring settings (Fail2ban)
    "monitor": {
        "enabled": False,
        "engine": "fail2ban",
        "max_retry": 5,
        "ban_time": 600,             # seconds (10 minutes)
        "find_time": 600,            # seconds
        "ban_action": "iptables",
        "notification": False,
        "notification_email": None,
        "log_path": "/var/log/ironstack/",
    },

    # Anti-Cheat settings
    "anti_cheat": {
        "enabled": False,
        "engine": "cinagu",          # cinagu, tibet, custom
        "game_type": "auto",         # fps, rts, chess, auto
        "detection_modes": [
            "aimbot",
            "wallhack",
            "scripts",
            "macros",
            "speedhack",
        ],
        "sensitivity": "medium",     # low, medium, high
        "auto_ban": False,
        "ban_duration": 86400,       # seconds (24 hours)
        "log_suspicious": True,
        "report_path": None,
    },

    # Scanner settings
    "scanner": {
        "enabled": False,
        "engines": ["sqlmap", "nmap"],
        "scan_timeout": 300,         # seconds
        "max_depth": 3,
        "threads": 10,
        "user_agent": "IronStack-Scanner/1.0",
        "proxy": None,
        "rate_limit": 10,            # requests per second
        "output_format": "json",     # json, html, pdf
        "output_dir": "scans/",
    },

    # Disassembler settings
    "disassembler": {
        "enabled": False,
        "engine": "capstone",
        "architecture": "auto",      # auto, x86, x64, arm, arm64
        "mode": "auto",              # auto, 32, 64
        "syntax": "intel",           # intel, at&t
    },

    # Emulator settings
    "emulator": {
        "enabled": False,
        "engine": "unicorn",
        "architecture": "auto",
        "mode": "auto",
        "timeout": 60,               # seconds
        "max_instructions": 1000000,
    },

    # Hooker settings (Frida)
    "hooker": {
        "enabled": False,
        "engine": "frida",
        "target_type": "auto",       # auto, process, device
        "scripts_dir": "hooks/",
        "auto_unhook": True,
    },
}


@dataclass
class IronStackConfig:
    """
    IronStack configuration class.

    Handles all configuration settings for IronStack layers.

    Attributes:
        data: Configuration dictionary
        config_path: Path to configuration file
    """

    data: Dict[str, Any] = field(default_factory=lambda: deepcopy(DEFAULT_CONFIG))
    config_path: Optional[Path] = None

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()

    def _validate(self):
        """Validate configuration values."""
        # Validate mode
        valid_modes = ["defense", "attack", "full"]
        if self.data["core"]["mode"] not in valid_modes:
            raise ConfigurationError(
                f"Invalid mode: {self.data['core']['mode']}. "
                f"Must be one of: {', '.join(valid_modes)}"
            )

        # Validate log level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.data["core"]["log_level"] not in valid_levels:
            raise ConfigurationError(
                f"Invalid log level: {self.data['core']['log_level']}"
            )

        # Validate WAF settings
        if self.data["waf"]["enabled"]:
            valid_engines = ["auto", "python", "bunkerweb"]
            if self.data["waf"]["engine"] not in valid_engines:
                raise ConfigurationError(
                    f"Invalid WAF engine: {self.data['waf']['engine']}"
                )

            if self.data["waf"]["engine"] == "python":
                if not (1 <= self.data["waf"]["paranoia_level"] <= 4):
                    raise ConfigurationError("Paranoia level must be between 1 and 4")

        # Validate code protection settings
        if self.data["code_protection"]["enabled"]:
            valid_modes = ["basic", "normal", "max"]
            if self.data["code_protection"]["mode"] not in valid_modes:
                raise ConfigurationError(
                    f"Invalid protection mode: {self.data['code_protection']['mode']}"
                )

            if not (0 <= self.data["code_protection"]["obfuscation_level"] <= 3):
                raise ConfigurationError("Obfuscation level must be between 0 and 3")

    # ==========================================
    # Class Methods - Factory
    # ==========================================

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> "IronStackConfig":
        """
        Load configuration from file.

        Supports YAML (.yaml, .yml) and JSON (.json) formats.

        Args:
            path: Path to configuration file

        Returns:
            IronStackConfig instance

        Raises:
            ConfigurationError: If file not found or invalid format
        """
        path = Path(path)

        if not path.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")

        try:
            with open(path, "r", encoding="utf-8") as f:
                if path.suffix in (".yaml", ".yml"):
                    config_data = yaml.safe_load(f)
                elif path.suffix == ".json":
                    config_data = json.load(f)
                else:
                    raise ConfigurationError(
                        f"Unsupported config format: {path.suffix}. "
                        f"Use .yaml, .yml, or .json"
                    )
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ConfigurationError(f"Failed to parse config file: {e}") from e

        # Merge with defaults
        merged = cls._deep_merge(deepcopy(DEFAULT_CONFIG), config_data or {})

        return cls(data=merged, config_path=path)

    @classmethod
    def from_dict(cls, config_dict: Dict[str, Any]) -> "IronStackConfig":
        """
        Create configuration from dictionary.

        Args:
            config_dict: Configuration dictionary

        Returns:
            IronStackConfig instance
        """
        merged = cls._deep_merge(deepcopy(DEFAULT_CONFIG), config_dict)
        return cls(data=merged)

    @classmethod
    def from_env(cls) -> "IronStackConfig":
        """
        Create configuration from environment variables.

        Environment variables prefixed with IRONSTACK_ are used.

        Examples:
            IRONSTACK_MODE=full
            IRONSTACK_WAF_ENABLED=true
            IRONSTACK_WAF_ENGINE=bunkerweb

        Returns:
            IronStackConfig instance
        """
        config = cls()

        for key, value in os.environ.items():
            if key.startswith("IRONSTACK_"):
                # Convert IRONSTACK_WAF_ENABLED to ["waf"]["enabled"]
                parts = key.lower().replace("ironstack_", "").split("_")

                # Navigate to correct position in config
                current = config.data
                for part in parts[:-1]:
                    if part not in current:
                        current[part] = {}
                    current = current[part]

                # Set value with type conversion
                final_key = parts[-1]
                current[final_key] = cls._convert_env_value(value)

        return config

    # ==========================================
    # Save Methods
    # ==========================================

    def to_file(self, path: Union[str, Path], format: str = "yaml"):
        """
        Save configuration to file.

        Args:
            path: Output file path
            format: Output format ("yaml" or "json")
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            if format == "yaml":
                yaml.dump(self.data, f, default_flow_style=False, allow_unicode=True)
            elif format == "json":
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            else:
                raise ConfigurationError(f"Unsupported format: {format}")

        self.config_path = path

    def to_dict(self) -> Dict[str, Any]:
        """Export configuration as dictionary."""
        return deepcopy(self.data)

    # ==========================================
    # Access Methods
    # ==========================================

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "waf.port", "core.mode")
            default: Default value if key not found

        Returns:
            Configuration value

        Examples:
            >>> config.get("waf.port")
            8080
            >>> config.get("nonexistent", "default")
            'default'
        """
        keys = key.split(".")
        current = self.data

        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default

        return current

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.

        Args:
            key: Configuration key (e.g., "waf.port")
            value: Value to set

        Examples:
            >>> config.set("waf.port", 9090)
            >>> config.set("core.mode", "full")
        """
        keys = key.split(".")
        current = self.data

        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        current[keys[-1]] = value
        self._validate()

    def enable_layer(self, layer: str):
        """Enable a specific layer."""
        if layer in self.data:
            self.data[layer]["enabled"] = True

    def disable_layer(self, layer: str):
        """Disable a specific layer."""
        if layer in self.data:
            self.data[layer]["enabled"] = False

    def is_layer_enabled(self, layer: str) -> bool:
        """Check if a layer is enabled."""
        return self.data.get(layer, {}).get("enabled", False)

    def get_enabled_layers(self) -> list:
        """Get list of enabled layers."""
        layers = ["waf", "code_protection", "crypto", "monitor",
                   "anti_cheat", "scanner", "disassembler", "emulator", "hooker"]
        return [layer for layer in layers if self.is_layer_enabled(layer)]

    # BunkerWeb-specific helpers
    def enable_bunkerweb(self, target_url: str = "http://localhost:8000", listen_port: int = 8080):
        """Enable BunkerWeb engine for WAF."""
        self.data["waf"]["enabled"] = True
        self.data["waf"]["engine"] = "bunkerweb"
        self.data["waf"]["bunkerweb"]["enabled"] = True
        self.data["waf"]["bunkerweb"]["target_url"] = target_url
        self.data["waf"]["bunkerweb"]["listen_port"] = listen_port

    def disable_bunkerweb(self):
        """Disable BunkerWeb and fall back to Python engine."""
        self.data["waf"]["engine"] = "python"
        self.data["waf"]["bunkerweb"]["enabled"] = False

    def is_bunkerweb_enabled(self) -> bool:
        """Check if BunkerWeb engine is active."""
        return (self.data["waf"]["enabled"] and
                self.data["waf"]["engine"] == "bunkerweb" and
                self.data["waf"]["bunkerweb"]["enabled"])

    # ==========================================
    # Utility Methods
    # ==========================================

    def copy(self) -> "IronStackConfig":
        """Create a deep copy of the configuration."""
        return IronStackConfig(
            data=deepcopy(self.data),
            config_path=self.config_path,
        )

    def reset(self):
        """Reset configuration to defaults."""
        self.data = deepcopy(DEFAULT_CONFIG)
        self.config_path = None

    def merge(self, other: Union[Dict[str, Any], "IronStackConfig"]):
        """
        Merge another configuration into this one.

        Args:
            other: Configuration dictionary or IronStackConfig instance
        """
        if isinstance(other, IronStackConfig):
            other_data = other.data
        else:
            other_data = other

        self.data = self._deep_merge(self.data, other_data)
        self._validate()

    @staticmethod
    def _deep_merge(base: Dict, override: Dict) -> Dict:
        """
        Deep merge two dictionaries.

        Args:
            base: Base dictionary
            override: Override dictionary

        Returns:
            Merged dictionary
        """
        result = deepcopy(base)

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = IronStackConfig._deep_merge(result[key], value)
            else:
                result[key] = deepcopy(value)

        return result

    @staticmethod
    def _convert_env_value(value: str) -> Any:
        """
        Convert environment variable string to appropriate type.

        Args:
            value: String value from environment

        Returns:
            Converted value (bool, int, float, or str)
        """
        # Boolean
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # Integer
        try:
            return int(value)
        except ValueError:
            pass

        # Float
        try:
            return float(value)
        except ValueError:
            pass

        # List (comma-separated)
        if "," in value:
            return [item.strip() for item in value.split(",")]

        # String
        return value

    # ==========================================
    # Magic Methods
    # ==========================================

    def __repr__(self) -> str:
        enabled = self.get_enabled_layers()
        return f"IronStackConfig(layers={enabled})"

    def __str__(self) -> str:
        lines = ["IronStack Configuration:", "=" * 40]
        lines.append(f"Mode: {self.data['core']['mode']}")
        lines.append(f"Enabled layers: {', '.join(self.get_enabled_layers()) or 'none'}")

        if self.config_path:
            lines.append(f"Config file: {self.config_path}")

        return "\n".join(lines)

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style access."""
        return self.get(key)

    def __setitem__(self, key: str, value: Any):
        """Allow dictionary-style setting."""
        self.set(key, value)

    def __contains__(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None


# ==========================================
# Helper Functions
# ==========================================

def load_config(path: Optional[Union[str, Path]] = None) -> IronStackConfig:
    """
    Load configuration from file, environment, or defaults.

    Priority:
    1. Explicit file path
    2. IRONSTACK_CONFIG environment variable
    3. ./ironstack.yaml
    4. ./ironstack.yml
    5. ./ironstack.json
    6. Default configuration

    Args:
        path: Optional explicit config file path

    Returns:
        IronStackConfig instance
    """
    # Explicit path
    if path:
        return IronStackConfig.from_file(path)

    # Environment variable
    env_config = os.environ.get("IRONSTACK_CONFIG")
    if env_config and Path(env_config).exists():
        return IronStackConfig.from_file(env_config)

    # Common config file locations
    common_paths = [
        Path("ironstack.yaml"),
        Path("ironstack.yml"),
        Path("ironstack.json"),
        Path("config/ironstack.yaml"),
        Path("config/ironstack.yml"),
        Path("config/ironstack.json"),
    ]

    for config_path in common_paths:
        if config_path.exists():
            return IronStackConfig.from_file(config_path)

    # Check for environment variables
    if any(key.startswith("IRONSTACK_") for key in os.environ):
        return IronStackConfig.from_env()

    # Default
    return IronStackConfig()