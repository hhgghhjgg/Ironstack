#!/usr/bin/env python3
"""
Core module for IronStack - Main class and quick access functions.
"""

import os
import sys
import logging
from typing import Optional, Dict, Any, List, Union
from pathlib import Path

from .config import IronStackConfig
from .exceptions import (
    IronStackError,
    IronStackConfigError,
    IronStackProtectionError,
    IronStackScanError,
    LayerNotAvailableError,
)
from .logging_config import setup_logging, get_logger

# Setup logger
logger = get_logger(__name__)


class IronStack:
    """
    IronStack - Security Swiss Army Knife.
    
    A unified security library that combines WAF, Code Protection,
    Anti-Cheat, and Red Team tools in one easy-to-use package.
    
    Attributes:
        mode (str): Operation mode - "defense", "attack", or "full"
        version (str): Current version of IronStack
        config (IronStackConfig): Configuration object
    
    Basic Usage:
        >>> from ironstack import IronStack
        >>> is_stack = IronStack(mode="defense")
        >>> is_stack.protect("./my-project")
    
    Advanced Usage:
        >>> is_stack = IronStack(mode="full", config="ironstack.yaml")
        >>> is_stack.enable_waf(port=8080)
        >>> is_stack.enable_code_protection()
        >>> is_stack.scan("https://example.com")
    """
    
    def __init__(
        self,
        mode: str = "defense",
        config: Optional[Union[str, Dict[str, Any]]] = None,
        verbose: bool = False,
        debug: bool = False,
    ):
        """
        Initialize IronStack.
        
        Args:
            mode: Operation mode.
                - "defense": Only defensive tools (WAF, code protection, anti-cheat)
                - "attack": Only offensive tools (scanner, hooks, disassembler)
                - "full": All tools enabled
            config: Path to config file or config dictionary
            verbose: Enable verbose output
            debug: Enable debug mode
        
        Raises:
            IronStackConfigError: If configuration is invalid
        """
        self._version = "0.1.0"
        self._mode = mode.lower()
        self._verbose = verbose
        self._debug = debug
        
        # Validate mode
        valid_modes = ["defense", "attack", "full"]
        if self._mode not in valid_modes:
            raise IronStackConfigError(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}"
            )
        
        # Setup logging
        self._log_level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
        setup_logging(level=self._log_level)
        
        # Load configuration
        self.config = self._load_config(config)
        
        # Initialize layers
        self._layers = {
            # Defense layers
            "waf": None,
            "protector": None,
            "crypto": None,
            "monitor": None,
            "anti_cheat": None,
            # Attack layers
            "scanner": None,
            "hooker": None,
            "disassembler": None,
            "emulator": None,
        }
        
        # Track active layers
        self._active_layers = []
        
        # Statistics
        self._stats = {
            "requests_checked": 0,
            "threats_blocked": 0,
            "files_protected": 0,
            "scans_performed": 0,
            "vulnerabilities_found": 0,
        }
        
        logger.info(f"🛡️ IronStack v{self._version} initialized in '{self._mode}' mode")
        
        # Auto-enable layers based on mode
        self._auto_enable_layers()
    
    def _load_config(self, config: Optional[Union[str, Dict[str, Any]]]) -> IronStackConfig:
        """
        Load configuration from file or dictionary.
        
        Args:
            config: Path to config file or config dictionary
            
        Returns:
            IronStackConfig object
        
        Raises:
            IronStackConfigError: If config file not found or invalid
        """
        if config is None:
            return IronStackConfig()
        
        if isinstance(config, dict):
            return IronStackConfig.from_dict(config)
        
        if isinstance(config, str):
            config_path = Path(config)
            if not config_path.exists():
                raise IronStackConfigError(f"Config file not found: {config}")
            return IronStackConfig.from_file(config_path)
        
        raise IronStackConfigError(f"Invalid config type: {type(config)}")
    
    def _auto_enable_layers(self):
        """Auto-enable layers based on mode."""
        if self._mode in ["defense", "full"]:
            self._activate_defense_layers()
        
        if self._mode in ["attack", "full"]:
            self._activate_attack_layers()
    
    def _activate_defense_layers(self):
        """Activate defense layers."""
        # These will be fully implemented when each layer module is built
        logger.info("Defense layers ready (WAF, Protector, Crypto, Monitor, Anti-Cheat)")
    
    def _activate_attack_layers(self):
        """Activate attack layers."""
        # These will be fully implemented when each layer module is built
        logger.info("Attack layers ready (Scanner, Hooker, Disassembler, Emulator)")
    
    # ==========================================
    # Public API - Quick Protect
    # ==========================================
    
    def protect(self, target: str) -> Dict[str, Any]:
        """
        Protect a project, file, or endpoint.
        
        Automatically detects the target type and applies appropriate protection.
        
        Args:
            target: Path to project/file or URL to protect
            
        Returns:
            Dictionary with protection results
            
        Examples:
            >>> is_stack = IronStack()
            >>> result = is_stack.protect("./my-project")
            >>> print(result["status"])
            'success'
        """
        logger.info(f"🔒 Protecting: {target}")
        
        result = {
            "target": target,
            "timestamp": self._get_timestamp(),
            "mode": self._mode,
            "layers_applied": [],
            "status": "success",
            "details": {},
        }
        
        try:
            # Auto-detect target type
            target_type = self._detect_target_type(target)
            result["target_type"] = target_type
            
            if target_type == "web":
                self._protect_web(target, result)
            elif target_type == "python_code":
                self._protect_code(target, result)
            elif target_type == "binary":
                self._protect_binary(target, result)
            elif target_type == "project":
                self._protect_project(target, result)
            else:
                result["status"] = "error"
                result["error"] = f"Unknown target type: {target_type}"
        
        except Exception as e:
            logger.error(f"Protection failed: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            raise IronStackProtectionError(f"Failed to protect {target}: {e}") from e
        
        return result
    
    def _detect_target_type(self, target: str) -> str:
        """
        Auto-detect target type.
        
        Args:
            target: Target path or URL
            
        Returns:
            Target type string
        """
        # Check if URL
        if target.startswith(("http://", "https://")):
            return "web"
        
        # Check if Python file
        if target.endswith(".py"):
            return "python_code"
        
        # Check if binary
        binary_extensions = [".exe", ".dll", ".so", ".dylib", ".bin"]
        if any(target.endswith(ext) for ext in binary_extensions):
            return "binary"
        
        # Check if directory (project)
        if os.path.isdir(target):
            return "project"
        
        # Check if file exists
        if os.path.isfile(target):
            return "file"
        
        return "unknown"
    
    def _protect_web(self, target: str, result: Dict[str, Any]):
        """Protect a web endpoint."""
        result["layers_applied"].append("waf")
        result["details"]["waf"] = {"url": target, "status": "configured"}
        logger.info(f"✅ Web protection configured for {target}")
    
    def _protect_code(self, target: str, result: Dict[str, Any]):
        """Protect Python code."""
        result["layers_applied"].append("code_protection")
        result["details"]["code_protection"] = {"file": target, "status": "configured"}
        logger.info(f"✅ Code protection configured for {target}")
    
    def _protect_binary(self, target: str, result: Dict[str, Any]):
        """Protect binary file."""
        result["layers_applied"].append("binary_analysis")
        result["details"]["binary_analysis"] = {"file": target, "status": "configured"}
        logger.info(f"✅ Binary analysis configured for {target}")
    
    def _protect_project(self, target: str, result: Dict[str, Any]):
        """Protect entire project directory."""
        # Find all Python files
        py_files = list(Path(target).rglob("*.py"))
        result["layers_applied"].append("code_protection")
        result["details"]["project"] = {
            "path": target,
            "python_files": len(py_files),
            "status": "configured",
        }
        logger.info(f"✅ Project protection configured for {target} ({len(py_files)} Python files)")
    
    # ==========================================
    # Public API - Quick Scan
    # ==========================================
    
    def scan(self, target: str) -> Dict[str, Any]:
        """
        Scan a target for vulnerabilities.
        
        Args:
            target: URL, IP, or file path to scan
            
        Returns:
            Dictionary with scan results
            
        Examples:
            >>> is_stack = IronStack()
            >>> result = is_stack.scan("https://example.com")
            >>> print(result["findings"])
        """
        logger.info(f"🔍 Scanning: {target}")
        
        if self._mode not in ["attack", "full"]:
            raise LayerNotAvailableError(
                "Scanning requires 'attack' or 'full' mode. "
                f"Current mode: '{self._mode}'"
            )
        
        result = {
            "target": target,
            "timestamp": self._get_timestamp(),
            "status": "completed",
            "findings": [],
            "risk_score": 0,
            "details": {},
        }
        
        try:
            # Perform scan (placeholder - full implementation in scanner module)
            self._stats["scans_performed"] += 1
            result["scan_id"] = f"SCAN-{self._stats['scans_performed']:04d}"
            
            logger.info(f"✅ Scan completed for {target}")
        
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            result["status"] = "error"
            result["error"] = str(e)
            raise IronStackScanError(f"Failed to scan {target}: {e}") from e
        
        return result
    
    # ==========================================
    # Public API - Status
    # ==========================================
    
    def status(self) -> Dict[str, Any]:
        """
        Get current IronStack status.
        
        Returns:
            Dictionary with status information
            
        Examples:
            >>> is_stack = IronStack()
            >>> status = is_stack.status()
            >>> print(status["mode"])
            'defense'
        """
        return {
            "version": self._version,
            "mode": self._mode,
            "active_layers": self._active_layers,
            "layers": {
                name: "active" if layer else "inactive"
                for name, layer in self._layers.items()
            },
            "stats": self._stats,
            "config": self.config.to_dict(),
        }
    
    # ==========================================
    # Public API - Layer Management
    # ==========================================
    
    def enable_waf(self, **kwargs) -> "IronStack":
        """Enable Web Application Firewall layer."""
        logger.info("Enabling WAF layer...")
        # Will be fully implemented in defense/waf.py
        self._active_layers.append("waf")
        return self
    
    def enable_code_protection(self, **kwargs) -> "IronStack":
        """Enable Code Protection layer."""
        logger.info("Enabling Code Protection layer...")
        # Will be fully implemented in defense/protector.py
        self._active_layers.append("code_protection")
        return self
    
    def enable_anti_cheat(self, **kwargs) -> "IronStack":
        """Enable Anti-Cheat layer."""
        logger.info("Enabling Anti-Cheat layer...")
        # Will be fully implemented in defense/anti_cheat/
        self._active_layers.append("anti_cheat")
        return self
    
    def enable_scanner(self, **kwargs) -> "IronStack":
        """Enable Vulnerability Scanner layer."""
        if self._mode not in ["attack", "full"]:
            raise LayerNotAvailableError("Scanner requires attack/full mode")
        logger.info("Enabling Scanner layer...")
        # Will be fully implemented in attack/scanner.py
        self._active_layers.append("scanner")
        return self
    
    # ==========================================
    # Public API - Utilities
    # ==========================================
    
    def version_info(self) -> str:
        """Get version information string."""
        return f"IronStack v{self._version} ({self._mode} mode)"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics."""
        return self._stats.copy()
    
    def reset_stats(self):
        """Reset statistics."""
        for key in self._stats:
            self._stats[key] = 0
        logger.info("Statistics reset")
    
    def export_config(self, filepath: str):
        """
        Export current configuration to file.
        
        Args:
            filepath: Path to save configuration
        """
        self.config.to_file(filepath)
        logger.info(f"Configuration exported to {filepath}")
    
    # ==========================================
    # Internal Helpers
    # ==========================================
    
    def _get_timestamp(self) -> str:
        """Get ISO format timestamp."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()
    
    def __repr__(self) -> str:
        return f"IronStack(mode='{self._mode}', version='{self._version}')"
    
    def __str__(self) -> str:
        layers_count = len(self._active_layers)
        return f"🛡️ IronStack v{self._version} | Mode: {self._mode} | Active Layers: {layers_count}"
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup."""
        logger.info("IronStack shutting down...")
        # Cleanup will be added here
        return False


# ==========================================
# Module-level singleton
# ==========================================

_default_instance: Optional[IronStack] = None


def get_instance(mode: str = "defense", **kwargs) -> IronStack:
    """
    Get or create default IronStack instance.
    
    Args:
        mode: Operation mode
        **kwargs: Additional arguments for IronStack
        
    Returns:
        IronStack instance
    """
    global _default_instance
    if _default_instance is None:
        _default_instance = IronStack(mode=mode, **kwargs)
    return _default_instance


def reset_instance():
    """Reset the default instance."""
    global _default_instance
    _default_instance = None
    logger.info("Default instance reset")


# ==========================================
# Quick access functions
# ==========================================

def protect(target: str, mode: str = "defense", **kwargs) -> Dict[str, Any]:
    """
    Quick protect - single function call.
    
    This is the simplest way to use IronStack.
    
    Args:
        target: Path or URL to protect
        mode: Operation mode
        **kwargs: Additional arguments
        
    Returns:
        Protection results dictionary
        
    Examples:
        >>> import ironstack
        >>> ironstack.protect(".")
    """
    is_stack = get_instance(mode=mode, **kwargs)
    return is_stack.protect(target)


def scan(target: str, mode: str = "attack", **kwargs) -> Dict[str, Any]:
    """
    Quick scan - single function call.
    
    Args:
        target: URL, IP, or path to scan
        mode: Operation mode (must be 'attack' or 'full')
        **kwargs: Additional arguments
        
    Returns:
        Scan results dictionary
        
    Examples:
        >>> import ironstack
        >>> ironstack.scan("https://example.com")
    """
    is_stack = get_instance(mode=mode, **kwargs)
    return is_stack.scan(target)


def status(mode: str = "defense", **kwargs) -> Dict[str, Any]:
    """
    Quick status check.
    
    Args:
        mode: Operation mode
        **kwargs: Additional arguments
        
    Returns:
        Status dictionary
    """
    is_stack = get_instance(mode=mode, **kwargs)
    return is_stack.status()


def version_info() -> str:
    """Get version information."""
    return f"IronStack v0.1.0"
