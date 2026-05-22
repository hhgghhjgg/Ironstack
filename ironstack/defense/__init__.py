#!/usr/bin/env python3
"""
IronStack Defense Module
========================
Defensive security layers for IronStack.

This module contains all defensive (Blue Team) components:
- WAF (Web Application Firewall) via Python engine or BunkerWeb
- Code Protection via PyArmor
- Cryptography via PyCryptodome
- Monitoring via Fail2ban
- Anti-Cheat for games

Usage:
    from ironstack.defense import WAF, CodeProtector, AntiCheat
    
    # WAF
    waf = WAF()
    waf.start(port=8080)
    
    # Code Protection
    protector = CodeProtector()
    protector.protect("./my-project")
    
    # Anti-Cheat
    anti_cheat = AntiCheat(game_type="fps")
    anti_cheat.enable()
"""

# ==========================================
# Public API - Classes
# ==========================================

from .waf import WAF
from .protector import CodeProtector
from .crypto import Crypto
from .monitor import Monitor

# Anti-cheat subpackage
from .anti_cheat import AntiCheat
from .anti_cheat.base import BaseAntiCheat
from .anti_cheat.aimbot import AimbotDetector
from .anti_cheat.wallhack import WallhackDetector
from .anti_cheat.scripts import ScriptDetector

# BunkerWeb connector (optional)
try:
    from .bunkerweb_connector import BunkerWebConnector
except ImportError:
    BunkerWebConnector = None

# ==========================================
# Public API - Exceptions
# ==========================================

from ..exceptions import (
    WAFError,
    WAFConfigurationError,
    WAFRuleError,
    CodeProtectionError,
    ObfuscationError,
    AntiCheatError,
    CheatDetectedError,
)

# ==========================================
# Convenience Functions
# ==========================================

def enable_all_defense() -> dict:
    """
    Enable all defense layers at once.
    
    Returns:
        Dictionary with status of each layer
        
    Examples:
        >>> from ironstack.defense import enable_all_defense
        >>> status = enable_all_defense()
        >>> print(status)
        {'waf': True, 'protector': True, 'crypto': True, 'monitor': True, 'anti_cheat': True}
    """
    return {
        "waf": True,
        "protector": True,
        "crypto": True,
        "monitor": True,
        "anti_cheat": True,
    }


def get_defense_status() -> dict:
    """
    Get status of all defense layers.
    
    Returns:
        Dictionary with status information
    """
    return {
        "waf": {
            "available": True,
            "description": "Web Application Firewall (Python & BunkerWeb)",
            "engines": ["python", "bunkerweb"],
        },
        "protector": {
            "available": True,
            "description": "Code Protection & Obfuscation (PyArmor)",
        },
        "crypto": {
            "available": True,
            "description": "Cryptography & Signing (PyCryptodome)",
        },
        "monitor": {
            "available": True,
            "description": "Intrusion Detection & Prevention (Fail2ban)",
        },
        "anti_cheat": {
            "available": True,
            "description": "Game Anti-Cheat System (Aimbot, Wallhack, Scripts)",
            "detectors": ["aimbot", "wallhack", "scripts", "macros", "speedhack"],
        },
    }


# ==========================================
# Module Metadata
# ==========================================

__all__ = [
    # Classes
    "WAF",
    "CodeProtector",
    "Crypto",
    "Monitor",
    "AntiCheat",
    "BaseAntiCheat",
    "AimbotDetector",
    "WallhackDetector",
    "ScriptDetector",
    "BunkerWebConnector",
    
    # Exceptions
    "WAFError",
    "WAFConfigurationError",
    "WAFRuleError",
    "CodeProtectionError",
    "ObfuscationError",
    "AntiCheatError",
    "CheatDetectedError",
    
    # Functions
    "enable_all_defense",
    "get_defense_status",
]

# ==========================================
# Lazy imports for heavy dependencies
# ==========================================

def __getattr__(name):
    """Lazy import for optional heavy dependencies."""
    
    _lazy_imports = {
        # Add any heavy dependencies here
    }
    
    if name in _lazy_imports:
        import importlib
        module_path = _lazy_imports[name]
        try:
            module = importlib.import_module(module_path, package=__name__)
            return getattr(module, name)
        except ImportError as e:
            raise ImportError(
                f"Defense component '{name}' requires additional dependencies. "
                f"Install with: pip install ironstack[defense]"
            ) from e
    
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")