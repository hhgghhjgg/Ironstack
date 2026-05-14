#!/usr/bin/env python3
"""
IronStack Attack Module
=======================
Offensive security (Red Team) tools for IronStack.

This module contains all offensive security components:
- Vulnerability Scanner (SQLMap, Nmap integration)
- Dynamic Instrumentation (Frida hooks)
- Disassembler (Capstone)
- Emulator (Unicorn)

These tools are for AUTHORIZED security testing only.
Always obtain proper permission before scanning targets.

Usage:
    from ironstack.attack import Scanner, Hooker, Disassembler, Emulator
    
    # Scan for vulnerabilities
    scanner = Scanner()
    result = scanner.scan_web("https://example.com")
    
    # Hook a process
    hooker = Hooker()
    hooker.attach(pid=1234)
    
    # Disassemble binary
    disasm = Disassembler()
    code = disasm.disassemble(binary_data)
    
    # Emulate code
    emulator = Emulator()
    emulator.run(shellcode)
"""

import warnings

# Show warning about responsible use
warnings.warn(
    "IronStack Attack module contains offensive security tools. "
    "Use only on systems you own or have explicit permission to test. "
    "Unauthorized use may violate laws and regulations.",
    UserWarning,
    stacklevel=2,
)

# ==========================================
# Public API - Classes
# ==========================================

from .scanner import Scanner
from .hooker import Hooker
from .disassembler import Disassembler
from .emulator import Emulator

# ==========================================
# Public API - Exceptions
# ==========================================

from ..exceptions import (
    IronStackScanError,
    ScanFailedError,
    ScanTimeoutError,
    VulnerabilityFoundError,
    ConnectionError,
)

# ==========================================
# Convenience Functions
# ==========================================

def quick_scan(target: str, scan_type: str = "web") -> dict:
    """
    Perform a quick security scan.
    
    Args:
        target: Target URL or IP
        scan_type: Type of scan (web, network, sql)
        
    Returns:
        Scan results dictionary
        
    Examples:
        >>> from ironstack.attack import quick_scan
        >>> result = quick_scan("https://example.com", "web")
        >>> print(result["findings"])
    """
    scanner = Scanner()
    
    if scan_type == "web":
        return scanner.scan_web(target)
    elif scan_type == "network":
        return scanner.scan_network(target)
    elif scan_type == "sql":
        return scanner.scan_sql_injection(target)
    else:
        return {"error": f"Unknown scan type: {scan_type}"}


def get_attack_status() -> dict:
    """
    Get status of all attack modules.
    
    Returns:
        Dictionary with status information
    """
    status = {
        "scanner": {
            "available": True,
            "description": "Vulnerability Scanner (SQLMap, Nmap)",
            "capabilities": [
                "web_scanning",
                "sql_injection_testing",
                "port_scanning",
                "service_detection",
            ],
        },
        "hooker": {
            "available": _check_frida_available(),
            "description": "Dynamic Instrumentation (Frida)",
            "capabilities": [
                "process_hooking",
                "function_interception",
                "memory_analysis",
                "runtime_modification",
            ],
        },
        "disassembler": {
            "available": _check_capstone_available(),
            "description": "Binary Disassembler (Capstone)",
            "capabilities": [
                "x86_disassembly",
                "x64_disassembly",
                "arm_disassembly",
                "arm64_disassembly",
            ],
        },
        "emulator": {
            "available": _check_unicorn_available(),
            "description": "CPU Emulator (Unicorn)",
            "capabilities": [
                "code_emulation",
                "shellcode_analysis",
                "sandbox_execution",
            ],
        },
    }
    return status


def _check_frida_available() -> bool:
    """Check if Frida is available."""
    try:
        import frida
        return True
    except ImportError:
        return False


def _check_capstone_available() -> bool:
    """Check if Capstone is available."""
    try:
        import capstone
        return True
    except ImportError:
        return False


def _check_unicorn_available() -> bool:
    """Check if Unicorn is available."""
    try:
        import unicorn
        return True
    except ImportError:
        return False


# ==========================================
# Module Metadata
# ==========================================

__all__ = [
    # Classes
    "Scanner",
    "Hooker",
    "Disassembler",
    "Emulator",
    
    # Functions
    "quick_scan",
    "get_attack_status",
    
    # Exceptions
    "IronStackScanError",
    "ScanFailedError",
    "ScanTimeoutError",
    "VulnerabilityFoundError",
    "ConnectionError",
]

# ==========================================
# Version Information
# ==========================================

ATTACK_MODULE_VERSION = "0.1.0"

# ==========================================
# Lazy imports for heavy dependencies
# ==========================================

def __getattr__(name):
    """Lazy import for heavy dependencies."""
    
    _lazy_imports = {
        # Add heavy dependency imports here if needed
    }
    
    if name in _lazy_imports:
        import importlib
        module_path = _lazy_imports[name]
        try:
            module = importlib.import_module(module_path, package=__name__)
            return getattr(module, name)
        except ImportError as e:
            raise ImportError(
                f"Attack component '{name}' requires additional dependencies. "
                f"Install with: pip install ironstack[attack]"
            ) from e
    
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
