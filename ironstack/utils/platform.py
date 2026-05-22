#!/usr/bin/env python3
"""
Platform detection and system information utilities for IronStack.
"""

import os
import sys
import platform
import socket
import struct
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from ..logging_config import get_logger

logger = get_logger(__name__)


# ==========================================
# Platform Detection
# ==========================================

def is_windows() -> bool:
    """Check if running on Windows."""
    return platform.system() == "Windows"


def is_linux() -> bool:
    """Check if running on Linux."""
    return platform.system() == "Linux"


def is_macos() -> bool:
    """Check if running on macOS."""
    return platform.system() == "Darwin"


def is_unix() -> bool:
    """Check if running on Unix-like system (Linux, macOS, BSD)."""
    return platform.system() in ("Linux", "Darwin", "FreeBSD", "OpenBSD", "NetBSD")


def is_64bit() -> bool:
    """Check if running on 64-bit system."""
    return sys.maxsize > 2**32


def get_arch() -> str:
    """
    Get CPU architecture.
    
    Returns:
        Architecture string (x86, x64, arm, arm64, etc.)
    """
    machine = platform.machine().lower()
    
    arch_map = {
        "x86_64": "x64",
        "amd64": "x64",
        "i386": "x86",
        "i486": "x86",
        "i586": "x86",
        "i686": "x86",
        "x86": "x86",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "arm",
        "armv6l": "arm",
        "armv8l": "arm64",
        "ppc64le": "ppc64",
        "s390x": "s390x",
    }
    
    return arch_map.get(machine, machine)


def get_python_version() -> Dict[str, Any]:
    """
    Get Python version information.
    
    Returns:
        Dictionary with Python version details
    """
    return {
        "version": platform.python_version(),
        "major": sys.version_info.major,
        "minor": sys.version_info.minor,
        "micro": sys.version_info.micro,
        "release_level": sys.version_info.releaselevel,
        "implementation": platform.python_implementation(),
        "compiler": platform.python_compiler(),
        "executable": sys.executable,
    }


def get_platform_info() -> Dict[str, Any]:
    """
    Get comprehensive platform information.
    
    Returns:
        Dictionary with platform details
    """
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "architecture": get_arch(),
        "is_64bit": is_64bit(),
        "is_windows": is_windows(),
        "is_linux": is_linux(),
        "is_macos": is_macos(),
        "hostname": socket.gethostname(),
        "python": get_python_version(),
        "processor": platform.processor(),
    }


# ==========================================
# System Information
# ==========================================

def get_system_info() -> Dict[str, Any]:
    """
    Get detailed system information.
    
    Returns:
        Dictionary with system details
    """
    info = {
        "platform": get_platform_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disk": get_disk_info(),
        "network": get_network_info(),
        "environment": get_env_summary(),
    }
    
    return info


def get_cpu_info() -> Dict[str, Any]:
    """
    Get CPU information.
    
    Returns:
        Dictionary with CPU details
    """
    cpu_info = {
        "count": os.cpu_count(),
        "physical_cores": None,
        "logical_cores": os.cpu_count(),
    }
    
    try:
        import psutil
        cpu_info["physical_cores"] = psutil.cpu_count(logical=False)
        cpu_info["logical_cores"] = psutil.cpu_count(logical=True)
        cpu_info["percent_used"] = psutil.cpu_percent(interval=1)
        cpu_info["frequency_mhz"] = psutil.cpu_freq().current if psutil.cpu_freq() else None
    except ImportError:
        pass
    
    if is_linux():
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if "model name" in line:
                        cpu_info["model"] = line.split(":")[1].strip()
                        break
        except Exception:
            pass
    elif is_windows():
        cpu_info["model"] = platform.processor()
    elif is_macos():
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True, text=True,
            )
            cpu_info["model"] = result.stdout.strip()
        except Exception:
            pass
    
    return cpu_info


def get_memory_info() -> Dict[str, Any]:
    """
    Get memory information.
    
    Returns:
        Dictionary with memory details
    """
    memory_info = {
        "total_bytes": 0,
        "available_bytes": 0,
        "used_bytes": 0,
        "percent_used": 0,
        "total_human": "Unknown",
        "av