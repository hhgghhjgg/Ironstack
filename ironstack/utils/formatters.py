#!/usr/bin/env python3
"""
Data formatting and conversion utilities for IronStack.
"""

import json
import time
import datetime
from typing import Any, Optional, Union, Dict, List

from ..logging_config import get_logger

logger = get_logger(__name__)


# ==========================================
# Byte Formatting
# ==========================================

def format_bytes(
    size: Union[int, float],
    precision: int = 2,
    binary: bool = True,
) -> str:
    """
    Format byte size to human-readable string.
    
    Args:
        size: Size in bytes
        precision: Number of decimal places
        binary: Use binary (1024) or decimal (1000) units
        
    Returns:
        Formatted string
        
    Examples:
        >>> format_bytes(1024)
        '1.00 KB'
        >>> format_bytes(1048576)
        '1.00 MB'
    """
    if size < 0:
        return "0 B"
    
    if binary:
        base = 1024
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    else:
        base = 1000
        units = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    
    for unit in units:
        if size < base or unit == units[-1]:
            return f"{size:.{precision}f} {unit}"
        size /= base
    
    return f"{size:.{precision}f} {units[-1]}"


def parse_bytes(size_str: str) -> int:
    """
    Parse a human-readable byte string to integer.
    
    Args:
        size_str: Size string (e.g., "1.5 GB", "500MB")
        
    Returns:
        Size in bytes
    """
    if not size_str:
        return 0
    
    size_str = size_str.strip().upper()
    
    units = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3,
             "TB": 1024**4, "PB": 1024**5, "KIB": 1024, "MIB": 1024**2,
             "GIB": 1024**3, "TIB": 1024**4}
    
    import re
    match = re.match(r'^([\d.]+)\s*([A-Z]+)$', size_str)
    
    if not match:
        return 0
    
    number = float(match.group(1))
    unit = match.group(2)
    
    if unit in units:
        return int(number * units[unit])
    
    return int(number)


# ==========================================
# Time Formatting
# ==========================================

def format_duration(
    seconds: Union[int, float],
    show_ms: bool = False,
    compact: bool = False,
) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        show_ms: Include milliseconds
        compact: Use compact format (e.g., "1h2m3s")
        
    Returns:
        Formatted string
    """
    if seconds < 0:
        return "0s" if compact else "0 seconds"
    
    ms = int((seconds % 1) * 1000)
    seconds = int(seconds)
    
    periods = [
        ("year", "y", 365 * 24 * 3600),
        ("month", "mo", 30 * 24 * 3600),
        ("week", "w", 7 * 24 * 3600),
        ("day", "d", 24 * 3600),
        ("hour", "h", 3600),
        ("minute", "m", 60),
        ("second", "s", 1),
    ]
    
    parts = []
    
    for long_name, short_name, period_seconds in periods:
        if seconds >= period_seconds:
            value = seconds // period_seconds
            seconds %= period_seconds
            
            if compact:
                parts.append(f"{value}{short_name}")
            else:
                name = long_name if value == 1 else long_name + "s"
                parts.append(f"{value} {name}")
    
    if show_ms and ms > 0:
        parts.append(f"{ms}ms")
    
    if not parts:
        return "0s" if compact else "0 seconds"
    
    return " ".join(parts) if compact else ", ".join(parts)


def format_timestamp(
    timestamp: Optional[Union[int, float]] = None,
    format: str = "%Y-%m-%d %H:%M:%S",
    utc: bool = True,
) -> str:
    """
    Format a Unix timestamp to string.
    
    Args:
        timestamp: Unix timestamp (uses current time if None)
        format: Date format string
        utc: Use UTC timezone
        
    Returns:
        Formatted date string
    """
    if timestamp is None:
        timestamp = time.time()
    
    if utc:
        dt = datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    else:
        dt = datetime.datetime.fromtimestamp(timestamp)
    
    return dt.strftime(format)


def time_ago(timestamp: Union[int, float]) -> str:
    """
    Get relative time description (e.g., "2 minutes ago").
    
    Args:
        timestamp: Unix timestamp
        
    Returns:
        Relative time string
    """
    now = time.time()
    diff = now - timestamp
    
    if diff < 0:
        return "in the future"
    elif diff < 10:
        return "just now"
    elif diff < 60:
        secs = int(diff)
        return f"{secs} second{'s' if secs != 1 else ''} ago"
    elif diff < 3600:
        mins = int(diff / 60)
        return f"{mins} minute{'s' if mins != 1 else ''} ago"
    elif diff < 86400:
        hours = int(diff / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    elif diff < 2592000:
        days = int(diff /