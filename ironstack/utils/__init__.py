#!/usr/bin/env python3
"""
IronStack Utilities Module
==========================
Utility functions and helpers for IronStack.

This module provides common utilities used across all IronStack layers:
- Input validation and sanitization
- Data formatting and conversion
- Platform detection and compatibility

Usage:
    from ironstack.utils import validate_ip, format_bytes, get_platform_info
"""

# ==========================================
# Public API
# ==========================================

from .validators import (
    validate_ip,
    validate_url,
    validate_email,
    validate_port,
    validate_file_path,
    validate_json,
    sanitize_input,
    sanitize_html,
    sanitize_sql,
    is_valid_ip,
    is_valid_url,
    is_valid_email,
)

from .formatters import (
    format_bytes,
    format_duration,
    format_timestamp,
    format_table,
    format_json_pretty,
    format_list,
    format_percentage,
    truncate_string,
    colorize_severity,
    to_json,
    from_json,
)

from .platform import (
    get_platform_info,
    is_windows,
    is_linux,
    is_macos,
    is_64bit,
    get_python_version,
    get_arch,
    check_dependency,
    get_system_info,
)

# ==========================================
# What gets exported
# ==========================================

__all__ = [
    # Validators
    "validate_ip",
    "validate_url",
    "validate_email",
    "validate_port",
    "validate_file_path",
    "validate_json",
    "sanitize_input",
    "sanitize_html",
    "sanitize_sql",
    "is_valid_ip",
    "is_valid_url",
    "is_valid_email",
    
    # Formatters
    "format_bytes",
    "format_duration",
    "format_timestamp",
    "format_table",
    "format_json_pretty",
    "format_list",
    "format_percentage",
    "truncate_string",
    "colorize_severity",
    "to_json",
    "from_json",
    
    # Platform
    "get_platform_info",
    "is_windows",
    "is_linux",
    "is_macos",
    "is_64bit",
    "get_python_version",
    "get_arch",
    "check_dependency",
    "get_system_info",
]
