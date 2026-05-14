#!/usr/bin/env python3
"""
Input validation and sanitization utilities for IronStack.
"""

import re
import json
import ipaddress
import html as html_module
from pathlib import Path
from typing import Any, Optional, Union, Dict, List
from urllib.parse import urlparse

from ..logging_config import get_logger

logger = get_logger(__name__)


# ==========================================
# Regular Expressions
# ==========================================

IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

IPV6_PATTERN = re.compile(
    r'^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'
    r'\[?(?:[0-9a-fA-F]{1,4}:){1,7}:|'
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|'
    r'(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|'
    r'[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|'
    r':(?::[0-9a-fA-F]{1,4}){1,7}|'
    r'fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|'
    r'::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

URL_PATTERN = re.compile(
    r'^(https?|ftp)://'
    r'[^\s/$.?#].[^\s]*$',
    re.IGNORECASE,
)

EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
)

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

HASH_PATTERNS = {
    "md5": re.compile(r'^[a-fA-F0-9]{32}$'),
    "sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
    "sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
    "sha512": re.compile(r'^[a-fA-F0-9]{128}$'),
}

SQL_KEYWORDS = [
    "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
    "ALTER", "TRUNCATE", "UNION", "JOIN", "WHERE", "FROM",
    "EXEC", "EXECUTE", "DECLARE", "CAST", "CONVERT",
]

XSS_PATTERNS = [
    re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript\s*:', re.IGNORECASE),
    re.compile(r'on\w+\s*=\s*["\'].*?["\']', re.IGNORECASE),
    re.compile(r'<iframe[^>]*>', re.IGNORECASE),
    re.compile(r'<embed[^>]*>', re.IGNORECASE),
    re.compile(r'<object[^>]*>', re.IGNORECASE),
    re.compile(r'eval\s*\(', re.IGNORECASE),
    re.compile(r'document\.cookie', re.IGNORECASE),
]


# ==========================================
# IP Validation
# ==========================================

def validate_ip(ip: str) -> Dict[str, Any]:
    """
    Validate an IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address string
        
    Returns:
        Dictionary with validation result
        
    Examples:
        >>> validate_ip("192.168.1.1")
        {'valid': True, 'version': 4, 'ip': '192.168.1.1'}
        >>> validate_ip("invalid")
        {'valid': False, 'error': 'Invalid IP address'}
    """
    ip = ip.strip()
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return {
            "valid": True,
            "version": ip_obj.version,
            "ip": str(ip_obj),
            "is_private": ip_obj.is_private,
            "is_loopback": ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
        }
    except ValueError:
        return {
            "valid": False,
            "error": "Invalid IP address",
            "ip": ip,
        }


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    return validate_ip(ip)["valid"]


# ==========================================
# URL Validation
# ==========================================

def validate_url(url: str) -> Dict[str, Any]:
    """
    Validate a URL.
    
    Args:
        url: URL string
        
    Returns:
        Dictionary with validation result
        
    Examples:
        >>> validate_url("https://example.com")
        {'valid': True, 'scheme': 'https', 'host': 'example.com'}
    """
    url = url.strip()
    
    if not url:
        return {"valid": False, "error": "Empty URL"}
    
    if not URL_PATTERN.match(url):
        return {"valid": False, "error": "Invalid URL format", "url": url}
    
    try:
        parsed = urlparse(url)
        
        return {
            "valid": True,
            "url": url,
            "scheme": parsed.scheme,
            "host": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path or "/",
            "query": parsed.query,
            "fragment": parsed.fragment,
        }
    except Exception as e:
        return {"valid": False, "error": str(e), "url": url}


def is_valid_url(url: str) -> bool:
    """Check if string is a valid URL."""
    return validate_url(url)["valid"]


# ==========================================
# Email Validation
# ==========================================

def validate_email(email: str) -> Dict[str, Any]:
    """
    Validate an email address.
    
    Args:
        email: Email address string
        
    Returns:
        Dictionary with validation result
        
    Examples:
        >>> validate_email("user@example.com")
        {'valid': True, 'local_part': 'user', 'domain': 'example.com'}
    """
    email = email.strip().lower()
    
    if not email:
        return {"valid": False, "error": "Empty email address"}
    
    if len(email) > 254:
        return {"valid": False, "error": "Email address too long"}
    
    if not EMAIL_PATTERN.match(email):
        return {"valid": False, "error": "Invalid email format"}
    
    local_part, domain = email.split("@")
    
    if len(local_part) > 64:
        return {"valid": False, "error": "Local part too long"}
    
    return {
        "valid": True,
        "email": email,
        "local_part": local_part,
        "domain": domain,
    }


def is_valid_email(email: str) -> bool:
    """Check if string is a valid email address."""
    return validate_email(email)["valid"]


# ==========================================
# Port Validation
# ==========================================

def validate_port(port: Union[int, str]) -> Dict[str, Any]:
    """
    Validate a port number.
    
    Args:
        port: Port number
        
    Returns:
        Dictionary with validation result
        
    Examples:
        >>> validate_port(8080)
        {'valid': True, 'port': 8080}
        >>> validate_port(99999)
        {'valid': False, 'error': 'Port must be between 1 and 65535'}
    """
    try:
        port_num = int(port)
    except (ValueError, TypeError):
        return {"valid": False, "error": "Port must be a number"}
    
    if not 1 <= port_num <= 65535:
        return {
            "valid": False,
            "error": "Port must be between 1 and 65535",
            "port": port_num,
        }
    
    # Well-known ports warning
    is_well_known = port_num < 1024
    
    return {
        "valid": True,
        "port": port_num,
        "is_well_known": is_well_known,
        "is_registered": 1024 <= port_num <= 49151,
        "is_dynamic": port_num > 49151,
    }


# ==========================================
# File Path Validation
# ==========================================

def validate_file_path(path: Union[str, Path]) -> Dict[str, Any]:
    """
    Validate a file path.
    
    Args:
        path: File path string or Path object
        
    Returns:
        Dictionary with validation result
    """
    try:
        path = Path(path)
        
        # Check for path traversal
        path_str = str(path)
        if ".." in path_str.split(path_str.replace("\\", "/")):
            return {"valid": False, "error": "Path traversal detected"}
        
        exists = path.exists()
        is_file = path.is_file() if exists else False
        is_dir = path.is_dir() if exists else False
        
        return {
            "valid": True,
            "path": str(path.absolute()),
            "exists": exists,
            "is_file": is_file,
            "is_dir": is_dir,
            "name": path.name,
            "suffix": path.suffix,
            "parent": str(path.parent),
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


# ==========================================
# JSON Validation
# ==========================================

def validate_json(data: Union[str, bytes, Dict, List]) -> Dict[str, Any]:
    """
    Validate JSON data.
    
    Args:
        data: JSON string, bytes, or parsed object
        
    Returns:
        Dictionary with validation result
        
    Examples:
        >>> validate_json('{"key": "value"}')
        {'valid': True, 'type': 'object'}
        >>> validate_json('invalid')
        {'valid': False, 'error': 'Invalid JSON'}
    """
    if isinstance(data, (dict, list)):
        return {
            "valid": True,
            "type": "object" if isinstance(data, dict) else "array",
        }
    
    if isinstance(data, bytes):
        data = data.decode("utf-8", errors="ignore")
    
    if not isinstance(data, str):
        return {"valid": False, "error": "Input must be string or parsed object"}
    
    try:
        parsed = json.loads(data)
        return {
            "valid": True,
            "type": "object" if isinstance(parsed, dict) else "array",
        }
    except json.JSONDecodeError as e:
        return {
            "valid": False,
            "error": f"Invalid JSON: {e}",
        }


# ==========================================
# Input Sanitization
# ==========================================

def sanitize_input(
    value: str,
    strip: bool = True,
    lower: bool = False,
    max_length: Optional[int] = None,
    allowed_chars: Optional[str] = None,
) -> str:
    """
    Sanitize general input.
    
    Args:
        value: Input string
        strip: Strip whitespace
        lower: Convert to lowercase
        max_length: Truncate to max length
        allowed_chars: Regex of allowed characters
        
    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        value = str(value)
    
    if strip:
        value = value.strip()
    
    if lower:
        value = value.lower()
    
    if allowed_chars:
        value = re.sub(f"[^{re.escape(allowed_chars)}]", "", value)
    
    if max_length and len(value) > max_length:
        value = value[:max_length]
    
    return value


def sanitize_html(html_str: str) -> str:
    """
    Sanitize HTML to prevent XSS.
    
    Args:
        html_str: HTML string
        
    Returns:
        Sanitized HTML string
    """
    if not html_str:
        return ""
    
    # Escape HTML entities
    sanitized = html_module.escape(html_str, quote=True)
    
    # Remove known XSS patterns
    for pattern in XSS_PATTERNS:
        sanitized = pattern.sub("", sanitized)
    
    return sanitized


def sanitize_sql(value: str) -> str:
    """
    Sanitize input for SQL queries.
    
    Note: This is a basic sanitizer. Use parameterized queries
    (prepared statements) for real SQL injection prevention.
    
    Args:
        value: Input string
        
    Returns:
        Sanitized string
    """
    if not value:
        return ""
    
    # Escape single quotes
    sanitized = value.replace("'", "''")
    
    # Escape backslashes
    sanitized = sanitized.replace("\\", "\\\\")
    
    # Remove SQL comments
    sanitized = re.sub(r'--.*$', '', sanitized)
    sanitized = re.sub(r'/\*.*?\*/', '', sanitized, flags=re.DOTALL)
    
    # Check for SQL keywords (warning only)
    for keyword in SQL_KEYWORDS:
        if re.search(rf'\b{keyword}\b', sanitized, re.IGNORECASE):
            logger.warning(f"SQL keyword detected in input: {keyword}")
    
    return sanitized


# ==========================================
# Type Validation
# ==========================================

def validate_hash(hash_str: str, algorithm: str = "sha256") -> Dict[str, Any]:
    """
    Validate a hash string.
    
    Args:
        hash_str: Hash string
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
    Returns:
        Dictionary with validation result
    """
    if algorithm not in HASH_PATTERNS:
        return {"valid": False, "error": f"Unknown algorithm: {algorithm}"}
    
    pattern = HASH_PATTERNS[algorithm]
    is_valid = bool(pattern.match(hash_str.strip()))
    
    return {
        "valid": is_valid,
        "algorithm": algorithm,
        "hash": hash_str.strip() if is_valid else hash_str,
    }


def validate_integer(
    value: Any,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Validate an integer value.
    
    Args:
        value: Value to validate
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Dictionary with validation result
    """
    try:
        num = int(value)
    except (ValueError, TypeError):
        return {"valid": False, "error": "Not a valid integer"}
    
    if min_value is not None and num < min_value:
        return {"valid": False, "error": f"Value must be >= {min_value}"}
    
    if max_value is not None and num > max_value:
        return {"valid": False, "error": f"Value must be <= {max_value}"}
    
    return {"valid": True, "value": num}


def validate_string(
    value: Any,
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    pattern: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validate a string value.
    
    Args:
        value: Value to validate
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        pattern: Regex pattern to match
        
    Returns:
        Dictionary with validation result
    """
    if not isinstance(value, str):
        return {"valid": False, "error": "Not a valid string"}
    
    if min_length is not None and len(value) < min_length:
        return {"valid": False, "error": f"String too short (min: {min_length})"}
    
    if max_length is not None and len(value) > max_length:
        return {"valid": False, "error": f"String too long (max: {max_length})"}
    
    if pattern and not re.match(pattern, value):
        return {"valid": False, "error": "String does not match required pattern"}
    
    return {"valid": True, "value": value, "length": len(value)}


# ==========================================
# Security Validation
# ==========================================

def validate_password_strength(password: str) -> Dict[str, Any]:
    """
    Validate password strength.
    
    Args:
        password: Password string
        
    Returns:
        Dictionary with strength assessment
    """
    if not password:
        return {"valid": False, "error": "Password is empty", "score": 0}
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 3
    elif len(password) >= 10:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters")
    
    # Character variety
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add uppercase letters")
    
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add lowercase letters")
    
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Add numbers")
    
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>/?\\|`~]', password):
        score += 2
    else:
        feedback.append("Add special characters")
    
    # Common password check
    common_passwords = [
        "password", "123456", "qwerty", "admin",
        "letmein", "welcome", "monkey", "dragon",
    ]
    if password.lower() in common_passwords:
        score = max(0, score - 3)
        feedback.append("This is a commonly used password")
    
    # Determine strength
    if score >= 7:
        strength = "very_strong"
    elif score >= 5:
        strength = "strong"
    elif score >= 3:
        strength = "moderate"
    elif score >= 1:
        strength = "weak"
    else:
        strength = "very_weak"
    
    return {
        "valid": score >= 3,
        "score": score,
        "max_score": 8,
        "strength": strength,
        "feedback": feedback if feedback else ["Password is strong!"],
    }


def detect_attack_patterns(input_str: str) -> Dict[str, Any]:
    """
    Detect common attack patterns in input.
    
    Args:
        input_str: Input string to analyze
        
    Returns:
        Dictionary with detection results
    """
    patterns_found = []
    
    # SQL Injection
    sql_patterns = [
        (r"(\bUNION\b.*\bSELECT\b)", "SQL Injection - UNION SELECT"),
        (r"('|\")\s*OR\s*('|\")?\s*\d+\s*=\s*\d+", "SQL Injection - OR injection"),
        (r"(--|\#|\/\*)", "SQL Injection - Comment injection"),
        (r"(\bDROP\b.*\bTABLE\b)", "SQL Injection - DROP TABLE"),
        (r"(\bEXEC\b|\bEXECUTE\b)", "SQL Injection - Command execution"),
    ]
    
    for pattern, description in sql_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            patterns_found.append({"type": "sql_injection", "description": description})
    
    # XSS
    xss_patterns = [
        (r"<script[^>]*>", "XSS - Script tag"),
        (r"javascript\s*:", "XSS - JavaScript protocol"),
        (r"on\w+\s*=", "XSS - Event handler"),
        (r"<iframe[^>]*>", "XSS - Iframe injection"),
    ]
    
    for pattern, description in xss_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            patterns_found.append({"type": "xss", "description": description})
    
    # Path Traversal
    if re.search(r"\.\.\/|\.\.\\", input_str):
        patterns_found.append({"type": "path_traversal", "description": "Directory traversal attempt"})
    
    # Command Injection
    cmd_patterns = [
        (r"[;&|`]\s*(cat|ls|id|whoami|pwd)", "Command injection"),
        (r"\$\([^)]*\)", "Command substitution"),
    ]
    
    for pattern, description in cmd_patterns:
        if re.search(pattern, input_str, re.IGNORECASE):
            patterns_found.append({"type": "command_injection", "description": description})
    
    return {
        "suspicious": len(patterns_found) > 0,
        "patterns_found": patterns_found,
        "count": len(patterns_found),
    }
