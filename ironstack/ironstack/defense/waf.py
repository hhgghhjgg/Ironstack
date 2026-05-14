#!/usr/bin/env python3
"""
Web Application Firewall (WAF) module for IronStack.
Integrates with Coraza WAF engine for HTTP protection.
"""

import os
import json
import time
import threading
from typing import Dict, Any, Optional, List, Union, Callable
from pathlib import Path

from ..logging_config import get_logger
from ..exceptions import (
    WAFError,
    WAFConfigurationError,
    WAFRuleError,
)

logger = get_logger(__name__)


# ==========================================
# Default WAF Rules
# ==========================================

DEFAULT_WAF_RULES = {
    # SQL Injection patterns
    "sql_injection": [
        r"(?i)(\bUNION\b.*\bSELECT\b)",
        r"(?i)(\bSELECT\b.*\bFROM\b.*\bWHERE\b)",
        r"(?i)(\bINSERT\b.*\bINTO\b)",
        r"(?i)(\bDROP\b.*\bTABLE\b)",
        r"(?i)(\bDELETE\b.*\bFROM\b)",
        r"(?i)(\bUPDATE\b.*\bSET\b)",
        r"('|\")\s*(OR|AND)\s*('|\")?\s*\d+\s*=\s*\d+",
        r"(?i)(\bEXEC\b|\bEXECUTE\b).*\(",
        r"(--|\#|\/\*)",
    ],
    
    # XSS patterns
    "xss": [
        r"(?i)(<script[^>]*>)",
        r"(?i)(javascript\s*:)",
        r"(?i)(onload\s*=)",
        r"(?i)(onerror\s*=)",
        r"(?i)(onclick\s*=)",
        r"(?i)(onmouseover\s*=)",
        r"(?i)(eval\s*\()",
        r"(?i)(document\.cookie)",
        r"(?i)(document\.location)",
        r"(?i)(<iframe[^>]*>)",
        r"(?i)(<embed[^>]*>)",
        r"(?i)(<object[^>]*>)",
    ],
    
    # Path traversal
    "path_traversal": [
        r"\.\.\/",
        r"\.\.\\",
        r"(?i)(\/etc\/passwd)",
        r"(?i)(\/etc\/shadow)",
        r"(?i)(\/proc\/self\/)",
        r"(?i)(C:\\Windows\\System32)",
        r"(?i)(\.\.%2f)",
        r"(?i)(\.\.%5c)",
    ],
    
    # Command injection
    "command_injection": [
        r"(?i)(\bping\b\s+-)",
        r"(?i)(\bwget\b\s+)",
        r"(?i)(\bcurl\b\s+)",
        r"(?i)(\bnslookup\b\s+)",
        r"(?i)(\bcmd\b\s*\/)",
        r"(?i)(\bnc\b\s+-)",
        r"(?i)(\bnetcat\b\s+)",
        r"(;\s*(cat|ls|id|whoami|uname))",
        r"(\|\s*(cat|ls|id|whoami))",
        r"(`[^`]*`)",
        r"(\$\([^)]*\))",
    ],
    
    # File inclusion
    "file_inclusion": [
        r"(?i)(php://)",
        r"(?i)(data://)",
        r"(?i)(expect://)",
        r"(?i)(input://)",
        r"(?i)(file://)",
        r"(?i)(include\s*\()",
        r"(?i)(require\s*\()",
    ],
    
    # Scanner detection
    "scanner": [
        r"(?i)(sqlmap)",
        r"(?i)(nikto)",
        r"(?i)(nessus)",
        r"(?i)(burp\s*suite)",
        r"(?i)(acunetix)",
        r"(?i)(netsparker)",
        r"(?i)(appscan)",
        r"(?i)(webinspect)",
        r"(?i)(openvas)",
    ],
    
    # Malicious user agents
    "malicious_ua": [
        r"(?i)(sqlmap\/)",
        r"(?i)(nikto\/)",
        r"(?i)(nessus\/)",
        r"(?i)(nmap\s*)",
        r"(?i)(masscan\/)",
        r"(?i)(zgrab\/)",
    ],
    
    # HTTP method attacks
    "method_attack": [
        r"(?i)(TRACE)",
        r"(?i)(TRACK)",
        r"(?i)(DEBUG)",
        r"(?i)(CONNECT)",
    ],
    
    # Protocol violations
    "protocol_violation": [
        r"(%00)",
        r"(%0d%0a)",
        r"(Content-Length:\s*0)",
    ],
}


# ==========================================
# WAF Rule Class
# ==========================================

class WAFRule:
    """
    Represents a single WAF rule.
    
    Attributes:
        rule_id: Unique rule identifier
        name: Rule name
        category: Rule category
        pattern: Regex pattern to match
        severity: Rule severity (critical, high, medium, low)
        action: Action to take (block, log, allow)
        description: Rule description
    """
    
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        pattern: str,
        severity: str = "medium",
        action: str = "block",
        description: str = "",
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.pattern = pattern
        self.severity = severity
        self.action = action
        self.description = description
        self.hits = 0
        self.last_hit = None
    
    def to_dict(self) -> dict:
        """Convert rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "pattern": self.pattern,
            "severity": self.severity,
            "action": self.action,
            "description": self.description,
            "hits": self.hits,
            "last_hit": self.last_hit,
        }
    
    def __repr__(self) -> str:
        return f"WAFRule(id='{self.rule_id}', name='{self.name}', severity='{self.severity}')"


# ==========================================
# WAF Request Checker
# ==========================================

class WAFRequestChecker:
    """
    Checks HTTP requests against WAF rules.
    """
    
    def __init__(self, rules: List[WAFRule]):
        self.rules = rules
    
    def check(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check a request against all rules.
        
        Args:
            request_data: Request data with keys: method, path, headers, body, query_params
            
        Returns:
            Result dictionary with 'allowed', 'matched_rules', 'action'
        """
        import re
        
        result = {
            "allowed": True,
            "matched_rules": [],
            "action": "allow",
            "score": 0,
        }
        
        # Convert request to string for pattern matching
        request_str = json.dumps(request_data, default=str).lower()
        
        for rule in self.rules:
            try:
                if re.search(rule.pattern, request_str, re.IGNORECASE):
                    rule.hits += 1
                    rule.last_hit = time.time()
                    
                    matched = {
                        "rule_id": rule.rule_id,
                        "name": rule.name,
                        "category": rule.category,
                        "severity": rule.severity,
                        "action": rule.action,
                    }
                    result["matched_rules"].append(matched)
                    
                    # Calculate severity score
                    severity_scores = {
                        "critical": 10,
                        "high": 7,
                        "medium": 4,
                        "low": 1,
                    }
                    result["score"] += severity_scores.get(rule.severity, 4)
                    
                    # Block immediately on critical
                    if rule.severity == "critical" or rule.action == "block":
                        result["allowed"] = False
                        result["action"] = "block"
            except re.error as e:
                logger.error(f"Invalid regex pattern for rule {rule.rule_id}: {e}")
        
        return result


# ==========================================
# WAF Rate Limiter
# ==========================================

class WAFRateLimiter:
    """
    Rate limiter for WAF.
    Tracks request counts per IP address.
    """
    
    def __init__(
        self,
        max_requests: int = 100,
        time_window: int = 60,
        burst: int = 20,
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.burst = burst
        self._requests = {}  # {ip: [(timestamp, ...)]}
        self._blocked_ips = {}  # {ip: block_until_timestamp}
        self._lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> tuple:
        """
        Check if request from IP is allowed.
        
        Args:
            ip: Client IP address
            
        Returns:
            Tuple of (allowed: bool, retry_after: int)
        """
        now = time.time()
        
        with self._lock:
            # Check if IP is blocked
            if ip in self._blocked_ips:
                if now < self._blocked_ips[ip]:
                    retry_after = int(self._blocked_ips[ip] - now)
                    return False, retry_after
                else:
                    del self._blocked_ips[ip]
            
            # Initialize tracking
            if ip not in self._requests:
                self._requests[ip] = []
            
            # Remove old requests
            cutoff = now - self.time_window
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            
            # Add current request
            self._requests[ip].append(now)
            
            # Check limits
            request_count = len(self._requests[ip])
            
            if request_count > self.max_requests + self.burst:
                # Block the IP
                ban_time = self.time_window * 2
                self._blocked_ips[ip] = now + ban_time
                return False, ban_time
            
            if request_count > self.max_requests:
                # Rate limited but not blocked
                return True, 0  # Allow but log warning
        
        return True, 0
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        now = time.time()
        with self._lock:
            return {
                "tracked_ips": len(self._requests),
                "blocked_ips": len(self._blocked_ips),
                "total_requests": sum(len(reqs) for reqs in self._requests.values()),
            }
    
    def reset(self):
        """Reset all tracking data."""
        with self._lock:
            self._requests.clear()
            self._blocked_ips.clear()


# ==========================================
# Main WAF Class
# ==========================================

class WAF:
    """
    Web Application Firewall for IronStack.
    
    Provides HTTP request inspection, attack detection,
    rate limiting, and IP blocking.
    
    Attributes:
        config: WAF configuration dictionary
        rules: List of active WAF rules
        rate_limiter: Rate limiter instance
        checker: Request checker instance
    
    Basic Usage:
        >>> from ironstack.defense import WAF
        >>> waf = WAF()
        >>> waf.start(port=8080)
        >>> result = waf.check_request(request_data)
        >>> print(result["allowed"])
        True
    
    Advanced Usage:
        >>> waf = WAF(config={
        ...     "port": 9090,
        ...     "paranoia_level": 3,
        ...     "block_on_attack": True,
        ...     "rate_limiting": {"enabled": True, "max_requests": 50}
        ... })
        >>> waf.add_custom_rule("XSS_FILTER", r"<script>", "xss", "critical")
        >>> waf.start()
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        rules: Optional[List[WAFRule]] = None,
        mode: str = "normal",
    ):
        """
        Initialize WAF.
        
        Args:
            config: WAF configuration dictionary
            rules: Custom list of WAF rules
            mode: Operation mode (strict, normal, permissive)
        """
        # Default configuration
        self.config = {
            "enabled": True,
            "port": 8080,
            "listen_address": "127.0.0.1",
            "paranoia_level": 1,
            "block_on_attack": True,
            "anomaly_threshold": 5,
            "outbound_threshold": 4,
            "audit_log": True,
            "audit_log_path": None,
            "rate_limiting": {
                "enabled": True,
                "max_requests": 100,
                "time_window": 60,
                "burst": 20,
            },
            "ip_whitelist": [],
            "ip_blacklist": [],
            "allowed_methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
            "max_body_size": 10 * 1024 * 1024,  # 10MB
            "max_headers_size": 8 * 1024,       # 8KB
            "response_obfuscation": False,
            "certificate_pinning": False,
        }
        
        # Merge with provided config
        if config:
            self._deep_merge(self.config, config)
        
        # Set mode
        valid_modes = ["strict", "normal", "permissive"]
        if mode not in valid_modes:
            raise WAFConfigurationError(f"Invalid mode: {mode}. Must be one of: {valid_modes}")
        self.mode = mode
        
        # Apply mode overrides
        self._apply_mode_overrides()
        
        # Initialize rules
        self.rules = rules or self._load_default_rules()
        
        # Initialize components
        self.checker = WAFRequestChecker(self.rules)
        
        # Initialize rate limiter
        rl_config = self.config["rate_limiting"]
        self.rate_limiter = WAFRateLimiter(
            max_requests=rl_config.get("max_requests", 100),
            time_window=rl_config.get("time_window", 60),
            burst=rl_config.get("burst", 20),
        )
        
        # State
        self._running = False
        self._start_time = None
        self._stats = {
            "requests_checked": 0,
            "requests_blocked": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
        }
        
        logger.info(f"🛡️ WAF initialized in {mode} mode with {len(self.rules)} rules")
    
    def _apply_mode_overrides(self):
        """Apply configuration overrides based on mode."""
        if self.mode == "strict":
            self.config["paranoia_level"] = 3
            self.config["anomaly_threshold"] = 3
            self.config["block_on_attack"] = True
        elif self.mode == "normal":
            self.config["paranoia_level"] = 1
            self.config["anomaly_threshold"] = 5
            self.config["block_on_attack"] = True
        elif self.mode == "permissive":
            self.config["paranoia_level"] = 1
            self.config["anomaly_threshold"] = 10
            self.config["block_on_attack"] = False
    
    def _load_default_rules(self) -> List[WAFRule]:
        """Load default WAF rules."""
        rules = []
        rule_counter = 1000
        
        for category, patterns in DEFAULT_WAF_RULES.items():
            for i, pattern in enumerate(patterns):
                rule = WAFRule(
                    rule_id=f"WAF-{rule_counter}",
                    name=f"{category}_{i}",
                    category=category,
                    pattern=pattern,
                    severity=self._get_severity(category),
                    action="block" if self.config["block_on_attack"] else "log",
                    description=f"Default {category} detection rule",
                )
                rules.append(rule)
                rule_counter += 1
        
        return rules
    
    def _get_severity(self, category: str) -> str:
        """Get default severity for a category."""
        severity_map = {
            "sql_injection": "critical",
            "xss": "high",
            "command_injection": "critical",
            "file_inclusion": "high",
            "path_traversal": "high",
            "scanner": "medium",
            "malicious_ua": "low",
            "method_attack": "medium",
            "protocol_violation": "low",
        }
        return severity_map.get(category, "medium")
    
    def _deep_merge(self, base: dict, override: dict):
        """Deep merge two dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    # ==========================================
    # Rule Management
    # ==========================================
    
    def add_rule(
        self,
        name: str,
        pattern: str,
        category: str,
        severity: str = "medium",
        action: str = "block",
        description: str = "",
    ) -> WAFRule:
        """
        Add a custom rule.
        
        Args:
            name: Rule name
            pattern: Regex pattern
            category: Rule category
            severity: Severity level
            action: Action to take
            description: Rule description
            
        Returns:
            Created WAFRule
        """
        rule = WAFRule(
            rule_id=f"CUSTOM-{len(self.rules) + 1}",
            name=name,
            category=category,
            pattern=pattern,
            severity=severity,
            action=action,
            description=description,
        )
        
        self.rules.append(rule)
        self.checker = WAFRequestChecker(self.rules)
        
        logger.info(f"Added custom rule: {rule.name}")
        return rule
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        original_count = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        
        if len(self.rules) < original_count:
            self.checker = WAFRequestChecker(self.rules)
            logger.info(f"Removed rule: {rule_id}")
            return True
        
        return False
    
    def get_rules(self, category: Optional[str] = None) -> List[dict]:
        """Get all rules, optionally filtered by category."""
        if category:
            return [r.to_dict() for r in self.rules if r.category == category]
        return [r.to_dict() for r in self.rules]
    
    def clear_rules(self):
        """Remove all rules."""
        self.rules.clear()
        self.checker = WAFRequestChecker(self.rules)
        logger.info("All rules cleared")
    
    def load_rules_from_file(self, filepath: Union[str, Path]):
        """
        Load rules from a JSON file.
        
        Args:
            filepath: Path to rules JSON file
        """
        filepath = Path(filepath)
        
        if not filepath.exists():
            raise WAFConfigurationError(f"Rules file not found: {filepath}")
        
        with open(filepath, "r") as f:
            rules_data = json.load(f)
        
        loaded_count = 0
        for rule_data in rules_data:
            self.add_rule(**rule_data)
            loaded_count += 1
        
        logger.info(f"Loaded {loaded_count} rules from {filepath}")
    
    # ==========================================
    # Request Checking
    # ==========================================
    
    def check_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check an HTTP request against WAF rules.
        
        Args:
            request_data: Dictionary with request details:
                - method: HTTP method
                - path: Request path
                - headers: Request headers dict
                - body: Request body
                - query_params: Query parameters dict
                - ip: Client IP address
                
        Returns:
            Result dictionary with:
                - allowed: Whether request is allowed
                - matched_rules: List of matched rules
                - action: Action taken (allow/block/log)
                - score: Anomaly score
                - message: Human-readable message
                
        Examples:
            >>> waf = WAF()
            >>> result = waf.check_request({
            ...     "method": "GET",
            ...     "path": "/login",
            ...     "headers": {"User-Agent": "Mozilla/5.0"},
            ...     "body": "user=admin' OR '1'='1",
            ...     "query_params": {},
            ...     "ip": "192.168.1.1"
            ... })
            >>> print(result["allowed"])
            False
        """
        if not self.config["enabled"]:
            return {"allowed": True, "action": "allow", "score": 0, "matched_rules": []}
        
        self._stats["requests_checked"] += 1
        
        # Validate required fields
        required_fields = ["method", "path", "headers"]
        for field in required_fields:
            if field not in request_data:
                raise WAFError(f"Missing required field in request: {field}")
        
        # Check IP whitelist/blacklist
        ip = request_data.get("ip", "unknown")
        
        if ip in self.config["ip_whitelist"]:
            return {
                "allowed": True,
                "action": "allow",
                "score": 0,
                "matched_rules": [],
                "message": "IP whitelisted",
            }
        
        if ip in self.config["ip_blacklist"]:
            self._stats["requests_blocked"] += 1
            return {
                "allowed": False,
                "action": "block",
                "score": 100,
                "matched_rules": [{"rule_id": "BLACKLIST", "name": "IP Blacklisted"}],
                "message": "IP is blacklisted",
            }
        
        # Check HTTP method
        method = request_data["method"].upper()
        if method not in self.config["allowed_methods"]:
            self._stats["requests_blocked"] += 1
            return {
                "allowed": False,
                "action": "block",
                "score": 50,
                "matched_rules": [{"rule_id": "METHOD_DENIED", "name": "Method Not Allowed"}],
                "message": f"HTTP method {method} is not allowed",
            }
        
        # Rate limiting
        if self.config["rate_limiting"]["enabled"]:
            allowed, retry_after = self.rate_limiter.is_allowed(ip)
            if not allowed:
                self._stats["requests_blocked"] += 1
                return {
                    "allowed": False,
                    "action": "block",
                    "score": 100,
                    "matched_rules": [{"rule_id": "RATE_LIMIT", "name": "Rate Limit Exceeded"}],
                    "message": f"Rate limit exceeded. Retry after {retry_after}s",
                    "retry_after": retry_after,
                }
        
        # Check body size
        body = request_data.get("body", "")
        if len(str(body)) > self.config["max_body_size"]:
            return {
                "allowed": False,
                "action": "block",
                "score": 30,
                "matched_rules": [{"rule_id": "BODY_SIZE", "name": "Body Too Large"}],
                "message": "Request body exceeds maximum size",
            }
        
        # Run rule checker
        result = self.checker.check(request_data)
        
        # Apply anomaly threshold
        threshold = self.config["anomaly_threshold"]
        if result["score"] >= threshold:
            result["allowed"] = False
            result["action"] = "block"
            self._stats["attacks_detected"] += 1
        
        if not result["allowed"]:
            self._stats["requests_blocked"] += 1
            result["message"] = f"Request blocked: {len(result['matched_rules'])} rules matched (score: {result['score']})"
        else:
            result["message"] = "Request allowed"
        
        # Audit logging
        if self.config["audit_log"]:
            self._audit_log(request_data, result)
        
        return result
    
    def _audit_log(self, request_data: Dict[str, Any], result: Dict[str, Any]):
        """Log request to audit log."""
        audit_entry = {
            "timestamp": time.time(),
            "request": {
                "method": request_data.get("method"),
                "path": request_data.get("path"),
                "ip": request_data.get("ip", "unknown"),
            },
            "result": {
                "allowed": result["allowed"],
                "score": result["score"],
                "matched_rules": result["matched_rules"],
            },
        }
        
        # Write to audit log file if configured
        audit_path = self.config.get("audit_log_path")
        if audit_path:
            try:
                with open(audit_path, "a") as f:
                    f.write(json.dumps(audit_entry) + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit log: {e}")
        
        # Always log attacks
        if not result["allowed"]:
            logger.warning(f"🚫 Attack detected: {result['message']}")
        else:
            logger.debug(f"✅ Request allowed: {request_data.get('path')}")
    
    # ==========================================
    # Server Management
    # ==========================================
    
    def start(self, port: Optional[int] = None, **kwargs):
        """
        Start WAF server.
        
        Note: Full server implementation requires integration
        with a web framework or proxy. This method sets up
        the configuration for server mode.
        
        Args:
            port: Port to listen on (overrides config)
            **kwargs: Additional configuration
        """
        if port:
            self.config["port"] = port
        
        self._running = True
        self._start_time = time.time()
        
        logger.info(f"🛡️ WAF started (mode: {self.mode}, rules: {len(self.rules)})")
        logger.info(f"   Listen: {self.config['listen_address']}:{self.config['port']}")
        
        return self
    
    def stop(self):
        """Stop WAF server."""
        self._running = False
        logger.info("WAF stopped")
    
    @property
    def is_running(self) -> bool:
        """Check if WAF is running."""
        return self._running
    
    # ==========================================
    # Statistics & Status
    # ==========================================
    
    def get_stats(self) -> dict:
        """Get WAF statistics."""
        rate_stats = self.rate_limiter.get_stats()
        
        return {
            **self._stats,
            "rate_limiter": rate_stats,
            "uptime": time.time() - self._start_time if self._start_time else 0,
            "rules_count": len(self.rules),
            "mode": self.mode,
        }
    
    def get_status(self) -> dict:
        """Get WAF status."""
        return {
            "enabled": self.config["enabled"],
            "running": self._running,
            "mode": self.mode,
            "rules_count": len(self.rules),
            "paranoia_level": self.config["paranoia_level"],
            "block_on_attack": self.config["block_on_attack"],
            "rate_limiting_enabled": self.config["rate_limiting"]["enabled"],
            "stats": self.get_stats(),
        }
    
    def reset_stats(self):
        """Reset all statistics."""
        self._stats = {
            "requests_checked": 0,
            "requests_blocked": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
        }
        self.rate_limiter.reset()
        
        # Reset rule hit counters
        for rule in self.rules:
            rule.hits = 0
            rule.last_hit = None
        
        logger.info("WAF statistics reset")
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return f"WAF(mode='{self.mode}', rules={len(self.rules)}, running={self._running})"
    
    def __str__(self) -> str:
        status = "RUNNING" if self._running else "STOPPED"
        return f"🛡️ WAF [{status}] | Mode: {self.mode} | Rules: {len(self.rules)} | Blocked: {self._stats['requests_blocked']}"
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False
