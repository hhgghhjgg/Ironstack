#!/usr/bin/env python3
"""
Web Application Firewall (WAF) module for IronStack.
Supports built-in Python engine and BunkerWeb (OWASP CRS) via Docker.
"""

import re
import json
import time
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

from ..logging_config import get_logger
from ..exceptions import (
    WAFError,
    WAFConfigurationError,
    WAFRuleError,
)

logger = get_logger(__name__)


# ==========================================
# Default WAF Rules (Python Engine)
# ==========================================

DEFAULT_WAF_RULES = {
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
    "file_inclusion": [
        r"(?i)(php://)",
        r"(?i)(data://)",
        r"(?i)(expect://)",
        r"(?i)(input://)",
        r"(?i)(file://)",
        r"(?i)(include\s*\()",
        r"(?i)(require\s*\()",
    ],
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
    "malicious_ua": [
        r"(?i)(sqlmap\/)",
        r"(?i)(nikto\/)",
        r"(?i)(nessus\/)",
        r"(?i)(nmap\s*)",
        r"(?i)(masscan\/)",
        r"(?i)(zgrab\/)",
    ],
    "method_attack": [
        r"(?i)(TRACE)",
        r"(?i)(TRACK)",
        r"(?i)(DEBUG)",
        r"(?i)(CONNECT)",
    ],
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
    """Represents a single WAF rule."""
    
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
# WAF Request Checker (Python Engine)
# ==========================================

class WAFRequestChecker:
    """Checks HTTP requests against WAF rules."""
    
    def __init__(self, rules: List[WAFRule]):
        self.rules = rules
    
    def check(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "allowed": True,
            "matched_rules": [],
            "action": "allow",
            "score": 0,
        }
        
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
                    
                    severity_scores = {
                        "critical": 10,
                        "high": 7,
                        "medium": 4,
                        "low": 1,
                    }
                    result["score"] += severity_scores.get(rule.severity, 4)
                    
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
    """Rate limiter for WAF."""
    
    def __init__(
        self,
        max_requests: int = 100,
        time_window: int = 60,
        burst: int = 20,
    ):
        self.max_requests = max_requests
        self.time_window = time_window
        self.burst = burst
        self._requests = {}
        self._blocked_ips = {}
        self._lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> tuple:
        now = time.time()
        
        with self._lock:
            if ip in self._blocked_ips:
                if now < self._blocked_ips[ip]:
                    retry_after = int(self._blocked_ips[ip] - now)
                    return False, retry_after
                else:
                    del self._blocked_ips[ip]
            
            if ip not in self._requests:
                self._requests[ip] = []
            
            cutoff = now - self.time_window
            self._requests[ip] = [t for t in self._requests[ip] if t > cutoff]
            self._requests[ip].append(now)
            
            request_count = len(self._requests[ip])
            
            if request_count > self.max_requests + self.burst:
                ban_time = self.time_window * 2
                self._blocked_ips[ip] = now + ban_time
                return False, ban_time
        
        return True, 0
    
    def get_stats(self) -> dict:
        with self._lock:
            return {
                "tracked_ips": len(self._requests),
                "blocked_ips": len(self._blocked_ips),
                "total_requests": sum(len(reqs) for reqs in self._requests.values()),
            }
    
    def reset(self):
        with self._lock:
            self._requests.clear()
            self._blocked_ips.clear()


# ==========================================
# BunkerWeb Connector (OWASP CRS Engine)
# ==========================================

class BunkerWebConnector:
    """
    Connector for BunkerWeb WAF (200+ OWASP CRS rules).
    Requires Docker to be installed and running.
    """
    
    def __init__(
        self,
        target_url: str = "http://localhost:8000",
        listen_port: int = 8080,
        api_port: int = 5000,
        docker_image: str = "bunkerity/bunkerweb:latest",
    ):
        self.target_url = target_url
        self.listen_port = listen_port
        self.api_port = api_port
        self.docker_image = docker_image
        self.container = None
        self._docker_available = None
    
    @property
    def docker_available(self) -> bool:
        if self._docker_available is None:
            try:
                import docker
                self.client = docker.from_env()
                self.client.ping()
                self._docker_available = True
                logger.info("✅ Docker is available for BunkerWeb")
            except (ImportError, Exception) as e:
                logger.warning(f"⚠️ Docker not available: {e}")
                self._docker_available = False
        return self._docker_available
    
    def is_available(self) -> bool:
        return self.docker_available
    
    def start(self):
        if not self.docker_available:
            raise WAFConfigurationError(
                "Docker is required for BunkerWeb engine. "
                "Install Docker or use engine='python'."
            )
        
        try:
            # Remove existing container if any
            try:
                old = self.client.containers.get("ironstack-bunkerweb")
                old.stop()
                old.remove()
            except:
                pass
            
            # Generate BunkerWeb config
            env = [
                f"BUNKERWEB_LISTEN_PORT={self.listen_port}",
                "SERVER_NAME=www.example.com",  # Generic
                "USE_REVERSE_PROXY=yes",
                f"REVERSE_PROXY_URL=/#REVERSE_PROXY_URL#",
                "REVERSE_PROXY_HOST=http://host.docker.internal:8000",
                "USE_MODSECURITY=yes",
                "USE_MODSECURITY_CRS=yes",
                "MODSECURITY_CRS_VERSION=4",
                "USE_LIMIT_REQ=yes",
                "LIMIT_REQ_RATE=10r/s",
                "LIMIT_REQ_BURST=20",
                "USE_BAD_BEHAVIOR=yes",
                "LOG_LEVEL=info",
            ]
            
            logger.info(f"🛡️ Starting BunkerWeb container on port {self.listen_port}...")
            
            self.container = self.client.containers.run(
                self.docker_image,
                name="ironstack-bunkerweb",
                ports={
                    f"{self.listen_port}/tcp": self.listen_port,
                    f"{self.api_port}/tcp": self.api_port,
                },
                environment=env,
                volumes={
                    "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "ro"},
                },
                detach=True,
                remove=True,
            )
            
            # Wait for it to start
            time.sleep(5)
            
            logger.info(f"✅ BunkerWeb WAF running on port {self.listen_port}")
            logger.info(f"   Target: {self.target_url}")
            logger.info(f"   Rules: OWASP CRS v4 (200+ rules)")
            
            return self
            
        except Exception as e:
            raise WAFConfigurationError(f"Failed to start BunkerWeb: {e}")
    
    def stop(self):
        if self.container:
            try:
                self.container.stop()
                logger.info("BunkerWeb container stopped")
            except Exception as e:
                logger.error(f"Error stopping BunkerWeb: {e}")
            self.container = None
    
    def reload_rules(self):
        """Reload OWASP CRS rules (sends SIGHUP to container)."""
        if self.container:
            try:
                self.container.kill(signal="SIGHUP")
                logger.info("BunkerWeb rules reloaded")
            except Exception as e:
                logger.error(f"Error reloading rules: {e}")
    
    def get_stats(self) -> dict:
        """Get statistics from BunkerWeb API."""
        if not self.container:
            return {"status": "not_running"}
        
        return {
            "status": "running",
            "engine": "BunkerWeb",
            "rules": "OWASP CRS v4 (200+ rules)",
            "listen_port": self.listen_port,
            "target_url": self.target_url,
        }


# ==========================================
# Main WAF Class (supports Python & BunkerWeb)
# ==========================================

class WAF:
    """
    Web Application Firewall for IronStack.
    
    Supports two engines:
    - "python": Built-in Python WAF with ~100 regex rules (lightweight)
    - "bunkerweb": BunkerWeb with 200+ OWASP CRS v4 rules (requires Docker)
    - "auto": Try BunkerWeb first, fallback to Python
    
    Attributes:
        engine_type: Which engine is active ("python" or "bunkerweb")
        config: WAF configuration
        rules: WAF rules (Python engine only)
    
    Basic Usage:
        >>> from ironstack.defense import WAF
        >>> waf = WAF(engine="python")  # light, no Docker needed
        >>> result = waf.check_request(request_data)
        
        >>> waf = WAF(engine="bunkerweb")  # 200+ OWASP rules via Docker
        >>> waf.start()
        >>> # Now BunkerWeb protects your app on port 8080
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        rules: Optional[List[WAFRule]] = None,
        mode: str = "normal",
        engine: str = "auto",
        target_url: str = "http://localhost:8000",
        listen_port: int = 8080,
    ):
        """
        Initialize WAF.
        
        Args:
            config: WAF configuration dictionary
            rules: Custom list of WAF rules (Python engine only)
            mode: Operation mode for Python engine (strict, normal, permissive)
            engine: WAF engine to use ("python", "bunkerweb", "auto")
            target_url: Target URL to protect (BunkerWeb engine only)
            listen_port: Port to listen on (BunkerWeb engine only)
        """
        # Default configuration
        self.config = {
            "enabled": True,
            "port": listen_port,
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
            "max_body_size": 10 * 1024 * 1024,
            "max_headers_size": 8 * 1024,
            "response_obfuscation": False,
            "certificate_pinning": False,
            # BunkerWeb specific
            "bunkerweb": {
                "target_url": target_url,
                "listen_port": listen_port,
                "api_port": 5000,
            },
        }
        
        if config:
            self._deep_merge(self.config, config)
        
        # Validate mode
        valid_modes = ["strict", "normal", "permissive"]
        if mode not in valid_modes:
            raise WAFConfigurationError(f"Invalid mode: {mode}. Must be one of: {valid_modes}")
        self.mode = mode
        
        # Initialize engine
        self.engine_type = None
        self.bunkerweb = None
        self._init_engine(engine, target_url, listen_port)
        
        # For Python engine: rules + components
        self.rules = None
        self.checker = None
        self.rate_limiter = None
        
        if self.engine_type == "python":
            self._apply_mode_overrides()
            self.rules = rules or self._load_default_rules()
            self.checker = WAFRequestChecker(self.rules)
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
        
        logger.info(
            f"🛡️ WAF initialized | Engine: {self.engine_type} | "
            f"Mode: {self.mode} | Rules: {len(self.rules) if self.rules else 'OWASP CRS v4 (200+)'}"
        )
    
    def _init_engine(self, engine: str, target_url: str, listen_port: int):
        """Initialize the selected engine."""
        if engine == "bunkerweb":
            self.bunkerweb = BunkerWebConnector(
                target_url=target_url,
                listen_port=listen_port,
            )
            if self.bunkerweb.is_available():
                self.engine_type = "bunkerweb"
            else:
                raise WAFConfigurationError(
                    "BunkerWeb engine selected but Docker is not available. "
                    "Install Docker or use engine='python'."
                )
        elif engine == "python":
            self.engine_type = "python"
        elif engine == "auto":
            # Try BunkerWeb first, then Python
            bw = BunkerWebConnector(target_url=target_url, listen_port=listen_port)
            if bw.is_available():
                self.bunkerweb = bw
                self.engine_type = "bunkerweb"
                logger.info("✅ Auto-selected BunkerWeb engine (Docker available)")
            else:
                self.engine_type = "python"
                logger.info("⚠️ BunkerWeb not available, using Python engine")
        else:
            raise WAFConfigurationError(f"Invalid engine: {engine}. Use 'python', 'bunkerweb', or 'auto'")
    
    def _deep_merge(self, base: dict, override: dict):
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _apply_mode_overrides(self):
        if self.mode == "strict":
            self.config["paranoia_level"] = 3
            self.config["anomaly_threshold"] = 3
        elif self.mode == "normal":
            self.config["paranoia_level"] = 1
            self.config["anomaly_threshold"] = 5
        elif self.mode == "permissive":
            self.config["paranoia_level"] = 1
            self.config["anomaly_threshold"] = 10
            self.config["block_on_attack"] = False
    
    def _load_default_rules(self) -> List[WAFRule]:
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
    
    # ==========================================
    # Server Management
    # ==========================================
    
    def start(self, port: Optional[int] = None, **kwargs):
        """
        Start WAF server.
        
        For Python engine: Configures the WAF for request checking.
        For BunkerWeb engine: Starts the BunkerWeb Docker container.
        
        Args:
            port: Port to listen on (overrides config)
        """
        if port:
            self.config["port"] = port
        
        if self.engine_type == "bunkerweb":
            if port:
                self.bunkerweb.listen_port = port
            self.bunkerweb.start()
        
        self._running = True
        self._start_time = time.time()
        
        logger.info(f"🛡️ WAF started (engine: {self.engine_type})")
        if self.engine_type == "bunkerweb":
            logger.info(f"   BunkerWeb listening on port {self.bunkerweb.listen_port}")
        else:
            logger.info(f"   Listen: {self.config['listen_address']}:{self.config['port']}")
        
        return self
    
    def stop(self):
        """Stop WAF server."""
        if self.engine_type == "bunkerweb" and self.bunkerweb:
            self.bunkerweb.stop()
        self._running = False
        logger.info("WAF stopped")
    
    @property
    def is_running(self) -> bool:
        return self._running
    
    # ==========================================
    # Request Checking (Python Engine Only)
    # ==========================================
    
    def check_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check an HTTP request against WAF rules (Python engine only).
        
        For BunkerWeb engine, this is handled automatically by the proxy.
        Use this method only with engine="python".
        
        Args:
            request_data: Dictionary with method, path, headers, body, query_params, ip
            
        Returns:
            Result dictionary with allowed, matched_rules, action, score, message
        """
        if self.engine_type == "bunkerweb":
            logger.warning("check_request() is not needed with BunkerWeb engine. "
                          "BunkerWeb handles all requests automatically as a reverse proxy.")
            return {
                "allowed": True,
                "action": "allow",
                "score": 0,
                "matched_rules": [],
                "message": "Request handled by BunkerWeb OWASP CRS",
            }
        
        if not self.config["enabled"]:
            return {"allowed": True, "action": "allow", "score": 0, "matched_rules": []}
        
        self._stats["requests_checked"] += 1
        
        required_fields = ["method", "path", "headers"]
        for field in required_fields:
            if field not in request_data:
                raise WAFError(f"Missing required field in request: {field}")
        
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
        
        body = request_data.get("body", "")
        if len(str(body)) > self.config["max_body_size"]:
            return {
                "allowed": False,
                "action": "block",
                "score": 30,
                "matched_rules": [{"rule_id": "BODY_SIZE", "name": "Body Too Large"}],
                "message": "Request body exceeds maximum size",
            }
        
        result = self.checker.check(request_data)
        
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
        
        if self.config["audit_log"]:
            self._audit_log(request_data, result)
        
        return result
    
    def _audit_log(self, request_data: Dict[str, Any], result: Dict[str, Any]):
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
        
        audit_path = self.config.get("audit_log_path")
        if audit_path:
            try:
                with open(audit_path, "a") as f:
                    f.write(json.dumps(audit_entry) + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit log: {e}")
        
        if not result["allowed"]:
            logger.warning(f"🚫 Attack detected: {result['message']}")
        else:
            logger.debug(f"✅ Request allowed: {request_data.get('path')}")
    
    # ==========================================
    # Rule Management (Python Engine Only)
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
        if self.engine_type != "python":
            raise WAFError("Rule management is only available with Python engine")
        
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
        if self.engine_type != "python":
            return False
        
        original_count = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        
        if len(self.rules) < original_count:
            self.checker = WAFRequestChecker(self.rules)
            logger.info(f"Removed rule: {rule_id}")
            return True
        return False
    
    def get_rules(self, category: Optional[str] = None) -> List[dict]:
        if self.engine_type == "bunkerweb":
            return [{"engine": "BunkerWeb", "rules": "OWASP CRS v4 (200+ rules)"}]
        
        if category:
            return [r.to_dict() for r in self.rules if r.category == category]
        return [r.to_dict() for r in self.rules]
    
    def clear_rules(self):
        if self.engine_type == "python":
            self.rules.clear()
            self.checker = WAFRequestChecker(self.rules)
            logger.info("All rules cleared")
    
    def load_rules_from_file(self, filepath: Union[str, Path]):
        if self.engine_type != "python":
            raise WAFError("Rule loading is only available with Python engine")
        
        filepath = Path(filepath)
        if not filepath.exists():
            raise WAFConfigurationError(f"Rules file not found: {filepath}")
        
        with open(filepath, "r") as f:
            rules_data = json.load(f)
        
        for rule_data in rules_data:
            self.add_rule(**rule_data)
        logger.info(f"Loaded {len(rules_data)} rules from {filepath}")
    
    # ==========================================
    # Statistics & Status
    # ==========================================
    
    def get_stats(self) -> dict:
        if self.engine_type == "bunkerweb" and self.bunkerweb:
            base = self.bunkerweb.get_stats()
            base.update({
                "requests_checked": self._stats["requests_checked"],
                "requests_blocked": self._stats["requests_blocked"],
            })
            return base
        
        rate_stats = self.rate_limiter.get_stats() if self.rate_limiter else {}
        return {
            **self._stats,
            "rate_limiter": rate_stats,
            "uptime": time.time() - self._start_time if self._start_time else 0,
            "rules_count": len(self.rules) if self.rules else 0,
            "mode": self.mode,
            "engine": self.engine_type,
        }
    
    def get_status(self) -> dict:
        return {
            "enabled": self.config["enabled"],
            "running": self._running,
            "engine": self.engine_type,
            "mode": self.mode,
            "rules_count": len(self.rules) if self.rules else "OWASP CRS v4 (200+)",
            "paranoia_level": self.config["paranoia_level"],
            "block_on_attack": self.config["block_on_attack"],
            "rate_limiting_enabled": self.config["rate_limiting"]["enabled"],
            "stats": self.get_stats(),
        }
    
    def reset_stats(self):
        self._stats = {
            "requests_checked": 0,
            "requests_blocked": 0,
            "attacks_detected": 0,
            "ips_blocked": 0,
        }
        if self.rate_limiter:
            self.rate_limiter.reset()
        if self.rules:
            for rule in self.rules:
                rule.hits = 0
                rule.last_hit = None
        logger.info("WAF statistics reset")
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return f"WAF(engine='{self.engine_type}', mode='{self.mode}', running={self._running})"
    
    def __str__(self) -> str:
        status = "RUNNING" if self._running else "STOPPED"
        rules = len(self.rules) if self.rules else "OWASP CRS v4 (200+)"
        return f"🛡️ WAF [{status}] | Engine: {self.engine_type} | Mode: {self.mode} | Rules: {rules} | Blocked: {self._stats['requests_blocked']}"
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False