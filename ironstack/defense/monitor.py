#!/usr/bin/env python3
"""
Monitoring and Intrusion Detection module for IronStack.
Integrates with Fail2ban for automated threat response and IP blocking.
"""

import os
import re
import time
import json
import socket
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Set, Callable
from datetime import datetime, timedelta
from collections import defaultdict

from ..logging_config import get_logger
from ..exceptions import (
    IronStackError,
    ConfigurationError,
    ValidationError,
)

logger = get_logger(__name__)


# ==========================================
# Constants
# ==========================================

DEFAULT_MAX_RETRY = 5
DEFAULT_BAN_TIME = 600  # 10 minutes
DEFAULT_FIND_TIME = 600  # 10 minutes window
DEFAULT_LOG_PATH = "/var/log/ironstack/"
DEFAULT_ALERT_THRESHOLD = 10  # Alerts per minute before escalation

# Common attack patterns to monitor
ATTACK_PATTERNS = {
    "brute_force": [
        r"Failed password",
        r"authentication failure",
        r"invalid user",
        r"login failed",
        r"incorrect password",
        r"403 Forbidden",
    ],
    "port_scan": [
        r"scan detected",
        r"port scan",
        r"connection refused",
        r"SYN.*scan",
    ],
    "dos_attempt": [
        r"connection flood",
        r"rate limit exceeded",
        r"too many requests",
        r"429 Too Many Requests",
    ],
    "sql_injection": [
        r"SQL injection",
        r"UNION SELECT",
        r"sqlmap",
    ],
    "xss_attempt": [
        r"XSS detected",
        r"<script",
        r"javascript:",
    ],
    "path_traversal": [
        r"\.\.\/",
        r"path traversal",
        r"directory traversal",
    ],
}


# ==========================================
# Alert System
# ==========================================

class Alert:
    """
    Represents a security alert.
    """
    
    def __init__(
        self,
        alert_type: str,
        source_ip: str,
        message: str,
        severity: str = "medium",
        details: Optional[Dict[str, Any]] = None,
    ):
        self.alert_type = alert_type
        self.source_ip = source_ip
        self.message = message
        self.severity = severity
        self.timestamp = datetime.now()
        self.details = details or {}
        self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate a unique alert ID."""
        import hashlib
        data = f"{self.timestamp.isoformat()}:{self.source_ip}:{self.alert_type}"
        return hashlib.md5(data.encode()).hexdigest()[:12]
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "type": self.alert_type,
            "source_ip": self.source_ip,
            "message": self.message,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }
    
    def __repr__(self) -> str:
        return f"Alert(type='{self.alert_type}', ip='{self.source_ip}', severity='{self.severity}')"


class AlertManager:
    """
    Manages security alerts with deduplication and rate limiting.
    """
    
    def __init__(self, alert_threshold: int = DEFAULT_ALERT_THRESHOLD):
        self.alert_threshold = alert_threshold
        self.alerts: List[Alert] = []
        self.alert_counts: Dict[str, int] = defaultdict(int)
        self.last_reset = time.time()
        self._callbacks: List[Callable] = []
        self._lock = threading.Lock()
    
    def add_alert(self, alert: Alert):
        """
        Add a new alert.
        
        Args:
            alert: Alert instance
        """
        with self._lock:
            # Reset counts periodically
            if time.time() - self.last_reset > 60:
                self.alert_counts.clear()
                self.last_reset = time.time()
            
            # Check for duplicate
            alert_key = f"{alert.alert_type}:{alert.source_ip}"
            self.alert_counts[alert_key] += 1
            
            # Only add if not too frequent
            if self.alert_counts[alert_key] <= 3:
                self.alerts.append(alert)
                
                # Trigger callbacks
                for callback in self._callbacks:
                    try:
                        callback(alert)
                    except Exception as e:
                        logger.error(f"Alert callback error: {e}")
                
                # Log alert
                if alert.severity == "critical":
                    logger.critical(f"🚨 {alert.message}")
                elif alert.severity == "high":
                    logger.error(f"🔴 {alert.message}")
                elif alert.severity == "medium":
                    logger.warning(f"🟡 {alert.message}")
                else:
                    logger.info(f"🔵 {alert.message}")
    
    def get_alerts(
        self,
        alert_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """
        Get filtered alerts.
        
        Args:
            alert_type: Filter by type
            severity: Filter by severity
            source_ip: Filter by IP
            limit: Maximum number of alerts
            
        Returns:
            List of alert dictionaries
        """
        with self._lock:
            filtered = self.alerts.copy()
            
            if alert_type:
                filtered = [a for a in filtered if a.alert_type == alert_type]
            if severity:
                filtered = [a for a in filtered if a.severity == severity]
            if source_ip:
                filtered = [a for a in filtered if a.source_ip == source_ip]
            
            return [a.to_dict() for a in filtered[-limit:]]
    
    def get_stats(self) -> dict:
        """Get alert statistics."""
        with self._lock:
            severities = defaultdict(int)
            types = defaultdict(int)
            
            for alert in self.alerts[-1000:]:
                severities[alert.severity] += 1
                types[alert.alert_type] += 1
            
            return {
                "total_alerts": len(self.alerts),
                "by_severity": dict(severities),
                "by_type": dict(types),
                "recent_alerts": len([a for a in self.alerts 
                                    if (datetime.now() - a.timestamp).seconds < 300]),
            }
    
    def register_callback(self, callback: Callable):
        """Register a callback for new alerts."""
        self._callbacks.append(callback)
    
    def clear_alerts(self):
        """Clear all alerts."""
        with self._lock:
            self.alerts.clear()
            self.alert_counts.clear()


# ==========================================
# IP Blocker
# ==========================================

class IPBlocker:
    """
    Manages IP blocking with automatic unblock.
    """
    
    def __init__(
        self,
        ban_time: int = DEFAULT_BAN_TIME,
        max_retry: int = DEFAULT_MAX_RETRY,
        find_time: int = DEFAULT_FIND_TIME,
    ):
        self.ban_time = ban_time
        self.max_retry = max_retry
        self.find_time = find_time
        
        self.blocked_ips: Dict[str, float] = {}  # ip -> unblock_time
        self.failed_attempts: Dict[str, List[float]] = defaultdict(list)  # ip -> [timestamps]
        self.whitelist: Set[str] = set()
        self._lock = threading.Lock()
        self._block_count = 0
    
    def add_whitelist(self, ip: str):
        """Add IP to whitelist."""
        self.whitelist.add(ip)
        logger.info(f"✅ IP whitelisted: {ip}")
    
    def remove_whitelist(self, ip: str):
        """Remove IP from whitelist."""
        self.whitelist.discard(ip)
        logger.info(f"IP removed from whitelist: {ip}")
    
    def record_failure(self, ip: str) -> bool:
        """
        Record a failed attempt from an IP.
        
        Args:
            ip: Source IP address
            
        Returns:
            True if IP should be blocked
        """
        if ip in self.whitelist:
            return False
        
        with self._lock:
            now = time.time()
            
            # Check if already blocked
            if ip in self.blocked_ips:
                if now < self.blocked_ips[ip]:
                    return True  # Still blocked
                else:
                    del self.blocked_ips[ip]  # Unblock expired
            
            # Record failure
            if ip not in self.failed_attempts:
                self.failed_attempts[ip] = []
            
            self.failed_attempts[ip].append(now)
            
            # Remove old attempts outside find_time window
            cutoff = now - self.find_time
            self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if t > cutoff]
            
            # Check if threshold exceeded
            if len(self.failed_attempts[ip]) >= self.max_retry:
                self._block_ip(ip)
                return True
            
            return False
    
    def _block_ip(self, ip: str):
        """Block an IP address."""
        with self._lock:
            self.blocked_ips[ip] = time.time() + self.ban_time
            self._block_count += 1
            logger.warning(f"🚫 IP blocked: {ip} (ban_time: {self.ban_time}s)")
            
            # Clear failed attempts
            self.failed_attempts.pop(ip, None)
    
    def block_ip_immediately(self, ip: str, duration: Optional[int] = None):
        """
        Immediately block an IP.
        
        Args:
            ip: IP address to block
            duration: Block duration in seconds
        """
        if ip in self.whitelist:
            logger.warning(f"Cannot block whitelisted IP: {ip}")
            return
        
        ban_duration = duration or self.ban_time
        with self._lock:
            self.blocked_ips[ip] = time.time() + ban_duration
            self._block_count += 1
            logger.warning(f"🚫 IP immediately blocked: {ip} (duration: {ban_duration}s)")
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        with self._lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                logger.info(f"✅ IP unblocked: {ip}")
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        if ip in self.whitelist:
            return False
        
        with self._lock:
            if ip in self.blocked_ips:
                if time.time() < self.blocked_ips[ip]:
                    return True
                else:
                    del self.blocked_ips[ip]
            return False
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of currently blocked IPs."""
        now = time.time()
        with self._lock:
            # Clean expired blocks
            expired = [ip for ip, t in self.blocked_ips.items() if now >= t]
            for ip in expired:
                del self.blocked_ips[ip]
            
            return [
                {
                    "ip": ip,
                    "blocked_until": datetime.fromtimestamp(unblock_time).isoformat(),
                    "remaining_seconds": int(unblock_time - now),
                }
                for ip, unblock_time in self.blocked_ips.items()
            ]
    
    def get_stats(self) -> dict:
        """Get IP blocker statistics."""
        with self._lock:
            return {
                "blocked_count": len(self.blocked_ips),
                "total_blocks": self._block_count,
                "whitelisted_ips": len(self.whitelist),
                "tracked_ips": len(self.failed_attempts),
            }
    
    def clear_all(self):
        """Clear all blocks and tracking."""
        with self._lock:
            self.blocked_ips.clear()
            self.failed_attempts.clear()
            logger.info("All blocks cleared")


# ==========================================
# Log Monitor
# ==========================================

class LogMonitor:
    """
    Monitors log files for attack patterns.
    """
    
    def __init__(
        self,
        log_paths: Optional[List[Union[str, Path]]] = None,
        patterns: Optional[Dict[str, List[str]]] = None,
    ):
        self.log_paths = log_paths or []
        self.patterns = patterns or ATTACK_PATTERNS
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._file_positions: Dict[str, int] = {}
        self._alert_manager: Optional[AlertManager] = None
        self._ip_blocker: Optional[IPBlocker] = None
    
    def set_alert_manager(self, alert_manager: AlertManager):
        """Set alert manager for reporting."""
        self._alert_manager = alert_manager
    
    def set_ip_blocker(self, ip_blocker: IPBlocker):
        """Set IP blocker for automated response."""
        self._ip_blocker = ip_blocker
    
    def add_log_path(self, path: Union[str, Path]):
        """Add a log file to monitor."""
        self.log_paths.append(Path(path))
    
    def start(self):
        """Start log monitoring in background thread."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("📊 Log monitoring started")
    
    def stop(self):
        """Stop log monitoring."""
        self._monitoring = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Log monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._monitoring:
            for log_path in self.log_paths:
                try:
                    self._check_log_file(Path(log_path))
                except Exception as e:
                    logger.error(f"Error monitoring {log_path}: {e}")
            
            time.sleep(2)  # Check every 2 seconds
    
    def _check_log_file(self, log_path: Path):
        """Check a log file for new entries."""
        if not log_path.exists():
            return
        
        file_key = str(log_path)
        current_size = log_path.stat().st_size
        
        # Get last position
        last_position = self._file_positions.get(file_key, 0)
        
        # File was rotated or truncated
        if current_size < last_position:
            last_position = 0
        
        # No new data
        if current_size == last_position:
            return
        
        # Read new data
        with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(last_position)
            new_lines = f.readlines()
        
        # Update position
        self._file_positions[file_key] = f.tell()
        
        # Analyze new lines
        for line in new_lines:
            self._analyze_line(line.strip())
    
    def _analyze_line(self, line: str):
        """Analyze a log line for attack patterns."""
        if not line:
            return
        
        for attack_type, patterns in self.patterns.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Extract IP from line
                        ip = self._extract_ip(line)
                        
                        if self._alert_manager:
                            alert = Alert(
                                alert_type=attack_type,
                                source_ip=ip or "unknown",
                                message=f"Detected {attack_type}: {line[:100]}",
                                severity=self._get_severity(attack_type),
                                details={"log_line": line, "pattern": pattern},
                            )
                            self._alert_manager.add_alert(alert)
                        
                        if self._ip_blocker and ip:
                            self._ip_blocker.record_failure(ip)
                        
                        break  # One match per line is enough
                except re.error:
                    continue
    
    def _extract_ip(self, line: str) -> Optional[str]:
        """Extract IP address from a log line."""
        # IPv4 pattern
        ipv4_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
        match = re.search(ipv4_pattern, line)
        if match:
            return match.group(1)
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'\b([0-9a-fA-F:]+:+[0-9a-fA-F:]+)\b'
        match = re.search(ipv6_pattern, line)
        if match:
            return match.group(1)
        
        return None
    
    def _get_severity(self, attack_type: str) -> str:
        """Get severity for attack type."""
        severity_map = {
            "brute_force": "high",
            "port_scan": "medium",
            "dos_attempt": "high",
            "sql_injection": "critical",
            "xss_attempt": "high",
            "path_traversal": "high",
        }
        return severity_map.get(attack_type, "medium")


# ==========================================
# System Monitor
# ==========================================

class SystemMonitor:
    """
    Monitors system resources and detects anomalies.
    """
    
    def __init__(self):
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._stats: Dict[str, List[float]] = defaultdict(list)
        self._max_history = 60  # Keep 60 data points
    
    def start(self):
        """Start system monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("💻 System monitoring started")
    
    def stop(self):
        """Stop system monitoring."""
        self._monitoring = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._monitoring:
            try:
                self._collect_stats()
            except Exception as e:
                logger.error(f"System monitor error: {e}")
            
            time.sleep(10)  # Collect every 10 seconds
    
    def _collect_stats(self):
        """Collect system statistics."""
        import psutil
        
        # CPU
        cpu_percent = psutil.cpu_percent(interval=1)
        self._stats["cpu"].append(cpu_percent)
        
        # Memory
        memory = psutil.virtual_memory()
        self._stats["memory"].append(memory.percent)
        
        # Disk
        disk = psutil.disk_usage('/')
        self._stats["disk"].append(disk.percent)
        
        # Network
        net_io = psutil.net_io_counters()
        self._stats["network_sent"].append(net_io.bytes_sent)
        self._stats["network_recv"].append(net_io.bytes_recv)
        
        # Trim history
        for key in self._stats:
            if len(self._stats[key]) > self._max_history:
                self._stats[key] = self._stats[key][-self._max_history:]
    
    def get_stats(self) -> dict:
        """Get current system statistics."""
        if not self._stats["cpu"]:
            return {"status": "No data collected yet"}
        
        return {
            "cpu": {
                "current": self._stats["cpu"][-1] if self._stats["cpu"] else 0,
                "average": sum(self._stats["cpu"]) / len(self._stats["cpu"]),
                "max": max(self._stats["cpu"]),
            },
            "memory": {
                "current": self._stats["memory"][-1] if self._stats["memory"] else 0,
                "average": sum(self._stats["memory"]) / len(self._stats["memory"]),
                "max": max(self._stats["memory"]),
            },
            "disk": {
                "current": self._stats["disk"][-1] if self._stats["disk"] else 0,
            },
        }
    
    def is_under_attack(self) -> bool:
        """Check if system shows signs of attack (high CPU/memory)."""
        stats = self.get_stats()
        
        if stats.get("status") == "No data collected yet":
            return False
        
        cpu_high = stats["cpu"]["current"] > 90
        memory_high = stats["memory"]["current"] > 90
        
        return cpu_high or memory_high


# ==========================================
# Fail2ban Integration
# ==========================================

class Fail2banIntegration:
    """
    Integration with Fail2ban for automated IP blocking.
    """
    
    def __init__(self):
        self._enabled = False
        self._fail2ban_available = self._check_fail2ban()
    
    def _check_fail2ban(self) -> bool:
        """Check if fail2ban-client is available."""
        try:
            result = subprocess.run(
                ["fail2ban-client", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def is_available(self) -> bool:
        """Check if Fail2ban is available."""
        return self._fail2ban_available
    
    def ban_ip(self, ip: str, jail: str = "custom") -> bool:
        """
        Ban an IP using Fail2ban.
        
        Args:
            ip: IP address to ban
            jail: Fail2ban jail name
            
        Returns:
            True if successful
        """
        if not self._fail2ban_available:
            logger.warning("Fail2ban not available")
            return False
        
        try:
            subprocess.run(
                ["fail2ban-client", "set", jail, "banip", ip],
                capture_output=True,
                timeout=10,
            )
            logger.info(f"Fail2ban banned IP: {ip}")
            return True
        except Exception as e:
            logger.error(f"Fail2ban ban failed: {e}")
            return False
    
    def unban_ip(self, ip: str, jail: str = "custom") -> bool:
        """Unban an IP using Fail2ban."""
        if not self._fail2ban_available:
            return False
        
        try:
            subprocess.run(
                ["fail2ban-client", "set", jail, "unbanip", ip],
                capture_output=True,
                timeout=10,
            )
            logger.info(f"Fail2ban unbanned IP: {ip}")
            return True
        except Exception as e:
            logger.error(f"Fail2ban unban failed: {e}")
            return False
    
    def get_banned_ips(self, jail: str = "custom") -> List[str]:
        """Get list of banned IPs from Fail2ban."""
        if not self._fail2ban_available:
            return []
        
        try:
            result = subprocess.run(
                ["fail2ban-client", "status", jail],
                capture_output=True,
                timeout=10,
                text=True,
            )
            
            # Parse output for banned IPs
            ips = []
            for line in result.stdout.split("\n"):
                if "Banned IP list:" in line:
                    ip_list = line.split(":")[-1].strip()
                    if ip_list:
                        ips = [ip.strip() for ip in ip_list.split()]
            
            return ips
        except Exception:
            return []


# ==========================================
# Main Monitor Class
# ==========================================

class Monitor:
    """
    Main monitoring interface for IronStack.
    
    Combines alert management, IP blocking, log monitoring,
    system monitoring, and Fail2ban integration.
    
    Usage:
        >>> from ironstack.defense import Monitor
        >>> monitor = Monitor()
        >>> monitor.start()
        >>> monitor.block_ip("192.168.1.100")
        >>> stats = monitor.get_stats()
    """
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        max_retry: int = DEFAULT_MAX_RETRY,
        ban_time: int = DEFAULT_BAN_TIME,
        find_time: int = DEFAULT_FIND_TIME,
    ):
        """
        Initialize Monitor.
        
        Args:
            config: Configuration dictionary
            max_retry: Max failed attempts before blocking
            ban_time: Block duration in seconds
            find_time: Time window for counting failures
        """
        # Default configuration
        self.config = {
            "enabled": True,
            "max_retry": max_retry,
            "ban_time": ban_time,
            "find_time": find_time,
            "alert_threshold": DEFAULT_ALERT_THRESHOLD,
            "log_paths": [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/apache2/access.log",
                "/var/log/nginx/access.log",
            ],
            "notification_enabled": False,
            "notification_email": None,
        }
        
        if config:
            self._deep_merge(self.config, config)
        
        # Initialize components
        self.alert_manager = AlertManager(
            alert_threshold=self.config["alert_threshold"]
        )
        
        self.ip_blocker = IPBlocker(
            ban_time=self.config["ban_time"],
            max_retry=self.config["max_retry"],
            find_time=self.config["find_time"],
        )
        
        self.log_monitor = LogMonitor(
            log_paths=[Path(p) for p in self.config["log_paths"] if Path(p).exists()],
        )
        self.log_monitor.set_alert_manager(self.alert_manager)
        self.log_monitor.set_ip_blocker(self.ip_blocker)
        
        self.system_monitor = SystemMonitor()
        self.fail2ban = Fail2banIntegration()
        
        # Register alert callback for IP blocking
        self.alert_manager.register_callback(self._on_alert)
        
        # State
        self._running = False
        self._stats = {
            "ips_blocked": 0,
            "alerts_generated": 0,
            "attacks_detected": 0,
        }
        
        logger.info("📊 Monitor initialized")
    
    def _deep_merge(self, base: dict, override: dict):
        """Deep merge two dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _on_alert(self, alert: Alert):
        """Handle new alerts."""
        self._stats["alerts_generated"] += 1
        
        if alert.severity in ("high", "critical"):
            self._stats["attacks_detected"] += 1
            
            # Auto-block for critical alerts
            if alert.severity == "critical" and alert.source_ip != "unknown":
                self.ip_blocker.block_ip_immediately(alert.source_ip)
    
    # ==========================================
    # Control Methods
    # ==========================================
    
    def start(self):
        """Start all monitoring components."""
        if self._running:
            return
        
        self._running = True
        self.log_monitor.start()
        self.system_monitor.start()
        logger.info("📊 Monitor started")
    
    def stop(self):
        """Stop all monitoring components."""
        self._running = False
        self.log_monitor.stop()
        self.system_monitor.stop()
        logger.info("Monitor stopped")
    
    # ==========================================
    # IP Management
    # ==========================================
    
    def block_ip(self, ip: str, duration: Optional[int] = None):
        """Block an IP address."""
        self.ip_blocker.block_ip_immediately(ip, duration)
        self._stats["ips_blocked"] += 1
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self.ip_blocker.unblock_ip(ip)
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return self.ip_blocker.is_blocked(ip)
    
    def whitelist_ip(self, ip: str):
        """Add IP to whitelist."""
        self.ip_blocker.add_whitelist(ip)
    
    def get_blocked_ips(self) -> List[dict]:
        """Get blocked IPs."""
        return self.ip_blocker.get_blocked_ips()
    
    # ==========================================
    # Alert Methods
    # ==========================================
    
    def get_alerts(self, **kwargs) -> List[dict]:
        """Get security alerts."""
        return self.alert_manager.get_alerts(**kwargs)
    
    def clear_alerts(self):
        """Clear all alerts."""
        self.alert_manager.clear_alerts()
    
    # ==========================================
    # Statistics
    # ==========================================
    
    def get_stats(self) -> dict:
        """Get comprehensive monitoring statistics."""
        return {
            "ip_blocker": self.ip_blocker.get_stats(),
            "alerts": self.alert_manager.get_stats(),
            "system": self.system_monitor.get_stats(),
            "monitor": self._stats,
            "fail2ban_available": self.fail2ban.is_available(),
            "running": self._running,
        }
    
    def reset_stats(self):
        """Reset all statistics."""
        self._stats = {
            "ips_blocked": 0,
            "alerts_generated": 0,
            "attacks_detected": 0,
        }
        self.ip_blocker.clear_all()
        self.alert_manager.clear_alerts()
        logger.info("Statistics reset")
    
    # ==========================================
    # Magic Methods
    # ==========================================
    
    def __repr__(self) -> str:
        return f"Monitor(running={self._running}, blocked={len(self.ip_blocker.get_blocked_ips())})"
    
    def __str__(self) -> str:
        status = "RUNNING" if self._running else "STOPPED"
        return f"📊 Monitor [{status}] | Blocked IPs: {len(self.ip_blocker.get_blocked_ips())} | Alerts: {self.alert_manager.get_stats()['total_alerts']}"
    
    def __enter__(self):
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False
