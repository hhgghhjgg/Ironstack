#!/usr/bin/env python3
"""
Vulnerability Scanner module for IronStack.
Integrates with SQLMap, Nmap, and custom scanners for security testing.
"""

import os
import re
import json
import time
import socket
import threading
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin

from ..logging_config import get_logger
from ..exceptions import (
    IronStackScanError,
    ScanFailedError,
    ScanTimeoutError,
    VulnerabilityFoundError,
    ConnectionError,
)

logger = get_logger(__name__)


# ==========================================
# Constants
# ==========================================

DEFAULT_SCAN_TIMEOUT = 300  # 5 minutes
DEFAULT_THREADS = 10
DEFAULT_USER_AGENT = "IronStack-Scanner/1.0"
DEFAULT_MAX_DEPTH = 3
DEFAULT_RATE_LIMIT = 10  # requests per second

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

WEB_VULNERABILITY_CHECKS = [
    "sql_injection",
    "xss",
    "csrf",
    "path_traversal",
    "command_injection",
    "file_inclusion",
    "open_redirect",
    "directory_listing",
    "backup_files",
    "git_exposure",
    "env_exposure",
    "debug_endpoints",
    "default_credentials",
    "misconfiguration",
    "ssl_issues",
    "headers_missing",
]


# ==========================================
# Scan Result Classes
# ==========================================

class Vulnerability:
    """Represents a found vulnerability."""
    
    def __init__(
        self,
        vuln_type: str,
        severity: str,
        title: str,
        description: str,
        location: str,
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ):
        self.vuln_type = vuln_type
        self.severity = severity  # critical, high, medium, low, info
        self.title = title
        self.description = description
        self.location = location
        self.evidence = evidence
        self.remediation = remediation
        self.cvss_score = cvss_score
        self.timestamp = datetime.now()
    
    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "timestamp": self.timestamp.isoformat(),
        }


class ScanResult:
    """Represents a complete scan result."""
    
    def __init__(self, target: str, scan_type: str):
        self.target = target
        self.scan_type = scan_type
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        self.vulnerabilities: List[Vulnerability] = []
        self.open_ports: List[Dict[str, Any]] = []
        self.services: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.risk_score: int = 0
    
    def add_vulnerability(self, vuln: Vulnerability):
        self.vulnerabilities.append(vuln)
        self._update_risk_score()
    
    def _update_risk_score(self):
        severity_scores = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 1,
        }
        self.risk_score = min(100, sum(
            severity_scores.get(v.severity, 5) for v in self.vulnerabilities
        ))
    
    def finalize(self):
        self.end_time = datetime.now()
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_type": self.scan_type,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "open_ports": self.open_ports,
            "services": self.services,
            "findings": self.findings,
            "errors": self.errors,
            "risk_score": self.risk_score,
            "severity_counts": {
                "critical": sum(1 for v in self.vulnerabilities if v.severity == "critical"),
                "high": sum(1 for v in self.vulnerabilities if v.severity == "high"),
                "medium": sum(1 for v in self.vulnerabilities if v.severity == "medium"),
                "low": sum(1 for v in self.vulnerabilities if v.severity == "low"),
                "info": sum(1 for v in self.vulnerabilities if v.severity == "info"),
            },
        }


# ==========================================
# Port Scanner
# ==========================================

class PortScanner:
    """
    TCP port scanner for discovering open ports and services.
    """
    
    def __init__(
        self,
        timeout: float = 2.0,
        threads: int = 50,
    ):
        self.timeout = timeout
        self.threads = threads
        self._lock = threading.Lock()
        self._results: List[Dict[str, Any]] = []
    
    def scan(
        self,
        host: str,
        ports: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Scan ports on a host.
        
        Args:
            host: Target host
            ports: List of ports to scan (default: common ports)
            
        Returns:
            List of open port information
        """
        if ports is None:
            ports = list(COMMON_PORTS.keys())
        
        self._results = []
        threads = []
        
        for port in ports:
            while len(threads) >= self.threads:
                threads = [t for t in threads if t.is_alive()]
                time.sleep(0.01)
            
            t = threading.Thread(target=self._scan_port, args=(host, port))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join(timeout=self.timeout + 1)
        
        return sorted(self._results, key=lambda r: r["port"])
    
    def _scan_port(self, host: str, port: int):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service = self._detect_service(host, port)
                banner = self._grab_banner(host, port)
                
                with self._lock:
                    self._results.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "state": "open",
                    })
        except Exception as e:
            logger.debug(f"Port {port} scan error: {e}")
    
    def _detect_service(self, host: str, port: int) -> str:
        """Detect service running on port."""
        return COMMON_PORTS.get(port, "unknown")
    
    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Try to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((host, port))
            
            # Send generic request
            if port in (80, 443, 8080, 8443):
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port in (21, 22, 25, 110, 143):
                pass  # Wait for banner
            
            time.sleep(0.5)
            banner = sock.recv(1024)
            sock.close()
            
            return banner.decode("utf-8", errors="ignore").strip()
        except Exception:
            return None


# ==========================================
# Web Vulnerability Scanner
# ==========================================

class WebVulnerabilityScanner:
    """
    Scanner for web application vulnerabilities.
    """
    
    def __init__(
        self,
        timeout: int = DEFAULT_SCAN_TIMEOUT,
        max_depth: int = DEFAULT_MAX_DEPTH,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        self.timeout = timeout
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self.session = self._create_session()
        self.visited_urls: Set[str] = set()
        self.found_vulnerabilities: List[Vulnerability] = []
    
    def _create_session(self):
        """Create HTTP session."""
        try:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            
            session = requests.Session()
            session.headers.update({
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/json,*/*",
            })
            
            retry = Retry(total=2, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            
            return session
        except ImportError:
            logger.warning("requests library not available")
            return None
    
    def scan(self, target_url: str) -> List[Vulnerability]:
        """
        Scan a web application for vulnerabilities.
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            List of found vulnerabilities
        """
        self.visited_urls.clear()
        self.found_vulnerabilities.clear()
        
        logger.info(f"🔍 Starting web scan: {target_url}")
        
        try:
            # Crawl the site first
            urls = self._crawl(target_url)
            
            # Check each URL
            for url in urls:
                self._check_sql_injection(url)
                self._check_xss(url)
                self._check_path_traversal(url)
                self._check_directory_listing(url)
                self._check_backup_files(url)
                self._check_git_exposure(url)
                self._check_env_exposure(url)
                self._check_headers(url)
                self._check_ssl(url)
                
                # Rate limiting
                time.sleep(1 / self.rate_limit)
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
        
        return self.found_vulnerabilities
    
    def _crawl(self, start_url: str, depth: int = 0) -> List[str]:
        """Crawl website to discover URLs."""
        if depth > self.max_depth or start_url in self.visited_urls:
            return []
        
        self.visited_urls.add(start_url)
        
        if not self.session:
            return [start_url]
        
        urls = [start_url]
        
        try:
            response = self.session.get(start_url, timeout=10, verify=False)
            
            # Extract links from HTML
            if "text/html" in response.headers.get("Content-Type", ""):
                from html.parser import HTMLParser
                
                class LinkExtractor(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.links = []
                    
                    def handle_starttag(self, tag, attrs):
                        if tag in ("a", "link", "script", "img", "form"):
                            for attr_name, attr_value in attrs:
                                if attr_name in ("href", "src", "action"):
                                    self.links.append(attr_value)
                
                parser = LinkExtractor()
                parser.feed(response.text)
                
                base_url = response.url
                for link in parser.links:
                    absolute_url = urljoin(base_url, link)
                    parsed = urlparse(absolute_url)
                    
                    # Only follow same domain
                    if parsed.netloc == urlparse(start_url).netloc:
                        if absolute_url not in self.visited_urls:
                            urls.extend(self._crawl(absolute_url, depth + 1))
        
        except Exception as e:
            logger.debug(f"Crawl error for {start_url}: {e}")
        
        return urls
    
    def _check_sql_injection(self, url: str):
        """Check for SQL injection vulnerabilities."""
        sql_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 100--",
        ]
        
        for payload in sql_payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}id={payload}"
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                text = response.text.lower()
                
                sql_errors = [
                    "sql syntax",
                    "mysql error",
                    "ora-",
                    "postgresql error",
                    "sqlite",
                    "microsoft sql",
                    "odbc driver",
                    "syntax error",
                    "unclosed quotation mark",
                ]
                
                for error in sql_errors:
                    if error in text:
                        self.found_vulnerabilities.append(Vulnerability(
                            vuln_type="sql_injection",
                            severity="critical",
                            title="SQL Injection Vulnerability",
                            description=f"SQL injection detected with payload: {payload}",
                            location=url,
                            evidence=f"Error message found: {error}",
                            remediation="Use parameterized queries or prepared statements",
                        ))
                        return
                        
            except Exception:
                continue
    
    def _check_xss(self, url: str):
        """Check for XSS vulnerabilities."""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
        ]
        
        for payload in xss_payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}q={payload}"
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                if payload in response.text:
                    self.found_vulnerabilities.append(Vulnerability(
                        vuln_type="xss",
                        severity="high",
                        title="Cross-Site Scripting (XSS)",
                        description=f"XSS detected with payload: {payload}",
                        location=url,
                        evidence=f"Payload reflected in response",
                        remediation="Sanitize and encode user input properly",
                    ))
                    return
                    
            except Exception:
                continue
    
    def _check_path_traversal(self, url: str):
        """Check for path traversal vulnerabilities."""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        ]
        
        for payload in traversal_payloads:
            test_url = f"{url}{'&' if '?' in url else '?'}file={payload}"
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                indicators = [
                    "root:x:0:0:",
                    "[extensions]",
                    "root:/root:/bin/bash",
                ]
                
                for indicator in indicators:
                    if indicator in response.text:
                        self.found_vulnerabilities.append(Vulnerability(
                            vuln_type="path_traversal",
                            severity="critical",
                            title="Path Traversal Vulnerability",
                            description=f"Path traversal detected with payload: {payload}",
                            location=url,
                            evidence=f"Found indicator: {indicator}",
                            remediation="Validate and sanitize file paths, use whitelist",
                        ))
                        return
                        
            except Exception:
                continue
    
    def _check_directory_listing(self, url: str):
        """Check for directory listing enabled."""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            
            indicators = [
                "Index of /",
                "Directory Listing For",
                "Parent Directory",
                "[To Parent Directory]",
            ]
            
            for indicator in indicators:
                if indicator in response.text:
                    self.found_vulnerabilities.append(Vulnerability(
                        vuln_type="directory_listing",
                        severity="medium",
                        title="Directory Listing Enabled",
                        description="Directory listing is enabled, exposing file structure",
                        location=url,
                        evidence=f"Found: {indicator}",
                        remediation="Disable directory listing in web server configuration",
                    ))
                    return
                    
        except Exception:
            pass
    
    def _check_backup_files(self, url: str):
        """Check for exposed backup files."""
        backup_extensions = [
            ".bak", ".backup", ".old", ".orig", ".swp",
            ".save", ".tar", ".gz", ".zip", ".7z", ".sql",
            "~", ".copy", ".tmp",
        ]
        
        base_url = url.rstrip("/")
        
        for ext in backup_extensions:
            test_url = f"{base_url}{ext}"
            
            try:
                response = self.session.head(test_url, timeout=3, verify=False)
                
                if response.status_code == 200:
                    self.found_vulnerabilities.append(Vulnerability(
                        vuln_type="backup_exposed",
                        severity="high",
                        title="Backup File Exposed",
                        description=f"Backup file accessible: {test_url}",
                        location=test_url,
                        evidence=f"HTTP {response.status_code}",
                        remediation="Remove backup files from web root",
                    ))
                    
            except Exception:
                continue
    
    def _check_git_exposure(self, url: str):
        """Check for exposed .git directory."""
        test_url = url.rstrip("/") + "/.git/HEAD"
        
        try:
            response = self.session.get(test_url, timeout=5, verify=False)
            
            if "ref:" in response.text:
                self.found_vulnerabilities.append(Vulnerability(
                    vuln_type="git_exposure",
                    severity="critical",
                    title="Git Repository Exposed",
                    description=".git directory is accessible, source code can be downloaded",
                    location=test_url,
                    evidence=response.text[:100],
                    remediation="Block access to .git directory in web server",
                ))
                
        except Exception:
            pass
    
    def _check_env_exposure(self, url: str):
        """Check for exposed .env files."""
        env_paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.development",
            "/.env.backup",
        ]
        
        base_url = url.rstrip("/")
        
        for env_path in env_paths:
            test_url = base_url.split("?")[0].rstrip("/") + env_path
            
            try:
                response = self.session.get(test_url, timeout=5, verify=False)
                
                env_indicators = [
                    "DB_PASSWORD=",
                    "SECRET_KEY=",
                    "API_KEY=",
                    "APP_KEY=",
                    "DATABASE_URL=",
                ]
                
                for indicator in env_indicators:
                    if indicator in response.text:
                        self.found_vulnerabilities.append(Vulnerability(
                            vuln_type="env_exposure",
                            severity="critical",
                            title="Environment File Exposed",
                            description=".env file with secrets is accessible",
                            location=test_url,
                            evidence=f"Found: {indicator}",
                            remediation="Block access to .env files, never commit to VCS",
                        ))
                        return
                        
            except Exception:
                continue
    
    def _check_headers(self, url: str):
        """Check for missing security headers."""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            headers = response.headers
            
            security_headers = {
                "Strict-Transport-Security": "HSTS not enabled",
                "Content-Security-Policy": "CSP not set",
                "X-Content-Type-Options": "X-Content-Type-Options missing",
                "X-Frame-Options": "Clickjacking protection missing",
                "X-XSS-Protection": "XSS protection header missing",
                "Referrer-Policy": "Referrer-Policy not set",
                "Permissions-Policy": "Permissions-Policy not set",
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in headers:
                    missing_headers.append(f"{header}: {message}")
            
            if missing_headers:
                self.found_vulnerabilities.append(Vulnerability(
                    vuln_type="missing_headers",
                    severity="medium",
                    title="Missing Security Headers",
                    description="One or more security headers are missing",
                    location=url,
                    evidence=", ".join(missing_headers[:3]),
                    remediation="Configure web server to include security headers",
                ))
                
        except Exception:
            pass
    
    def _check_ssl(self, url: str):
        """Check SSL/TLS configuration."""
        if not url.startswith("https://"):
            return
        
        try:
            import ssl
            import socket
            
            hostname = urlparse(url).hostname
            
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET),
                server_hostname=hostname,
            ) as s:
                s.settimeout(5)
                s.connect((hostname, 443))
                
                cert = s.getpeercert()
                cipher = s.cipher()
                
                # Check TLS version
                tls_version = cipher[1]
                if tls_version in ("TLSv1.0", "TLSv1.1"):
                    self.found_vulnerabilities.append(Vulnerability(
                        vuln_type="weak_tls",
                        severity="high",
                        title="Weak TLS Version",
                        description=f"Server supports weak TLS: {tls_version}",
                        location=url,
                        evidence=f"TLS version: {tls_version}",
                        remediation="Disable TLS 1.0 and 1.1, use TLS 1.2+",
                    ))
                    
        except Exception as e:
            logger.debug(f"SSL check error: {e}")


# ==========================================
# SQL Injection Scanner (SQLMap Integration)
# ==========================================

class SQLInjectionScanner:
    """
    Advanced SQL injection scanner with SQLMap integration.
    """
    
    def __init__(self):
        self.sqlmap_available = self._check_sqlmap()
    
    def _check_sqlmap(self) -> bool:
        """Check if SQLMap is available."""
        try:
            result = subprocess.run(
                ["sqlmap", "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def scan(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 300,
    ) -> List[Vulnerability]:
        """
        Scan for SQL injection using SQLMap.
        
        Args:
            url: Target URL
            method: HTTP method
            data: POST data
            cookie: Session cookie
            timeout: Scan timeout
            
        Returns:
            List of vulnerabilities
        """
        vulnerabilities = []
        
        if not self.sqlmap_available:
            logger.warning("SQLMap not available. Install with: apt install sqlmap")
            return vulnerabilities
        
        cmd = [
            "sqlmap",
            "-u", url,
            "--batch",
            "--random-agent",
            "--level=2",
            "--risk=2",
            "--output-dir=/tmp/ironstack-sqlmap",
            "--timeout", str(timeout),
        ]
        
        if method.upper() == "POST":
            cmd.extend(["--data", data or ""])
        
        if cookie:
            cmd.extend(["--cookie", cookie])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout + 30,
                text=True,
            )
            
            output = result.stdout
            
            # Parse SQLMap output for vulnerabilities
            if "is vulnerable" in output.lower():
                # Extract vulnerable parameter info
                param_match = re.search(r"Parameter\s+['\"]?(\w+)['\"]?\s+is vulnerable", output)
                param = param_match.group(1) if param_match else "unknown"
                
                vulnerabilities.append(Vulnerability(
                    vuln_type="sql_injection",
                    severity="critical",
                    title="SQL Injection (SQLMap Confirmed)",
                    description=f"SQLMap confirmed SQL injection vulnerability",
                    location=url,
                    evidence=f"Vulnerable parameter: {param}",
                    remediation="Use parameterized queries",
                    cvss_score=9.8,
                ))
            
        except subprocess.TimeoutExpired:
            logger.warning(f"SQLMap scan timed out for {url}")
        except Exception as e:
            logger.error(f"SQLMap error: {e}")
        
        return vulnerabilities


# ==========================================
# Main Scanner Class
# ==========================================

class Scanner:
    """
    Main vulnerability scanner for IronStack.
    
    Combines port scanning, web vulnerability scanning,
    and SQL injection testing.
    
    Usage:
        >>> from ironstack.attack import Scanner
        >>> scanner = Scanner()
        >>> result = scanner.scan_web("https://example.com")
        >>> print(result.risk_score)
    """
    
    def __init__(
        self,
        timeout: int = DEFAULT_SCAN_TIMEOUT,
        threads: int = DEFAULT_THREADS,
        max_depth: int = DEFAULT_MAX_DEPTH,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        user_agent: str = DEFAULT_USER_AGENT,
    ):
        """
        Initialize Scanner.
        
        Args:
            timeout: Scan timeout in seconds
            threads: Number of threads
            max_depth: Crawl depth
            rate_limit: Requests per second
            user_agent: User agent string
        """
        self.timeout = timeout
        self.threads = threads
        self.max_depth = max_depth
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        
        # Initialize sub-scanners
        self.port_scanner = PortScanner(timeout=2.0)
        self.web_scanner = WebVulnerabilityScanner(
            timeout=timeout,
            max_depth=max_depth,
            rate_limit=rate_limit,
            user_agent=user_agent,
        )
        self.sql_scanner = SQLInjectionScanner()
        
        logger.info(f"🔍 Scanner initialized ({threads} threads)")
    
    # ==========================================
    # Scan Methods
    # ==========================================
    
    def scan_web(self, target: str) -> ScanResult:
        """
        Perform a full web vulnerability scan.
        
        Args:
            target: Target URL
            
        Returns:
            ScanResult with findings
        """
        result = ScanResult(target, "web")
        
        logger.info(f"🔍 Scanning: {target}")
        
        # Crawl and scan
        try:
            vulnerabilities = self.web_scanner.scan(target)
            for vuln in vulnerabilities:
                result.add_vulnerability(vuln)
        except Exception as e:
            result.errors.append(f"Web scan error: {e}")
        
        # SQL injection scan
        try:
            sql_vulns = self.sql_scanner.scan(target)
            for vuln in sql_vulns:
                result.add_vulnerability(vuln)
        except Exception as e:
            result.errors.append(f"SQL scan error: {e}")
        
        # Port scan
        try:
            hostname = urlparse(target).hostname
            open_ports = self.port_scanner.scan(hostname)
            result.open_ports = open_ports
        except Exception as e:
            result.errors.append(f"Port scan error: {e}")
        
        result.finalize()
        
        logger.info(
            f"✅ Scan complete: {len(result.vulnerabilities)} vulns, "
            f"risk score: {result.risk_score}"
        )
        
        return result
    
    def scan_network(self, target: str, ports: Optional[List[int]] = None) -> ScanResult:
        """
        Scan network ports.
        
        Args:
            target: Target IP or hostname
            ports: Ports to scan
            
        Returns:
            ScanResult with port information
        """
        result = ScanResult(target, "network")
        
        logger.info(f"🔍 Scanning ports on: {target}")
        
        try:
            open_ports = self.port_scanner.scan(target, ports)
            result.open_ports = open_ports
            
            # Detect services
            for port_info in open_ports:
                if port_info["state"] == "open":
                    result.services.append({
                        "port": port_info["port"],
                        "service": port_info["service"],
                        "banner": port_info.get("banner"),
                    })
        except Exception as e:
            result.errors.append(f"Network scan error: {e}")
        
        result.finalize()
        return result
    
    def scan_sql_injection(
        self,
        url: str,
        method: str = "GET",
        data: Optional[str] = None,
        cookie: Optional[str] = None,
    ) -> ScanResult:
        """
        Scan for SQL injection specifically.
        
        Args:
            url: Target URL
            method: HTTP method
            data: POST data
            cookie: Session cookie
            
        Returns:
            ScanResult with SQL injection findings
        """
        result = ScanResult(url, "sql_injection")
        
        logger.info(f"🔍 SQL injection scan: {url}")
        
        try:
            vulns = self.sql_scanner.scan(url, method, data, cookie)
            for vuln in vulns:
                result.add_vulnerability(vuln)
        except Exception as e:
            result.errors.append(f"SQL scan error: {e}")
        
        result.finalize()
        return result
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """
        Perform a quick scan and return summary.
        
        Args:
            target: Target URL or IP
            
        Returns:
            Dictionary with scan summary
        """
        result = self.scan_web(target)
        return {
            "target": target,
            "risk_score": result.risk_score,
            "vulnerabilities_count": len(result.vulnerabilities),
            "open_ports_count": len(result.open_ports),
            "severity_counts": result.to_dict()["severity_counts"],
            "top_vulnerabilities": [
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "title": v.title,
                    "location": v.location,
                }
                for v in sorted(
                    result.vulnerabilities,
                    key=lambda v: ["critical", "high", "medium", "low", "info"].index(v.severity)
                )[:5]
            ],
        }
    
    # ==========================================
    # Report Generation
    # ==========================================
    
    def generate_report(
        self,
        result: ScanResult,
        output_path: Optional[str] = None,
        format: str = "json",
    ) -> str:
        """
        Generate a scan report.
        
        Args:
            result: ScanResult to report
            output_path: Output file path
            format: Output format (json, html, text)
            
        Returns:
            Report content
        """
        if format == "json":
            report = json.dumps(result.to_dict(), indent=2, default=str)
        elif format == "text":
            report = self._generate_text_report(result)
        elif format == "html":
            report = self._generate_html_report(result)
        else:
            report = json.dumps(result.to_dict(), indent=2, default=str)
        
        if output_path:
            with open(output_path, "w") as f:
                f.write(report)
            logger.info(f"Report saved to {output_path}")
        
        return report
    
    def _generate_text_report(self, result: ScanResult) -> str:
        """Generate text format report."""
        data = result.to_dict()
        
        lines = [
            "=" * 60,
            "IRONSTACK SECURITY SCAN REPORT",
            "=" * 60,
            f"Target: {data['target']}",
            f"Scan Type: {data['scan_type']}",
            f"Start Time: {data['start_time']}",
            f"End Time: {data['end_time']}",
            f"Duration: {data['duration_seconds']:.2f}s",
            f"Risk Score: {data['risk_score']}/100",
            "",
            "-" * 60,
            "VULNERABILITY SUMMARY",
            "-" * 60,
            f"Critical: {data['severity_counts']['critical']}",
            f"High: {data['severity_counts']['high']}",
            f"Medium: {data['severity_counts']['medium']}",
            f"Low: {data['severity_counts']['low']}",
            f"Info: {data['severity_counts']['info']}",
            f"Total: {sum(data['severity_counts'].values())}",
            "",
        ]
        
        if data["vulnerabilities"]:
            lines.append("-" * 60)
            lines.append("VULNERABILITIES FOUND")
            lines.append("-" * 60)
            
            for i, vuln in enumerate(data["vulnerabilities"], 1):
                lines.extend([
                    f"\n{i}. [{vuln['severity'].upper()}] {vuln['title']}",
                    f"   Type: {vuln['type']}",
                    f"   Location: {vuln['location']}",
                    f"   Description: {vuln['description']}",
                    f"   Remediation: {vuln.get('remediation', 'N/A')}",
                ])
        
        if data["open_ports"]:
            lines.append("\n" + "-" * 60)
            lines.append("OPEN PORTS")
            lines.append("-" * 60)
            for port in data["open_ports"]:
                lines.append(f"  {port['port']}/tcp - {port['service']}")
        
        lines.append("\n" + "=" * 60)
        lines.append("END OF REPORT")
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def _generate_html_report(self, result: ScanResult) -> str:
        """Generate HTML format report."""
        data = result.to_dict()
        
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        
        vuln_rows = ""
        for vuln in data["vulnerabilities"]:
            color = severity_colors.get(vuln["severity"], "#6c757d")
            vuln_rows += f"""
            <tr>
                <td style="color:{color};font-weight:bold">[{vuln['severity'].upper()}]</td>
                <td>{vuln['title']}</td>
                <td>{vuln['type']}</td>
                <td>{vuln['location']}</td>
            </tr>"""
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>IronStack Scan Report - {data['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #1a1a2e; color: white; padding: 20px; border-radius: 10px; }}
                .summary {{ display: flex; gap: 10px; margin: 20px 0; }}
                .card {{ padding: 15px; border-radius: 8px; color: white; flex: 1; text-align: center; }}
                .critical {{ background: {severity_colors['critical']}; }}
                .high {{ background: {severity_colors['high']}; }}
                .medium {{ background: {severity_colors['medium']}; }}
                .low {{ background: {severity_colors['low']}; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
                th {{ background: #f8f9fa; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ IronStack Security Scan Report</h1>
                <p>Target: {data['target']}</p>
                <p>Risk Score: {data['risk_score']}/100</p>
            </div>
            
            <div class="summary">
                <div class="card critical">Critical<br><h2>{data['severity_counts']['critical']}</h2></div>
                <div class="card high">High<br><h2>{data['severity_counts']['high']}</h2></div>
                <div class="card medium">Medium<br><h2>{data['severity_counts']['medium']}</h2></div>
                <div class="card low">Low<br><h2>{data['severity_counts']['low']}</h2></div>
            </div>
            
            <h2>Vulnerabilities</h2>
            <table>
                <tr><th>Severity</th><th>Title</th><th>Type</th><th>Location</th></tr>
                {vuln_rows}
            </table>
            
            <p><em>Generated: {data['end_time']}</em></p>
        </body>
        </html>
        """
        
        return html
    
    # ==========================================
    # Utility
    # ==========================================
    
    def check_availability(self, host: str, port: int = 80) -> bool:
        """Check if a host is reachable."""
        try:
            socket.create_connection((host, port), timeout=5)
            return True
        except Exception:
            return False
    
    def get_scan_status(self) -> dict:
        """Get scanner status."""
        return {
            "sqlmap_available": self.sql_scanner.sqlmap_available,
            "threads": self.threads,
            "timeout": self.timeout,
            "max_depth": self.max_depth,
            "rate_limit": self.rate_limit,
        }
    
    def __repr__(self) -> str:
        return f"Scanner(sqlmap={self.sql_scanner.sqlmap_available}, threads={self.threads})"
