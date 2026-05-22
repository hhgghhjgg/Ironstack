#!/usr/bin/env python3
"""
BunkerWeb Connector for IronStack
==================================
Standalone connector for BunkerWeb WAF (200+ OWASP CRS rules).
Requires Docker to be installed and running.

Usage:
    from ironstack.defense.bunkerweb_connector import BunkerWebConnector
    
    bw = BunkerWebConnector(target_url="http://localhost:8000", listen_port=8080)
    bw.start()
    # Your app is now protected behind BunkerWeb on port 8080
    bw.stop()
"""

import time
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from ..logging_config import get_logger
from ..exceptions import WAFConfigurationError

logger = get_logger(__name__)


class BunkerWebConnector:
    """
    Connector for BunkerWeb WAF (OWASP CRS v4 with 200+ rules).
    
    BunkerWeb runs as a Docker container and acts as a reverse proxy
    in front of your application, filtering all incoming HTTP traffic
    through the OWASP Core Rule Set.
    
    Requirements:
        - Docker installed and running
        - docker Python package (pip install docker)
    
    Attributes:
        target_url: The backend application URL to protect
        listen_port: Port on which BunkerWeb will listen for incoming traffic
        api_port: Port for BunkerWeb's internal API
        docker_image: Docker image to use
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
        """Check if Docker is available and the Python docker package is installed."""
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
        """Return True if BunkerWeb can be used (Docker is ready)."""
        return self.docker_available
    
    def start(self):
        """
        Start the BunkerWeb container.
        
        Raises:
            WAFConfigurationError: If Docker is not available.
        """
        if not self.docker_available:
            raise WAFConfigurationError(
                "Docker is required for BunkerWeb engine. "
                "Install Docker and the docker Python package (pip install docker)."
            )
        
        try:
            # Remove any existing container with the same name
            try:
                old = self.client.containers.get("ironstack-bunkerweb")
                old.stop()
                old.remove()
                logger.info("Removed existing ironstack-bunkerweb container")
            except Exception:
                pass
            
            # BunkerWeb environment configuration
            env = [
                f"BUNKERWEB_LISTEN_PORT={self.listen_port}",
                "SERVER_NAME=www.example.com",  # Generic server name
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
            logger.info(f"   Target URL: {self.target_url}")
            logger.info(f"   Rules: OWASP CRS v4 (200+ rules)")
            
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
                remove=True,  # Automatically remove when stopped
            )
            
            # Give the container a moment to initialize
            time.sleep(5)
            
            logger.info(f"✅ B