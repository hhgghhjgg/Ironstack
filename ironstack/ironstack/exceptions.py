#!/usr/bin/env python3
"""
Custom exceptions for IronStack.
All exceptions inherit from IronStackError base class.
"""

from typing import Optional, Any


# ==========================================
# Base Exception
# ==========================================

class IronStackError(Exception):
    """
    Base exception for all IronStack errors.
    
    Attributes:
        message: Error message
        code: Error code for programmatic handling
        details: Additional error details
    """
    
    def __init__(
        self,
        message: str = "An error occurred in IronStack",
        code: Optional[str] = None,
        details: Optional[dict] = None,
    ):
        self.message = message
        self.code = code or self.__class__.__name__
        self.details = details or {}
        super().__init__(self.message)
    
    def to_dict(self) -> dict:
        """Convert exception to dictionary."""
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }
    
    def __str__(self) -> str:
        if self.details:
            return f"[{self.code}] {self.message} - Details: {self.details}"
        return f"[{self.code}] {self.message}"
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message='{self.message}', code='{self.code}')"


# ==========================================
# Configuration Errors
# ==========================================

class IronStackConfigError(IronStackError):
    """Raised when configuration is invalid."""
    
    def __init__(self, message: str = "Configuration error", **kwargs):
        super().__init__(message=message, code="CONFIG_ERROR", **kwargs)


class ConfigurationError(IronStackConfigError):
    """Raised when there's a configuration problem."""
    
    def __init__(self, message: str = "Invalid configuration", **kwargs):
        super().__init__(message=message, **kwargs)


class ConfigFileNotFoundError(IronStackConfigError):
    """Raised when configuration file is not found."""
    
    def __init__(self, path: str, **kwargs):
        super().__init__(
            message=f"Configuration file not found: {path}",
            details={"path": path},
            **kwargs,
        )


class ConfigValidationError(IronStackConfigError):
    """Raised when configuration validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"field": field} if field else {},
            **kwargs,
        )


# ==========================================
# Protection Errors
# ==========================================

class IronStackProtectionError(IronStackError):
    """Raised when protection fails."""
    
    def __init__(self, message: str = "Protection failed", **kwargs):
        super().__init__(message=message, code="PROTECTION_ERROR", **kwargs)


class ProtectionFailedError(IronStackProtectionError):
    """Raised when a protection operation fails."""
    
    def __init__(self, message: str = "Protection operation failed", target: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"target": target} if target else {},
            **kwargs,
        )


class WAFError(IronStackProtectionError):
    """Raised when WAF encounters an error."""
    
    def __init__(self, message: str = "WAF error", **kwargs):
        super().__init__(message=message, code="WAF_ERROR", **kwargs)


class WAFConfigurationError(WAFError):
    """Raised when WAF configuration is invalid."""
    
    def __init__(self, message: str = "WAF configuration error", **kwargs):
        super().__init__(message=message, **kwargs)


class WAFRuleError(WAFError):
    """Raised when a WAF rule fails."""
    
    def __init__(self, message: str = "WAF rule error", rule_id: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"rule_id": rule_id} if rule_id else {},
            **kwargs,
        )


class CodeProtectionError(IronStackProtectionError):
    """Raised when code protection fails."""
    
    def __init__(self, message: str = "Code protection error", **kwargs):
        super().__init__(message=message, code="CODE_PROTECTION_ERROR", **kwargs)


class ObfuscationError(CodeProtectionError):
    """Raised when code obfuscation fails."""
    
    def __init__(self, message: str = "Obfuscation failed", file: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"file": file} if file else {},
            **kwargs,
        )


class AntiCheatError(IronStackProtectionError):
    """Raised when anti-cheat system encounters an error."""
    
    def __init__(self, message: str = "Anti-cheat error", **kwargs):
        super().__init__(message=message, code="ANTI_CHEAT_ERROR", **kwargs)


class CheatDetectedError(AntiCheatError):
    """Raised when cheating is detected."""
    
    def __init__(
        self,
        message: str = "Cheating detected",
        cheat_type: Optional[str] = None,
        player_id: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(
            message=message,
            details={
                "cheat_type": cheat_type,
                "player_id": player_id,
            },
            **kwargs,
        )


# ==========================================
# Scan Errors
# ==========================================

class IronStackScanError(IronStackError):
    """Raised when a scan fails."""
    
    def __init__(self, message: str = "Scan failed", **kwargs):
        super().__init__(message=message, code="SCAN_ERROR", **kwargs)


class ScanFailedError(IronStackScanError):
    """Raised when a scan operation fails."""
    
    def __init__(self, message: str = "Scan operation failed", target: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"target": target} if target else {},
            **kwargs,
        )


class ScanTimeoutError(IronStackScanError):
    """Raised when a scan times out."""
    
    def __init__(self, timeout: Optional[int] = None, **kwargs):
        super().__init__(
            message=f"Scan timed out after {timeout} seconds" if timeout else "Scan timed out",
            details={"timeout": timeout},
            **kwargs,
        )


class VulnerabilityFoundError(IronStackScanError):
    """Raised when a vulnerability is found during scanning."""
    
    def __init__(
        self,
        message: str = "Vulnerability found",
        vulnerability_type: Optional[str] = None,
        severity: Optional[str] = None,
        **kwargs,
    ):
        super().__init__(
            message=message,
            details={
                "type": vulnerability_type,
                "severity": severity,
            },
            **kwargs,
        )


# ==========================================
# Dependency Errors
# ==========================================

class IronStackDependencyError(IronStackError):
    """Raised when a dependency is missing or incompatible."""
    
    def __init__(self, message: str = "Dependency error", **kwargs):
        super().__init__(message=message, code="DEPENDENCY_ERROR", **kwargs)


class DependencyNotFoundError(IronStackDependencyError):
    """Raised when a required dependency is not found."""
    
    def __init__(
        self,
        dependency_name: str,
        install_hint: Optional[str] = None,
        **kwargs,
    ):
        message = f"Dependency not found: {dependency_name}"
        if install_hint:
            message += f". Install with: {install_hint}"
        
        super().__init__(
            message=message,
            details={
                "dependency": dependency_name,
                "install_hint": install_hint,
            },
            **kwargs,
        )


class DependencyVersionError(IronStackDependencyError):
    """Raised when a dependency version is incompatible."""
    
    def __init__(
        self,
        dependency_name: str,
        required_version: str,
        found_version: str,
        **kwargs,
    ):
        super().__init__(
            message=f"Dependency version mismatch: {dependency_name} "
                    f"(required: {required_version}, found: {found_version})",
            details={
                "dependency": dependency_name,
                "required": required_version,
                "found": found_version,
            },
            **kwargs,
        )


# ==========================================
# Layer Errors
# ==========================================

class LayerError(IronStackError):
    """Raised when there's an issue with a layer."""
    
    def __init__(self, message: str = "Layer error", layer: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            code="LAYER_ERROR",
            details={"layer": layer} if layer else {},
            **kwargs,
        )


class LayerNotAvailableError(LayerError):
    """Raised when a layer is not available in current mode."""
    
    def __init__(self, message: str = "Layer not available", layer: Optional[str] = None, **kwargs):
        super().__init__(message=message, layer=layer, **kwargs)


class LayerNotInitializedError(LayerError):
    """Raised when trying to use a layer that hasn't been initialized."""
    
    def __init__(self, layer: str, **kwargs):
        super().__init__(
            message=f"Layer '{layer}' has not been initialized. Call enable_{layer}() first.",
            layer=layer,
            **kwargs,
        )


class LayerAlreadyEnabledError(LayerError):
    """Raised when trying to enable an already enabled layer."""
    
    def __init__(self, layer: str, **kwargs):
        super().__init__(
            message=f"Layer '{layer}' is already enabled.",
            layer=layer,
            **kwargs,
        )


class LayerConfigError(LayerError):
    """Raised when layer configuration is invalid."""
    
    def __init__(self, message: str, layer: Optional[str] = None, **kwargs):
        super().__init__(message=message, layer=layer, **kwargs)


# ==========================================
# Input/Output Errors
# ==========================================

class IronStackIOError(IronStackError):
    """Raised when an I/O operation fails."""
    
    def __init__(self, message: str = "I/O error", **kwargs):
        super().__init__(message=message, code="IO_ERROR", **kwargs)


class FileNotFoundError(IronStackIOError):
    """Raised when a file is not found."""
    
    def __init__(self, path: str, **kwargs):
        super().__init__(
            message=f"File not found: {path}",
            details={"path": path},
            **kwargs,
        )


class FilePermissionError(IronStackIOError):
    """Raised when there's a permission issue."""
    
    def __init__(self, path: str, **kwargs):
        super().__init__(
            message=f"Permission denied: {path}",
            details={"path": path},
            **kwargs,
        )


class FileFormatError(IronStackIOError):
    """Raised when file format is invalid."""
    
    def __init__(self, message: str, path: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"path": path} if path else {},
            **kwargs,
        )


# ==========================================
# Network Errors
# ==========================================

class IronStackNetworkError(IronStackError):
    """Raised when a network operation fails."""
    
    def __init__(self, message: str = "Network error", **kwargs):
        super().__init__(message=message, code="NETWORK_ERROR", **kwargs)


class ConnectionError(IronStackNetworkError):
    """Raised when connection fails."""
    
    def __init__(self, host: str, port: Optional[int] = None, **kwargs):
        target = f"{host}:{port}" if port else host
        super().__init__(
            message=f"Connection failed: {target}",
            details={"host": host, "port": port},
            **kwargs,
        )


class TimeoutError(IronStackNetworkError):
    """Raised when an operation times out."""
    
    def __init__(self, message: str = "Operation timed out", timeout: Optional[int] = None, **kwargs):
        super().__init__(
            message=message,
            details={"timeout": timeout},
            **kwargs,
        )


# ==========================================
# Authentication/Authorization Errors
# ==========================================

class IronStackAuthError(IronStackError):
    """Raised when authentication or authorization fails."""
    
    def __init__(self, message: str = "Authentication error", **kwargs):
        super().__init__(message=message, code="AUTH_ERROR", **kwargs)


class AuthenticationFailedError(IronStackAuthError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed", **kwargs):
        super().__init__(message=message, **kwargs)


class AuthorizationFailedError(IronStackAuthError):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Authorization failed", permission: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            details={"permission": permission} if permission else {},
            **kwargs,
        )


# ==========================================
# Validation Errors
# ==========================================

class ValidationError(IronStackError):
    """Raised when validation fails."""
    
    def __init__(self, message: str = "Validation failed", field: Optional[str] = None, **kwargs):
        super().__init__(
            message=message,
            code="VALIDATION_ERROR",
            details={"field": field} if field else {},
            **kwargs,
        )


class InputValidationError(ValidationError):
    """Raised when input validation fails."""
    
    def __init__(self, message: str = "Invalid input", **kwargs):
        super().__init__(message=message, **kwargs)


# ==========================================
# Not Implemented / Deprecated
# ==========================================

class NotImplementedError(IronStackError):
    """Raised when a feature is not yet implemented."""
    
    def __init__(self, feature: str, version: Optional[str] = None, **kwargs):
        message = f"Feature not implemented: {feature}"
        if version:
            message += f" (planned for version {version})"
        super().__init__(
            message=message,
            code="NOT_IMPLEMENTED",
            details={"feature": feature, "planned_version": version},
            **kwargs,
        )


class DeprecatedError(IronStackError):
    """Raised when using a deprecated feature."""
    
    def __init__(self, feature: str, alternative: Optional[str] = None, **kwargs):
        message = f"'{feature}' is deprecated"
        if alternative:
            message += f". Use '{alternative}' instead."
        super().__init__(
            message=message,
            code="DEPRECATED",
            details={"feature": feature, "alternative": alternative},
            **kwargs,
        )


# ==========================================
# Rate Limit Errors
# ==========================================

class RateLimitExceededError(IronStackError):
    """Raised when rate limit is exceeded."""
    
    def __init__(
        self,
        message: str = "Rate limit exceeded",
        limit: Optional[int] = None,
        retry_after: Optional[int] = None,
        **kwargs,
    ):
        super().__init__(
            message=message,
            code="RATE_LIMIT",
            details={
                "limit": limit,
                "retry_after": retry_after,
            },
            **kwargs,
        )


# ==========================================
# Export all exceptions
# ==========================================

__all__ = [
    # Base
    "IronStackError",
    
    # Config
    "IronStackConfigError",
    "ConfigurationError",
    "ConfigFileNotFoundError",
    "ConfigValidationError",
    
    # Protection
    "IronStackProtectionError",
    "ProtectionFailedError",
    "WAFError",
    "WAFConfigurationError",
    "WAFRuleError",
    "CodeProtectionError",
    "ObfuscationError",
    "AntiCheatError",
    "CheatDetectedError",
    
    # Scan
    "IronStackScanError",
    "ScanFailedError",
    "ScanTimeoutError",
    "VulnerabilityFoundError",
    
    # Dependency
    "IronStackDependencyError",
    "DependencyNotFoundError",
    "DependencyVersionError",
    
    # Layer
    "LayerError",
    "LayerNotAvailableError",
    "LayerNotInitializedError",
    "LayerAlreadyEnabledError",
    "LayerConfigError",
    
    # I/O
    "IronStackIOError",
    "FileNotFoundError",
    "FilePermissionError",
    "FileFormatError",
    
    # Network
    "IronStackNetworkError",
    "ConnectionError",
    "TimeoutError",
    
    # Auth
    "IronStackAuthError",
    "AuthenticationFailedError",
    "AuthorizationFailedError",
    
    # Validation
    "ValidationError",
    "InputValidationError",
    
    # Feature
    "NotImplementedError",
    "DeprecatedError",
    
    # Rate Limit
    "RateLimitExceededError",
  ]
