#!/usr/bin/env python3
"""
Logging configuration for IronStack.
Provides consistent logging setup across all modules.
"""

import os
import sys
import logging
import logging.handlers
from pathlib import Path
from typing import Optional, Union
from datetime import datetime


# ==========================================
# Constants
# ==========================================

DEFAULT_LOG_FORMAT = (
    "[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s"
)

DETAILED_LOG_FORMAT = (
    "[%(asctime)s] [%(levelname)-8s] [%(name)s] "
    "[%(filename)s:%(lineno)d] [%(funcName)s] %(message)s"
)

COLORED_LOG_FORMAT = (
    "%(log_color)s[%(asctime)s] [%(levelname)-8s] [%(name)s] %(message)s%(reset)s"
)

SIMPLE_LOG_FORMAT = "%(levelname)-8s: %(message)s"

LOG_COLORS = {
    'DEBUG': 'cyan',
    'INFO': 'green',
    'WARNING': 'yellow',
    'ERROR': 'red',
    'CRITICAL': 'red,bg_white',
}


# ==========================================
# Custom Formatters
# ==========================================

class ColoredFormatter(logging.Formatter):
    """
    Custom formatter with ANSI color support.
    Works without external dependencies.
    """
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[1;41m', # Red background
        'RESET': '\033[0m',       # Reset
    }
    
    def format(self, record):
        # Add color to levelname
        color = self.COLORS.get(record.levelname, '')
        reset = self.COLORS['RESET']
        record.levelname = f"{color}{record.levelname}{reset}"
        
        # Add color to entire message for critical/error
        if record.levelno >= logging.ERROR:
            record.msg = f"{color}{record.msg}{reset}"
        
        return super().format(record)


class IronStackFormatter(logging.Formatter):
    """
    Custom formatter for IronStack logs.
    Adds extra fields if available.
    """
    
    def format(self, record):
        # Add extra fields if they exist
        if hasattr(record, 'layer'):
            record.layer = f"[{record.layer}]"
        else:
            record.layer = ""
        
        if hasattr(record, 'request_id'):
            record.request_id = f"[{record.request_id}]"
        else:
            record.request_id = ""
        
        return super().format(record)


# ==========================================
# Custom Handlers
# ==========================================

class SafeRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """
    Rotating file handler that handles permission errors gracefully.
    """
    
    def __init__(self, *args, **kwargs):
        try:
            super().__init__(*args, **kwargs)
        except (PermissionError, FileNotFoundError) as e:
            print(f"Warning: Could not create log file: {e}", file=sys.stderr)
            # Fall back to stderr
            self.stream = sys.stderr
    
    def emit(self, record):
        try:
            super().emit(record)
        except Exception:
            self.handleError(record)


# ==========================================
# Logging Setup
# ==========================================

def setup_logging(
    level: Union[str, int] = logging.INFO,
    log_format: Optional[str] = None,
    log_file: Optional[Union[str, Path]] = None,
    log_dir: Optional[Union[str, Path]] = None,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    use_colors: bool = True,
    verbose: bool = False,
    debug: bool = False,
    module_levels: Optional[dict] = None,
) -> logging.Logger:
    """
    Set up logging for IronStack.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Custom log format string
        log_file: Path to log file
        log_dir: Directory for log files (creates dated log file)
        max_bytes: Maximum bytes per log file before rotation
        backup_count: Number of backup files to keep
        use_colors: Enable colored output for console
        verbose: Enable verbose output (INFO level)
        debug: Enable debug output (DEBUG level)
        module_levels: Dictionary of module-specific log levels
        
    Returns:
        Root logger for IronStack
        
    Examples:
        >>> setup_logging(level=logging.DEBUG, log_file="ironstack.log")
        >>> setup_logging(verbose=True, use_colors=True)
    """
    
    # Determine log level
    if debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    # Get root logger
    root_logger = logging.getLogger("ironstack")
    root_logger.setLevel(level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Prevent propagation to parent loggers
    root_logger.propagate = False
    
    # ==========================================
    # Console Handler
    # ==========================================
    
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    
    if use_colors and sys.stderr.isatty():
        formatter = ColoredFormatter(
            fmt=log_format or DEFAULT_LOG_FORMAT,
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    else:
        formatter = IronStackFormatter(
            fmt=log_format or (DETAILED_LOG_FORMAT if debug else DEFAULT_LOG_FORMAT),
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # ==========================================
    # File Handler
    # ==========================================
    
    if log_file or log_dir:
        if log_dir:
            # Create dated log file in directory
            log_dir = Path(log_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            date_str = datetime.now().strftime("%Y%m%d")
            log_file = log_dir / f"ironstack_{date_str}.log"
        
        try:
            log_file = Path(log_file)
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = SafeRotatingFileHandler(
                filename=str(log_file),
                maxBytes=max_bytes,
                backupCount=backup_count,
                encoding='utf-8',
            )
            file_handler.setLevel(logging.DEBUG)  # Always log DEBUG to file
            
            file_formatter = IronStackFormatter(
                fmt=DETAILED_LOG_FORMAT,
                datefmt='%Y-%m-%d %H:%M:%S',
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)
            
        except Exception as e:
            root_logger.warning(f"Could not set up file logging: {e}")
    
    # ==========================================
    # Module-specific levels
    # ==========================================
    
    if module_levels:
        for module_name, module_level in module_levels.items():
            module_logger = logging.getLogger(module_name)
            if isinstance(module_level, str):
                module_level = getattr(logging, module_level.upper(), logging.INFO)
            module_logger.setLevel(module_level)
    
    # Log startup info
    root_logger.debug(f"Logging initialized at level: {logging.getLevelName(level)}")
    
    return root_logger


# ==========================================
# Convenience Functions
# ==========================================

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
        
    Examples:
        >>> logger = get_logger(__name__)
        >>> logger.info("Hello from my module!")
    """
    if not name.startswith("ironstack"):
        name = f"ironstack.{name}"
    
    return logging.getLogger(name)


def set_log_level(level: Union[str, int]):
    """
    Change log level at runtime.
    
    Args:
        level: New log level
        
    Examples:
        >>> set_log_level("DEBUG")
        >>> set_log_level(logging.WARNING)
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    
    logger = logging.getLogger("ironstack")
    logger.setLevel(level)
    
    for handler in logger.handlers:
        if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stderr:
            handler.setLevel(level)
    
    logger.info(f"Log level changed to: {logging.getLevelName(level)}")


def enable_debug():
    """Enable debug logging."""
    set_log_level(logging.DEBUG)


def enable_verbose():
    """Enable verbose logging."""
    set_log_level(logging.INFO)


def disable_logging():
    """Disable all logging."""
    set_log_level(logging.CRITICAL + 1)


def silence_module(module_name: str):
    """
    Silence logging for a specific module.
    
    Args:
        module_name: Module name to silence
    """
    logging.getLogger(module_name).setLevel(logging.CRITICAL + 1)


# ==========================================
# Context Managers
# ==========================================

class LoggingContext:
    """
    Context manager for temporary logging level changes.
    
    Examples:
        >>> with LoggingContext(logging.DEBUG):
        ...     # All logs in this block will be DEBUG level
        ...     logger.debug("This will be shown")
    """
    
    def __init__(self, level: Union[str, int]):
        self.level = level
        self.previous_level = None
    
    def __enter__(self):
        logger = logging.getLogger("ironstack")
        self.previous_level = logger.level
        set_log_level(self.level)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        set_log_level(self.previous_level)


class LogCapture:
    """
    Context manager to capture log output.
    
    Examples:
        >>> with LogCapture() as logs:
        ...     logger.info("Test message")
        >>> print(logs.getvalue())
        [INFO] Test message
    """
    
    def __init__(self, logger_name: str = "ironstack", level: int = logging.DEBUG):
        self.logger_name = logger_name
        self.level = level
        self.stream = None
        self.handler = None
    
    def __enter__(self):
        import io
        self.stream = io.StringIO()
        self.handler = logging.StreamHandler(self.stream)
        self.handler.setLevel(self.level)
        
        logger = logging.getLogger(self.logger_name)
        logger.addHandler(self.handler)
        
        return self.stream
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        logger = logging.getLogger(self.logger_name)
        logger.removeHandler(self.handler)
        self.handler.close()


# ==========================================
# Logging Decorators
# ==========================================

def log_call(logger: Optional[logging.Logger] = None, level: int = logging.DEBUG):
    """
    Decorator to log function calls.
    
    Args:
        logger: Logger to use (creates one if None)
        level: Log level for messages
        
    Examples:
        >>> @log_call()
        ... def my_function(x, y):
        ...     return x + y
    """
    if logger is None:
        logger = get_logger(__name__)
    
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger.log(level, f"Calling {func.__name__}(args={args}, kwargs={kwargs})")
            try:
                result = func(*args, **kwargs)
                logger.log(level, f"{func.__name__} returned: {result}")
                return result
            except Exception as e:
                logger.error(f"{func.__name__} raised: {e}")
                raise
        return wrapper
    return decorator


def log_execution_time(logger: Optional[logging.Logger] = None):
    """
    Decorator to log function execution time.
    
    Examples:
        >>> @log_execution_time()
        ... def slow_function():
        ...     time.sleep(1)
    """
    if logger is None:
        logger = get_logger(__name__)
    
    def decorator(func):
        import time
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            elapsed = time.perf_counter() - start
            logger.debug(f"{func.__name__} took {elapsed:.4f} seconds")
            return result
        return wrapper
    return decorator


# ==========================================
# IronStack-specific loggers
# ==========================================

def get_waf_logger() -> logging.Logger:
    """Get logger for WAF layer."""
    return get_logger("ironstack.defense.waf")


def get_protection_logger() -> logging.Logger:
    """Get logger for code protection layer."""
    return get_logger("ironstack.defense.protector")


def get_anti_cheat_logger() -> logging.Logger:
    """Get logger for anti-cheat layer."""
    return get_logger("ironstack.defense.anti_cheat")


def get_scanner_logger() -> logging.Logger:
    """Get logger for scanner layer."""
    return get_logger("ironstack.attack.scanner")


def get_hooker_logger() -> logging.Logger:
    """Get logger for hooker layer."""
    return get_logger("ironstack.attack.hooker")


# ==========================================
# Module initialization
# ==========================================

# Create default logger on import
_default_logger = get_logger("ironstack")

# Suppress noisy third-party loggers
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("requests").setLevel(logging.WARNING)

__all__ = [
    "setup_logging",
    "get_logger",
    "set_log_level",
    "enable_debug",
    "enable_verbose",
    "disable_logging",
    "silence_module",
    "LoggingContext",
    "LogCapture",
    "log_call",
    "log_execution_time",
    "get_waf_logger",
    "get_protection_logger",
    "get_anti_cheat_logger",
    "get_scanner_logger",
    "get_hooker_logger",
]
