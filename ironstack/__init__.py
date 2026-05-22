#!/usr/bin/env python3
"""
IronStack - Security Swiss Army Knife
=====================================
A unified security library combining WAF, Code Protection,
Anti-Cheat, and Red Team tools in one package.

Usage:
    import ironstack

    # Quick protect
    ironstack.protect(".")

    # Full control
    is_stack = ironstack.IronStack(mode="defense")
    is_stack.protect("./my-project")
"""

__version__ = "0.1.0"
__author__ = "IronStack Team"
__email__ = "your.email@example.com"
__license__ = "MIT"
__copyright__ = "Copyright 2024 IronStack"
__url__ = "https://github.com/your-username/ironstack"
__description__ = "Security Swiss Army Knife"
__status__ = "Alpha"

# =====================================
# Public API - Classes
# =====================================
from .core import IronStack

# =====================================
# Public API - Quick Functions
# =====================================
from .core import (
    protect,
    scan,
    status,
    version_info,
    get_instance,
)

# =====================================
# Public API - Exceptions
# =====================================
from .exceptions import (
    IronStackError,
    IronStackConfigError,
    IronStackProtectionError,
    IronStackScanError,
    IronStackDependencyError,
    LayerNotAvailableError,
    ProtectionFailedError,
    ScanFailedError,
    DependencyNotFoundError,
    ConfigurationError,
)

# =====================================
# What gets exported with "from ironstack import *"
# =====================================
__all__ = [
    # Main class
    "IronStack",

    # Quick functions
    "protect",
    "scan",
    "status",
    "version_info",
    "get_instance",

    # Exceptions
    "IronStackError",
    "IronStackConfigError",
    "IronStackProtectionError",
    "IronStackScanError",
    "IronStackDependencyError",
    "LayerNotAvailableError",
    "ProtectionFailedError",
    "ScanFailedError",
    "DependencyNotFoundError",
    "ConfigurationError",

    # Metadata
    "__version__",
    "__author__",
    "__license__",
]

# =====================================
# Lazy imports for optional layers
# =====================================
def __getattr__(name):
    """Lazy import for optional components."""

    _lazy_imports = {
        # Defense layer
        "WAF": ".defense.waf",
        "CodeProtector": ".defense.protector",
        "Crypto": ".defense.crypto",
        "Monitor": ".defense.monitor",
        "AntiCheat": ".defense.anti_cheat",

        # Attack layer
        "Scanner": ".attack.scanner",
        "Hooker": ".attack.hooker",
        "Disassembler": ".attack.disassembler",
        "Emulator": ".attack.emulator",
    }

    if name in _lazy_imports:
        import importlib
        module_path = _lazy_imports[name]
        try:
            module = importlib.import_module(module_path, package=__name__)
            return getattr(module, name)
        except ImportError as e:
            raise ImportError(
                f"Optional layer '{name}' is not available. "
                f"Install with: pip install ironstack[{module_path.split('.')[1]}]"
            ) from e

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")

# =====================================
# Package initialization check
# =====================================
def _check_dependencies():
    """Check core dependencies on import."""
    missing = []

    try:
        import requests
    except ImportError:
        missing.append("requests")

    try:
        import yaml
    except ImportError:
        missing.append("pyyaml")

    if missing:
        import warnings
        warnings.warn(
            f"IronStack: Missing core dependencies: {', '.join(missing)}. "
            f"Install with: pip install {' '.join(missing)}",
            ImportWarning,
            stacklevel=2,
        )

# Run check on import
_check_dependencies()

# =====================================
# Welcome message (only in interactive mode)
# =====================================
import sys as _sys

def _show_welcome():
    """Show welcome message in interactive mode."""
    if hasattr(_sys, 'ps1') or 'IPython' in _sys.modules:
        print(f"""
╔══════════════════════════════════════════════╗
║          🛡️  IronStack v{__version__}  🛡️              ║
║     Security Swiss Army Knife               ║
║                                              ║
║  Quick Start:                                ║
║    import ironstack                          ║
║    ironstack.protect(".")                    ║
║                                              ║
║  Docs: {__url__}        ║
╚══════════════════════════════════════════════╝
""")

_show_welcome()