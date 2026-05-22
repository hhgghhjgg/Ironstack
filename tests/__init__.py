#!/usr/bin/env python3
"""
IronStack Test Suite
====================
Test suite for IronStack Security Swiss Army Knife.

This package contains all unit tests and integration tests
for the IronStack library.

Test Structure:
    tests/
    ├── __init__.py              # This file
    ├── conftest.py              # Shared fixtures and configuration
    ├── test_core.py             # Core module tests
    ├── test_config.py           # Configuration tests
    ├── test_defense/
    │   ├── __init__.py
    │   ├── test_waf.py          # WAF tests
    │   ├── test_protector.py    # Code protection tests
    │   ├── test_crypto.py       # Cryptography tests
    │   ├── test_monitor.py      # Monitoring tests
    │   └── test_anti_cheat.py   # Anti-cheat tests
    ├── test_attack/
    │   ├── __init__.py
    │   ├── test_scanner.py      # Scanner tests
    │   ├── test_hooker.py       # Hooker tests
    │   ├── test_disassembler.py # Disassembler tests
    │   └── test_emulator.py     # Emulator tests
    └── test_utils/
        ├── __init__.py
        ├── test_validators.py   # Validator tests
        ├── test_formatters.py   # Formatter tests
        └── test_platform.py     # Platform tests

Running Tests:
    # Run all tests
    pytest tests/
    
    # Run specific test file
    pytest tests/test_core.py
    
    # Run with coverage
    pytest tests/ --cov=ironstack
    
    # Run only defense tests
    pytest tests/test_defense/
    
    # Run with verbose output
    pytest tests/ -v
"""

import sys
import os

# Ensure the project root is in the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))