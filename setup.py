#!/usr/bin/env python3
"""
IronStack - Security Swiss Army Knife
Setup script for pip installation
"""

from setuptools import setup, find_packages
import os
import re

# Read the long description from README.md
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read version from package __init__.py without importing
def get_version():
    version_file = os.path.join("ironstack", "__init__.py")
    with open(version_file, "r", encoding="utf-8") as f:
        content = f.read()
    match = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", content)
    if match:
        return match.group(1)
    raise RuntimeError("Unable to find version string in ironstack/__init__.py")

# Core dependencies (required for basic functionality)
core_requires = [
    "requests>=2.28.0",
    "pyyaml>=6.0",
    "colorama>=0.4.6",
    "rich>=13.0.0",
    "click>=8.1.0",
]

# Defense layer dependencies
defense_requires = [
    # WAF
    # "coraza-waf>=0.3.0",  # If/when available as Python bindings
    # Code protection
    "pyarmor>=8.0.0",
    # Cryptography
    "pycryptodome>=3.18.0",
    "cryptography>=41.0.0",
    # Monitoring / fail2ban
    # fail2ban is not a pip package, we handle it via system integration
]

# Attack layer dependencies (Red Team)
attack_requires = [
    "frida-tools>=12.0.0",
    "frida>=16.0.0",
    "capstone>=5.0.0",
    "unicorn>=2.0.1",
    "python-nmap>=0.7.1",
    "sqlmap>=1.7.0",       # May require additional installation steps
    "scapy>=2.5.0",
    "pwntools>=4.11.0",
]

# Anti-cheat layer (optional, gaming focused)
anticheat_requires = [
    # No specific PyPI packages yet; integration with external tools
]

# Development & testing
dev_requires = [
    "pytest>=8.0.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.12.0",
    "black>=24.0.0",
    "flake8>=7.0.0",
    "mypy>=1.8.0",
    "pre-commit>=3.6.0",
    "tox>=4.0.0",
    "build>=1.0.0",
    "twine>=5.0.0",
    "sphinx>=7.0.0",
    "sphinx-rtd-theme>=2.0.0",
]

# Documentation
docs_requires = [
    "sphinx>=7.0.0",
    "sphinx-rtd-theme>=2.0.0",
    "myst-parser>=3.0.0",
]

setup(
    name="ironstack",
    version=get_version(),
    author="Your Name",
    author_email="your.email@example.com",
    description="IronStack - Security Swiss Army Knife: WAF, Code Protection, Anti-Cheat, Red Team tools in one package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/ironstack",
    project_urls={
        "Bug Tracker": "https://github.com/your-username/ironstack/issues",
        "Documentation": "https://ironstack.readthedocs.io",
        "Source Code": "https://github.com/your-username/ironstack",
    },
    packages=find_packages(include=["ironstack", "ironstack.*"]),
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=core_requires,
    extras_require={
        "defense": defense_requires,
        "attack": attack_requires,
        "anticheat": anticheat_requires,
        "full": core_requires + defense_requires + attack_requires + anticheat_requires,
        "dev": dev_requires,
        "docs": docs_requires,
        "all": core_requires + defense_requires + attack_requires + anticheat_requires + dev_requires + docs_requires,
    },
    entry_points={
        "console_scripts": [
            "ironstack=ironstack.cli:main",
        ],
    },
    zip_safe=False,
    keywords=[
        "security",
        "waf",
        "firewall",
        "code-protection",
        "obfuscation",
        "anti-cheat",
        "penetration-testing",
        "red-team",
        "blue-team",
        "python",
        "coraza",
        "pyarmor",
        "frida",
        "capstone",
        "unicorn",
        "sqlmap",
        "nmap",
    ],
)
