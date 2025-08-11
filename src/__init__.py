#!/usr/bin/env python3
"""
NetPenTool - Network Penetration Testing Framework

A comprehensive toolkit for authorized network security assessments.
Provides utilities for ARP manipulation, DHCP exploitation, and credential testing.

Author: Security Research Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__license__ = "MIT"
__description__ = "Network Penetration Testing Framework"

# Core module imports
try:
    from .core import arp_module, dhcp_module, bruteforce_module
except ImportError:
    # Graceful degradation if modules are not available
    arp_module = None
    dhcp_module = None
    bruteforce_module = None

# Utility imports
try:
    from .utils import network_utils, logger, config_manager
except ImportError:
    network_utils = None
    logger = None
    config_manager = None

# Version compatibility check
import sys
if sys.version_info < (3, 8):
    raise RuntimeError("NetPenTool requires Python 3.8 or higher")

# Platform compatibility
import platform
SUPPORTED_PLATFORMS = ['Windows', 'Linux', 'Darwin']
if platform.system() not in SUPPORTED_PLATFORMS:
    import warnings
    warnings.warn(f"Platform {platform.system()} may not be fully supported")

# Export public API
__all__ = [
    '__version__',
    '__author__',
    '__license__',
    '__description__',
    'arp_module',
    'dhcp_module', 
    'bruteforce_module',
    'network_utils',
    'logger',
    'config_manager'
]