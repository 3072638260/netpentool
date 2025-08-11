#!/usr/bin/env python3
"""
NetPenTool Core Modules

This package contains the core attack and exploitation modules for the
NetPenTool framework. Each module implements specific attack vectors
commonly used in authorized penetration testing.

Modules:
    arp_module: ARP spoofing and network manipulation
    dhcp_module: DHCP exploitation and network disruption
    bruteforce_module: Authentication testing and credential validation

Security Notice:
    These modules are designed for authorized security testing only.
    Ensure proper authorization before use.
"""

import logging
from typing import Optional, Dict, Any

# Module version and metadata
__version__ = "1.0.0"
__author__ = "Security Research Team"

# Configure module logger
logger = logging.getLogger(__name__)

# Module availability tracking
_available_modules = {}

def _check_module_dependencies(module_name: str, required_packages: list) -> bool:
    """
    Check if required dependencies are available for a module.
    
    Args:
        module_name: Name of the module to check
        required_packages: List of required package names
        
    Returns:
        bool: True if all dependencies are available
    """
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        logger.warning(f"Module {module_name} unavailable. Missing: {missing_packages}")
        return False
    
    return True

# ARP Module
try:
    if _check_module_dependencies('arp', ['scapy']):
        from . import arp
        arp_module = arp
        _available_modules['arp'] = True
        logger.debug("ARP module loaded successfully")
    else:
        arp_module = None
        _available_modules['arp'] = False
except ImportError as e:
    logger.warning(f"Failed to load ARP module: {e}")
    arp_module = None
    _available_modules['arp'] = False

# DHCP Module
try:
    if _check_module_dependencies('dhcp', ['scapy']):
        from . import dhcp
        dhcp_module = dhcp
        _available_modules['dhcp'] = True
        logger.debug("DHCP module loaded successfully")
    else:
        dhcp_module = None
        _available_modules['dhcp'] = False
except ImportError as e:
    logger.warning(f"Failed to load DHCP module: {e}")
    dhcp_module = None
    _available_modules['dhcp'] = False

# Bruteforce Module
try:
    if _check_module_dependencies('bruteforce', ['requests']):
        from . import bruteforce
        bruteforce_module = bruteforce
        _available_modules['bruteforce'] = True
        logger.debug("Bruteforce module loaded successfully")
    else:
        bruteforce_module = None
        _available_modules['bruteforce'] = False
except ImportError as e:
    logger.warning(f"Failed to load Bruteforce module: {e}")
    bruteforce_module = None
    _available_modules['bruteforce'] = False

def get_available_modules() -> Dict[str, bool]:
    """
    Get the availability status of all core modules.
    
    Returns:
        Dict[str, bool]: Module name to availability mapping
    """
    return _available_modules.copy()

def get_module_info() -> Dict[str, Any]:
    """
    Get comprehensive information about the core modules package.
    
    Returns:
        Dict[str, Any]: Package information including version, modules, etc.
    """
    return {
        'version': __version__,
        'author': __author__,
        'available_modules': _available_modules,
        'total_modules': len(_available_modules),
        'loaded_modules': sum(_available_modules.values())
    }

# Export public API
__all__ = [
    'arp_module',
    'dhcp_module',
    'bruteforce_module',
    'get_available_modules',
    'get_module_info',
    '__version__',
    '__author__'
]