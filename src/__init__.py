#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES - 网络渗透测试工具集

这是TRAES项目的核心包初始化文件。
TRAES (Tactical Reconnaissance and Attack Exploitation Suite) 
是一个专业的网络渗透测试工具集。

作者: Security Researcher
版本: 1.0.0
许可证: MIT
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__license__ = "MIT"
__description__ = "专业的网络渗透测试工具集"

# 导入核心模块
try:
    from .core import arp_module, dhcp_module, bruteforce_module
except ImportError:
    # 如果核心模块不存在，创建占位符
    arp_module = None
    dhcp_module = None
    bruteforce_module = None

# 导入工具模块
try:
    from .utils import network_utils, logger, config_manager
except ImportError:
    # 如果工具模块不存在，创建占位符
    network_utils = None
    logger = None
    config_manager = None

# 版本兼容性检查
import sys
if sys.version_info < (3, 7):
    raise RuntimeError("TRAES requires Python 3.7 or higher")

# 平台兼容性检查
import platform
supported_platforms = ['Windows', 'Linux', 'Darwin']
current_platform = platform.system()
if current_platform not in supported_platforms:
    import warnings
    warnings.warn(f"TRAES may not work properly on {current_platform}")

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