#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 工具模块包

提供各种实用工具和辅助功能，包括：
- 网络工具
- 日志管理
- 配置管理
- 文件操作
- 加密工具
- 系统信息

作者: Security Researcher
版本: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__license__ = "MIT"
__description__ = "TRAES 工具模块包"

# 导入工具模块
try:
    from .network_utils import NetworkUtils
    from .logger import setup_logger, get_logger
    from .config_manager import ConfigManager
    from .file_utils import FileUtils
    from .crypto_utils import CryptoUtils
    from .system_utils import SystemUtils
    
    __all__ = [
        'NetworkUtils',
        'setup_logger',
        'get_logger', 
        'ConfigManager',
        'FileUtils',
        'CryptoUtils',
        'SystemUtils'
    ]
    
except ImportError as e:
    print(f"警告: 部分工具模块导入失败: {e}")
    print("某些功能可能不可用")
    
    __all__ = []

def check_dependencies():
    """
    检查工具模块依赖
    
    Returns:
        bool: 所有依赖都满足返回True
    """
    required_packages = [
        'requests',
        'psutil', 
        'colorama',
        'loguru',
        'cryptography',
        'netifaces'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"缺少以下依赖包: {', '.join(missing_packages)}")
        print(f"请运行: pip install {' '.join(missing_packages)}")
        return False
    
    return True

# 模块信息
print(f"TRAES 工具模块包 v{__version__} 已加载")
print(f"作者: {__author__}")
print(f"许可证: {__license__}")