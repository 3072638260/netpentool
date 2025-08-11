#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES - Tactical Reconnaissance and Attack Exploitation Suite
网络渗透测试工具集核心包

这是TRAES项目的核心包初始化文件，定义了项目的基本信息和模块导入。

作者: Security Researcher
版本: 1.0.0
许可证: MIT
描述: 专业的网络渗透测试工具集，提供ARP攻击、DHCP攻击、密码爆破等功能
"""

__version__ = "1.0.0"
__author__ = "Security Researcher"
__license__ = "MIT"
__description__ = "TRAES - 网络渗透测试工具集"

# 版本信息
VERSION_INFO = {
    "major": 1,
    "minor": 0,
    "patch": 0,
    "release": "stable"
}

# 项目信息
PROJECT_INFO = {
    "name": "TRAES",
    "full_name": "Tactical Reconnaissance and Attack Exploitation Suite",
    "description": "专业的网络渗透测试工具集",
    "author": __author__,
    "version": __version__,
    "license": __license__,
    "repository": "https://github.com/netpentool/netpentool",
    "documentation": "https://github.com/netpentool/netpentool/wiki"
}

# 导入核心模块
try:
    # 核心攻击模块
    from .core import arp, dhcp, bruteforce
    
    # 实用工具模块
    from .utils import network, crypto, logger
    
    # 数据处理模块
    from .data import parser, validator
    
    __all__ = [
        'arp', 'dhcp', 'bruteforce',
        'network', 'crypto', 'logger',
        'parser', 'validator',
        'VERSION_INFO', 'PROJECT_INFO'
    ]
    
except ImportError as e:
    # 如果某些模块不存在，只导入基本信息
    __all__ = ['VERSION_INFO', 'PROJECT_INFO']
    import warnings
    warnings.warn(f"部分模块导入失败: {e}", ImportWarning)

# 兼容性检查
import sys
import platform

# Python版本检查
if sys.version_info < (3, 7):
    raise RuntimeError("TRAES 需要 Python 3.7 或更高版本")

# 平台兼容性检查
SUPPORTED_PLATFORMS = ['Windows', 'Linux', 'Darwin']
current_platform = platform.system()

if current_platform not in SUPPORTED_PLATFORMS:
    import warnings
    warnings.warn(
        f"当前平台 {current_platform} 可能不被完全支持。"
        f"推荐平台: {', '.join(SUPPORTED_PLATFORMS)}",
        UserWarning
    )

# 权限检查（仅在Linux/macOS上）
if current_platform in ['Linux', 'Darwin']:
    import os
    if os.geteuid() != 0:
        import warnings
        warnings.warn(
            "检测到非root权限运行，某些功能可能受限。"
            "建议使用sudo运行以获得完整功能。",
            UserWarning
        )

def get_version():
    """
    获取版本信息
    
    Returns:
        str: 版本字符串
    """
    return __version__

def get_project_info():
    """
    获取项目信息
    
    Returns:
        dict: 项目信息字典
    """
    return PROJECT_INFO.copy()

def check_dependencies():
    """
    检查依赖库是否安装
    
    Returns:
        dict: 依赖检查结果
    """
    dependencies = {
        'scapy': False,
        'colorama': False,
        'loguru': False,
        'psutil': False,
        'requests': False,
        'cryptography': False,
        'netifaces': False,
        'paramiko': False,
        'ftplib': False,
        'telnetlib': False
    }
    
    for dep in dependencies:
        try:
            __import__(dep)
            dependencies[dep] = True
        except ImportError:
            dependencies[dep] = False
    
    return dependencies

def print_banner():
    """
    打印项目横幅
    """
    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║  {Fore.RED}████████{Fore.CYAN} ██████   █████  ███████ ███████                    ║
║     {Fore.RED}██{Fore.CYAN}    ██   ██ ██   ██ ██      ██                         ║
║     {Fore.RED}██{Fore.CYAN}    ██████  ███████ █████   ███████                    ║
║     {Fore.RED}██{Fore.CYAN}    ██   ██ ██   ██ ██           ██                    ║
║     {Fore.RED}██{Fore.CYAN}    ██   ██ ██   ██ ███████ ███████                    ║
║                                                              ║
║  {Fore.YELLOW}Tactical Reconnaissance and Attack Exploitation Suite{Fore.CYAN}       ║
║  {Fore.GREEN}Version: {__version__}{Fore.CYAN}                                              ║
║  {Fore.MAGENTA}Author: {__author__}{Fore.CYAN}                                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
        
    except ImportError:
        # 如果colorama不可用，使用简单横幅
        print(f"""
===============================================================
                            TRAES
        Tactical Reconnaissance and Attack Exploitation Suite
                        Version: {__version__}
                    Author: {__author__}
===============================================================
        """)

# 初始化时的自动检查
if __name__ != '__main__':
    # 静默检查依赖
    missing_deps = [dep for dep, available in check_dependencies().items() if not available]
    if missing_deps:
        import warnings
        warnings.warn(
            f"缺少以下依赖库: {', '.join(missing_deps)}\n"
            "请运行: pip install -r requirements.txt",
            ImportWarning
        )