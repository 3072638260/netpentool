#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 核心攻击模块包

本包包含TRAES工具集的核心攻击功能模块：
- ARP攻击模块 (arp.py)
- DHCP攻击模块 (dhcp.py) 
- 密码爆破模块 (bruteforce.py)

所有模块都遵循统一的接口设计，支持配置文件和命令行参数。
"""

# 尝试导入各个攻击模块
try:
    from .arp import ARPAttack
    arp_module = ARPAttack
except ImportError:
    arp_module = None

try:
    from .dhcp import DHCPAttack
    dhcp_module = DHCPAttack
except ImportError:
    dhcp_module = None

try:
    from .bruteforce import BruteForce
    bruteforce_module = BruteForce
except ImportError:
    bruteforce_module = None

# 模块依赖检查
def check_dependencies():
    """
    检查核心模块的依赖是否满足
    
    Returns:
        dict: 依赖检查结果
    """
    dependencies = {
        'scapy': False,
        'psutil': False,
        'colorama': False,
        'loguru': False
    }
    
    try:
        import scapy
        dependencies['scapy'] = True
    except ImportError:
        pass
        
    try:
        import psutil
        dependencies['psutil'] = True
    except ImportError:
        pass
        
    try:
        import colorama
        dependencies['colorama'] = True
    except ImportError:
        pass
        
    try:
        import loguru
        dependencies['loguru'] = True
    except ImportError:
        pass
    
    return dependencies

__all__ = [
    'arp_module',
    'dhcp_module', 
    'bruteforce_module',
    'check_dependencies'
]