#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 项目安装脚本
自动安装依赖、创建必要目录、检查环境

使用方法:
python install.py
python install.py --check-only  # 仅检查环境
"""

import os
import sys
import subprocess
import platform
import argparse
from pathlib import Path

def print_banner():
    """打印安装横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    TRAES 安装脚本                           ║
║              网络渗透测试工具集安装程序                      ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """检查Python版本"""
    print("[+] 检查Python版本...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("[!] 错误: 需要Python 3.7或更高版本")
        print(f"[!] 当前版本: {version.major}.{version.minor}.{version.micro}")
        return False
    print(f"[✓] Python版本: {version.major}.{version.minor}.{version.micro}")
    return True

def check_pip():
    """检查pip是否可用"""
    print("[+] 检查pip...")
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], 
                      check=True, capture_output=True)
        print("[✓] pip可用")
        return True
    except subprocess.CalledProcessError:
        print("[!] 错误: pip不可用")
        return False

def install_requirements():
    """安装依赖包"""
    print("[+] 安装依赖包...")
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("[!] 错误: requirements.txt文件不存在")
        return False
    
    try:
        cmd = [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
        subprocess.run(cmd, check=True)
        print("[✓] 依赖包安装完成")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] 错误: 依赖包安装失败 - {e}")
        return False

def check_directories():
    """检查并创建必要目录"""
    print("[+] 检查项目目录结构...")
    
    directories = [
        "src",
        "src/core",
        "src/utils",
        "config",
        "logs",
        "data",
        "output",
        "temp"
    ]
    
    for directory in directories:
        dir_path = Path(directory)
        if not dir_path.exists():
            dir_path.mkdir(parents=True, exist_ok=True)
            print(f"[+] 创建目录: {directory}")
        else:
            print(f"[✓] 目录存在: {directory}")
    
    return True

def check_permissions():
    """检查权限（仅Linux/Mac）"""
    if platform.system() in ["Linux", "Darwin"]:
        print("[+] 检查权限...")
        if os.geteuid() == 0:
            print("[!] 警告: 正在以root权限运行")
            print("[!] 建议: 某些功能可能需要root权限，但日常使用请避免")
        else:
            print("[✓] 非root用户运行")
    return True

def check_network_tools():
    """检查网络工具可用性"""
    print("[+] 检查网络工具...")
    
    tools = {
        "ping": "ping",
        "nmap": "nmap",
        "netstat": "netstat"
    }
    
    available_tools = []
    
    for tool_name, command in tools.items():
        try:
            if platform.system() == "Windows":
                subprocess.run(["where", command], 
                             check=True, capture_output=True)
            else:
                subprocess.run(["which", command], 
                             check=True, capture_output=True)
            print(f"[✓] {tool_name} 可用")
            available_tools.append(tool_name)
        except subprocess.CalledProcessError:
            print(f"[!] {tool_name} 不可用")
    
    if "nmap" not in available_tools:
        print("[!] 建议安装nmap以获得完整功能")
        if platform.system() == "Windows":
            print("[!] 下载地址: https://nmap.org/download.html")
        elif platform.system() == "Darwin":
            print("[!] 安装命令: brew install nmap")
        else:
            print("[!] 安装命令: sudo apt-get install nmap 或 sudo yum install nmap")
    
    return True

def create_config_files():
    """创建默认配置文件"""
    print("[+] 检查配置文件...")
    
    config_file = Path("config/config.json")
    if config_file.exists():
        print("[✓] 配置文件已存在")
    else:
        print("[!] 配置文件不存在，请确保config.json文件正确创建")
    
    return True

def run_basic_test():
    """运行基本测试"""
    print("[+] 运行基本测试...")
    
    try:
        # 测试导入主要模块
        sys.path.insert(0, str(Path.cwd()))
        
        # 测试配置管理器
        from src.utils.config_manager import ConfigManager
        config = ConfigManager()
        print("[✓] 配置管理器测试通过")
        
        # 测试日志系统
        from src.utils.logger import TraesLogger
        logger = TraesLogger()
        print("[✓] 日志系统测试通过")
        
        # 测试网络工具
        from src.utils.network_utils import NetworkUtils
        net_utils = NetworkUtils()
        print("[✓] 网络工具测试通过")
        
        print("[✓] 所有基本测试通过")
        return True
        
    except ImportError as e:
        print(f"[!] 模块导入失败: {e}")
        return False
    except Exception as e:
        print(f"[!] 测试失败: {e}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="TRAES 安装脚本")
    parser.add_argument("--check-only", action="store_true", 
                       help="仅检查环境，不安装依赖")
    parser.add_argument("--skip-test", action="store_true", 
                       help="跳过基本测试")
    
    args = parser.parse_args()
    
    print_banner()
    
    # 检查步骤
    checks = [
        ("Python版本", check_python_version),
        ("pip可用性", check_pip),
        ("目录结构", check_directories),
        ("权限检查", check_permissions),
        ("网络工具", check_network_tools),
        ("配置文件", create_config_files)
    ]
    
    print("\n" + "="*60)
    print("开始环境检查...")
    print("="*60)
    
    failed_checks = []
    
    for check_name, check_func in checks:
        try:
            if not check_func():
                failed_checks.append(check_name)
        except Exception as e:
            print(f"[!] {check_name}检查失败: {e}")
            failed_checks.append(check_name)
        print()
    
    # 安装依赖（如果不是仅检查模式）
    if not args.check_only:
        print("="*60)
        print("开始安装依赖...")
        print("="*60)
        
        if not install_requirements():
            failed_checks.append("依赖安装")
        print()
    
    # 运行基本测试（如果不跳过）
    if not args.skip_test and not args.check_only:
        print("="*60)
        print("运行基本测试...")
        print("="*60)
        
        if not run_basic_test():
            failed_checks.append("基本测试")
        print()
    
    # 输出结果
    print("="*60)
    print("安装结果")
    print("="*60)
    
    if failed_checks:
        print(f"[!] 以下检查失败: {', '.join(failed_checks)}")
        print("[!] 请解决上述问题后重新运行安装脚本")
        return 1
    else:
        print("[✓] 所有检查通过！")
        print("[✓] TRAES 环境配置完成")
        print("\n使用方法:")
        print("  python main.py --help")
        print("  python main.py --mode scan --target 192.168.1.1")
        print("  python main.py --mode arp --target 192.168.1.0/24")
        return 0

if __name__ == "__main__":
    sys.exit(main())