#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES - 网络渗透测试工具集主程序
作者: Security Researcher
版本: 1.0.0
描述: 专业的网络渗透测试工具集，支持ARP攻击、DHCP攻击、密码爆破等功能

使用示例:
    python main.py --mode arp --target 192.168.1.100 --gateway 192.168.1.1
    python main.py --mode dhcp --interface eth0 --attack-type starvation
    python main.py --mode bruteforce --target 192.168.1.100 --service ssh
"""

import sys
import os
import argparse
import json
from pathlib import Path

# 添加src目录到Python路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from colorama import init, Fore, Style
    from loguru import logger
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install -r requirements.txt")
    sys.exit(1)

# 初始化colorama
init(autoreset=True)

def setup_logger(log_level="INFO", log_file=None):
    """
    配置日志系统
    
    Args:
        log_level (str): 日志级别
        log_file (str): 日志文件路径
    """
    logger.remove()  # 移除默认处理器
    
    # 控制台输出
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>"
    )
    
    # 文件输出
    if log_file:
        logger.add(
            log_file,
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
            rotation="10 MB",
            retention="7 days"
        )

def load_config(config_path="config/config.json"):
    """
    加载配置文件
    
    Args:
        config_path (str): 配置文件路径
        
    Returns:
        dict: 配置字典
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"配置文件 {config_path} 不存在，使用默认配置")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"配置文件格式错误: {e}")
        return {}

def print_banner():
    """
    打印程序横幅
    """
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
║  {Fore.GREEN}Version: 1.0.0{Fore.CYAN}                                              ║
║  {Fore.MAGENTA}Author: Security Researcher{Fore.CYAN}                                ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def create_parser():
    """
    创建命令行参数解析器
    
    Returns:
        argparse.ArgumentParser: 参数解析器
    """
    parser = argparse.ArgumentParser(
        description="TRAES - 网络渗透测试工具集",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  ARP攻击:     python main.py --mode arp --target 192.168.1.100 --gateway 192.168.1.1
  DHCP攻击:    python main.py --mode dhcp --interface eth0
  密码爆破:    python main.py --mode bruteforce --target 192.168.1.100 --service ssh
  
注意: 本工具仅用于授权的安全测试，请确保在合法环境中使用。
        """
    )
    
    # 基本参数
    parser.add_argument('--mode', '-m', 
                       choices=['arp', 'dhcp', 'bruteforce', 'scan'],
                       required=True,
                       help='攻击模式选择')
    
    parser.add_argument('--target', '-t',
                       help='目标IP地址或IP范围')
    
    parser.add_argument('--interface', '-i',
                       help='网络接口名称')
    
    parser.add_argument('--config', '-c',
                       default='config/config.json',
                       help='配置文件路径')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='详细输出模式')
    
    parser.add_argument('--log-file',
                       help='日志文件路径')
    
    # ARP攻击参数
    arp_group = parser.add_argument_group('ARP攻击参数')
    arp_group.add_argument('--gateway', '-g',
                          help='网关IP地址')
    arp_group.add_argument('--spoof-mac',
                          help='伪造的MAC地址')
    arp_group.add_argument('--interval',
                          type=float, default=1.0,
                          help='ARP包发送间隔（秒）')
    
    # DHCP攻击参数
    dhcp_group = parser.add_argument_group('DHCP攻击参数')
    dhcp_group.add_argument('--attack-type',
                           choices=['starvation', 'rogue'],
                           default='starvation',
                           help='DHCP攻击类型')
    dhcp_group.add_argument('--threads',
                           type=int, default=10,
                           help='并发线程数')
    
    # 密码爆破参数
    brute_group = parser.add_argument_group('密码爆破参数')
    brute_group.add_argument('--service', '-s',
                            choices=['ssh', 'ftp', 'telnet', 'http', 'https'],
                            help='目标服务类型')
    brute_group.add_argument('--port', '-p',
                            type=int,
                            help='目标端口')
    brute_group.add_argument('--username', '-u',
                            help='用户名（单个）')
    brute_group.add_argument('--password',
                            help='密码（单个）')
    brute_group.add_argument('--userlist',
                            help='用户名字典文件')
    brute_group.add_argument('--passlist',
                            help='密码字典文件')
    
    return parser

def main():
    """
    主函数
    """
    # 打印横幅
    print_banner()
    
    # 解析命令行参数
    parser = create_parser()
    args = parser.parse_args()
    
    # 设置日志
    log_level = "DEBUG" if args.verbose else "INFO"
    setup_logger(log_level, args.log_file)
    
    # 加载配置
    config = load_config(args.config)
    
    logger.info("TRAES 网络渗透测试工具集启动")
    logger.info(f"运行模式: {args.mode}")
    
    try:
        # 根据模式选择相应的模块
        if args.mode == 'arp':
            from core.arp import ARPAttack
            attack = ARPAttack(config)
            attack.run(args)
            
        elif args.mode == 'dhcp':
            from core.dhcp import DHCPAttack
            attack = DHCPAttack(config)
            attack.run(args)
            
        elif args.mode == 'bruteforce':
            from core.bruteforce import BruteForce
            attack = BruteForce(config)
            attack.run(args)
            
        elif args.mode == 'scan':
            from utils.network import NetworkScanner
            scanner = NetworkScanner(config)
            scanner.run(args)
            
    except ImportError as e:
        logger.error(f"模块导入失败: {e}")
        logger.error("请确保所有核心模块文件存在")
        sys.exit(1)
        
    except KeyboardInterrupt:
        logger.warning("用户中断操作")
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)
    
    logger.info("程序执行完成")

if __name__ == '__main__':
    main()