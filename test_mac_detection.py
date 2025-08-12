#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MAC地址获取功能测试脚本

用于测试改进后的MAC地址获取功能，包括：
- ARP表查询
- ping预热
- ARP请求重试
- 多种获取策略

作者: Security Researcher
版本: 1.0.0
"""

import sys
import os
import argparse
import time
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

def setup_logger(verbose=False):
    """
    设置日志配置
    
    Args:
        verbose (bool): 是否启用详细日志
    """
    logger.remove()
    
    log_level = "DEBUG" if verbose else "INFO"
    
    logger.add(
        sys.stdout,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
        level=log_level,
        colorize=True
    )

def print_banner():
    """
    打印程序横幅
    """
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    TRAES MAC地址获取测试工具                    ║
║                                                              ║
║  功能: 测试改进后的MAC地址获取功能                              ║
║  版本: 1.0.0                                                ║
║  作者: Security Researcher                                   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def test_single_ip(attack, ip, interface=None):
    """
    测试单个IP的MAC地址获取
    
    Args:
        attack: ARP攻击实例
        ip (str): 目标IP地址
        interface (str): 网络接口
    """
    print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}测试目标: {ip}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
    
    start_time = time.time()
    
    try:
        mac = attack.get_mac_address(ip, interface)
        
        end_time = time.time()
        duration = end_time - start_time
        
        if mac:
            print(f"{Fore.GREEN}✓ 成功获取MAC地址: {mac}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}耗时: {duration:.2f}秒{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}✗ 无法获取MAC地址{Style.RESET_ALL}")
            print(f"{Fore.CYAN}耗时: {duration:.2f}秒{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        end_time = time.time()
        duration = end_time - start_time
        print(f"{Fore.RED}✗ 获取MAC地址时出错: {e}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}耗时: {duration:.2f}秒{Style.RESET_ALL}")
        return False

def test_batch_ips(attack, ip_file, interface=None):
    """
    批量测试IP的MAC地址获取
    
    Args:
        attack: ARP攻击实例
        ip_file (str): IP文件路径
        interface (str): 网络接口
    """
    try:
        targets = attack.load_targets_from_file(ip_file)
        
        if not targets:
            logger.error(f"无法从文件 {ip_file} 中加载目标")
            return
        
        print(f"\n{Fore.CYAN}批量测试开始，共 {len(targets)} 个目标{Style.RESET_ALL}")
        
        success_count = 0
        total_time = 0
        
        for i, ip in enumerate(targets, 1):
            print(f"\n{Fore.BLUE}[{i}/{len(targets)}] 测试 {ip}{Style.RESET_ALL}")
            
            start_time = time.time()
            success = test_single_ip(attack, ip, interface)
            end_time = time.time()
            
            if success:
                success_count += 1
            
            total_time += (end_time - start_time)
            
            # 避免过于频繁的请求
            if i < len(targets):
                time.sleep(0.5)
        
        # 统计结果
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}批量测试完成{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"总目标数: {len(targets)}")
        print(f"成功获取: {success_count}")
        print(f"失败数量: {len(targets) - success_count}")
        print(f"成功率: {success_count/len(targets)*100:.1f}%")
        print(f"总耗时: {total_time:.2f}秒")
        print(f"平均耗时: {total_time/len(targets):.2f}秒/目标")
        
    except Exception as e:
        logger.error(f"批量测试时出错: {e}")

def main():
    """
    主函数
    """
    parser = argparse.ArgumentParser(
        description="TRAES MAC地址获取测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  测试单个IP:
    python test_mac_detection.py --ip 192.168.0.1 --interface WLAN
    
  批量测试:
    python test_mac_detection.py --batch ip.txt --interface WLAN
    
  详细日志:
    python test_mac_detection.py --ip 192.168.0.1 --verbose
        """
    )
    
    parser.add_argument('--ip', help='测试单个IP地址')
    parser.add_argument('--batch', help='批量测试，指定IP文件路径')
    parser.add_argument('--interface', '-i', help='网络接口名称 (如: WLAN, eth0)')
    parser.add_argument('--verbose', '-v', action='store_true', help='启用详细日志')
    parser.add_argument('--config', default='config/config.json', help='配置文件路径')
    
    args = parser.parse_args()
    
    # 检查参数
    if not args.ip and not args.batch:
        parser.error("必须指定 --ip 或 --batch 参数")
    
    if args.ip and args.batch:
        parser.error("--ip 和 --batch 参数不能同时使用")
    
    # 打印横幅
    print_banner()
    
    # 设置日志
    setup_logger(args.verbose)
    
    try:
        # 导入ARP攻击模块
        from core.arp import ARPAttack
        
        # 加载配置
        config = {}
        if os.path.exists(args.config):
            import json
            with open(args.config, 'r', encoding='utf-8') as f:
                config = json.load(f)
        
        # 创建攻击实例
        attack = ARPAttack(config)
        
        logger.info("MAC地址获取测试开始")
        
        if args.ip:
            # 单个IP测试
            logger.info(f"测试单个IP: {args.ip}")
            if args.interface:
                logger.info(f"使用网络接口: {args.interface}")
            
            success = test_single_ip(attack, args.ip, args.interface)
            
            if success:
                logger.info("单个IP测试成功")
            else:
                logger.warning("单个IP测试失败")
        
        elif args.batch:
            # 批量测试
            if not os.path.exists(args.batch):
                logger.error(f"文件不存在: {args.batch}")
                sys.exit(1)
            
            logger.info(f"批量测试文件: {args.batch}")
            if args.interface:
                logger.info(f"使用网络接口: {args.interface}")
            
            test_batch_ips(attack, args.batch, args.interface)
        
        logger.info("MAC地址获取测试完成")
        
    except ImportError as e:
        logger.error(f"模块导入失败: {e}")
        logger.error("请确保所有核心模块文件存在")
        sys.exit(1)
    
    except KeyboardInterrupt:
        logger.warning("用户中断测试")
        sys.exit(0)
    
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
        if args.verbose:
            import traceback
            logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()