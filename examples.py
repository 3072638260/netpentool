#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 使用示例脚本
展示各个功能模块的基本用法

使用方法:
python examples.py --demo scan
python examples.py --demo arp
python examples.py --demo dhcp
python examples.py --demo bruteforce
python examples.py --demo all
"""

import sys
import argparse
import time
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent))

try:
    from src.utils.logger import TraesLogger
    from src.utils.config_manager import ConfigManager
    from src.utils.network_utils import NetworkUtils
    from src.core.scanner import NetworkScanner
    from src.core.arp import ARPAttack
    from src.core.dhcp import DHCPAttack
    from src.core.bruteforce import BruteForce
except ImportError as e:
    print(f"[!] 模块导入失败: {e}")
    print("[!] 请先运行 python install.py 安装依赖")
    sys.exit(1)

def print_banner():
    """打印横幅"""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║                    TRAES 使用示例                           ║
║              网络渗透测试工具集演示程序                      ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def demo_scanner():
    """演示网络扫描功能"""
    print("\n" + "="*50)
    print("网络扫描演示")
    print("="*50)
    
    try:
        # 初始化扫描器
        scanner = NetworkScanner()
        
        # 演示端口扫描
        print("[+] 演示端口扫描...")
        target = "127.0.0.1"
        ports = [22, 80, 443, 3389, 5432]
        
        print(f"[+] 扫描目标: {target}")
        print(f"[+] 扫描端口: {ports}")
        
        # 模拟扫描结果
        open_ports = []
        for port in ports:
            print(f"[+] 扫描端口 {port}...", end=" ")
            time.sleep(0.1)  # 模拟扫描延迟
            
            # 模拟结果（实际应该调用真实扫描函数）
            if port in [80, 443]:  # 假设这些端口开放
                print("开放")
                open_ports.append(port)
            else:
                print("关闭")
        
        print(f"\n[✓] 扫描完成，发现开放端口: {open_ports}")
        
        # 演示服务识别
        print("\n[+] 演示服务识别...")
        for port in open_ports:
            if port == 80:
                print(f"[+] 端口 {port}: HTTP 服务")
            elif port == 443:
                print(f"[+] 端口 {port}: HTTPS 服务")
        
        print("[✓] 网络扫描演示完成")
        
    except Exception as e:
        print(f"[!] 扫描演示失败: {e}")

def demo_arp():
    """演示ARP攻击功能"""
    print("\n" + "="*50)
    print("ARP攻击演示")
    print("="*50)
    
    try:
        # 初始化ARP攻击器
        arp_attack = ARPAttack()
        
        print("[+] 演示ARP扫描...")
        network = "192.168.1.0/24"
        print(f"[+] 扫描网络: {network}")
        
        # 模拟ARP扫描结果
        discovered_hosts = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Router"},
            {"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff", "vendor": "PC"},
            {"ip": "192.168.1.101", "mac": "11:22:33:44:55:66", "vendor": "Mobile"}
        ]
        
        print("[+] 发现的主机:")
        for host in discovered_hosts:
            print(f"    {host['ip']} - {host['mac']} ({host['vendor']})")
        
        print("\n[+] 演示ARP欺骗配置...")
        target_ip = "192.168.1.100"
        gateway_ip = "192.168.1.1"
        
        print(f"[+] 目标主机: {target_ip}")
        print(f"[+] 网关地址: {gateway_ip}")
        print("[+] 攻击类型: 双向ARP欺骗")
        print("[!] 注意: 这是演示模式，未执行实际攻击")
        
        # 模拟攻击过程
        print("\n[+] 模拟攻击过程...")
        for i in range(3):
            print(f"[+] 发送ARP欺骗包 {i+1}/3")
            time.sleep(0.5)
        
        print("[✓] ARP攻击演示完成")
        
    except Exception as e:
        print(f"[!] ARP演示失败: {e}")

def demo_dhcp():
    """演示DHCP攻击功能"""
    print("\n" + "="*50)
    print("DHCP攻击演示")
    print("="*50)
    
    try:
        # 初始化DHCP攻击器
        dhcp_attack = DHCPAttack()
        
        print("[+] 演示DHCP发现...")
        print("[+] 扫描DHCP服务器...")
        
        # 模拟DHCP服务器发现
        dhcp_servers = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "lease_time": 86400}
        ]
        
        for server in dhcp_servers:
            print(f"[+] 发现DHCP服务器: {server['ip']} ({server['mac']})")
            print(f"    租约时间: {server['lease_time']}秒")
        
        print("\n[+] 演示DHCP饥饿攻击配置...")
        print("[+] 攻击类型: DHCP地址池耗尽")
        print("[+] 请求数量: 100")
        print("[!] 注意: 这是演示模式，未执行实际攻击")
        
        # 模拟攻击过程
        print("\n[+] 模拟攻击过程...")
        for i in range(5):
            fake_mac = f"aa:bb:cc:dd:ee:{i:02x}"
            print(f"[+] 使用伪造MAC {fake_mac} 请求IP地址")
            time.sleep(0.3)
        
        print("[✓] DHCP攻击演示完成")
        
    except Exception as e:
        print(f"[!] DHCP演示失败: {e}")

def demo_bruteforce():
    """演示密码爆破功能"""
    print("\n" + "="*50)
    print("密码爆破演示")
    print("="*50)
    
    try:
        # 初始化爆破器
        bruteforce = BruteForce()
        
        print("[+] 演示SSH密码爆破...")
        target = "192.168.1.100"
        port = 22
        
        print(f"[+] 目标主机: {target}:{port}")
        print("[+] 协议: SSH")
        
        # 模拟用户名和密码字典
        usernames = ["admin", "root", "user", "test"]
        passwords = ["123456", "password", "admin", "root"]
        
        print(f"[+] 用户名字典: {len(usernames)} 个")
        print(f"[+] 密码字典: {len(passwords)} 个")
        print(f"[+] 总组合数: {len(usernames) * len(passwords)}")
        
        print("\n[+] 模拟爆破过程...")
        found_credentials = []
        
        for username in usernames[:2]:  # 只演示前2个用户名
            for password in passwords[:2]:  # 只演示前2个密码
                print(f"[+] 尝试: {username}:{password}", end=" ")
                time.sleep(0.2)
                
                # 模拟爆破结果
                if username == "admin" and password == "admin":
                    print("成功!")
                    found_credentials.append((username, password))
                else:
                    print("失败")
        
        if found_credentials:
            print(f"\n[✓] 发现有效凭据: {found_credentials}")
        else:
            print("\n[!] 未发现有效凭据")
        
        print("[!] 注意: 这是演示模式，未执行实际爆破")
        print("[✓] 密码爆破演示完成")
        
    except Exception as e:
        print(f"[!] 爆破演示失败: {e}")

def demo_utils():
    """演示工具函数"""
    print("\n" + "="*50)
    print("工具函数演示")
    print("="*50)
    
    try:
        # 演示网络工具
        print("[+] 演示网络工具...")
        net_utils = NetworkUtils()
        
        # 获取本机IP
        local_ip = net_utils.get_local_ip()
        print(f"[+] 本机IP: {local_ip}")
        
        # 获取网络接口
        interfaces = net_utils.get_network_interfaces()
        print(f"[+] 网络接口数量: {len(interfaces)}")
        
        # 演示配置管理
        print("\n[+] 演示配置管理...")
        config = ConfigManager()
        
        # 读取配置
        log_level = config.get('logging.level', 'INFO')
        print(f"[+] 日志级别: {log_level}")
        
        # 演示日志系统
        print("\n[+] 演示日志系统...")
        logger = TraesLogger()
        
        logger.info("这是一条信息日志")
        logger.warning("这是一条警告日志")
        logger.error("这是一条错误日志")
        
        print("[✓] 工具函数演示完成")
        
    except Exception as e:
        print(f"[!] 工具演示失败: {e}")

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="TRAES 使用示例")
    parser.add_argument("--demo", choices=["scan", "arp", "dhcp", "bruteforce", "utils", "all"],
                       default="all", help="选择演示模块")
    parser.add_argument("--verbose", action="store_true", help="详细输出")
    
    args = parser.parse_args()
    
    print_banner()
    
    print("\n[!] 重要提醒:")
    print("[!] 这些示例仅用于学习和授权测试")
    print("[!] 请勿在未授权的网络环境中使用")
    print("[!] 使用者需承担相应的法律责任")
    
    input("\n按回车键继续演示...")
    
    # 根据选择运行演示
    if args.demo == "scan" or args.demo == "all":
        demo_scanner()
    
    if args.demo == "arp" or args.demo == "all":
        demo_arp()
    
    if args.demo == "dhcp" or args.demo == "all":
        demo_dhcp()
    
    if args.demo == "bruteforce" or args.demo == "all":
        demo_bruteforce()
    
    if args.demo == "utils" or args.demo == "all":
        demo_utils()
    
    print("\n" + "="*60)
    print("演示完成")
    print("="*60)
    print("[✓] 所有演示已完成")
    print("\n更多使用方法:")
    print("  python main.py --help")
    print("  python main.py --mode scan --target 192.168.1.1 --ports 80,443")
    print("  python main.py --mode arp --target 192.168.1.0/24 --discover")
    print("  python main.py --mode bruteforce --target 192.168.1.100 --service ssh")

if __name__ == "__main__":
    main()