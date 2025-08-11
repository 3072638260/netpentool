#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TRAES 网络扫描模块

实现多种网络扫描功能，包括：
- 端口扫描（TCP/UDP）
- 服务识别
- 操作系统指纹识别
- 漏洞扫描
- 网络发现
- 路径扫描
- 子域名扫描

作者: Security Researcher
版本: 1.0.0
"""

import sys
import time
import socket
import threading
import ipaddress
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Dict, Any, Tuple

try:
    import requests
    import dns.resolver
    from scapy.all import sr1, IP, TCP, UDP, ICMP
    from loguru import logger
    from colorama import Fore, Style
except ImportError as e:
    print(f"缺少必要的依赖库: {e}")
    print("请运行: pip install requests dnspython scapy loguru colorama")
    sys.exit(1)

class NetworkScanner:
    """
    网络扫描类
    
    实现各种网络扫描功能。
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        初始化网络扫描模块
        
        Args:
            config (dict): 配置字典
        """
        self.config = config or {}
        self.scan_config = self.config.get('scan', {})
        self.security_config = self.config.get('security', {})
        
        # 扫描参数
        self.max_threads = self.scan_config.get('max_threads', 100)
        self.timeout = self.scan_config.get('timeout', 3)
        self.delay = self.scan_config.get('delay', 0.01)
        self.max_ports = self.scan_config.get('max_ports', 65535)
        
        # 常用端口列表
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ]
        
        # 服务指纹
        self.service_banners = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            6379: 'Redis',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt',
            9200: 'Elasticsearch',
            27017: 'MongoDB'
        }
        
        # 白名单配置
        self.whitelist_enabled = self.security_config.get('whitelist', {}).get('enabled', True)
        self.whitelist_ips = set(self.security_config.get('whitelist', {}).get('ips', []))
        
        # 内部状态
        self.running = False
        self.scan_results = []
        self.open_ports = {}
        
        logger.info("网络扫描模块初始化完成")
    
    def is_whitelisted(self, ip: str) -> bool:
        """
        检查IP地址是否在白名单中
        
        Args:
            ip (str): IP地址
            
        Returns:
            bool: 如果在白名单中返回True
        """
        if not self.whitelist_enabled:
            return False
        return ip in self.whitelist_ips
    
    def ping_host(self, target: str) -> bool:
        """
        Ping主机检查是否在线
        
        Args:
            target (str): 目标IP地址
            
        Returns:
            bool: 主机在线返回True
        """
        try:
            # 使用系统ping命令
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', '1000', target]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
            
        except Exception:
            # 如果ping失败，尝试使用scapy发送ICMP包
            try:
                response = sr1(IP(dst=target)/ICMP(), timeout=2, verbose=False)
                return response is not None
            except Exception:
                return False
    
    def tcp_port_scan(self, target: str, port: int) -> Tuple[bool, str]:
        """
        TCP端口扫描
        
        Args:
            target (str): 目标IP地址
            port (int): 端口号
            
        Returns:
            tuple: (端口开放状态, 服务banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # 端口开放，尝试获取banner
                banner = self.get_service_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, ""
                
        except Exception as e:
            logger.debug(f"TCP扫描错误 {target}:{port} - {e}")
            return False, ""
    
    def udp_port_scan(self, target: str, port: int) -> bool:
        """
        UDP端口扫描
        
        Args:
            target (str): 目标IP地址
            port (int): 端口号
            
        Returns:
            bool: 端口开放状态
        """
        try:
            # 使用scapy发送UDP包
            response = sr1(IP(dst=target)/UDP(dport=port), timeout=2, verbose=False)
            
            if response is None:
                # 没有响应，可能端口开放
                return True
            elif response.haslayer(ICMP):
                # 收到ICMP错误，端口关闭
                return False
            else:
                # 收到UDP响应，端口开放
                return True
                
        except Exception as e:
            logger.debug(f"UDP扫描错误 {target}:{port} - {e}")
            return False
    
    def get_service_banner(self, sock: socket.socket, port: int) -> str:
        """
        获取服务banner信息
        
        Args:
            sock (socket): 已连接的socket
            port (int): 端口号
            
        Returns:
            str: 服务banner信息
        """
        try:
            # 根据端口发送特定的探测包
            if port == 80 or port == 8080:
                sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            elif port == 21:
                pass  # FTP服务器通常主动发送banner
            elif port == 22:
                pass  # SSH服务器通常主动发送banner
            elif port == 25:
                pass  # SMTP服务器通常主动发送banner
            else:
                # 对于其他端口，发送通用探测
                sock.send(b"\r\n")
            
            # 接收响应
            sock.settimeout(2)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                return banner[:100]  # 限制banner长度
            else:
                return self.service_banners.get(port, 'Unknown')
                
        except Exception:
            return self.service_banners.get(port, 'Unknown')
    
    def syn_scan(self, target: str, port: int) -> bool:
        """
        SYN扫描（隐蔽扫描）
        
        Args:
            target (str): 目标IP地址
            port (int): 端口号
            
        Returns:
            bool: 端口开放状态
        """
        try:
            # 发送SYN包
            response = sr1(
                IP(dst=target)/TCP(dport=port, flags="S"),
                timeout=2,
                verbose=False
            )
            
            if response is None:
                return False
            elif response.haslayer(TCP):
                if response[TCP].flags == 18:  # SYN+ACK
                    # 发送RST包关闭连接
                    sr1(
                        IP(dst=target)/TCP(dport=port, flags="R"),
                        timeout=1,
                        verbose=False
                    )
                    return True
                elif response[TCP].flags == 4:  # RST
                    return False
            
            return False
            
        except Exception as e:
            logger.debug(f"SYN扫描错误 {target}:{port} - {e}")
            return False
    
    def scan_port_range(self, target: str, start_port: int, end_port: int,
                       scan_type: str = 'tcp') -> Dict[int, Dict[str, Any]]:
        """
        扫描端口范围
        
        Args:
            target (str): 目标IP地址
            start_port (int): 起始端口
            end_port (int): 结束端口
            scan_type (str): 扫描类型 (tcp/udp/syn)
            
        Returns:
            dict: 开放端口信息
        """
        if self.is_whitelisted(target):
            logger.warning(f"目标 {target} 在白名单中，跳过扫描")
            return {}
        
        logger.info(f"开始扫描 {target}:{start_port}-{end_port} ({scan_type.upper()})")
        
        open_ports = {}
        self.running = True
        
        def scan_single_port(port):
            if not self.running:
                return
            
            try:
                if scan_type.lower() == 'tcp':
                    is_open, banner = self.tcp_port_scan(target, port)
                elif scan_type.lower() == 'udp':
                    is_open = self.udp_port_scan(target, port)
                    banner = self.service_banners.get(port, 'Unknown')
                elif scan_type.lower() == 'syn':
                    is_open = self.syn_scan(target, port)
                    banner = self.service_banners.get(port, 'Unknown')
                else:
                    logger.error(f"不支持的扫描类型: {scan_type}")
                    return
                
                if is_open:
                    port_info = {
                        'port': port,
                        'protocol': scan_type.upper(),
                        'service': self.service_banners.get(port, 'Unknown'),
                        'banner': banner if scan_type.lower() == 'tcp' else '',
                        'state': 'open'
                    }
                    open_ports[port] = port_info
                    
                    logger.success(
                        f"[{Fore.GREEN}开放{Style.RESET_ALL}] {target}:{port} "
                        f"({port_info['service']}) - {banner[:50] if banner else ''}"
                    )
                
                # 添加延迟
                if self.delay > 0:
                    time.sleep(self.delay)
                    
            except Exception as e:
                logger.debug(f"扫描端口 {port} 时出错: {e}")
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                ports = range(start_port, end_port + 1)
                futures = [executor.submit(scan_single_port, port) for port in ports]
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"扫描任务执行错误: {e}")
                        
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止扫描")
        except Exception as e:
            logger.error(f"端口扫描过程中出错: {e}")
        finally:
            self.running = False
            
        logger.info(f"扫描完成，发现 {len(open_ports)} 个开放端口")
        return open_ports
    
    def service_detection(self, target: str, port: int) -> Dict[str, str]:
        """
        服务版本检测
        
        Args:
            target (str): 目标IP地址
            port (int): 端口号
            
        Returns:
            dict: 服务信息
        """
        service_info = {
            'service': 'Unknown',
            'version': 'Unknown',
            'banner': ''
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            if sock.connect_ex((target, port)) == 0:
                # 获取详细banner
                banner = self.get_service_banner(sock, port)
                service_info['banner'] = banner
                
                # 解析服务和版本信息
                if port == 80 or port == 8080:
                    if 'Server:' in banner:
                        server_line = [line for line in banner.split('\n') if 'Server:' in line]
                        if server_line:
                            service_info['service'] = 'HTTP'
                            service_info['version'] = server_line[0].split('Server:')[1].strip()
                elif port == 22:
                    if 'SSH' in banner:
                        service_info['service'] = 'SSH'
                        service_info['version'] = banner.split()[0] if banner.split() else 'Unknown'
                elif port == 21:
                    if 'FTP' in banner:
                        service_info['service'] = 'FTP'
                        service_info['version'] = banner.strip()
                else:
                    service_info['service'] = self.service_banners.get(port, 'Unknown')
            
            sock.close()
            
        except Exception as e:
            logger.debug(f"服务检测错误 {target}:{port} - {e}")
        
        return service_info
    
    def os_fingerprint(self, target: str) -> Dict[str, str]:
        """
        操作系统指纹识别
        
        Args:
            target (str): 目标IP地址
            
        Returns:
            dict: 操作系统信息
        """
        os_info = {
            'os': 'Unknown',
            'confidence': '0%'
        }
        
        try:
            # 简单的TTL值检测
            response = sr1(IP(dst=target)/ICMP(), timeout=3, verbose=False)
            
            if response and response.haslayer(IP):
                ttl = response[IP].ttl
                
                if ttl <= 64:
                    if ttl > 60:
                        os_info['os'] = 'Linux/Unix'
                        os_info['confidence'] = '70%'
                    else:
                        os_info['os'] = 'Linux/Unix (Old)'
                        os_info['confidence'] = '60%'
                elif ttl <= 128:
                    if ttl > 120:
                        os_info['os'] = 'Windows'
                        os_info['confidence'] = '70%'
                    else:
                        os_info['os'] = 'Windows (Old)'
                        os_info['confidence'] = '60%'
                elif ttl <= 255:
                    os_info['os'] = 'Cisco/Network Device'
                    os_info['confidence'] = '60%'
                
        except Exception as e:
            logger.debug(f"OS指纹识别错误 {target} - {e}")
        
        return os_info
    
    def discover_hosts(self, network: str) -> List[str]:
        """
        网络主机发现
        
        Args:
            network (str): 网络地址 (如 192.168.1.0/24)
            
        Returns:
            list: 活跃主机IP列表
        """
        logger.info(f"开始发现网络 {network} 中的主机")
        
        active_hosts = []
        self.running = True
        
        try:
            network_obj = ipaddress.ip_network(network, strict=False)
            hosts = list(network_obj.hosts())
            
            def ping_host_wrapper(ip):
                if not self.running:
                    return
                
                ip_str = str(ip)
                if self.ping_host(ip_str):
                    active_hosts.append(ip_str)
                    logger.success(f"[{Fore.GREEN}活跃{Style.RESET_ALL}] {ip_str}")
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(ping_host_wrapper, ip) for ip in hosts]
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"主机发现任务执行错误: {e}")
                        
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止主机发现")
        except Exception as e:
            logger.error(f"主机发现过程中出错: {e}")
        finally:
            self.running = False
            
        logger.info(f"主机发现完成，发现 {len(active_hosts)} 个活跃主机")
        return active_hosts
    
    def subdomain_scan(self, domain: str, wordlist: List[str] = None) -> List[str]:
        """
        子域名扫描
        
        Args:
            domain (str): 主域名
            wordlist (list): 子域名字典
            
        Returns:
            list: 发现的子域名列表
        """
        if not wordlist:
            wordlist = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging',
                'api', 'blog', 'shop', 'forum', 'support', 'help',
                'news', 'portal', 'secure', 'vpn', 'remote'
            ]
        
        logger.info(f"开始扫描域名 {domain} 的子域名")
        
        found_subdomains = []
        self.running = True
        
        def check_subdomain(subdomain):
            if not self.running:
                return
            
            full_domain = f"{subdomain}.{domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = self.timeout
                answers = resolver.resolve(full_domain, 'A')
                
                if answers:
                    ips = [str(answer) for answer in answers]
                    found_subdomains.append({
                        'subdomain': full_domain,
                        'ips': ips
                    })
                    logger.success(
                        f"[{Fore.GREEN}发现{Style.RESET_ALL}] {full_domain} -> {', '.join(ips)}"
                    )
                    
            except Exception:
                pass  # 子域名不存在
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"子域名扫描任务执行错误: {e}")
                        
        except KeyboardInterrupt:
            logger.info("收到中断信号，停止子域名扫描")
        except Exception as e:
            logger.error(f"子域名扫描过程中出错: {e}")
        finally:
            self.running = False
            
        logger.info(f"子域名扫描完成，发现 {len(found_subdomains)} 个子域名")
        return found_subdomains
    
    def stop_scan(self):
        """
        停止扫描
        """
        logger.info("正在停止扫描...")
        self.running = False
    
    def run(self, args):
        """
        运行网络扫描模块
        
        Args:
            args: 命令行参数对象
        """
        try:
            if args.mode == 'port':
                # 端口扫描
                if not args.target:
                    logger.error("端口扫描模式需要指定目标")
                    return
                
                if args.port_range:
                    start_port, end_port = map(int, args.port_range.split('-'))
                elif args.ports:
                    ports = [int(p) for p in args.ports.split(',')]
                    start_port, end_port = min(ports), max(ports)
                else:
                    # 使用常用端口
                    start_port, end_port = min(self.common_ports), max(self.common_ports)
                
                scan_type = args.scan_type or 'tcp'
                results = self.scan_port_range(args.target, start_port, end_port, scan_type)
                
                if results:
                    print(f"\n{Fore.GREEN}开放端口:{Style.RESET_ALL}")
                    for port, info in results.items():
                        print(f"{port}/{info['protocol']} - {info['service']} - {info['banner'][:50]}")
            
            elif args.mode == 'host':
                # 主机发现
                if not args.network:
                    logger.error("主机发现模式需要指定网络")
                    return
                
                hosts = self.discover_hosts(args.network)
                
                if hosts:
                    print(f"\n{Fore.GREEN}活跃主机:{Style.RESET_ALL}")
                    for i, host in enumerate(hosts, 1):
                        print(f"{i}. {host}")
            
            elif args.mode == 'subdomain':
                # 子域名扫描
                if not args.domain:
                    logger.error("子域名扫描模式需要指定域名")
                    return
                
                wordlist = None
                if args.wordlist:
                    try:
                        with open(args.wordlist, 'r') as f:
                            wordlist = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        logger.error(f"加载字典文件失败: {e}")
                        return
                
                subdomains = self.subdomain_scan(args.domain, wordlist)
                
                if subdomains:
                    print(f"\n{Fore.GREEN}发现的子域名:{Style.RESET_ALL}")
                    for i, sub in enumerate(subdomains, 1):
                        print(f"{i}. {sub['subdomain']} -> {', '.join(sub['ips'])}")
            
            else:
                logger.error(f"未知的扫描模式: {args.mode}")
                
        except Exception as e:
            logger.error(f"网络扫描执行失败: {e}")
        finally:
            self.stop_scan()

# 如果直接运行此模块
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TRAES 网络扫描模块")
    parser.add_argument('--mode', '-m', required=True,
                       choices=['port', 'host', 'subdomain'],
                       help='扫描模式')
    parser.add_argument('--target', '-t', help='目标IP地址')
    parser.add_argument('--network', '-n', help='目标网络 (如 192.168.1.0/24)')
    parser.add_argument('--domain', '-d', help='目标域名')
    parser.add_argument('--port-range', '-p', help='端口范围 (如 1-1000)')
    parser.add_argument('--ports', help='指定端口 (逗号分隔)')
    parser.add_argument('--scan-type', choices=['tcp', 'udp', 'syn'], help='扫描类型')
    parser.add_argument('--wordlist', '-w', help='字典文件路径')
    parser.add_argument('--threads', type=int, help='线程数')
    parser.add_argument('--timeout', type=int, help='超时时间')
    
    args = parser.parse_args()
    
    # 创建扫描实例
    scanner = NetworkScanner()
    
    if args.threads:
        scanner.max_threads = args.threads
    if args.timeout:
        scanner.timeout = args.timeout
    
    try:
        scanner.run(args)
    except KeyboardInterrupt:
        print("\n用户中断扫描")
        scanner.stop_scan()